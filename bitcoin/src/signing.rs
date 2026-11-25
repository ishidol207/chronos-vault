use std::collections::HashSet;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1, ecdsa::Signature};
use bitcoin::{CompressedPublicKey, SegwitV0Sighash, Witness, ecdsa};
use serde::{Deserialize, Serialize};
use threshold_ecdsa_online::{PresignRecord, Secp256k1Share, combine_pair};

use crate::transaction::{Prepared, prepare};
use crate::{SignRequest, SignedTransaction, VaultError};

/// Public transport document shared with both signers. All parties rebuild the
/// unsigned transaction from the same prevouts, amounts and payment intent.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningPackage {
    pub public_key: CompressedPublicKey,
    pub signers: [u64; 2],
    pub request: SignRequest,
    pub unsigned_tx_hex: String,
}

#[derive(Debug, Serialize)]
pub struct PaymentReview {
    pub sender_address: String,
    pub recipient_address: String,
    pub sent_sat: u64,
    pub fee_sat: u64,
    pub change_sat: u64,
    pub input_sighashes: Vec<SegwitV0Sighash>,
}

impl SigningPackage {
    pub fn new(
        public_key: CompressedPublicKey,
        signers: [u64; 2],
        request: SignRequest,
    ) -> Result<Self, VaultError> {
        if signers[0] == signers[1] {
            return Err(VaultError::WrongParty);
        }
        let prepared = prepare(&public_key, &request)?;
        prepared.check_funding(&request, &public_key)?;
        let unsigned_tx_hex = serialize_hex(&prepared.tx);
        Ok(Self {
            public_key,
            signers,
            request,
            unsigned_tx_hex,
        })
    }

    /// Rebuild and validate before presenting this summary for local approval.
    pub fn review(&self) -> Result<PaymentReview, VaultError> {
        let plan = self.checked()?;
        Ok(PaymentReview {
            sender_address: self.request.sender_address.clone(),
            recipient_address: self.request.recipient_address.clone(),
            sent_sat: plan.sent_sat,
            fee_sat: plan.fee_sat,
            change_sat: plan.change_sat,
            input_sighashes: plan.digests,
        })
    }

    fn checked(&self) -> Result<Prepared, VaultError> {
        if self.signers[0] == self.signers[1] {
            return Err(VaultError::WrongParty);
        }
        let prepared = prepare(&self.public_key, &self.request)?;
        if self.unsigned_tx_hex != serialize_hex(&prepared.tx) {
            return Err(VaultError::PackageMismatch);
        }
        prepared.check_funding(&self.request, &self.public_key)?;
        Ok(prepared)
    }
}

/// Obtained locally at key generation, independent of the coordinator's package.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerIdentity {
    pub party_id: u64,
    pub peer_id: u64,
    pub public_key: CompressedPublicKey,
}

impl SignerIdentity {
    pub fn check_quorum(&self, package: &SigningPackage) -> Result<(), VaultError> {
        if self.public_key != package.public_key
            || self.party_id == self.peer_id
            || !package.signers.contains(&self.party_id)
            || !package.signers.contains(&self.peer_id)
        {
            return Err(VaultError::WrongParty);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputShare {
    pub sighash: SegwitV0Sighash,
    pub partial: Secp256k1Share,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartyResponse {
    pub party_id: u64,
    pub inputs: Vec<InputShare>,
}

pub(crate) struct PendingShare {
    pub(crate) nonce_ids: Vec<[u8; 32]>,
    pub(crate) response: PartyResponse,
}

pub(crate) fn stage_share(
    identity: &SignerIdentity,
    package: &SigningPackage,
    records: Vec<PresignRecord>,
) -> Result<PendingShare, VaultError> {
    identity.check_quorum(package)?;
    let prepared = package.checked()?;
    let nonce_ids: Vec<_> = records.iter().map(PresignRecord::nonce_id).collect();
    if records.len() != prepared.digests.len()
        || nonce_ids.iter().collect::<HashSet<_>>().len() != records.len()
    {
        return Err(VaultError::InvalidPresign);
    }
    let inputs = records
        .into_iter()
        .zip(prepared.digests)
        .map(|(record, sighash)| {
            let partial = record
                .sign(sighash.to_byte_array())
                .ok_or(VaultError::InvalidPresign)?;
            Ok(InputShare { sighash, partial })
        })
        .collect::<Result<_, VaultError>>()?;
    Ok(PendingShare {
        nonce_ids,
        response: PartyResponse {
            party_id: identity.party_id,
            inputs,
        },
    })
}

/// The signer supplies a durable create-if-absent store for public nonce IDs.
/// A failed claim never releases a signature share.
pub fn sign_share(
    identity: &SignerIdentity,
    package: &SigningPackage,
    records: Vec<PresignRecord>,
    claim_unused: impl FnOnce(&[[u8; 32]]) -> Result<(), VaultError>,
) -> Result<PartyResponse, VaultError> {
    let pending = stage_share(identity, package, records)?;
    claim_unused(&pending.nonce_ids)?;
    Ok(pending.response)
}

pub fn combine(
    package: &SigningPackage,
    a: &PartyResponse,
    b: &PartyResponse,
) -> Result<SignedTransaction, VaultError> {
    let mut prepared = package.checked()?;
    if a.party_id == b.party_id
        || ![a.party_id, b.party_id]
            .iter()
            .all(|id| package.signers.contains(id))
    {
        return Err(VaultError::WrongParty);
    }
    if a.inputs.len() != prepared.digests.len() || b.inputs.len() != prepared.digests.len() {
        return Err(VaultError::InvalidShares);
    }

    let secp = Secp256k1::verification_only();
    let mut used = HashSet::new();
    for (index, sighash) in prepared.digests.into_iter().enumerate() {
        let (left, right) = (&a.inputs[index], &b.inputs[index]);
        if left.sighash != sighash
            || right.sighash != sighash
            || !used.insert(left.partial.r.to_bytes())
        {
            return Err(VaultError::InvalidShares);
        }
        let compact =
            combine_pair(&left.partial, &right.partial).ok_or(VaultError::InvalidShares)?;
        let sig = Signature::from_compact(&compact).map_err(|_| VaultError::InvalidShares)?;
        secp.verify_ecdsa(&Message::from(sighash), &sig, &package.public_key.0)
            .map_err(|_| VaultError::InvalidShares)?;
        prepared.tx.input[index].witness =
            Witness::p2wpkh(&ecdsa::Signature::sighash_all(sig), &package.public_key.0);
    }
    Ok(SignedTransaction {
        txid: prepared.tx.compute_txid(),
        raw_tx_hex: serialize_hex(&prepared.tx),
        sent_sat: prepared.sent_sat,
        change_sat: prepared.change_sat,
        fee_sat: prepared.fee_sat,
        vsize: prepared.tx.vsize(),
    })
}

// Copyright (c) 2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use std::{collections::HashSet, fmt::Debug};

use generic_array::{typenum::U32, GenericArray};
use rand::{CryptoRng, RngCore};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use sha3::{Digest, Keccak256};
use tracing::{error, info};
use threshold_ecdsa_online::{PartialSignature, SigningScalar};
use zeroize::Zeroize;

use crate::{
    curve::{CurveTrait, ScalarTrait, SignatureTrait, VerifyingKeyTrait},
    errors::{CallerError, InternalError, Result},
    keygen::KeySharePublic,
    local_storage::LocalStorage,
    messages::{Message, MessageType, SignMessageType},
    participant::{InnerProtocolParticipant, ProcessOutcome},
    protocol::{ProtocolType, SharedContext},
    sign::non_interactive_sign::share::SignatureShare,
    zkp::ProofContext,
    Identifier, ParticipantConfig, ParticipantIdentifier, PresignRecord, ProtocolParticipant,
};

/// A participant that runs the non-interactive signing protocol.
///
/// # Protocol input
/// The protocol takes two fields as input:
/// - a message digest, which is the hash of the message to be signed. This
///   library expects a 256-bit digest (e.g. produced by SHA3-256 (Keccak)).
/// - a [`PresignRecord`]. This must be fresh (never used for any other
///   execution of the threshold ECDSA protocol, even a failed run) and must
///   have been generated using the private share of the key under which the
///   caller desires a signature.
///
///
/// # Protocol output
/// Upon successful completion, the participant outputs a Signature.
/// The signature is on the message which was used to produce the provided
///   input message digest. It verifies under the public verification key
/// corresponding to the private signing key used to produce the input
///   [`PresignRecord`].
///
/// # 🔒 Storage requirement
/// The [`PresignRecord`] provided as input must be discarded; no copies should
/// remain after use.
#[derive(Debug, Default)]
pub struct SignParticipant<C: CurveTrait> {
    sid: Identifier,
    storage: LocalStorage,
    input: Input<C>,
    config: ParticipantConfig,
}

/// Input for the non-interactive signing protocol.
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(bound = "C: CurveTrait")]
pub struct Input<C: CurveTrait> {
    message: Vec<u8>,
    presign_record: PresignRecord<C>,
    public_key_shares: Vec<KeySharePublic<C>>,
    threshold: usize,
}

impl<C: CurveTrait> Input<C> {
    /// Construct a new input for signing.
    ///
    /// The `public_key_shares` should be the same ones used to generate the
    /// [`PresignRecord`].
    pub fn new(
        message: &[u8],
        record: PresignRecord<C>,
        public_key_shares: Vec<KeySharePublic<C>>,
        threshold: usize,
    ) -> Self {
        Self {
            message: message.to_vec(),
            presign_record: record,
            public_key_shares,
            threshold,
        }
    }

    /// Retrieve the presign record.
    pub(crate) fn presign_record(&self) -> &PresignRecord<C> {
        &self.presign_record
    }

    /// Compute the digest. Note that this forces a clone of the [`Keccak256`]
    /// object.
    pub(crate) fn digest_hash(&self) -> GenericArray<u8, U32> {
        Keccak256::digest(&self.message)
    }

    /// Compute the public key.
    pub fn public_key(&self) -> Result<C::VerifyingKey> {
        // Add up all the key shares
        let public_key_point = self
            .public_key_shares
            .iter()
            .fold(C::IDENTITY, |sum, share| sum + *share.as_ref());

        C::VerifyingKey::from_point(public_key_point)
    }
}

/// Context for fiat-Shamir proofs generated in the non-interactive signing
/// protocol.
///
/// Note that this is only used in the case of identifiable abort, which is not
/// yet implemented. A correct execution of signing does not involve any ZK
/// proofs.
pub(crate) struct SignContext<C: CurveTrait> {
    shared_context: SharedContext<C>,
    message_digest: [u8; 32],
}

impl<C: CurveTrait> ProofContext for SignContext<C> {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        Ok([
            self.shared_context.as_bytes()?,
            self.message_digest.to_vec(),
        ]
        .concat())
    }
}

impl<C: CurveTrait> SignContext<C> {
    /// Build a [`SignContext`] from a [`SignParticipant`].
    pub(crate) fn collect(p: &SignParticipant<C>) -> Self {
        Self {
            shared_context: SharedContext::collect(p),
            message_digest: p.input.digest_hash().into(),
        }
    }
}

mod storage {

    use crate::{
        curve::CurveTrait, local_storage::TypeTag,
        sign::non_interactive_sign::share::SignatureShare,
    };
    pub(super) struct Share<C: CurveTrait> {
        _c: std::marker::PhantomData<C>,
    }
    impl<C: CurveTrait> TypeTag for Share<C> {
        type Value = SignatureShare<C>;
    }

    pub(super) struct XProj<C: CurveTrait> {
        _c: std::marker::PhantomData<C>,
    }
    impl<C: CurveTrait> TypeTag for XProj<C> {
        type Value = C::Scalar;
    }
}

impl<C: CurveTrait> ProtocolParticipant for SignParticipant<C> {
    type Input = Input<C>;

    type Output = C::ECDSASignature;

    fn ready_type() -> MessageType {
        MessageType::Sign(SignMessageType::Ready)
    }

    fn protocol_type() -> ProtocolType {
        ProtocolType::Sign
    }

    fn new(
        sid: Identifier,
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
        input: Self::Input,
    ) -> Result<Self>
    where
        Self: Sized,
    {
        let config = ParticipantConfig::new(id, &other_participant_ids)?;

        // The input must contain exactly one public key per participant ID.
        let public_key_pids = input
            .public_key_shares
            .iter()
            .map(|share| share.participant())
            .collect::<HashSet<_>>();
        let pids = std::iter::once(id)
            .chain(other_participant_ids)
            .collect::<HashSet<_>>();
        if public_key_pids != pids || config.count() != input.public_key_shares.len() {
            Err(CallerError::BadInput)?
        }
        if config.count() < input.threshold {
            Err(CallerError::BadInput)?
        }

        Ok(Self {
            sid,
            config,
            input,
            storage: Default::default(),
        })
    }

    fn id(&self) -> ParticipantIdentifier {
        self.config.id()
    }

    fn other_ids(&self) -> &[ParticipantIdentifier] {
        self.config.other_ids()
    }

    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!("Processing message");
        match message.message_type() {
            MessageType::Sign(SignMessageType::Ready) => {
                let res = self.gen_round_one_msgs(rng, self.sid);
                if let Err(e) = res {
                    error!("Failed to generate round one messages: {:?}", e);
                    return Err(e);
                } else {
                    let msgs = res.unwrap();
                    info!(
                        "SIGN: Player {} generated round one message: {:?}",
                        self.id(),
                        msgs
                    );
                    return Ok(ProcessOutcome::Continue(msgs));
                }
            }
            MessageType::Sign(SignMessageType::RoundOneShare) => {
                self.handle_round_one_msg(message)?;
                if self.is_r1_done() {
                    info!("SIGN: Player {} is done with round one", self.id());
                    let output = self.compute_output()?;
                    return Ok(ProcessOutcome::Done(output));
                } else {
                    info!("SIGN: Player {} is not done with round one", self.id());
                    return Ok(ProcessOutcome::Continue(vec![]));
                }
            }
            _ => {
                error!(
                    "SIGN: Player {}: received unexpected message type {:?}",
                    self.id(),
                    message.message_type()
                );
                Err(CallerError::BadInput)?
            }
        }
    }

    fn sid(&self) -> Identifier {
        self.sid
    }
}

impl<C: CurveTrait> InnerProtocolParticipant for SignParticipant<C> {
    type Context = SignContext<C>;

    fn retrieve_context(&self) -> Self::Context {
        SignContext::collect(self)
    }

    fn local_storage(&self) -> &LocalStorage {
        &self.storage
    }

    fn local_storage_mut(&mut self) -> &mut LocalStorage {
        &mut self.storage
    }
}

impl<C: CurveTrait> SignParticipant<C> {
    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        _sid: Identifier,
    ) -> Result<Vec<Message>> {
        let record = self.input.presign_record();

        // Interpret the message digest as an integer mod `q`. This matches the way that
        // the k256 library converts a digest to a scalar.
        let digest_bytes = self.input.digest_hash();
        // Compute the digest as a C::Scalar
        let digest = C::Scalar::from_bytes(&digest_bytes)?.unwrap();

        // Compute the x-projection of `R` from the `PresignRecord`
        let x_projection = record.x_projection()?;

        // Compute the share
        let partial = C::Scalar::partial(
            x_projection, *record.mask_share(), *record.masked_key_share(), digest,
        );
        let share = SignatureShare::<C>::new(partial.r, partial.share);

        // Erase the presign record
        self.input.presign_record.zeroize();

        // Save pieces for our own use later
        self.storage
            .store::<storage::Share<C>>(self.id(), share.clone());
        self.storage
            .store::<storage::XProj<C>>(self.id(), x_projection);

        // Form output message
        let broadcast_msgs = Message::new(
            MessageType::Sign(SignMessageType::RoundOneShare),
            self.sid,
            self.id(),
            None,
            true,
            &share,
        )?;

        Ok(vec![broadcast_msgs])
    }

    fn handle_round_one_msg(&mut self, message: &Message) -> Result<()> {
        // Save this signature share
        let share = SignatureShare::try_from(message)?;
        self.storage
            .store_once::<storage::Share<C>>(message.from(), share)?;

        Ok(())
    }

    fn is_r1_done(&self) -> bool {
        self.storage
            .contains_for_all_ids::<storage::Share<C>>(&self.all_participants())
    }

    fn compute_output(&mut self) -> Result<<Self as ProtocolParticipant>::Output> {
        // Retrieve everyone's share and the x-projection we saved in round one
        // (This will fail if we're missing any shares)

        if !self.is_r1_done() {
            error!("Not all shares are available for signing.");
            return Err(InternalError::InternalInvariantFailed);
        }

        // Retrieve everyone's id and share
        let shares = self
            .all_participants()
            .into_iter()
            .map(|pid| self.storage.remove::<storage::Share<C>>(pid))
            .collect::<Result<Vec<_>>>()?;

        let x_projection = self.storage.remove::<storage::XProj<C>>(self.id())?;

        // Sum up the signature shares and convert to BIP-0062 format (negating if the
        // sum is > group order /2)
        let partials: Vec<_> = shares.into_iter()
            .map(|part| PartialSignature { r: part.r, share: part.share })
            .collect();
        let (r, sum) = C::Scalar::combine(&partials).ok_or(InternalError::ProtocolError(None))?;
        if r != x_projection {
            return Err(InternalError::ProtocolError(None));
        }

        let signature = C::ECDSASignature::from_scalars(
            &C::scalar_to_bn(&x_projection),
            &C::scalar_to_bn(&sum),
        )?;

        self.input
            .public_key()?
            .verify_signature(
                Keccak256::new_with_prefix(self.input.message.clone()),
                signature,
            )
            .map_err(|e| {
                error!("Failed to verify signature {:?}", e);
                InternalError::ProtocolError(None)
            })?;

        Ok(signature)
    }
}

#[cfg(test)]
pub mod test {
    use crate::{
        curve::{SignatureTrait, TestCurve, VerifyingKeyTrait},
        ParticipantIdentifier,
    };
    use std::{collections::HashMap, ops::Deref};

    use k256::{
        ecdsa::{signature::DigestVerifier, RecoveryId},
        elliptic_curve::ops::Reduce,
        U256,
    };
    use rand::{CryptoRng, Rng, RngCore};
    use sha3::{Digest, Keccak256};
    use tracing::debug;

    use crate::{
        curve::{CurveTrait, ScalarTrait},
        errors::Result,
        keygen,
        messages::{Message, MessageType},
        participant::ProcessOutcome,
        presign, sign,
        sign::non_interactive_sign::participant::Input,
        utils::testing::init_testing,
        Identifier, ParticipantConfig, ProtocolParticipant,
    };

    type PresignRecord = presign::PresignRecord<TestCurve>;

    type SignParticipant = super::SignParticipant<TestCurve>;

    #[test]
    fn signing_always_works() {
        for _ in 0..1000 {
            signing_produces_valid_signature().unwrap()
        }
    }

    /// This method is used for debugging. It "simulates" the non-distributed
    /// ECDSA signing algorithm by reconstructing the mask `k` and secret
    /// key fields from the presign records and keygen outputs,
    /// respectively, and using them to compute the signature.
    ///
    /// It can be used to check that the distributed signature is being computed
    /// correctly according to the presign record.
    pub fn compute_non_distributed_ecdsa(
        message: &[u8],
        records: &[PresignRecord],
        keygen_outputs: &[keygen::Output<TestCurve>],
    ) -> <TestCurve as CurveTrait>::ECDSASignature {
        let k = records
            .iter()
            .map(|record| record.mask_share())
            .fold(<TestCurve as CurveTrait>::Scalar::zero(), |a, b| a + b);

        let secret_key = keygen_outputs
            .iter()
            .map(|output| TestCurve::bn_to_scalar(output.private_key_share().as_ref()).unwrap())
            .fold(<TestCurve as CurveTrait>::Scalar::zero(), |a, b| a + b);

        let r = records[0].x_projection().unwrap();

        let m = <<TestCurve as CurveTrait>::Scalar as Reduce<U256>>::reduce_bytes(
            &Keccak256::digest(message),
        );

        let mut s: <TestCurve as CurveTrait>::Scalar = k * (m + r * secret_key);

        if s.is_high() {
            s = s.negate();
        }

        let signature = <TestCurve as CurveTrait>::ECDSASignature::from_scalars(
            &<TestCurve as CurveTrait>::scalar_to_bn(&r),
            &<TestCurve as CurveTrait>::scalar_to_bn(&s),
        )
        .unwrap();

        // These checks fail when the overall thing fails
        let public_key: <TestCurve as CurveTrait>::VerifyingKey =
            keygen_outputs[0].public_key().unwrap();

        assert!(public_key
            .verify_signature(Keccak256::new_with_prefix(message), signature)
            .is_ok());
        signature
    }

    #[test]
    fn signing_produces_valid_signature() -> Result<()> {
        let quorum_size = 4;
        let mut rng = &mut init_testing();
        let sid = Identifier::random(rng);

        // Prepare prereqs for making SignParticipants. Assume all the simulations
        // are stable (e.g. keep config order)
        let configs = ParticipantConfig::random_quorum(quorum_size, rng)?;
        let keygen_outputs = keygen::Output::simulate_set(&configs, rng);
        let presign_records = PresignRecord::simulate_set(&keygen_outputs, rng);

        let message = b"the quick brown fox jumped over the lazy dog";
        let digest = Keccak256::new_with_prefix(message);

        // Save some things for later -- a signature constructucted from the records and
        // the public key
        let non_distributed_sig =
            compute_non_distributed_ecdsa(message, &presign_records, &keygen_outputs);
        let public_key = &keygen_outputs[0].public_key().unwrap();

        // Form signing inputs and participants
        let inputs = std::iter::zip(keygen_outputs, presign_records).map(|(keygen, record)| {
            Input::new(
                message,
                record,
                keygen.public_key_shares().to_vec(),
                quorum_size,
            )
        });
        let mut quorum = std::iter::zip(configs, inputs)
            .map(|(config, input)| {
                SignParticipant::new(sid, config.id(), config.other_ids().to_vec(), input)
            })
            .collect::<Result<Vec<_>>>()?;

        // Prepare caching of data (outputs and messages) for protocol execution
        let mut outputs = HashMap::with_capacity(quorum_size);

        let mut inbox: HashMap<ParticipantIdentifier, Vec<Message>> =
            quorum.iter().map(|p| (p.id(), Vec::new())).collect();

        let quorum_ids: Vec<_> = quorum.iter().map(|p| p.id()).collect();
        for i in 0..quorum.len() {
            let p = &mut quorum[i];
            let mut broadcast_msgs = p.gen_round_one_msgs(&mut rng, sid)?;
            for (j, other_id) in quorum_ids.iter().enumerate() {
                if i != j {
                    broadcast_msgs[0].set_to(Some(*other_id));
                    inbox
                        .get_mut(other_id)
                        .unwrap()
                        .push(broadcast_msgs[0].clone());
                }
            }
        }

        // Each participant processes all R1 messages
        for p in quorum.iter_mut() {
            for msg in inbox.get(&p.id()).unwrap() {
                p.handle_round_one_msg(&msg)?;
            }
            let output = p.compute_output()?;
            outputs.insert(p.id(), output);
        }

        // Everyone should have gotten an output
        assert_eq!(outputs.len(), quorum.len());
        let signatures = outputs.into_values().collect::<Vec<_>>();

        // Everyone should have gotten the same output. We don't use a hashset because
        // the underlying signature type doesn't derive `Hash`
        assert!(signatures
            .windows(2)
            .all(|signature| signature[0] == signature[1]));

        // Make sure the signature we got matches the non-distributed one
        let distributed_sig = &signatures[0];
        assert_eq!(distributed_sig, &non_distributed_sig);

        // Verify that we have a valid signature under the public key for the `message`
        assert!(public_key
            .verify_digest(digest.clone(), distributed_sig.deref())
            .is_ok());

        // Check we are able to create a recoverable signature.
        let recid =
            RecoveryId::trial_recovery_from_digest(public_key, digest.clone(), distributed_sig)
                .expect("Failed to recover signature");
        let recovered_pk = <TestCurve as CurveTrait>::VerifyingKey::recover_from_digest(
            digest,
            distributed_sig,
            RecoveryId::from_byte(recid.into()).expect("Invalid recovery ID"),
        )
        .unwrap();
        assert_eq!(
            recovered_pk, *public_key,
            "Recovered public key does not match original one."
        );

        Ok(())
    }

    #[test]
    fn signing_fails_with_less_than_threshold() -> Result<()> {
        // create SignParticipant
        let threshold = 3;
        let rng = &mut init_testing();
        let sid = Identifier::random(rng);

        // create participant_ids
        let id = ParticipantIdentifier::random(rng);
        // not enough other participants
        let other_participant_ids = (0..threshold - 2)
            .map(|_| ParticipantIdentifier::random(rng))
            .collect::<Vec<_>>();
        let participant_ids = std::iter::once(id)
            .chain(other_participant_ids.clone())
            .collect::<Vec<_>>();

        // create input
        let message = b"the quick brown fox jumped over the lazy dog";
        let keygen_output = keygen::Output::simulate(&participant_ids, rng);
        let presign_record = PresignRecord::simulate();
        let input = Input::new(
            message,
            presign_record,
            keygen_output.public_key_shares().to_vec(),
            threshold,
        );

        let participant = SignParticipant::new(sid, id, other_participant_ids, input);
        assert!(participant.is_err());
        Ok(())
    }
}

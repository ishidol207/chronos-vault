use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Address, Amount, CompressedPublicKey, Network, OutPoint, Transaction, ecdsa};
use chronos_vault::{
    NETWORK, PresignRecord, SendAmount, SignRequest, SignedTransaction, SignerIdentity,
    SigningPackage, Utxo, VaultError, combine, sign_share,
};
use k256::{AffinePoint, ProjectivePoint, Scalar};
use serde_json::json;

struct TestWallet {
    key: CompressedPublicKey,
    address: String,
}

#[test]
fn exact_send_selects_largest_input_and_returns_valid_change_and_signature() {
    let (wallet, request) = fixture(SendAmount::Exact { sats: 5_000 });
    let signed = sign(&wallet, &request);
    let tx = decode(&signed);
    assert_eq!(tx.input.len(), 1);
    assert_eq!(
        tx.input[0].previous_output,
        OutPoint::new(request.utxos[1].txid, 0)
    );
    assert_eq!(tx.output.len(), 2);
    assert_eq!(
        tx.output[0].script_pubkey,
        address(&request.recipient_address).script_pubkey()
    );
    assert_eq!(tx.output[0].value.to_sat(), 5_000);
    assert_eq!(
        tx.output[1].script_pubkey,
        address(&wallet.address).script_pubkey()
    );
    assert_eq!(tx.output[1].value.to_sat(), 12_000 - 5_000 - 282);
    assert_eq!(signed.sent_sat, 5_000);
    assert_eq!(signed.change_sat, tx.output[1].value.to_sat());
    assert_eq!(signed.fee_sat, 282);
    verify_signed(&tx, &request, &signed);
}

#[test]
fn exact_send_absorbs_small_change_into_fee() {
    let (wallet, request) = fixture(SendAmount::Exact { sats: 11_600 });
    let signed = sign(&wallet, &request);
    let tx = decode(&signed);
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 1);
    assert_eq!(tx.output[0].value.to_sat(), 11_600);
    assert_eq!(signed.change_sat, 0);
    assert_eq!(signed.fee_sat, 400);
    verify_signed(&tx, &request, &signed);
}

#[test]
fn sweep_signs_all_inputs_and_sends_the_balance_minus_fee() {
    let (wallet, request) = fixture(SendAmount::Sweep);
    let signed = sign(&wallet, &request);
    let tx = decode(&signed);
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 1);
    assert_eq!(
        tx.output[0].script_pubkey,
        address(&request.recipient_address).script_pubkey()
    );
    assert_eq!(signed.fee_sat, 356);
    assert_eq!(signed.change_sat, 0);
    assert_eq!(signed.sent_sat, 16_000 - 356);
    assert_eq!(tx.output[0].value.to_sat(), signed.sent_sat);
    verify_signed(&tx, &request, &signed);
}

#[test]
fn signing_errors_distinguish_bad_sender_recipient_and_funds() {
    let (wallet, mut request) = fixture(SendAmount::Exact { sats: 5_000 });
    let sender = std::mem::replace(
        &mut request.sender_address,
        request.recipient_address.clone(),
    );
    assert_eq!(sign_error(&wallet, &request), "sender_address_mismatch");
    request.sender_address = sender;

    let mainnet = Address::p2wpkh(&public_key_for_test(), Network::Bitcoin);
    let recipient = std::mem::replace(&mut request.recipient_address, mainnet.to_string());
    assert_eq!(sign_error(&wallet, &request), "invalid_recipient_address");
    request.recipient_address = "bad-address".to_owned();
    assert_eq!(sign_error(&wallet, &request), "invalid_recipient_address");
    request.recipient_address = recipient;

    request.amount = SendAmount::Exact { sats: 16_000 };
    assert_eq!(sign_error(&wallet, &request), "insufficient_funds");
    request.amount = SendAmount::Exact { sats: 100 };
    assert_eq!(sign_error(&wallet, &request), "amount_below_dust");
    request.amount = SendAmount::Sweep;
    request.utxos.push(request.utxos[0].clone());
    assert_eq!(sign_error(&wallet, &request), "invalid_utxos");
    request.utxos.clear();
    assert_eq!(sign_error(&wallet, &request), "empty_utxos");
}

#[test]
fn json_signing_request_uses_app_field_names_and_bitcoin_txid() {
    let (wallet, request) = fixture(SendAmount::Exact { sats: 5_000 });
    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(
        value["amount"],
        serde_json::json!({"type": "exact", "sats": 5_000})
    );
    assert_eq!(value["utxos"][0]["txid"], request.utxos[0].txid.to_string());
    let decoded: SignRequest = serde_json::from_value(value).unwrap();
    assert_eq!(sign(&wallet, &decoded).sent_sat, 5_000);
}

fn fixture(amount: SendAmount) -> (TestWallet, SignRequest) {
    let point = ProjectivePoint::GENERATOR * Scalar::from(5u64);
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let key = CompressedPublicKey::from_slice(point.to_affine().to_encoded_point(true).as_bytes())
        .unwrap();
    let wallet = TestWallet {
        key,
        address: Address::p2wpkh(&key, NETWORK).to_string(),
    };
    let parents = [4000, 12000].map(|value| bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: OutPoint::null(),
            ..Default::default()
        }],
        output: vec![bitcoin::TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Address::p2wpkh(&key, NETWORK).script_pubkey(),
        }],
    });
    let request = SignRequest {
        funding_transactions: parents
            .iter()
            .map(|t| {
                (
                    t.compute_txid(),
                    bitcoin::consensus::encode::serialize_hex(t),
                )
            })
            .collect(),
        sender_address: wallet.address.clone(),
        recipient_address: Address::p2wpkh(&public_key_for_test(), NETWORK).to_string(),
        amount,
        fee_rate_sat_vb: 2,
        utxos: vec![
            Utxo {
                txid: parents[0].compute_txid(),
                vout: 0,
                value: 4_000,
            },
            Utxo {
                txid: parents[1].compute_txid(),
                vout: 0,
                value: 12_000,
            },
        ],
    };
    (wallet, request)
}

fn public_key_for_test() -> CompressedPublicKey {
    let public_key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        .parse()
        .unwrap();
    CompressedPublicKey(public_key)
}

fn address(value: &str) -> Address {
    value
        .parse::<Address<_>>()
        .unwrap()
        .require_network(NETWORK)
        .unwrap()
}

// Deterministic offline TPreSign vectors, only for these tests. The two
// records sum to k=nonce^-1 and chi=5*k for the known test public key.
fn records(inputs: usize, party: u64) -> Vec<PresignRecord> {
    (0..inputs)
        .map(|index| {
            let nonce = Scalar::from(13 + index as u64);
            let r = AffinePoint::from(ProjectivePoint::GENERATOR * nonce);
            let inv = nonce.invert().unwrap();
            let (k, chi) = if party == 1 {
                (Scalar::from(7u64), Scalar::from(11u64))
            } else {
                (
                    inv - Scalar::from(7u64),
                    Scalar::from(5u64) * inv - Scalar::from(11u64),
                )
            };
            serde_json::from_value(json!({"R":r,"k":k,"chi":chi})).unwrap()
        })
        .collect()
}

fn response(p: &SigningPackage, party: u64) -> chronos_vault::PartyResponse {
    let unsigned: Transaction = deserialize_hex(&p.unsigned_tx_hex).unwrap();
    sign_share(
        &SignerIdentity {
            party_id: party,
            peer_id: if party == 1 { 3 } else { 1 },
            public_key: p.public_key,
        },
        p,
        records(unsigned.input.len(), party),
        |_| Ok(()),
    )
    .unwrap()
}

fn sign(wallet: &TestWallet, request: &SignRequest) -> SignedTransaction {
    let p = SigningPackage::new(wallet.key, [1, 3], request.clone()).unwrap();
    combine(&p, &response(&p, 1), &response(&p, 3)).unwrap()
}

fn sign_error(wallet: &TestWallet, request: &SignRequest) -> &'static str {
    SigningPackage::new(wallet.key, [1, 3], request.clone())
        .unwrap_err()
        .code()
}

#[test]
fn rejects_duplicate_parties_missing_swapped_shares_and_invalid_signature() {
    let (w, request) = fixture(SendAmount::Sweep);
    assert!(SigningPackage::new(w.key, [1, 1], request.clone()).is_err());
    let p = SigningPackage::new(w.key, [1, 3], request).unwrap();
    let a = response(&p, 1);
    let b = response(&p, 3);
    assert!(combine(&p, &a, &a).is_err());
    let mut other = b.clone();
    other.party_id = 2;
    assert!(combine(&p, &a, &other).is_err());
    let mut other = b.clone();
    other.inputs.pop();
    assert!(combine(&p, &a, &other).is_err());
    let mut other = b.clone();
    other.inputs.swap(0, 1);
    assert!(combine(&p, &a, &other).is_err());
    let mut other = b.clone();
    other.inputs[0].partial.share += Scalar::ONE;
    assert!(combine(&p, &a, &other).is_err());
    let mut other = b.clone();
    other.inputs[0].partial.r += Scalar::ONE;
    assert!(combine(&p, &a, &other).is_err());
    assert!(combine(&p, &b, &a).is_ok());
}

#[test]
fn parties_rebuild_the_unsigned_payment_and_bind_responses_to_each_input_value() {
    let (w, req) = fixture(SendAmount::Sweep);
    let p = SigningPackage::new(w.key, [1, 3], req.clone()).unwrap();
    let (a, b) = (response(&p, 1), response(&p, 3));
    let id = SignerIdentity {
        party_id: 1,
        peer_id: 3,
        public_key: w.key,
    };
    let mut edited = p.clone();
    edited.unsigned_tx_hex.push_str("00");
    assert!(
        sign_share(&id, &edited, records(2, 1), |_| panic!(
            "invalid request claimed nonces"
        ))
        .is_err()
    );
    let mut changed = req;
    // Same input set, total, outputs and txid, but different prevout values.
    changed.utxos[0].value += 100;
    changed.utxos[1].value -= 100;
    let mut edited = p.clone();
    edited.request = changed;
    assert!(matches!(
        sign_share(&id, &edited, records(2, 1), |_| Ok(())),
        Err(VaultError::InvalidFunding)
    ));
    assert!(combine(&edited, &a, &b).is_err());
}

#[test]
fn a_party_checks_its_identity_record_count_and_one_use_reservation() {
    let (w, req) = fixture(SendAmount::Sweep);
    let p = SigningPackage::new(w.key, [1, 3], req).unwrap();
    let id = SignerIdentity {
        party_id: 1,
        peer_id: 3,
        public_key: w.key,
    };
    let wrong = SignerIdentity {
        party_id: 1,
        peer_id: 3,
        public_key: public_key_for_test(),
    };
    assert!(sign_share(&wrong, &p, records(2, 1), |_| Ok(())).is_err());
    assert!(sign_share(&id, &p, records(1, 1), |_| Ok(())).is_err());
    let mut reused = records(1, 1);
    reused.extend(records(1, 1));
    assert!(sign_share(&id, &p, reused, |_| Ok(())).is_err());
    let mut spent = std::collections::HashSet::new();
    let mut claim = |ids: &[[u8; 32]]| {
        if ids.iter().all(|id| spent.insert(*id)) {
            Ok(())
        } else {
            Err(VaultError::NonceStorage)
        }
    };
    assert!(sign_share(&id, &p, records(2, 1), &mut claim).is_ok());
    assert!(sign_share(&id, &p, records(2, 1), &mut claim).is_err());
}

fn decode(signed: &SignedTransaction) -> Transaction {
    deserialize_hex(&signed.raw_tx_hex).unwrap()
}

fn verify_signed(tx: &Transaction, request: &SignRequest, signed: &SignedTransaction) {
    let secp = Secp256k1::verification_only();
    let sender_script = address(&request.sender_address).script_pubkey();
    let mut sighashes = SighashCache::new(tx);
    let mut input_value = 0;
    for (index, input) in tx.input.iter().enumerate() {
        let utxo = request
            .utxos
            .iter()
            .find(|utxo| input.previous_output == OutPoint::new(utxo.txid, utxo.vout))
            .unwrap();
        input_value += utxo.value;
        assert!(input.script_sig.is_empty());
        assert_eq!(input.witness.len(), 2);
        let mut witness = input.witness.iter();
        let signature = ecdsa::Signature::from_slice(witness.next().unwrap()).unwrap();
        assert_eq!(signature.sighash_type, EcdsaSighashType::All);
        let public_key = PublicKey::from_slice(witness.next().unwrap()).unwrap();
        assert_eq!(
            Address::p2wpkh(&CompressedPublicKey(public_key), NETWORK).script_pubkey(),
            sender_script
        );
        let hash = sighashes
            .p2wpkh_signature_hash(
                index,
                &sender_script,
                Amount::from_sat(utxo.value),
                EcdsaSighashType::All,
            )
            .unwrap();
        secp.verify_ecdsa(&Message::from(hash), &signature.signature, &public_key)
            .unwrap();
    }
    let output_value: u64 = tx.output.iter().map(|output| output.value.to_sat()).sum();
    assert_eq!(input_value - output_value, signed.fee_sat);
    assert_eq!(tx.compute_txid(), signed.txid);
    assert_eq!(tx.vsize(), signed.vsize);
    assert!(signed.fee_sat >= request.fee_rate_sat_vb * signed.vsize as u64);
}

#[test]
fn imports_the_public_key_encoding_returned_by_tshare() {
    let key = k256::ecdsa::SigningKey::from_bytes(&Scalar::from(5u64).to_bytes()).unwrap();
    let exported = serde_json::to_string(key.verifying_key()).unwrap();
    let (wallet, _) = fixture(SendAmount::Sweep);
    assert_eq!(
        chronos_vault::parse_master_key(&exported).unwrap(),
        wallet.key
    );
}

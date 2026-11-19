use hex_literal::hex;
use k256::ecdsa::{signature::DigestVerifier, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

#[test]
// EIP-155, EIP-6979 compatibility test
// EIP-155: Chain ID in transaction signing
// EIP-191: for off-chain message signing -> not considered here
// EIP-6979: Deterministic usage of k in signatures -> threshold ECDSA cannot follow this
fn test_ethereum_compatibility() {
    let signing_key = SigningKey::from_bytes(
        &hex!("b8fc6b068e2d6106f925ae8f160ba05ad8fcecab055c0983464bd348a5f08523").into(),
    )
    .unwrap();

    // RLP encoded transaction data to be signed
    let message_hex = "0xee808504a817c80082520894bda5747bfd65f08deb54cb465eb87d40e51b197e880de0b6b3a764000080827a698080";
    let message_bytes = hex::decode(&message_hex[2..]).unwrap();
    let digest = Keccak256::new_with_prefix(message_bytes);
    let chain_id: u64 = 31337;
    let (sig, recid) = signing_key.sign_digest_recoverable(digest.clone()).unwrap();

    let v_eip155 = 35 + chain_id * 2 + recid.to_byte() as u64;
    println!("Signature r: {}", hex::encode(sig.r().to_bytes()));
    println!("Signature s: {}", hex::encode(sig.s().to_bytes()));
    println!("Signature v: {}", v_eip155);

    let verifying_key = VerifyingKey::recover_from_digest(digest.clone(), &sig, recid).unwrap();
    println!(
        "Verifying Key: {}",
        hex::encode(verifying_key.to_encoded_point(false).as_bytes())
    );

    assert_eq!(signing_key.verifying_key(), &verifying_key);
    assert!(verifying_key.verify_digest(digest, &sig).is_ok());
}

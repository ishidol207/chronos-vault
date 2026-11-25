mod error;
mod signing;
mod transaction;

#[cfg(not(target_arch = "wasm32"))]
pub mod mempool;
#[cfg(not(target_arch = "wasm32"))]
pub mod nonce;
#[cfg(all(target_arch = "wasm32", feature = "web-bindings"))]
mod wasm;
#[cfg(any(feature = "threshold-runner", feature = "browser-signer"))]
pub mod presign;
#[cfg(all(target_arch = "wasm32", feature = "browser-signer"))]
mod browser;

pub use error::VaultError;
pub use signing::{
    PartyResponse, PaymentReview, SignerIdentity, SigningPackage, combine, sign_share,
};
pub use threshold_ecdsa_online::PresignRecord;
pub use transaction::{SendAmount, SignRequest, SignedTransaction, Utxo};

pub const NETWORK: bitcoin::Network = bitcoin::Network::Testnet4;

/// Accept a compressed SEC1 key or the SubjectPublicKeyInfo hex returned by
/// threshold_ecdsa::get_master_pk (including its JSON string form).
pub fn parse_master_key(value: &str) -> Result<bitcoin::CompressedPublicKey, VaultError> {
    use k256::{elliptic_curve::sec1::ToEncodedPoint, pkcs8::DecodePublicKey};
    let decoded: String;
    let key = if value.trim().starts_with('"') {
        decoded = serde_json::from_str(value).map_err(|_| VaultError::InvalidMasterKey)?;
        decoded.as_str()
    } else {
        value.trim()
    };
    if let Ok(key) = key.parse() {
        return Ok(key);
    }
    let bytes = hex::decode(key).map_err(|_| VaultError::InvalidMasterKey)?;
    let key =
        k256::PublicKey::from_public_key_der(&bytes).map_err(|_| VaultError::InvalidMasterKey)?;
    bitcoin::CompressedPublicKey::from_slice(key.to_encoded_point(true).as_bytes())
        .map_err(|_| VaultError::InvalidMasterKey)
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("invalid secp256k1 master public key")]
    InvalidMasterKey,
    #[error("invalid Testnet4 P2WPKH sender address")]
    InvalidSenderAddress,
    #[error("the threshold public key does not match the sender")]
    SenderAddressMismatch,
    #[error("invalid Testnet4 recipient address")]
    InvalidRecipientAddress,
    #[error("the recipient amount is below the minimum of {minimum_sat} sat")]
    AmountBelowDust { minimum_sat: u64 },
    #[error("fee rate must be at least 1 sat/vB")]
    InvalidFeeRate,
    #[error("no UTXOs are available for the sender")]
    EmptyUtxos,
    #[error("the UTXO set contains an invalid amount or a duplicate outpoint")]
    InvalidUtxos,
    #[error("the available {available_sat} sat cannot cover the output and fee")]
    InsufficientFunds { available_sat: u64 },
    #[error("the transaction exceeds the standard Bitcoin weight limit")]
    TransactionTooLarge,
    #[error("transaction amount or fee is out of range")]
    AmountOutOfRange,
    #[error("could not construct the transaction signature hash")]
    Signing,
    #[error("funding transaction does not prove the selected prevout value and sender script")]
    InvalidFunding,
    #[error("unexpected signer or signing quorum")]
    WrongParty,
    #[error("unsigned transaction differs from the payment request")]
    PackageMismatch,
    #[error("missing, mismatched or invalid signature shares")]
    InvalidShares,
    #[error("expected a distinct fresh TPreSign record for every input")]
    InvalidPresign,
    #[error("could not reserve fresh presign records in signer storage")]
    NonceStorage,
    #[error("invalid signing request JSON")]
    InvalidRequest,
    #[error("could not encode the WASM response")]
    WasmResponse,
}

impl VaultError {
    /// Stable error code for application logic.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidMasterKey => "invalid_master_key",
            Self::InvalidSenderAddress => "invalid_sender_address",
            Self::SenderAddressMismatch => "sender_address_mismatch",
            Self::InvalidRecipientAddress => "invalid_recipient_address",
            Self::AmountBelowDust { .. } => "amount_below_dust",
            Self::InvalidFeeRate => "invalid_fee_rate",
            Self::EmptyUtxos => "empty_utxos",
            Self::InvalidUtxos => "invalid_utxos",
            Self::InsufficientFunds { .. } => "insufficient_funds",
            Self::TransactionTooLarge => "transaction_too_large",
            Self::AmountOutOfRange => "amount_out_of_range",
            Self::Signing => "signing",
            Self::InvalidFunding => "invalid_funding",
            Self::WrongParty => "wrong_party",
            Self::PackageMismatch => "package_mismatch",
            Self::InvalidShares => "invalid_shares",
            Self::InvalidPresign => "invalid_presign",
            Self::NonceStorage => "nonce_storage",
            Self::InvalidRequest => "invalid_request",
            Self::WasmResponse => "wasm_response",
        }
    }
}

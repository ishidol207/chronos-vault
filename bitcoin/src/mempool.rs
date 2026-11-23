//! Blocking client for the mempool.space Bitcoin Testnet4 REST API.

use std::time::Duration;

use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::{BlockHash, Transaction, Txid};
use reqwest::StatusCode;
use reqwest::blocking::{Client, RequestBuilder, Response};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

use crate::transaction::{MAX_MONEY_SAT, parse_sender_address};
use crate::{Utxo, VaultError};

pub const API_BASE_URL: &str = "https://mempool.space/testnet4/api";
pub const EXPLORER_BASE_URL: &str = "https://mempool.space/testnet4";

#[derive(Debug, Error)]
pub enum MempoolError {
    #[error(transparent)]
    InvalidAddress(#[from] VaultError),
    #[error("mempool.space request failed: {0}")]
    Transport(#[source] reqwest::Error),
    #[error("mempool.space returned HTTP {status}: {message}")]
    Http { status: StatusCode, message: String },
    #[error("mempool.space returned an invalid {0} response")]
    InvalidResponse(&'static str),
    #[error("mempool.space returned txid {returned}, expected {expected}")]
    BroadcastTxidMismatch { returned: Txid, expected: Txid },
    #[error("invalid raw transaction hex")]
    InvalidTransaction,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecommendedFees {
    pub fastest_fee: f64,
    pub half_hour_fee: f64,
    pub hour_fee: f64,
    pub economy_fee: f64,
    pub minimum_fee: f64,
}

impl RecommendedFees {
    /// Rounds the half-hour recommendation up to a whole satoshi per vbyte.
    pub fn half_hour_sat_vb(&self) -> Result<u64, MempoolError> {
        let rate = self.half_hour_fee;
        if !rate.is_finite() || !(0.0..=MAX_MONEY_SAT as f64).contains(&rate) {
            return Err(MempoolError::InvalidResponse("recommended fees"));
        }
        Ok(rate.ceil().max(1.0) as u64)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TransactionStatus {
    pub confirmed: bool,
    pub block_height: Option<u32>,
    pub block_hash: Option<BlockHash>,
    pub block_time: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct BroadcastReceipt {
    pub txid: Txid,
    pub explorer_url: String,
}

pub struct MempoolClient {
    client: Client,
}

impl MempoolClient {
    pub fn new() -> Result<Self, MempoolError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(MempoolError::Transport)?;
        Ok(Self { client })
    }

    pub fn utxos(&self, sender_address: &str) -> Result<Vec<Utxo>, MempoolError> {
        let address = parse_sender_address(sender_address)?;
        let url = format!("{API_BASE_URL}/address/{address}/utxo");
        read_json(self.client.get(url), "UTXO")
    }

    pub fn fetch_funding(
        &self,
        key: &bitcoin::CompressedPublicKey,
        request: &mut crate::SignRequest,
    ) -> Result<(), MempoolError> {
        let tx = crate::transaction::prepare(key, request)?.tx;
        for input in tx.input {
            let id = input.previous_output.txid;
            if let std::collections::btree_map::Entry::Vacant(entry) =
                request.funding_transactions.entry(id)
            {
                let response = send(self.client.get(format!("{API_BASE_URL}/tx/{id}/hex")))?;
                entry.insert(
                    response
                        .text()
                        .map_err(MempoolError::Transport)?
                        .trim()
                        .to_owned(),
                );
            }
        }
        Ok(())
    }

    pub fn recommended_fees(&self) -> Result<RecommendedFees, MempoolError> {
        let url = format!("{API_BASE_URL}/v1/fees/recommended");
        read_json(self.client.get(url), "recommended fees")
    }

    pub fn broadcast(&self, raw_tx_hex: &str) -> Result<BroadcastReceipt, MempoolError> {
        let transaction: Transaction =
            deserialize_hex(raw_tx_hex).map_err(|_| MempoolError::InvalidTransaction)?;
        let expected = transaction.compute_txid();
        let response = send(
            self.client
                .post(format!("{API_BASE_URL}/tx"))
                .header(reqwest::header::CONTENT_TYPE, "text/plain")
                .body(raw_tx_hex.to_owned()),
        )?;
        let returned = response
            .text()
            .map_err(MempoolError::Transport)?
            .trim()
            .parse()
            .map_err(|_| MempoolError::InvalidResponse("broadcast"))?;
        if expected != returned {
            return Err(MempoolError::BroadcastTxidMismatch { returned, expected });
        }
        Ok(BroadcastReceipt {
            txid: returned,
            explorer_url: format!("{EXPLORER_BASE_URL}/tx/{returned}"),
        })
    }

    pub fn transaction_status(&self, txid: Txid) -> Result<TransactionStatus, MempoolError> {
        let url = format!("{API_BASE_URL}/tx/{txid}/status");
        read_json(self.client.get(url), "transaction status")
    }
}

fn read_json<T: DeserializeOwned>(
    request: RequestBuilder,
    endpoint: &'static str,
) -> Result<T, MempoolError> {
    send(request)?.json().map_err(|error| {
        if error.is_decode() {
            MempoolError::InvalidResponse(endpoint)
        } else {
            MempoolError::Transport(error)
        }
    })
}

fn send(request: RequestBuilder) -> Result<Response, MempoolError> {
    let response = request.send().map_err(MempoolError::Transport)?;
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let message = response
        .text()
        .unwrap_or_default()
        .chars()
        .take(400)
        .collect();
    Err(MempoolError::Http { status, message })
}

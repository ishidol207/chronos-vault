use bitcoin::consensus::encode::deserialize_hex;
use std::collections::{BTreeMap, HashSet};

use bitcoin::absolute::LockTime;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, VarInt,
    Witness,
};
use bitcoin::{CompressedPublicKey, SegwitV0Sighash};
use serde::{Deserialize, Serialize};

use crate::{NETWORK, VaultError};

const MAX_STANDARD_WEIGHT: u64 = 400_000;
pub(crate) const MAX_MONEY_SAT: u64 = 21_000_000 * 100_000_000;

/// Prevout data from the sender's UTXO endpoint. Amounts are in satoshis.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Utxo {
    pub txid: Txid,
    pub vout: u32,
    pub value: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SendAmount {
    Exact { sats: u64 },
    Sweep,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    pub sender_address: String,
    pub recipient_address: String,
    pub amount: SendAmount,
    pub fee_rate_sat_vb: u64,
    pub utxos: Vec<Utxo>,
    /// Raw funding transactions, keyed by txid, for local prevout verification.
    pub funding_transactions: BTreeMap<Txid, String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SignedTransaction {
    pub txid: Txid,
    pub raw_tx_hex: String,
    pub sent_sat: u64,
    pub change_sat: u64,
    pub fee_sat: u64,
    pub vsize: usize,
}

pub(crate) struct Prepared {
    pub tx: Transaction,
    pub digests: Vec<SegwitV0Sighash>,
    pub sent_sat: u64,
    pub change_sat: u64,
    pub fee_sat: u64,
}

impl Prepared {
    pub(crate) fn check_funding(
        &self,
        request: &SignRequest,
        key: &CompressedPublicKey,
    ) -> Result<(), VaultError> {
        let script = Address::p2wpkh(key, NETWORK).script_pubkey();
        let values: BTreeMap<_, _> = request
            .utxos
            .iter()
            .map(|u| (OutPoint::new(u.txid, u.vout), u.value))
            .collect();
        let mut parents = BTreeMap::new();
        for input in &self.tx.input {
            let prev = input.previous_output;
            if let std::collections::btree_map::Entry::Vacant(entry) = parents.entry(prev.txid) {
                let raw = request
                    .funding_transactions
                    .get(&prev.txid)
                    .ok_or(VaultError::InvalidFunding)?;
                let parent: Transaction =
                    deserialize_hex(raw).map_err(|_| VaultError::InvalidFunding)?;
                if parent.compute_txid() != prev.txid {
                    return Err(VaultError::InvalidFunding);
                }
                entry.insert(parent);
            }
            let output = parents[&prev.txid]
                .output
                .get(prev.vout as usize)
                .ok_or(VaultError::InvalidFunding)?;
            if output.script_pubkey != script || values.get(&prev) != Some(&output.value.to_sat()) {
                return Err(VaultError::InvalidFunding);
            }
        }
        Ok(())
    }
}

pub(crate) fn prepare(
    public_key: &CompressedPublicKey,
    request: &SignRequest,
) -> Result<Prepared, VaultError> {
    let sender = parse_sender_address(&request.sender_address)?;
    let recipient = request
        .recipient_address
        .parse::<Address<_>>()
        .and_then(|address| address.require_network(NETWORK))
        .map_err(|_| VaultError::InvalidRecipientAddress)?;
    if recipient.address_type().is_none() {
        return Err(VaultError::InvalidRecipientAddress);
    }

    let mut coins: Vec<&Utxo> = request.utxos.iter().collect();
    let total_sat = validate_request(&coins, request.fee_rate_sat_vb)?;
    coins.sort_unstable_by(|a, b| {
        b.value
            .cmp(&a.value)
            .then_with(|| a.txid.cmp(&b.txid))
            .then_with(|| a.vout.cmp(&b.vout))
    });

    if Address::p2wpkh(public_key, NETWORK) != sender {
        return Err(VaultError::SenderAddressMismatch);
    }

    let sender_script = sender.script_pubkey();
    let recipient_script = recipient.script_pubkey();
    let plan = select_coins(
        &coins,
        total_sat,
        request.amount,
        request.fee_rate_sat_vb,
        &recipient_script,
        &sender_script,
    )?;
    let selected = &coins[..plan.input_count];
    let tx = build_transaction(selected, &plan, recipient_script, sender_script.clone());
    let mut cache = SighashCache::new(&tx);
    let digests = selected
        .iter()
        .enumerate()
        .map(|(index, coin)| {
            cache
                .p2wpkh_signature_hash(
                    index,
                    &sender_script,
                    Amount::from_sat(coin.value),
                    EcdsaSighashType::All,
                )
                .map_err(|_| VaultError::Signing)
        })
        .collect::<Result<_, _>>()?;
    Ok(Prepared {
        tx,
        digests,
        sent_sat: plan.sent_sat,
        change_sat: plan.change_sat,
        fee_sat: plan.fee_sat,
    })
}

pub(crate) fn parse_sender_address(address: &str) -> Result<Address, VaultError> {
    let checked = address
        .parse::<Address<_>>()
        .and_then(|address| address.require_network(NETWORK))
        .map_err(|_| VaultError::InvalidSenderAddress)?;
    if !checked.script_pubkey().is_p2wpkh() {
        return Err(VaultError::InvalidSenderAddress);
    }
    Ok(checked)
}

fn validate_request(coins: &[&Utxo], rate: u64) -> Result<u64, VaultError> {
    if rate == 0 {
        return Err(VaultError::InvalidFeeRate);
    }
    if coins.is_empty() {
        return Err(VaultError::EmptyUtxos);
    }
    let mut outpoints = HashSet::with_capacity(coins.len());
    let mut total: u64 = 0;
    for coin in coins {
        let outpoint = OutPoint::new(coin.txid, coin.vout);
        if coin.value == 0 || outpoint.is_null() || !outpoints.insert(outpoint) {
            return Err(VaultError::InvalidUtxos);
        }
        total = total
            .checked_add(coin.value)
            .filter(|total| *total <= MAX_MONEY_SAT)
            .ok_or(VaultError::InvalidUtxos)?;
    }
    Ok(total)
}

struct Plan {
    input_count: usize,
    sent_sat: u64,
    change_sat: u64,
    fee_sat: u64,
}

fn select_coins(
    coins: &[&Utxo],
    total_sat: u64,
    amount: SendAmount,
    rate: u64,
    recipient: &Script,
    sender: &Script,
) -> Result<Plan, VaultError> {
    let recipient_min = recipient.minimal_non_dust().to_sat().max(1);
    let insufficient = VaultError::InsufficientFunds {
        available_sat: total_sat,
    };

    let SendAmount::Exact { sats } = amount else {
        let fee = estimate_fee(coins.len(), &[recipient], rate)?
            .ok_or(VaultError::TransactionTooLarge)?;
        let sent = total_sat
            .checked_sub(fee)
            .filter(|sent| *sent >= recipient_min)
            .ok_or(insufficient)?;
        return Ok(Plan {
            input_count: coins.len(),
            sent_sat: sent,
            change_sat: 0,
            fee_sat: fee,
        });
    };

    if sats < recipient_min {
        return Err(VaultError::AmountBelowDust {
            minimum_sat: recipient_min,
        });
    }
    if sats > MAX_MONEY_SAT {
        return Err(VaultError::AmountOutOfRange);
    }
    if sats > total_sat {
        return Err(insufficient);
    }

    let change_min = sender.minimal_non_dust().to_sat();
    let mut selected_sat = 0;
    for (position, coin) in coins.iter().enumerate() {
        let input_count = position + 1;
        selected_sat += coin.value;
        let Some(fee_no_change) = estimate_fee(input_count, &[recipient], rate)? else {
            return Err(VaultError::TransactionTooLarge);
        };
        let Some(remainder) = selected_sat
            .checked_sub(sats)
            .filter(|remainder| *remainder >= fee_no_change)
        else {
            continue;
        };

        let with_change = estimate_fee(input_count, &[recipient, sender], rate)?
            .and_then(|fee| remainder.checked_sub(fee))
            .filter(|change| *change >= change_min);
        if let Some(change) = with_change {
            return Ok(Plan {
                input_count,
                sent_sat: sats,
                change_sat: change,
                fee_sat: remainder - change,
            });
        }
        // Near the weight limit, a no-change transaction can fit when a
        // change output cannot. Only absorb the remainder if it is small.
        if remainder - fee_no_change
            >= change_min + output_size(sender).saturating_mul(rate).min(MAX_MONEY_SAT)
        {
            return Err(VaultError::TransactionTooLarge);
        }
        return Ok(Plan {
            input_count,
            sent_sat: sats,
            change_sat: 0,
            fee_sat: remainder,
        });
    }
    Err(insufficient)
}

fn output_size(script: &Script) -> u64 {
    8 + VarInt(script.len() as u64).size() as u64 + script.len() as u64
}

fn estimate_fee(
    input_count: usize,
    output_scripts: &[&Script],
    rate: u64,
) -> Result<Option<u64>, VaultError> {
    let inputs = input_count as u64;
    let output_count = output_scripts.len() as u64;
    let outputs: u64 = output_scripts
        .iter()
        .map(|script| output_size(script))
        .sum();
    let overhead = 8 + VarInt(inputs).size() as u64 + VarInt(output_count).size() as u64;
    // Each stripped input is 41 bytes. A low-S DER signature plus sighash
    // byte is at most 72 bytes, so the P2WPKH witness adds at most 108 WU.
    let weight = 4 * (overhead + inputs * 41 + outputs) + 2 + inputs * 108;
    if weight > MAX_STANDARD_WEIGHT {
        return Ok(None);
    }
    weight
        .div_ceil(4)
        .checked_mul(rate)
        .filter(|fee| *fee <= MAX_MONEY_SAT)
        .map(Some)
        .ok_or(VaultError::AmountOutOfRange)
}

fn build_transaction(
    coins: &[&Utxo],
    plan: &Plan,
    recipient: ScriptBuf,
    sender: ScriptBuf,
) -> Transaction {
    let input = coins
        .iter()
        .map(|coin| TxIn {
            previous_output: OutPoint::new(coin.txid, coin.vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        })
        .collect();
    let mut output = vec![TxOut {
        value: Amount::from_sat(plan.sent_sat),
        script_pubkey: recipient,
    }];
    if plan.change_sat > 0 {
        output.push(TxOut {
            value: Amount::from_sat(plan.change_sat),
            script_pubkey: sender,
        });
    }
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input,
        output,
    }
}

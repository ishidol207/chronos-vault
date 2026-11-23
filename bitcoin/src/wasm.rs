use crate::parse_master_key;
use crate::{NETWORK, SignerIdentity, SigningPackage, VaultError, combine, signing::stage_share};
use bitcoin::Address;
use js_sys::{Error, JSON, Reflect};
use serde::{Serialize, de::DeserializeOwned};
use wasm_bindgen::prelude::*;

// All signers in an origin use the same durable nonce ledger. add() atomically
// rejects a reused nonce, including concurrent requests from another tab.
#[wasm_bindgen(inline_js = r#"
export async function claimBitcoinNonces(ids) {
    const db = await new Promise((resolve, reject) => {
        const req = indexedDB.open("chronos-bitcoin-signer", 1);
        req.onupgradeneeded = () => req.result.createObjectStore("spent");
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
    try {
        await new Promise((resolve, reject) => {
            const tx = db.transaction("spent", "readwrite", {durability: "strict"});
            tx.oncomplete = resolve;
            tx.onabort = () => reject(tx.error);
            for (const id of ids) tx.objectStore("spent").add(true, id);
        });
    } finally { db.close(); }
}
"#)]
extern "C" {
    #[wasm_bindgen(catch, js_name = claimBitcoinNonces)]
    async fn claim_nonces(ids: js_sys::Array) -> Result<JsValue, JsValue>;
}

#[wasm_bindgen(js_name = walletAddress)]
pub fn wallet_address(public_key: &str) -> Result<String, JsValue> {
    let key = parse_master_key(public_key).map_err(js_error)?;
    Ok(Address::p2wpkh(&key, NETWORK).to_string())
}

#[wasm_bindgen(js_name = prepareTransaction)]
pub fn prepare_transaction(
    key: &str,
    signers_json: &str,
    request_json: &str,
) -> Result<String, JsValue> {
    let key = parse_master_key(key).map_err(js_error)?;
    json_text(
        &SigningPackage::new(key, parse(signers_json)?, parse(request_json)?).map_err(js_error)?,
    )
}

#[wasm_bindgen(js_name = reviewTransaction)]
pub fn review_transaction(package: &str) -> Result<JsValue, JsValue> {
    to_js(
        &parse::<SigningPackage>(package)?
            .review()
            .map_err(js_error)?,
    )
}

#[wasm_bindgen(js_name = signShare)]
pub async fn sign_share(
    identity_json: String,
    package_json: String,
    records_json: String,
) -> Result<String, JsValue> {
    let records_json = zeroize::Zeroizing::new(records_json);
    let identity: SignerIdentity = parse(&identity_json)?;
    let pending =
        stage_share(&identity, &parse(&package_json)?, parse(&records_json)?).map_err(js_error)?;
    let ids = pending
        .nonce_ids
        .iter()
        .map(|id| JsValue::from_str(&hex::encode(id)))
        .collect();
    claim_nonces(ids)
        .await
        .map_err(|_| js_error(VaultError::NonceStorage))?;
    json_text(&pending.response)
}

#[wasm_bindgen(js_name = combineTransaction)]
pub fn combine_transaction(package: &str, a: &str, b: &str) -> Result<JsValue, JsValue> {
    to_js(&combine(&parse(package)?, &parse(a)?, &parse(b)?).map_err(js_error)?)
}

fn parse<T: DeserializeOwned>(input: &str) -> Result<T, JsValue> {
    serde_json::from_str(input).map_err(|_| js_error(VaultError::InvalidRequest))
}

fn json_text(value: &impl Serialize) -> Result<String, JsValue> {
    serde_json::to_string(value).map_err(|_| js_error(VaultError::WasmResponse))
}

fn to_js(value: &impl Serialize) -> Result<JsValue, JsValue> {
    let json = json_text(value)?;
    JSON::parse(&json).map_err(|_| js_error(VaultError::WasmResponse))
}

fn js_error(error: VaultError) -> JsValue {
    let js = Error::new(&error.to_string());
    let _ = Reflect::set(
        js.as_ref(),
        &JsValue::from_str("code"),
        &JsValue::from_str(error.code()),
    );
    js.into()
}

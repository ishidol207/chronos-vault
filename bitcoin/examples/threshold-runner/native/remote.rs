//! One locally held participant. The HTTP boundary carries only protocol messages and partial signatures.
use super::{Result, new_session, party_dir, party_store};
use bitcoin::hashes::{Hash, sha256};
use chronos_vault::presign::{Presigner, RoundOutput};
use chronos_vault::{
    PartyResponse, SignedTransaction, SignerIdentity, SigningPackage, VaultError, combine, nonce,
    parse_master_key, sign_share,
};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "snake_case")]
pub(super) enum Purpose {
    NormalSign,
    Recovery,
    Inheritance,
}

impl Purpose {
    pub(super) fn peer(self) -> u64 {
        match self {
            Self::NormalSign => 1,
            Self::Recovery | Self::Inheritance => 3,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Step {
    pub step: usize,
    pub messages: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Packet {
    Messages(Vec<String>),
    Share(PartyResponse),
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Response {
    pub step: usize,
    pub purpose: Purpose,
    pub package_sha256: String,
    pub session_ids: Vec<String>,
    pub packet: Packet,
}

pub(super) fn fingerprint(bytes: &[u8]) -> String {
    sha256::Hash::hash(bytes).to_string()
}

pub(super) fn check_package(
    wallet: &Path,
    package: &SigningPackage,
    purpose: Purpose,
) -> Result<usize> {
    let key = parse_master_key(&fs::read_to_string(wallet.join("public-key.json"))?)?;
    if key != package.public_key
        || !package.signers.contains(&2)
        || !package.signers.contains(&purpose.peer())
    {
        return Err("wrong wallet or signing pair for this purpose".into());
    }
    Ok(package.review()?.input_sighashes.len())
}

pub(super) fn allocate_ids(wallet: &Path, count: usize) -> Result<Vec<u64>> {
    fs::create_dir_all(wallet.join("sessions"))?;
    (0..count).map(|_| new_session(wallet)).collect()
}

pub(super) struct LocalSigner {
    package: SigningPackage,
    identity: SignerIdentity,
    dir: PathBuf,
    rounds: Presigner,
}

impl LocalSigner {
    pub(super) fn start(
        wallet: &Path,
        id: u64,
        peer: u64,
        package: SigningPackage,
        ids: Vec<u64>,
    ) -> Result<(Self, Packet)> {
        let dir = party_dir(wallet, id);
        let identity: SignerIdentity =
            serde_json::from_slice(&fs::read(dir.join(format!("peer-{peer}.json")))?)?;
        if identity.party_id != id || identity.peer_id != peer {
            return Err("wrong local identity".into());
        }
        let (aux, share) = party_store::open(&dir, id, &package.public_key)?;
        let (rounds, first) = Presigner::start(identity.clone(), &package, ids, &aux, &share)?;
        Ok((
            Self {
                package,
                identity,
                dir,
                rounds,
            },
            Packet::Messages(first),
        ))
    }

    pub(super) fn advance(&mut self, wire: &[String]) -> Result<Packet> {
        match self.rounds.advance(wire)? {
            RoundOutput::Messages(messages) => Ok(Packet::Messages(messages)),
            RoundOutput::Done(records) => Ok(Packet::Share(sign_share(
                &self.identity,
                &self.package,
                records,
                |ids| nonce::reserve(&self.dir, ids).map_err(|_| VaultError::NonceStorage),
            )?)),
        }
    }
}

fn endpoint(server: &str, suffix: &str) -> Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(server)?;
    if url.scheme() != "https"
        && !(url.scheme() == "http"
            && matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost")))
    {
        return Err("use HTTPS or a loopback HTTP address".into());
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("server URL must not contain credentials, query or fragment".into());
    }
    let path = format!("{}{suffix}", url.path().trim_end_matches('/'));
    url.set_path(&path);
    Ok(url)
}

fn http_client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(60))
        .build()?)
}

pub(super) fn run_client(
    wallet: &Path,
    payment: &Path,
    server: &str,
    purpose: Purpose,
) -> Result<()> {
    let url = endpoint(server, "/v1/signing/steps")?;
    let client = http_client()?;
    let mut ticket = Zeroizing::new(String::new());
    io::stdin().read_line(&mut ticket)?;
    let raw = fs::read(payment)?;
    let package: SigningPackage = serde_json::from_slice(&raw)?;
    let n = check_package(wallet, &package, purpose)?;
    let hash = fingerprint(&raw);
    let exchange = |step, messages| -> Result<Response> {
        let request = Step { step, messages };
        // Repeating the exact step is safe if the response was lost.
        let mut delay = Duration::from_millis(100);
        loop {
            match client
                .post(url.clone())
                .bearer_auth(ticket.trim())
                .json(&request)
                .send()
                .and_then(|r| r.error_for_status())
                .and_then(|r| r.json::<Response>())
            {
                Ok(reply)
                    if reply.step == step
                        && reply.purpose == purpose
                        && reply.package_sha256 == hash =>
                {
                    return Ok(reply);
                }
                Ok(_) => return Err("response does not match the approved transaction".into()),
                Err(e)
                    if delay <= Duration::from_secs(1)
                        && (e.status() == Some(reqwest::StatusCode::TOO_MANY_REQUESTS)
                            || e.is_connect()
                            || e.is_timeout()
                            || e.is_body()
                            || e.is_decode()) =>
                {
                    std::thread::sleep(delay);
                    delay *= 2;
                }
                Err(e) => return Err(e.into()),
            }
        }
    };
    let first = exchange(0, vec![])?;
    let ids = first
        .session_ids
        .iter()
        .map(|s| s.parse::<u64>())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if ids.len() != n {
        return Err("wrong session count".into());
    }
    fs::create_dir_all(wallet.join("sessions"))?;
    for sid in &ids {
        fs::File::create_new(wallet.join("sessions").join(sid.to_string()))?;
    }
    let (mut signer, mut local) =
        LocalSigner::start(wallet, purpose.peer(), 2, package.clone(), ids)?;
    let mut remote = first.packet;
    let mut step = 1;
    let signed: SignedTransaction = loop {
        match (local, remote) {
            (Packet::Messages(ours), Packet::Messages(theirs)) => {
                local = signer.advance(&theirs)?;
                remote = exchange(step, ours)?.packet;
                step += 1;
            }
            (Packet::Share(ours), Packet::Share(theirs)) => {
                break combine(&package, &ours, &theirs)?;
            }
            _ => return Err("participants finished at different rounds".into()),
        }
    };
    println!("{}", serde_json::to_string_pretty(&signed)?);
    Ok(())
}

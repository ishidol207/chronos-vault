//! One private WASM instance per participant, owned by the signing worker.
use crate::{
    PartyResponse, SignerIdentity, SigningPackage, combine,
    presign::{Presigner, RoundOutput},
    signing::stage_share,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::cell::RefCell;
use zeroize::Zeroizing;

#[link(wasm_import_module = "chronos")]
unsafe extern "C" {
    fn random_fill(ptr: *mut u8, len: usize);
}

fn browser_entropy(out: &mut [u8]) -> Result<(), getrandom::Error> {
    // The worker fills this live slice using crypto.getRandomValues or throws.
    unsafe { random_fill(out.as_mut_ptr(), out.len()) };
    Ok(())
}
getrandom::register_custom_getrandom!(browser_entropy);

struct Local {
    identity: SignerIdentity,
    package: SigningPackage,
    rounds: Presigner,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    Review {
        package: String,
    },
    Start {
        identity: SignerIdentity,
        package: String,
        ids: Vec<String>,
        secrets: String,
    },
    Advance {
        messages: Vec<String>,
    },
    Release,
    Combine {
        package: String,
        a: PartyResponse,
        b: PartyResponse,
    },
}

#[derive(Default)]
struct Engine {
    local: Option<Local>,
    pending: Option<PartyResponse>,
}

type Error = Box<dyn std::error::Error>;

impl Engine {
    fn run(&mut self, request: Request) -> Result<Value, Error> {
        Ok(match request {
            Request::Review { package } => {
                json!(serde_json::from_str::<SigningPackage>(&package)?.review()?)
            }
            Request::Start {
                identity,
                package,
                ids,
                secrets,
            } => {
                if self.local.is_some() || self.pending.is_some() {
                    return Err("participant already started".into());
                }
                let secrets = Zeroizing::new(secrets);
                let (aux, share): (String, String) = serde_json::from_str(&secrets)?;
                let (aux, share) = (Zeroizing::new(aux), Zeroizing::new(share));
                let ids = ids.iter().map(|id| id.parse()).collect::<Result<_, _>>()?;
                let package = serde_json::from_str(&package)?;
                let (rounds, messages) =
                    Presigner::start(identity.clone(), &package, ids, &aux, &share)?;
                self.local = Some(Local {
                    identity,
                    package,
                    rounds,
                });
                json!({"messages": messages})
            }
            Request::Advance { messages } => {
                let mut local = self.local.take().ok_or("participant unavailable")?;
                match local.rounds.advance(&messages)? {
                    RoundOutput::Messages(next) => {
                        self.local = Some(local);
                        json!({"messages": next})
                    }
                    RoundOutput::Done(records) => {
                        let pending = stage_share(&local.identity, &local.package, records)?;
                        self.pending = Some(pending.response);
                        json!({"nonce_ids": pending.nonce_ids.iter().map(hex::encode).collect::<Vec<_>>()})
                    }
                }
            }
            Request::Release => json!(self.pending.take().ok_or("no pending share")?),
            Request::Combine { package, a, b } => {
                json!(combine(&serde_json::from_str(&package)?, &a, &b)?)
            }
        })
    }
}

thread_local! {
    static ENGINE: RefCell<Engine> = RefCell::default();
    static INPUT: RefCell<Zeroizing<Vec<u8>>> = RefCell::new(Zeroizing::new(Vec::new()));
    static OUTPUT: RefCell<Vec<u8>> = RefCell::default();
}

// JS writes exactly len bytes to this initialized Rust-owned input before calling process.
#[unsafe(no_mangle)]
pub extern "C" fn input_buffer(len: usize) -> *mut u8 {
    INPUT.with_borrow_mut(|b| {
        b.resize(len, 0);
        b.as_mut_ptr()
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn process() -> usize {
    let response = INPUT.with_borrow_mut(|b| {
        let input = std::mem::replace(b, Zeroizing::new(Vec::new()));
        let result = serde_json::from_slice::<Request>(&input)
            .map_err(Error::from)
            .and_then(|request| ENGINE.with_borrow_mut(|e| e.run(request)));
        match result {
            Ok(value) => json!({"value":value}),
            Err(_) => json!({"error":"Invalid signer input, round, transaction or state"}),
        }
    });
    OUTPUT.with_borrow_mut(|out| {
        *out = response.to_string().into_bytes();
        out.len()
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn output_buffer() -> *const u8 {
    OUTPUT.with_borrow(|b| b.as_ptr())
}

use super::Result;
use super::remote::{
    LocalSigner, Packet, Purpose, Response, Step, allocate_ids, check_package, fingerprint,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware,
    response::IntoResponse,
    routing::{get, post},
};
use chronos_vault::SigningPackage;
use rand::{RngCore, rngs::OsRng};
use ring::{hmac, signature};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, TryLockError},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

const TTL: Duration = Duration::from_secs(600);
const MAX_TICKETS: usize = 32;
const MAX_BODY: usize = 8 * 1024 * 1024;

type ApiError = (StatusCode, &'static str);
const UNAUTHORIZED: ApiError = (StatusCode::UNAUTHORIZED, "invalid or expired credential");
const BUSY: ApiError = (
    StatusCode::TOO_MANY_REQUESTS,
    "server busy; retry the same request",
);
const CLOSED: ApiError = (
    StatusCode::GONE,
    "session closed; a new approval is required",
);
const INTERNAL: ApiError = (StatusCode::INTERNAL_SERVER_ERROR, "signer unavailable");

struct App {
    wallet: PathBuf,
    verifier_key: [u8; 32],
    ticket_key: hmac::Key,
    context: SigningContext,
    tickets: Mutex<HashMap<String, Ticket>>,
    work: Arc<Semaphore>,
}
struct Ticket {
    expires: Instant,
    session: Arc<Mutex<Session>>,
}
enum Phase {
    Approved(SigningPackage, usize),
    Active(Box<LocalSigner>),
    Finished,
    Failed,
}

struct Session {
    purpose: Purpose,
    package_hash: String,
    ids: Vec<String>,
    phase: Phase,
    last: Option<(String, Response)>,
}

impl Session {
    fn advance(&mut self, wallet: &Path, request: Step) -> std::result::Result<Response, ApiError> {
        if matches!(self.phase, Phase::Failed) {
            return Err(CLOSED);
        }
        let digest = fingerprint(&serde_json::to_vec(&request).map_err(|_| INTERNAL)?);
        if let Some((previous, reply)) = &self.last {
            if reply.step == request.step && previous == &digest {
                return Ok(reply.clone());
            }
        }
        let expected = self.last.as_ref().map_or(0, |(_, reply)| reply.step + 1);
        if request.step != expected || (request.step == 0 && !request.messages.is_empty()) {
            return Err((StatusCode::CONFLICT, "unexpected step or conflicting retry"));
        }

        // Remove state before calling the engine. A failed or interrupted round cannot be resumed.
        let packet = match std::mem::replace(&mut self.phase, Phase::Failed) {
            Phase::Approved(package, count) => {
                let ids = allocate_ids(wallet, count).map_err(|_| INTERNAL)?;
                self.ids = ids.iter().map(ToString::to_string).collect();
                let (signer, packet) =
                    LocalSigner::start(wallet, 2, self.purpose.peer(), package, ids)
                        .map_err(|_| INTERNAL)?;
                self.phase = Phase::Active(Box::new(signer));
                packet
            }
            Phase::Active(mut signer) => {
                let packet = signer.advance(&request.messages).map_err(|_| {
                    (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "round failed; session closed",
                    )
                })?;
                if matches!(packet, Packet::Messages(_)) {
                    self.phase = Phase::Active(signer);
                } else {
                    self.phase = Phase::Finished;
                }
                packet
            }
            Phase::Finished => {
                self.phase = Phase::Finished;
                return Err(CLOSED);
            }
            Phase::Failed => return Err(CLOSED),
        };
        let reply = Response {
            step: request.step,
            purpose: self.purpose,
            package_sha256: self.package_hash.clone(),
            session_ids: self.ids.clone(),
            packet,
        };
        self.last = Some((digest, reply.clone()));
        Ok(reply)
    }
}

fn bearer(headers: &HeaderMap) -> std::result::Result<&str, ApiError> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .filter(|s| !s.is_empty())
        .ok_or(UNAUTHORIZED)
}

#[derive(Clone, Serialize)]
struct SigningContext {
    instance_id: String,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenSession {
    package_json: String,
    authorization: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    Owner,
    Heir,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum InheritanceEvidence {
    DeathVerified,
    InactivityElapsed,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorization {
    audience: String,
    instance_id: String,
    public_key: String,
    package_sha256: String,
    purpose: Purpose,
    role: Role,
    face_verified: bool,
    inheritance_evidence: Option<InheritanceEvidence>,
    expires_at: u64,
}

impl Authorization {
    fn check(
        &self,
        context: &SigningContext,
        package_hash: &str,
    ) -> std::result::Result<(), ApiError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| INTERNAL)?
            .as_secs();
        if self.audience != "chronos-vault:testnet4:signing:v1"
            || self.instance_id != context.instance_id
            || self.public_key != context.public_key
            || self.package_sha256 != package_hash
            || self.expires_at <= now
            || self.expires_at > now + 120
        {
            return Err(UNAUTHORIZED);
        }
        let eligible = match self.purpose {
            Purpose::NormalSign | Purpose::Recovery => {
                matches!(self.role, Role::Owner) && self.inheritance_evidence.is_none()
            }
            Purpose::Inheritance => {
                matches!(self.role, Role::Heir) && self.inheritance_evidence.is_some()
            }
        };
        if !self.face_verified || !eligible {
            return Err((
                StatusCode::FORBIDDEN,
                "identity or inheritance condition not satisfied",
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct Grant {
    ticket: String,
    expires_in_seconds: u64,
}

async fn context(State(app): State<Arc<App>>) -> Json<SigningContext> {
    Json(app.context.clone())
}

async fn open_session(
    State(app): State<Arc<App>>,
    Json(body): Json<OpenSession>,
) -> std::result::Result<Json<Grant>, ApiError> {
    if body.authorization.len() > 4096 || body.signature.len() != 128 {
        return Err(UNAUTHORIZED);
    }
    let sig = hex::decode(&body.signature).map_err(|_| UNAUTHORIZED)?;
    signature::UnparsedPublicKey::new(&signature::ED25519, &app.verifier_key)
        .verify(body.authorization.as_bytes(), &sig)
        .map_err(|_| UNAUTHORIZED)?;
    let auth: Authorization =
        serde_json::from_str(&body.authorization).map_err(|_| UNAUTHORIZED)?;
    let package_hash = fingerprint(body.package_json.as_bytes());
    auth.check(&app.context, &package_hash)?;
    // Replaying an identical assertion can only recover the same signing session.
    let ticket = hex::encode(hmac::sign(&app.ticket_key, body.authorization.as_bytes()).as_ref());
    let permit = app.work.clone().try_acquire_owned().map_err(|_| BUSY)?;
    let purpose = auth.purpose;
    let wallet = app.wallet.clone();
    let (package, count) = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let package: SigningPackage = serde_json::from_str(&body.package_json)
            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid signing package"))?;
        let count = check_package(&wallet, &package, purpose).map_err(|_| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                "package, wallet or purpose mismatch",
            )
        })?;
        Ok((package, count))
    })
    .await
    .map_err(|_| INTERNAL)??;
    let mut tickets = app.tickets.lock().map_err(|_| INTERNAL)?;
    tickets.retain(|_, ticket| ticket.expires > Instant::now());
    auth.check(&app.context, &package_hash)?;
    let ticket_hash = fingerprint(ticket.as_bytes());
    if let Some(prior) = tickets.get(&ticket_hash) {
        return Ok(Json(Grant {
            ticket,
            expires_in_seconds: prior
                .expires
                .saturating_duration_since(Instant::now())
                .as_secs(),
        }));
    }
    if tickets.len() >= MAX_TICKETS {
        return Err(BUSY);
    }
    tickets.insert(
        ticket_hash,
        Ticket {
            expires: Instant::now() + TTL,
            session: Arc::new(Mutex::new(Session {
                purpose,
                package_hash,
                phase: Phase::Approved(package, count),
                ids: vec![],
                last: None,
            })),
        },
    );
    Ok(Json(Grant {
        ticket,
        expires_in_seconds: TTL.as_secs(),
    }))
}

async fn advance(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<Step>,
) -> std::result::Result<Json<Response>, ApiError> {
    let key = fingerprint(bearer(&headers)?.as_bytes());
    let (session, expires) = {
        let tickets = app.tickets.lock().map_err(|_| INTERNAL)?;
        let ticket = tickets
            .get(&key)
            .filter(|t| t.expires > Instant::now())
            .ok_or(UNAUTHORIZED)?;
        (ticket.session.clone(), ticket.expires)
    };
    let permit = app.work.clone().try_acquire_owned().map_err(|_| BUSY)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut state = session.try_lock().map_err(|e| match e {
            TryLockError::WouldBlock => BUSY,
            TryLockError::Poisoned(_) => CLOSED,
        })?;
        if expires <= Instant::now() {
            return Err(UNAUTHORIZED);
        }
        let reply = state.advance(&app.wallet, request)?;
        if expires <= Instant::now() {
            return Err(UNAUTHORIZED);
        }
        Ok(Json(reply))
    })
    .await
    .map_err(|_| CLOSED)?
}

pub(super) fn serve(wallet: PathBuf, listen: SocketAddr) -> Result<()> {
    let verifier_key: [u8; 32] = hex::decode(
        env::var("CHRONOS_AUTH_PUBLIC_KEY")
            .map_err(
                |_| "set CHRONOS_AUTH_PUBLIC_KEY to the biometric verifier's Ed25519 public key",
            )?
            .trim(),
    )?
    .try_into()
    .map_err(|_| "expected a 32-byte Ed25519 verifier public key")?;
    let mut boot_secret = zeroize::Zeroizing::new([0u8; 32]);
    OsRng.try_fill_bytes(&mut *boot_secret)?;
    let wallet = fs::canonicalize(wallet)?;
    let key =
        chronos_vault::parse_master_key(&fs::read_to_string(wallet.join("public-key.json"))?)?;
    // Verify that this host can open S before reporting readiness.
    super::party_store::open(&wallet.join("party-2"), 2, &key)?;
    let app = Arc::new(App {
        wallet,
        verifier_key,
        ticket_key: hmac::Key::new(hmac::HMAC_SHA256, &*boot_secret),
        context: SigningContext {
            instance_id: fingerprint(&*boot_secret),
            public_key: key.to_string(),
        },
        tickets: Mutex::new(HashMap::new()),
        work: Arc::new(Semaphore::new(4)),
    });
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            let listener = tokio::net::TcpListener::bind(listen).await?;
            eprintln!(
                "Testnet4 signing server listening on {}",
                listener.local_addr()?
            );
            let cleaner = Arc::clone(&app);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    if let Ok(mut map) = cleaner.tickets.lock() {
                        map.retain(|_, t| t.expires > Instant::now());
                    }
                }
            });
            let router = Router::new()
                .route("/health", get(|| async { "ok" }))
                .route("/v1/signing/context", get(context))
                .route("/v1/signing/sessions", post(open_session))
                .route("/v1/signing/steps", post(advance))
                .layer(DefaultBodyLimit::max(MAX_BODY))
                .layer(middleware::map_response(
                    |mut response: axum::response::Response| async move {
                        response
                            .headers_mut()
                            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
                        response.into_response()
                    },
                ))
                .with_state(app);
            axum::serve(listener, router).await
        })?;
    Ok(())
}

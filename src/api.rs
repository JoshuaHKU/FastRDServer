//! LOCAL FORK: the HTTP API the client's login dialog and address book expect.
//!
//! The client talks to `api-server`, which it derives as
//! `<rendezvous host>:<port - 2>` = **21114** when unset. Serving that port here
//! means an existing client finds this automatically, with no extra
//! configuration -- and it is the same port whose absence used to produce a
//! failed heartbeat every 18 seconds.
//!
//! Only the endpoints the open-source client actually needs are implemented.
//! Anything else 404s, which is not a gap: `AbModel` probes
//! `/api/ab/personal` and falls back to "legacy mode" on 404, where the whole
//! address book is one JSON document behind `GET/POST /api/ab`. Upstream added
//! that fallback for older servers; we are deliberately on that path.
//!
//! `axum` was already in Cargo.toml but unreferenced, so this adds no dependency.
//!
//! # Transport
//!
//! This serves **plain HTTP**. Passwords cross the wire in the clear, so 21114
//! must not be exposed to the internet directly -- terminate TLS in front of it
//! (nginx/Caddy) or keep the port on the private network.

use crate::account;
use crate::database::{Database, User};
use axum::{
    extract::Extension,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use hbb_common::tokio::sync::Mutex;
use hbb_common::{log, sealed};
use serde_json::{json, Value};
use sodiumoxide::crypto::{box_, sign};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

/// Failed logins tolerated per (username, IP) before a lockout.
const MAX_LOGIN_FAILURES: u32 = 5;
/// How long that lockout lasts.
const LOCKOUT_SECS: u64 = 300;

type FailMap = HashMap<String, (u32, Instant)>;

#[derive(Clone)]
pub struct ApiState {
    pub db: Database,
    failures: Arc<Mutex<FailMap>>,
    /// The server's signing key, converted once into the curve25519 pair sealed
    /// boxes need. `None` when the server runs without a key, in which case the
    /// encrypted path is simply unavailable.
    box_keys: Option<Arc<(box_::PublicKey, box_::SecretKey)>>,
}

impl ApiState {
    pub fn new(db: Database, sk: Option<sign::SecretKey>) -> Self {
        let box_keys = sk.and_then(|sk| match sealed::server_box_sk(&sk) {
            Ok(pair) => Some(Arc::new(pair)),
            Err(e) => {
                log::error!("cannot derive box keys from server key: {e}");
                None
            }
        });
        Self {
            db,
            failures: Default::default(),
            box_keys,
        }
    }

    /// Open a sealed request, returning the plaintext.
    fn unseal(&self, sealed_b64: &str) -> Option<Vec<u8>> {
        let keys = self.box_keys.as_ref()?;
        sealed::open_with(sealed_b64, &keys.0, &keys.1).ok()
    }

    /// Throttle by username *and* source IP together: keying on IP alone would
    /// let one NAT'd office lock out everyone behind it, and on username alone
    /// would let anyone lock out a known account from anywhere.
    async fn locked_out(&self, key: &str) -> bool {
        let mut m = self.failures.lock().await;
        match m.get(key) {
            Some((n, at)) if *n >= MAX_LOGIN_FAILURES => {
                if at.elapsed().as_secs() < LOCKOUT_SECS {
                    true
                } else {
                    m.remove(key);
                    false
                }
            }
            _ => false,
        }
    }

    async fn note_failure(&self, key: &str) {
        let mut m = self.failures.lock().await;
        let e = m.entry(key.to_owned()).or_insert((0, Instant::now()));
        e.0 += 1;
        e.1 = Instant::now();
    }

    async fn clear_failures(&self, key: &str) {
        self.failures.lock().await.remove(key);
    }
}

/// The client sends `Authorization: Bearer <token>`.
async fn user_from_headers(state: &ApiState, headers: &HeaderMap) -> Option<User> {
    let raw = headers.get("authorization")?.to_str().ok()?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?;
    state.db.user_by_token(token.trim()).await.ok().flatten()
}

fn token_from_headers(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("authorization")?.to_str().ok()?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?;
    Some(token.trim().to_owned())
}

/// Shape the client's `UserPayload.fromJson` expects.
fn user_payload(u: &User) -> Value {
    json!({
        "name": u.name,
        "display_name": u.name,
        "email": u.email.clone().unwrap_or_default(),
        "note": "",
        "status": u.status,
        "is_admin": u.is_admin,
        "avatar": "",
    })
}

// -------------------------------------------------------------------- handlers

async fn login(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // Encrypted form: {"sealed": "<base64>"} where the plaintext carries the
    // usual fields plus `ts` (anti-replay) and `reply_pk` (where to seal the
    // answer). Clients always use this; the plaintext form is kept so an admin
    // can curl the endpoint from the server itself.
    let mut reply_pk: Option<box_::PublicKey> = None;
    let body: Value = if let Some(sealed_b64) = body["sealed"].as_str() {
        let Some(plain) = state.unseal(sealed_b64) else {
            log::warn!("login: could not decrypt sealed payload");
            return (StatusCode::OK, Json(json!({"error": "Decryption failed"})));
        };
        let Ok(v) = serde_json::from_slice::<Value>(&plain) else {
            return (StatusCode::OK, Json(json!({"error": "Malformed payload"})));
        };
        let ts = v["ts"].as_i64().unwrap_or(0);
        if !sealed::timestamp_acceptable(ts) {
            // A sealed box on its own is replayable; the stamp is what bounds it.
            log::warn!("login: stale timestamp {ts}");
            return (StatusCode::OK, Json(json!({"error": "Stale request"})));
        }
        match v["reply_pk"].as_str().map(sealed::decode_pk) {
            Some(Ok(pk)) => reply_pk = Some(pk),
            Some(Err(_)) => {
                return (StatusCode::OK, Json(json!({"error": "Bad reply key"})));
            }
            None => {}
        }
        v
    } else {
        body
    };

    let name = body["username"].as_str().unwrap_or("").trim().to_owned();
    let password = body["password"].as_str().unwrap_or("").to_owned();
    let device_id = body["id"].as_str().unwrap_or("").to_owned();
    let peer_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_owned();

    if name.is_empty() || password.is_empty() {
        return (
            StatusCode::OK,
            Json(json!({"error": "Username or password is empty"})),
        );
    }

    let key = format!("{name}|{peer_ip}");
    if state.locked_out(&key).await {
        log::warn!("login locked out for {name} from {peer_ip}");
        return (
            StatusCode::OK,
            Json(json!({"error": "Too many failed attempts, try again later"})),
        );
    }

    match account::authenticate(&state.db, &name, &password).await {
        Ok(Some(user)) => {
            state.clear_failures(&key).await;
            match account::issue_token(&state.db, &user, &device_id).await {
                Ok(token) => {
                    log::info!("login ok: {name} from device {device_id}");
                    let payload = json!({
                        "access_token": token,
                        // The client treats this literal as "logged in".
                        "type": "access_token",
                        "user": user_payload(&user),
                    });
                    // Seal the answer to the caller's one-shot key, so the token
                    // is no more readable on the wire than the password was.
                    match reply_pk {
                        Some(pk) => {
                            let bytes = serde_json::to_vec(&payload).unwrap_or_default();
                            (
                                StatusCode::OK,
                                Json(json!({"sealed": sealed::seal_to(&bytes, &pk)})),
                            )
                        }
                        None => (StatusCode::OK, Json(payload)),
                    }
                }
                Err(e) => {
                    log::error!("issue token failed: {e}");
                    (StatusCode::OK, Json(json!({"error": "Server error"})))
                }
            }
        }
        Ok(None) => {
            state.note_failure(&key).await;
            log::warn!("login failed: {name} from {peer_ip}");
            // One message for "no such user" and "wrong password" alike, so the
            // response cannot be used to discover which usernames exist.
            (
                StatusCode::OK,
                Json(json!({"error": "Wrong username or password"})),
            )
        }
        Err(e) => {
            log::error!("authenticate failed: {e}");
            (StatusCode::OK, Json(json!({"error": "Server error"})))
        }
    }
}

async fn current_user(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    match user_from_headers(&state, &headers).await {
        Some(u) => (StatusCode::OK, Json(user_payload(&u))),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Not authenticated"})),
        ),
    }
}

async fn logout(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    if let Some(token) = token_from_headers(&headers) {
        let _ = state.db.delete_token(&token).await;
    }
    (StatusCode::OK, Json(json!({})))
}

/// Address book, legacy shape: the whole book as one JSON document per account.
///
/// The client probes `/api/ab/personal` first and drops into this mode when that
/// 404s, which it does here. Upstream keeps the fallback for older servers; we
/// use it deliberately, because a single document is all a handful of devices
/// needs and it avoids reimplementing the Pro server's multi-book API.
///
/// Reply shape is `{"data": "<json string>"}` -- note `data` is a *string*
/// containing JSON, not nested JSON. An empty book answers `null`, which the
/// client treats as "no entries" rather than an error.
async fn get_ab(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let Some(user) = user_from_headers(&state, &headers).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Not authenticated"})),
        );
    };
    match state.db.get_user_ab(&user.guid).await {
        Ok(Some(ab)) if !ab.is_empty() => (StatusCode::OK, Json(json!({ "data": ab }))),
        Ok(_) => (StatusCode::OK, Json(Value::Null)),
        Err(e) => {
            log::error!("get_ab failed: {e}");
            (StatusCode::OK, Json(json!({"error": "Server error"})))
        }
    }
}

/// Replace the whole book. The client sends the complete document every time, so
/// there is nothing to merge -- and merging would be wrong, since a deletion is
/// expressed only by the entry's absence.
async fn post_ab(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(user) = user_from_headers(&state, &headers).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Not authenticated"})),
        );
    };
    let data = body["data"].as_str().unwrap_or("");
    match state.db.set_user_ab(&user.guid, data).await {
        Ok(_) => {
            log::info!(
                "address book saved for {} ({} bytes)",
                user.name,
                data.len()
            );
            // Success is an empty body; the client checks for exactly that.
            (StatusCode::OK, Json(Value::Null))
        }
        Err(e) => {
            log::error!("set_ab failed: {e}");
            (StatusCode::OK, Json(json!({"error": "Server error"})))
        }
    }
}

/// Change one's own password while signed in.
///
/// Distinct from the admin CLI reset: this one requires the current password, so
/// a stolen token alone cannot lock the owner out. Every token is dropped
/// afterwards, including the caller's -- signing back in is the proof the change
/// took effect.
async fn change_password(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(user) = user_from_headers(&state, &headers).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Not authenticated"})),
        );
    };
    // Accept the sealed form here too: this carries passwords.
    let body: Value = if let Some(sealed_b64) = body["sealed"].as_str() {
        let Some(plain) = state.unseal(sealed_b64) else {
            return (StatusCode::OK, Json(json!({"error": "Decryption failed"})));
        };
        let Ok(v) = serde_json::from_slice::<Value>(&plain) else {
            return (StatusCode::OK, Json(json!({"error": "Malformed payload"})));
        };
        if !sealed::timestamp_acceptable(v["ts"].as_i64().unwrap_or(0)) {
            return (StatusCode::OK, Json(json!({"error": "Stale request"})));
        }
        v
    } else {
        body
    };

    let old = body["old_password"].as_str().unwrap_or("");
    let new = body["new_password"].as_str().unwrap_or("");
    if new.len() < 6 {
        return (
            StatusCode::OK,
            Json(json!({"error": "New password is too short"})),
        );
    }
    if !account::verify_password(old, &user.password) {
        log::warn!(
            "password change refused for {}: wrong current password",
            user.name
        );
        return (
            StatusCode::OK,
            Json(json!({"error": "Current password is wrong"})),
        );
    }
    let Ok(hash) = account::hash_password(new) else {
        return (StatusCode::OK, Json(json!({"error": "Server error"})));
    };
    match state.db.set_user_password(&user.guid, &hash).await {
        Ok(_) => {
            log::info!(
                "password changed for {}; all sessions signed out",
                user.name
            );
            (StatusCode::OK, Json(json!({"ok": true})))
        }
        Err(e) => {
            log::error!("set password failed: {e}");
            (StatusCode::OK, Json(json!({"error": "Server error"})))
        }
    }
}

/// No third-party sign-in here. The client expects a list and handles empty.
async fn login_options() -> Json<Value> {
    Json(json!([]))
}

async fn health() -> &'static str {
    "ok"
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/api/login", post(login))
        .route("/api/currentUser", post(current_user))
        .route("/api/logout", post(logout))
        .route("/api/login-options", get(login_options))
        .route("/api/ab", get(get_ab).post(post_ab))
        .route("/api/password", post(change_password))
        .route("/api/health", get(health))
        .layer(Extension(state))
}

/// Start the API server. Failure is logged and swallowed: the rendezvous service
/// must keep running even if this port is taken, since remote control does not
/// depend on it.
pub async fn serve(db: Database, port: u16, sk: Option<sign::SecretKey>) {
    let state = ApiState::new(db, sk);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    log::info!("API server listening on {addr}");
    if let Err(e) = axum::Server::bind(&addr)
        .serve(router(state).into_make_service())
        .await
    {
        log::error!("API server stopped: {e}");
    }
}

//! In-process, stateful mock of the VELA server's wire protocol.
//!
//! Implements the subset of `serverVELA` that the desktop core and the
//! android-client harness actually talk to: account registration, challenge /
//! signature verification, device enrollment, enrollment packages, the RMS
//! capsule, share-key registration, and the versioned / lamport-clocked vault
//! chunk API. The auth signature verification is real (`vela_crypto::signing`),
//! so a desktop client authenticating here is exercising its real signature
//! path, not a hand-waved substitute.
//!
//! Bearer tokens are opaque random strings (no PASETO), so no token rotation
//! happens and `X-New-Token` is never emitted — clients treat an absent
//! rotation header as "keep using the current token".

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post, put};
use axum::Router;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rand::RngCore;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use vela_crypto::signing;

/// Wrapper around the mock state so axum handlers can clone the handle.
#[derive(Clone)]
pub struct MockDb(Arc<Mutex<MockDbInner>>);

#[derive(Default)]
struct MockDbInner {
    users: HashMap<String, ()>,
    devices: HashMap<String, Device>,
    /// Single-use challenge -> when it was issued (60 s TTL).
    challenges: HashMap<String, std::time::Instant>,
    /// Bearer token -> device_id.
    tokens: HashMap<String, String>,
    /// Enrollment package token -> base64 ciphertext.
    enrollment_packages: HashMap<String, String>,
    /// Enrollment v3 grant id -> who may drive it (audit P-1).
    enroll_grants: HashMap<String, Grant>,
    /// Grant id -> the public keys a joining device presented. Written exactly
    /// once per grant, which is the property the whole design leans on.
    enroll_claims: HashMap<String, Claim>,
    /// Grant id -> what the joining device may collect once enrolled.
    enroll_results: HashMap<String, EnrollmentResult>,
    /// "user_id\0chunk_id" -> chunk.
    chunks: HashMap<String, Chunk>,
}

#[derive(Clone)]
struct Grant {
    user_id: String,
    device_id: String,
}

#[derive(Clone)]
struct Claim {
    hybrid_ek: Vec<u8>,
    hybrid_vk: Vec<u8>,
    device_name: Option<String>,
    device_type: Option<String>,
}

#[derive(Clone)]
struct EnrollmentResult {
    device_id: String,
    hybrid_vk: Vec<u8>,
}

#[derive(Clone)]
struct Device {
    device_id: String,
    user_id: String,
    hybrid_vk: Vec<u8>,
    rms_capsule: Vec<u8>,
}

#[derive(Clone)]
struct Chunk {
    version: i64,
    lamport_clock: i64,
    last_writer: Option<String>,
    ciphertext: Vec<u8>,
}

/// A running mock server on 127.0.0.1 with an OS-assigned free port.
pub struct MockServer {
    pub addr: SocketAddr,
    pub db: MockDb,
}

impl MockDb {
    fn new() -> Self {
        MockDb(Arc::new(Mutex::new(MockDbInner::default())))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MockDbInner> {
        self.0.lock().unwrap()
    }

    /// Direct inspection helper for tests (e.g. assert chunk count on the server).
    pub fn chunk_count(&self) -> usize {
        self.lock().chunks.len()
    }

    pub fn user_count(&self) -> usize {
        self.lock().users.len()
    }
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

fn random_token() -> String {
    format!("vela-mock-token-{}", Uuid::new_v4())
}

fn chunk_key(user_id: &str, chunk_id: &str) -> String {
    format!("{user_id}\u{0}{chunk_id}")
}

// ───────────────────────── response builders ─────────────────────────

fn json_response(status: StatusCode, value: serde_json::Value) -> Response {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&value).unwrap()))
        .unwrap()
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    json_response(status, serde_json::json!({ "error": code, "message": message }))
}

fn ok_json(value: serde_json::Value) -> Response {
    json_response(StatusCode::OK, value)
}

// ───────────────────────── auth ─────────────────────────

fn bearer_token(headers: &HeaderMap) -> Result<&str, Response> {
    let value = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "unauthorized", "missing bearer token"))?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "unauthorized", "malformed bearer token"))?;
    Ok(token)
}

fn auth_device(db: &MockDb, headers: &HeaderMap) -> Result<Device, Response> {
    let token = bearer_token(headers)?;
    let device_id = db
        .lock()
        .tokens
        .get(token)
        .cloned()
        .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "unauthorized", "token verification failed"))?;
    db.lock()
        .devices
        .get(&device_id)
        .cloned()
        .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "unauthorized", "device not found"))
}

/// Parse a single-use challenge: consumed on first use, 60 s TTL, 401 after.
fn consume_challenge(db: &MockDb, challenge_b64: &str) -> Result<Vec<u8>, Response> {
    let bytes = B64
        .decode(challenge_b64)
        .map_err(|_| error_response(StatusCode::UNAUTHORIZED, "unauthorized", "malformed challenge"))?;
    let mut inner = db.lock();
    let issued = inner
        .challenges
        .remove(challenge_b64)
        .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "unauthorized", "challenge missing or already used"))?;
    if issued.elapsed() > std::time::Duration::from_secs(60) {
        return Err(error_response(StatusCode::UNAUTHORIZED, "unauthorized", "challenge expired"));
    }
    Ok(bytes)
}

// ───────────────────────── handlers ─────────────────────────

#[derive(Deserialize)]
#[allow(dead_code)]
struct RegisterBody {
    hybrid_ek: String,
    hybrid_vk: String,
    device_name: Option<String>,
    device_type: Option<String>,
    share_ek: Option<String>,
}

async fn post_register(State(db): State<MockDb>, body: axum::body::Bytes) -> Response {
    let body: RegisterBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "bad_request", "malformed register body"),
    };
    match B64.decode(&body.hybrid_ek) {
        Ok(_) => {}
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "bad_request", "hybrid_ek is not valid base64"),
    }
    let hybrid_vk = match B64.decode(&body.hybrid_vk) {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "bad_request", "hybrid_vk is not valid base64"),
    };

    let user_id = Uuid::new_v4().to_string();
    let device_id = Uuid::new_v4().to_string();
    {
        let mut inner = db.lock();
        inner.users.insert(user_id.clone(), ());
        inner.devices.insert(
            device_id.clone(),
            Device {
                device_id: device_id.clone(),
                user_id: user_id.clone(),
                hybrid_vk,
                rms_capsule: Vec::new(),
            },
        );
        let token = random_token();
        inner.tokens.insert(token.clone(), device_id.clone());
    }
    ok_json(serde_json::json!({
        "user_id": user_id,
        "device_id": device_id,
        "token": db.lock().tokens.iter().find(|(_, d)| **d == device_id).map(|(t, _)| t.clone()).unwrap(),
    }))
}

async fn get_challenge(State(db): State<MockDb>) -> Response {
    let challenge_bytes = random_bytes(32);
    let challenge_b64 = B64.encode(&challenge_bytes);
    db.lock().challenges.insert(challenge_b64.clone(), std::time::Instant::now());
    ok_json(serde_json::json!({ "challenge": challenge_b64 }))
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct VerifyBody {
    device_id: String,
    challenge: String,
    signature: String,
    device_name: Option<String>,
    device_type: Option<String>,
}

async fn post_verify(State(db): State<MockDb>, body: axum::body::Bytes) -> Response {
    let body: VerifyBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "bad_request", "malformed verify body"),
    };
    let challenge_bytes = match consume_challenge(&db, &body.challenge) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let device = match db.lock().devices.get(&body.device_id).cloned() {
        Some(d) => d,
        None => return error_response(StatusCode::UNAUTHORIZED, "unauthorized", "device not found"),
    };
    if !verify_signature(&device.hybrid_vk, &signing::auth_message(&body.device_id, &challenge_bytes), &body.signature) {
        return error_response(StatusCode::UNAUTHORIZED, "unauthorized", "signature verification failed");
    }

    let token = random_token();
    {
        let mut inner = db.lock();
        inner.tokens.insert(token.clone(), device.device_id.clone());
    }
    ok_json(serde_json::json!({ "token": token, "user_id": device.user_id }))
}

fn verify_signature(hybrid_vk: &[u8], message: &[u8], signature_b64: &str) -> bool {
    let vk_bytes: &[u8; signing::HYBRID_VK_LEN] = match hybrid_vk.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let vk = match signing::HybridVerifyingKey::from_bytes(vk_bytes) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let sig_bytes = match B64.decode(signature_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig: &[u8; signing::HYBRID_SIG_LEN] = match sig_bytes.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig = match signing::HybridSignature::from_bytes(sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    signing::verify(&vk, message, &sig).unwrap_or(false)
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct EnrollBody {
    enrolling_device_id: String,
    challenge: String,
    auth_signature: String,
    new_device: NewDeviceBody,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct NewDeviceBody {
    hybrid_ek: String,
    hybrid_vk: String,
    rms_capsule: String,
    signature: String,
    device_name: Option<String>,
    device_type: Option<String>,
}

async fn post_enroll(State(db): State<MockDb>, body: axum::body::Bytes) -> Response {
    let body: EnrollBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "bad_request", "malformed enroll body"),
    };
    let challenge_bytes = match consume_challenge(&db, &body.challenge) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let enrolling = match db.lock().devices.get(&body.enrolling_device_id).cloned() {
        Some(d) => d,
        None => return error_response(StatusCode::UNAUTHORIZED, "unauthorized", "enrolling device not found"),
    };
    if !verify_signature(
        &enrolling.hybrid_vk,
        &signing::auth_message(&body.enrolling_device_id, &challenge_bytes),
        &body.auth_signature,
    ) {
        return error_response(StatusCode::UNAUTHORIZED, "unauthorized", "enrolling device auth signature invalid");
    }

    let new_ek = match B64.decode(&body.new_device.hybrid_ek) {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "bad_request", "new device hybrid_ek is not base64"),
    };
    let new_vk = match B64.decode(&body.new_device.hybrid_vk) {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "bad_request", "new device hybrid_vk is not base64"),
    };
    let capsule = match B64.decode(&body.new_device.rms_capsule) {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "bad_request", "new device rms_capsule is not base64"),
    };
    let enroll_message = signing::enrollment_message(&new_ek, &new_vk, &capsule);
    // The ENROLLING device signs the enrollment payload (proving it authorises
    // adding this device) — the real server verifies against device_a.hybrid_vk.
    if !verify_signature(&enrolling.hybrid_vk, &enroll_message, &body.new_device.signature) {
        return error_response(StatusCode::BAD_REQUEST, "bad_request", "enrolling device signature over enrollment payload invalid");
    }

    let new_device_id = Uuid::new_v4().to_string();
    {
        let mut inner = db.lock();
        inner.devices.insert(
            new_device_id.clone(),
            Device {
                device_id: new_device_id.clone(),
                user_id: enrolling.user_id.clone(),
                hybrid_vk: new_vk,
                rms_capsule: capsule,
            },
        );
    }
    ok_json(serde_json::json!({ "device_id": new_device_id }))
}

// ───────────────────── enrollment v3 rendezvous (audit P-1) ─────────────────
//
// Faithful to `serverVELA/.../rendezvous.rs` in the parts a client can observe
// or get wrong: a grant is bound to the device that opened it, admits exactly
// one claim, the enrolled keys come from the stored claim rather than the
// completion body, completing consumes both, and the result is collectable only
// by whoever holds the private half of the claimed key. A mock that were laxer
// than the server would let a broken client pass here and fail in production.

async fn post_enrollment_grant(State(db): State<MockDb>, headers: HeaderMap) -> Response {
    let device = match auth_device(&db, &headers) {
        Ok(d) => d,
        Err(resp) => return resp,
    };
    let grant_id = Uuid::new_v4().to_string();
    db.lock().enroll_grants.insert(
        grant_id.clone(),
        Grant { user_id: device.user_id, device_id: device.device_id },
    );
    ok_json(serde_json::json!({ "grant_id": grant_id, "expires_in": 300 }))
}

#[derive(Deserialize)]
struct ClaimBody {
    hybrid_ek: String,
    hybrid_vk: String,
    device_name: Option<String>,
    device_type: Option<String>,
}

async fn post_enrollment_claim(
    State(db): State<MockDb>,
    Path(grant_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let body: ClaimBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "bad_request", "malformed claim body"),
    };
    let (Ok(ek), Ok(vk)) = (B64.decode(&body.hybrid_ek), B64.decode(&body.hybrid_vk)) else {
        return error_response(StatusCode::BAD_REQUEST, "bad_request", "claim keys are not base64");
    };

    let mut inner = db.lock();
    if !inner.enroll_grants.contains_key(&grant_id) {
        return error_response(StatusCode::NOT_FOUND, "not_found", "enrollment grant not found or expired");
    }
    // First claim wins, and the loser is told. Silent replacement is what would
    // make a hijack invisible.
    if inner.enroll_claims.contains_key(&grant_id) {
        return error_response(
            StatusCode::CONFLICT,
            "conflict",
            "this enrollment code has already been used by another device",
        );
    }
    inner.enroll_claims.insert(
        grant_id,
        Claim { hybrid_ek: ek, hybrid_vk: vk, device_name: body.device_name, device_type: body.device_type },
    );
    ok_json(serde_json::json!({ "claimed": true }))
}

/// Load a grant and require the caller to be the device that opened it.
fn authorize_grant(db: &MockDb, grant_id: &str, headers: &HeaderMap) -> Result<Grant, Response> {
    let device = auth_device(db, headers)?;
    let grant = db.lock().enroll_grants.get(grant_id).cloned().ok_or_else(|| {
        error_response(StatusCode::NOT_FOUND, "not_found", "enrollment grant not found or expired")
    })?;
    if grant.user_id != device.user_id || grant.device_id != device.device_id {
        // Same message as "not found": whether a grant exists is not something
        // an unrelated caller should be able to probe.
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "enrollment grant not found or expired",
        ));
    }
    Ok(grant)
}

async fn get_enrollment_claim(
    State(db): State<MockDb>,
    Path(grant_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = authorize_grant(&db, &grant_id, &headers) {
        return resp;
    }
    match db.lock().enroll_claims.get(&grant_id).cloned() {
        Some(claim) => ok_json(serde_json::json!({
            "hybrid_ek": B64.encode(&claim.hybrid_ek),
            "hybrid_vk": B64.encode(&claim.hybrid_vk),
            "device_name": claim.device_name,
            "device_type": claim.device_type,
        })),
        None => error_response(StatusCode::NOT_FOUND, "not_found", "no device has claimed this code yet"),
    }
}

#[derive(Deserialize)]
struct CompleteBody {
    rms_capsule: String,
    signature: String,
}

async fn post_enrollment_complete(
    State(db): State<MockDb>,
    Path(grant_id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let grant = match authorize_grant(&db, &grant_id, &headers) {
        Ok(g) => g,
        Err(resp) => return resp,
    };
    let body: CompleteBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "bad_request", "malformed complete body"),
    };

    // Consume both together, so a replay finds nothing.
    let claim = {
        let mut inner = db.lock();
        let claim = match inner.enroll_claims.remove(&grant_id) {
            Some(c) => c,
            None => {
                return error_response(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "no device has claimed this code yet",
                )
            }
        };
        inner.enroll_grants.remove(&grant_id);
        claim
    };

    let capsule = match B64.decode(&body.rms_capsule) {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "bad_request", "rms_capsule is not base64"),
    };

    let primary = match db.lock().devices.get(&grant.device_id).cloned() {
        Some(d) => d,
        None => return error_response(StatusCode::UNAUTHORIZED, "unauthorized", "enrolling device not found"),
    };
    // Signed over the *stored* keys — so a primary cannot enrol something other
    // than what the user's fingerprint comparison was about.
    let message = signing::enrollment_message(&claim.hybrid_ek, &claim.hybrid_vk, &capsule);
    if !verify_signature(&primary.hybrid_vk, &message, &body.signature) {
        return error_response(StatusCode::BAD_REQUEST, "bad_request", "enrollment signature invalid");
    }

    let new_device_id = Uuid::new_v4().to_string();
    {
        let mut inner = db.lock();
        inner.devices.insert(
            new_device_id.clone(),
            Device {
                device_id: new_device_id.clone(),
                user_id: grant.user_id.clone(),
                hybrid_vk: claim.hybrid_vk.clone(),
                rms_capsule: capsule,
            },
        );
        inner.enroll_results.insert(
            grant_id,
            EnrollmentResult { device_id: new_device_id.clone(), hybrid_vk: claim.hybrid_vk },
        );
    }
    ok_json(serde_json::json!({ "device_id": new_device_id }))
}

#[derive(Deserialize)]
struct ResultBody {
    signature: String,
}

async fn post_enrollment_result(
    State(db): State<MockDb>,
    Path(grant_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let body: ResultBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "bad_request", "malformed result body"),
    };
    let message = signing::enrollment_result_message(&grant_id);

    // Completed: the claim is gone and the result carries the vk forward.
    if let Some(result) = db.lock().enroll_results.get(&grant_id).cloned() {
        if !verify_signature(&result.hybrid_vk, &message, &body.signature) {
            return error_response(StatusCode::UNAUTHORIZED, "unauthorized", "signature does not match the claimed key");
        }
        return ok_json(serde_json::json!({ "status": "enrolled", "device_id": result.device_id }));
    }

    // Not completed yet. Checked against the claimed key too, so "pending" is
    // not an answer someone holding only the code can get.
    if let Some(claim) = db.lock().enroll_claims.get(&grant_id).cloned() {
        if !verify_signature(&claim.hybrid_vk, &message, &body.signature) {
            return error_response(StatusCode::UNAUTHORIZED, "unauthorized", "signature does not match the claimed key");
        }
        return ok_json(serde_json::json!({ "status": "pending" }));
    }

    error_response(StatusCode::NOT_FOUND, "not_found", "enrollment grant not found or expired")
}

#[derive(Deserialize)]
struct StorePackageBody {
    token: String,
    ciphertext: String,
}

async fn post_enrollment_package(State(db): State<MockDb>, body: axum::body::Bytes) -> Response {
    let body: StorePackageBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "bad_request", "malformed enrollment package body"),
    };
    db.lock().enrollment_packages.insert(body.token, body.ciphertext);
    ok_json(serde_json::json!({ "ok": true }))
}

async fn get_enrollment_package(
    State(db): State<MockDb>,
    headers: HeaderMap,
    path: Option<Path<String>>,
) -> Response {
    let token = headers
        .get("x-enrollment-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| path.map(|Path(t)| t));
    let token = match token {
        Some(t) => t,
        None => return error_response(StatusCode::BAD_REQUEST, "bad_request", "missing enrollment token"),
    };
    match db.lock().enrollment_packages.get(&token).cloned() {
        Some(ciphertext) => ok_json(serde_json::json!({ "ciphertext": ciphertext })),
        None => error_response(StatusCode::NOT_FOUND, "not_found", "enrollment package not found"),
    }
}

async fn get_capsule(State(db): State<MockDb>, headers: HeaderMap) -> Response {
    let device = match auth_device(&db, &headers) {
        Ok(d) => d,
        Err(resp) => return resp,
    };
    if device.rms_capsule.is_empty() {
        return error_response(StatusCode::NOT_FOUND, "not_found", "no RMS capsule for this device");
    }
    ok_json(serde_json::json!({ "capsule": B64.encode(&device.rms_capsule) }))
}

async fn put_my_share_ek(State(db): State<MockDb>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    if let Err(resp) = auth_device(&db, &headers) {
        return resp;
    }
    let _ = body; // share key is intentionally not validated by the mock
    ok_json(serde_json::json!({ "ok": true }))
}

async fn get_sync_manifest(State(db): State<MockDb>, headers: HeaderMap) -> Response {
    let device = match auth_device(&db, &headers) {
        Ok(d) => d,
        Err(resp) => return resp,
    };
    let prefix = format!("{}{}", device.user_id, '\u{0}');
    let mut entries: Vec<serde_json::Value> = db
        .lock()
        .chunks
        .iter()
        .filter(|(key, _)| key.starts_with(&prefix))
        .map(|(key, chunk)| {
            let chunk_id = key[prefix.len()..].to_string();
            serde_json::json!({
                "chunk_id": chunk_id,
                "version": chunk.version,
                "lamport_clock": chunk.lamport_clock,
                "last_writer": chunk.last_writer,
            })
        })
        .collect();
    entries.sort_by(|a, b| a["chunk_id"].as_str().cmp(&b["chunk_id"].as_str()));
    ok_json(serde_json::json!({ "chunks": entries }))
}

async fn get_chunk(State(db): State<MockDb>, headers: HeaderMap, Path(chunk_id): Path<String>) -> Response {
    let device = match auth_device(&db, &headers) {
        Ok(d) => d,
        Err(resp) => return resp,
    };
    let chunk = match db.lock().chunks.get(&chunk_key(&device.user_id, &chunk_id)).cloned() {
        Some(c) => c,
        None => return error_response(StatusCode::NOT_FOUND, "not_found", "chunk not found"),
    };
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header("X-Chunk-Version", chunk.version.to_string())
        .header("X-Lamport-Clock", chunk.lamport_clock.to_string());
    if let Some(writer) = &chunk.last_writer {
        builder = builder.header("X-Last-Writer", writer.clone());
    }
    builder.body(Body::from(chunk.ciphertext)).unwrap()
}

async fn put_chunk(
    State(db): State<MockDb>,
    headers: HeaderMap,
    Path(chunk_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let device = match auth_device(&db, &headers) {
        Ok(d) => d,
        Err(resp) => return resp,
    };
    let if_match: i64 = match header_int(&headers, "if-match") {
        Some(v) => v,
        None => return error_response(StatusCode::BAD_REQUEST, "bad_request", "missing If-Match header"),
    };
    let lamport_clock: i64 = match header_int(&headers, "x-lamport-clock") {
        Some(v) => v,
        None => return error_response(StatusCode::BAD_REQUEST, "bad_request", "missing X-Lamport-Clock header"),
    };

    let key = chunk_key(&device.user_id, &chunk_id);
    let mut inner = db.lock();
    let existing = inner.chunks.get(&key);

    let new_version = match (if_match, existing) {
        (0, None) => 1,
        (0, Some(_)) => {
            return error_response(
                StatusCode::CONFLICT,
                "version_conflict",
                "chunk already exists; use If-Match with current version to update",
            )
        }
        (n, Some(existing)) if existing.version == n => n + 1,
        (_, _) => {
            return error_response(StatusCode::CONFLICT, "version_conflict", "version mismatch — re-sync before retrying")
        }
    };

    inner.chunks.insert(
        key,
        Chunk {
            version: new_version,
            lamport_clock,
            last_writer: Some(device.device_id.clone()),
            ciphertext: body.to_vec(),
        },
    );

    let builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header("X-Chunk-Version", new_version.to_string());
    builder.body(Body::from(serde_json::json!({ "version": new_version }).to_string())).unwrap()
}

async fn delete_chunk(State(db): State<MockDb>, headers: HeaderMap, Path(chunk_id): Path<String>) -> Response {
    let device = match auth_device(&db, &headers) {
        Ok(d) => d,
        Err(resp) => return resp,
    };
    let if_match: i64 = match header_int(&headers, "if-match") {
        Some(v) => v,
        None => return error_response(StatusCode::BAD_REQUEST, "bad_request", "missing If-Match header"),
    };
    let key = chunk_key(&device.user_id, &chunk_id);
    let mut inner = db.lock();
    let existing = match inner.chunks.get(&key) {
        Some(c) => c,
        None => return error_response(StatusCode::NOT_FOUND, "not_found", "chunk not found"),
    };
    if existing.version != if_match {
        return error_response(StatusCode::CONFLICT, "version_conflict", "version mismatch — re-sync before retrying");
    }
    let version = existing.version;
    inner.chunks.remove(&key);
    ok_json(serde_json::json!({ "deleted": true, "version": version }))
}

async fn health() -> Response {
    ok_json(serde_json::json!({ "status": "ok" }))
}

fn header_int(headers: &HeaderMap, name: &str) -> Option<i64> {
    headers.get(name).and_then(|v| v.to_str().ok()).and_then(|s| s.parse().ok())
}

// ───────────────────────── server ─────────────────────────

impl MockServer {
    /// Bind on 127.0.0.1:0 (OS-assigned free port) and serve until dropped.
    pub async fn spawn() -> Result<Self, Box<dyn std::error::Error>> {
        let db = MockDb::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let app = Router::new()
            .route("/health", get(health))
            .route("/account/register", post(post_register))
            .route("/auth/challenge", get(get_challenge))
            .route("/auth/verify", post(post_verify))
            .route("/device/enroll", post(post_enroll))
            .route("/device/enrollment-package", post(post_enrollment_package))
            .route("/device/enrollment-package/:token", get(get_enrollment_package))
            .route("/device/enrollment-grant", post(post_enrollment_grant))
            .route("/device/enrollment-grant/:id/claim", post(post_enrollment_claim))
            .route("/device/enrollment-grant/:id", get(get_enrollment_claim))
            .route("/device/enrollment-grant/:id/complete", post(post_enrollment_complete))
            .route("/device/enrollment-grant/:id/result", post(post_enrollment_result))
            .route("/device/capsule", get(get_capsule))
            .route("/share/my-ek", put(put_my_share_ek))
            .route("/vault/sync", get(get_sync_manifest))
            .route("/vault/chunk/:chunk_id", get(get_chunk).put(put_chunk).delete(delete_chunk))
            .with_state(db.clone());

        tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, app.into_make_service()).await {
                eprintln!("mock server error: {err}");
            }
        });

        Ok(MockServer { addr, db })
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Poll `/health` until the spawned serve task is accepting connections.
    pub async fn wait_ready(&self) {
        let client = reqwest::Client::new();
        for _ in 0..50 {
            if client.get(format!("{}/health", self.url())).send().await.map(|r| r.status().is_success()).unwrap_or(false) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("mock server did not become ready");
    }

    /// A bearer token for a given device (used to poke the server directly in tests).
    pub fn token_for_device(&self, device_id: &str) -> Option<String> {
        self.db
            .lock()
            .tokens
            .iter()
            .find(|(_, d)| *d == device_id)
            .map(|(t, _)| t.clone())
    }
}

//! Focused handler tests for the `/auth/verify` login driver.
//!
//! The pure driver tests live in `vela-session-policy/tests/login_driver.rs`.
//! These tests exercise the real Axum handler, the real sled challenge take,
//! the real hybrid verifier, the real PASETO signer and the real JTI tracker.

use std::net::SocketAddr;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;
use vela_crypto::signing::{auth_message, generate_keypair, sign, HybridSigningKey};
use vela_server::sqldb::{Db as _, TursoValue};

mod helpers;

const CLIENT_IP: [u8; 4] = [203, 0, 113, 77];

struct Seeded {
    device_id: Uuid,
    user_id: Uuid,
    signing_key: Vec<u8>,
}

async fn seed_device(state: &vela_server::state::AppState) -> Seeded {
    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let now = chrono::Utc::now().to_rfc3339();
    let (hybrid_vk, hybrid_sk) = std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (vk, sk) = generate_keypair().unwrap();
            (vk.to_bytes().to_vec(), sk.into_bytes())
        })
        .unwrap()
        .join()
        .unwrap();

    state
        .sqldb
        .execute(
            "INSERT INTO users (id, created_at) VALUES (?, ?)",
            vec![
                TursoValue::Text(user_id.to_string()),
                TursoValue::Text(now.clone()),
            ],
        )
        .await
        .unwrap();
    state
        .sqldb
        .execute(
            "INSERT INTO devices
             (id, user_id, hybrid_ek, hybrid_vk, created_at)
             VALUES (?, ?, ?, ?, ?)",
            vec![
                TursoValue::Text(device_id.to_string()),
                TursoValue::Text(user_id.to_string()),
                TursoValue::Text(B64.encode(vec![0u8; 1600])),
                TursoValue::Text(B64.encode(hybrid_vk)),
                TursoValue::Text(now),
            ],
        )
        .await
        .unwrap();

    Seeded {
        device_id,
        user_id,
        signing_key: hybrid_sk,
    }
}

async fn issue(app: &axum::Router, purpose: &str) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/challenge?purpose={purpose}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    serde_json::from_slice::<Value>(&body).unwrap()["challenge"]
        .as_str()
        .unwrap()
        .to_string()
}

fn signature_for(device_id: Uuid, challenge_b64: &str, signing_key: &[u8]) -> String {
    let challenge = B64.decode(challenge_b64).unwrap();
    let device_id = device_id.to_string();
    let signing_key = signing_key.to_vec();
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let sk = HybridSigningKey::from_bytes(&signing_key).unwrap();
            let message = auth_message(&device_id, &challenge);
            B64.encode(sign(&sk, &message).unwrap().to_bytes())
        })
        .unwrap()
        .join()
        .unwrap()
}

fn verify_request(device_id: Uuid, challenge: &str, signature: &str) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/auth/verify")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "device_id": device_id,
                "challenge": challenge,
                "signature": signature,
            })
            .to_string(),
        ))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((CLIENT_IP, 55123))));
    request
}

async fn body_json(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn successful_login_tracks_the_jti_and_replay_is_refused() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let seeded = seed_device(&state).await;

    let challenge = issue(&app, "login").await;
    let signature = signature_for(seeded.device_id, &challenge, &seeded.signing_key);
    let (status, body) = body_json(
        app.clone()
            .oneshot(verify_request(seeded.device_id, &challenge, &signature))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["token"].as_str().expect("token");
    assert_eq!(
        body["user_id"].as_str(),
        Some(seeded.user_id.to_string().as_str())
    );

    // The response token is the real PASETO and its JTI is tracked.
    let claims = vela_server::auth::token::TokenService::new(
        state.paseto_sk.clone(),
        state.paseto_pk.clone(),
    )
    .verify(token)
    .expect("issued token verifies");
    let tracked = state
        .store
        .smembers(&format!("device:jtis:{}", seeded.device_id))
        .unwrap();
    assert!(
        tracked.contains(&claims.jti),
        "issued JTI must be tracked before the response: {tracked:?}"
    );

    // The nonce was consumed by the successful request.
    assert!(state
        .store
        .get(&format!("challenge:{challenge}"))
        .unwrap()
        .is_none());
    let (status, _) = body_json(
        app.oneshot(verify_request(seeded.device_id, &challenge, &signature))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_purpose_login_nonce_is_refused_and_spent() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let seeded = seed_device(&state).await;

    // An enroll-purpose nonce presented at /auth/verify.
    let challenge = issue(&app, "enroll").await;
    let signature = signature_for(seeded.device_id, &challenge, &seeded.signing_key);
    let (status, body) = body_json(
        app.clone()
            .oneshot(verify_request(seeded.device_id, &challenge, &signature))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("different purpose"),
        "{body}"
    );
    assert!(state
        .store
        .get(&format!("challenge:{challenge}"))
        .unwrap()
        .is_none());

    // A second presentation is a plain missing/spent nonce, not a second
    // chance to use the enroll challenge.
    let (status, body) = body_json(
        app.oneshot(verify_request(seeded.device_id, &challenge, &signature))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("not found or already used"),
        "{body}"
    );
}

#[tokio::test]
async fn failed_verifier_returns_no_token_and_records_the_failure_streak() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let seeded = seed_device(&state).await;

    let challenge = issue(&app, "login").await;
    // Well-formed but wrong signature (all-zero bytes of the hybrid length).
    let bad_signature = B64.encode(vec![0u8; 4627 + 64]);
    let (status, body) = body_json(
        app.oneshot(verify_request(seeded.device_id, &challenge, &bad_signature))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.get("token").is_none(), "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("invalid device, challenge or signature"),
        "{body}"
    );
    assert!(state
        .store
        .get(&format!("challenge:{challenge}"))
        .unwrap()
        .is_none());

    // The handler's backoff failure side effect ran for this (ip, device).
    let ip = format!(
        "{}.{}.{}.{}",
        CLIENT_IP[0], CLIENT_IP[1], CLIENT_IP[2], CLIENT_IP[3]
    );
    let streak_key = format!("rl:streak:verify:{ip}:{}", seeded.device_id);
    assert!(
        state.store.get(&streak_key).unwrap().is_some(),
        "failed proof must increment the verification streak"
    );
    let fail_key = format!("rl:verify:fail:dev:{ip}:{}", seeded.device_id);
    assert!(
        state.store.get(&fail_key).unwrap().is_some(),
        "failed proof must consume the request-level failure budget"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_logins_with_one_nonce_yield_at_most_one_token() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let seeded = seed_device(&state).await;

    let challenge = issue(&app, "login").await;
    let signature = signature_for(seeded.device_id, &challenge, &seeded.signing_key);

    let first = app
        .clone()
        .oneshot(verify_request(seeded.device_id, &challenge, &signature));
    let second = app
        .clone()
        .oneshot(verify_request(seeded.device_id, &challenge, &signature));
    let (first, second) = tokio::join!(first, second);
    let first = body_json(first.unwrap()).await;
    let second = body_json(second.unwrap()).await;

    let successes = [&first, &second]
        .iter()
        .filter(|(status, _)| *status == StatusCode::OK)
        .count();
    assert_eq!(
        successes, 1,
        "one nonce must produce at most one accepted login: {first:?} / {second:?}"
    );
    let failure = if first.0 == StatusCode::OK {
        &second
    } else {
        &first
    };
    assert_eq!(failure.0, StatusCode::UNAUTHORIZED);
    assert!(failure.1.get("token").is_none());
    assert!(state
        .store
        .get(&format!("challenge:{challenge}"))
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn malformed_consumed_nonce_is_bad_request_before_failure_counting() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let seeded = seed_device(&state).await;
    // Corrupt stored nonce key with a valid login tag: take succeeds, decode fails.
    let challenge = "not-base64!";
    state
        .store
        .set_ex(&format!("challenge:{challenge}"), b"login", 60)
        .unwrap();
    let (status, body) = body_json(
        app.oneshot(verify_request(seeded.device_id, challenge, "unused"))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["message"]
        .as_str()
        .unwrap_or_default()
        .contains("invalid challenge encoding"));
    assert!(body.get("token").is_none());
    assert!(state
        .store
        .get(&format!("challenge:{challenge}"))
        .unwrap()
        .is_none());
    let ip = "203.0.113.77";
    assert!(state
        .store
        .get(&format!("rl:streak:verify:{ip}:{}", seeded.device_id))
        .unwrap()
        .is_none());
    assert!(state
        .store
        .get(&format!("rl:verify:fail:dev:{ip}:{}", seeded.device_id))
        .unwrap()
        .is_none());
}

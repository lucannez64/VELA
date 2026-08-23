//! Integration tests for VELA server.
//!
//! These tests require a running Postgres + Redis instance.
//! Set `DATABASE_URL` and `REDIS_URL` before running:
//!
//! ```sh
//! DATABASE_URL=postgres://vela:vela@localhost:5432/vela_test \
//! REDIS_URL=redis://localhost:6379 \
//! cargo test -- --test-threads=1
//! ```

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::json;
use std::net::SocketAddr;
use tower::ServiceExt;
use uuid::Uuid;

mod helpers;

async fn app() -> impl axum::ServiceExt<
    Request<Body>,
    Response = axum::response::Response,
    Error = std::convert::Infallible,
> {
    helpers::test_app().await
}

#[tokio::test]
async fn health_returns_ok() {
    let app = app().await;
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn register_creates_account_and_device() {
    let app = app().await;

    let body = serde_json::to_string(&json!({
        "hybrid_ek": B64.encode(vec![0u8; 1600]),
        "hybrid_vk": B64.encode(vec![0u8; 2624]),
    }))
    .unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/account/register")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["user_id"].is_string());
    assert!(v["device_id"].is_string());
}

#[tokio::test]
async fn register_rejects_bad_key_size() {
    let app = app().await;

    let body = serde_json::to_string(&json!({
        "hybrid_ek": B64.encode(vec![0u8; 10]),
        "hybrid_vk": B64.encode(vec![0u8; 2624]),
    }))
    .unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/account/register")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn challenge_returns_nonce() {
    let app = app().await;

    let req = Request::builder()
        .uri("/auth/challenge")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["challenge"].is_string());
}

#[tokio::test]
async fn production_auth_requires_https_when_proxy_headers_are_not_trusted() {
    let state = helpers::test_state_with_config(|cfg| {
        cfg.production = true;
        cfg.allow_insecure_lan = false;
        cfg.trust_proxy_headers = false;
    })
    .await;
    let app = vela_server::routes::build(state);

    let req = Request::builder()
        .uri("/auth/challenge")
        .header("x-forwarded-proto", "https")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UPGRADE_REQUIRED);
}

#[tokio::test]
async fn production_auth_accepts_https_from_trusted_loopback_proxy() {
    let state = helpers::test_state_with_config(|cfg| {
        cfg.production = true;
        cfg.allow_insecure_lan = false;
        cfg.trust_proxy_headers = true;
        cfg.trusted_proxy_cidrs = vec!["127.0.0.1/32".to_string(), "::1/128".to_string()];
    })
    .await;
    let app = vela_server::routes::build(state);

    let mut req = Request::builder()
        .uri("/auth/challenge")
        .header("x-forwarded-proto", "https")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 55123))));

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn production_auth_rejects_forwarded_https_from_untrusted_proxy() {
    let state = helpers::test_state_with_config(|cfg| {
        cfg.production = true;
        cfg.allow_insecure_lan = false;
        cfg.trust_proxy_headers = true;
        cfg.trusted_proxy_cidrs = vec!["127.0.0.1/32".to_string(), "::1/128".to_string()];
    })
    .await;
    let app = vela_server::routes::build(state);

    let mut req = Request::builder()
        .uri("/auth/challenge")
        .header("x-forwarded-proto", "https")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 10], 55123))));

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UPGRADE_REQUIRED);
}

#[tokio::test]
async fn auth_signature_succeeds_once_and_replay_fails() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let now = chrono::Utc::now().to_rfc3339();
    let (hybrid_vk, hybrid_sk) = std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (vk, sk) = vela_crypto::signing::generate_keypair().unwrap();
            (vk.to_bytes().to_vec(), sk.into_bytes())
        })
        .unwrap()
        .join()
        .unwrap();

    use vela_server::sqldb::{Db as _, TursoValue};
    state
        .sqldb
        .execute(
            "INSERT INTO users (id, created_at) VALUES (?, ?)",
            vec![TursoValue::Text(user_id.to_string()), TursoValue::Text(now.clone())],
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

    let challenge_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/challenge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let challenge_body = axum::body::to_bytes(challenge_resp.into_body(), 1024)
        .await
        .unwrap();
    let challenge_json: serde_json::Value = serde_json::from_slice(&challenge_body).unwrap();
    let challenge_b64 = challenge_json["challenge"].as_str().unwrap().to_string();
    let challenge = B64.decode(&challenge_b64).unwrap();
    let device_id_string = device_id.to_string();
    let signature = std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let sk = vela_crypto::signing::HybridSigningKey::from_bytes(&hybrid_sk).unwrap();
            let message = vela_crypto::signing::auth_message(&device_id_string, &challenge);
            B64.encode(
                vela_crypto::signing::sign(&sk, &message)
                    .unwrap()
                    .to_bytes(),
            )
        })
        .unwrap()
        .join()
        .unwrap();
    let verify_body = serde_json::to_string(&json!({
        "device_id": device_id,
        "challenge": challenge_b64,
        "signature": signature,
    }))
    .unwrap();

    let verify = || {
        Request::builder()
            .method("POST")
            .uri("/auth/verify")
            .header("content-type", "application/json")
            .body(Body::from(verify_body.clone()))
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(verify()).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        app.oneshot(verify()).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn logout_without_token_returns_401() {
    let app = app().await;

    let req = Request::builder()
        .method("POST")
        .uri("/auth/logout")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn devices_without_token_returns_401() {
    let app = app().await;

    let req = Request::builder()
        .uri("/devices")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn vault_sync_without_token_returns_401() {
    let app = app().await;

    let req = Request::builder()
        .uri("/vault/sync")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn delete_chunk_without_token_returns_401() {
    let app = app().await;

    let req = Request::builder()
        .method("DELETE")
        .uri("/vault/chunk/00000000-0000-0000-0000-000000000000")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

fn issue_token(state: &vela_server::state::AppState, user_id: Uuid, device_id: Uuid) -> String {
    let ts = vela_server::auth::token::TokenService::new(
        state.paseto_sk.clone(),
        state.paseto_pk.clone(),
    );
    let (token, jti) = ts.issue(user_id, device_id, None).unwrap();
    vela_server::rate_limit::track_device_jti(&state.store, &device_id.to_string(), &jti).unwrap();
    token
}

#[tokio::test]
async fn two_users_can_store_same_chunk_id() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());

    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();
    let device_a = Uuid::new_v4();
    let device_b = Uuid::new_v4();
    let now = chrono::Utc::now();

    use vela_server::sqldb::{Db as _, TursoValue};
    for user_id in [user_a, user_b] {
        state
            .sqldb
            .execute(
                "INSERT INTO users (id, created_at) VALUES (?, ?)",
                vec![TursoValue::Text(user_id.to_string()), TursoValue::Text(now.to_rfc3339())],
            )
            .await
            .unwrap();
    }

    for (device_id, user_id) in [(device_a, user_a), (device_b, user_b)] {
        state.sqldb.execute(
            "INSERT INTO devices
             (id, user_id, hybrid_ek, hybrid_vk, enrolled_by, rms_capsule, revoked, revoked_at, revoked_by, created_at)
             VALUES (?, ?, ?, ?, NULL, NULL, 0, NULL, NULL, ?)",
            vec![
                TursoValue::Text(device_id.to_string()),
                TursoValue::Text(user_id.to_string()),
                TursoValue::Text(B64.encode(vec![0u8; 1600])),
                TursoValue::Text(B64.encode(vec![0u8; 2624])),
                TursoValue::Text(now.to_rfc3339()),
            ],
        ).await.unwrap();
    }

    let token_a = issue_token(&state, user_a, device_a);
    let token_b = issue_token(&state, user_b, device_b);

    for token in [token_a, token_b] {
        let req = Request::builder()
            .method("PUT")
            .uri("/vault/chunk/vault-main")
            .header("authorization", format!("Bearer {}", token))
            .header("if-match", "0")
            .header("x-lamport-clock", "1")
            .body(Body::from(vec![1u8, 2, 3, 4]))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn recovery_initiate_unknown_user_returns_404() {
    let app = app().await;

    let body = serde_json::to_string(&json!({
        "user_id": "00000000-0000-0000-0000-000000000000"
    }))
    .unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/recovery/initiate")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Audit S-3: `/recovery/initiate` is unauthenticated and `user_id` is
/// attacker-controlled, so the per-victim cap must be keyed on the source too.
/// A third party burning the limit from its own IP must not lock the victim out
/// of their own recovery.
#[tokio::test]
async fn recovery_initiate_limit_cannot_be_burned_for_someone_else() {
    let app = vela_server::routes::build(helpers::test_state().await);
    let victim = Uuid::new_v4();

    let initiate = |ip: [u8; 4]| {
        let mut req = Request::builder()
            .method("POST")
            .uri("/recovery/initiate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&json!({ "user_id": victim })).unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((ip, 44444))));
        req
    };

    // The attacker spends its own (ip, user) budget, then is throttled.
    const ATTACKER: [u8; 4] = [203, 0, 113, 5];
    for i in 1..=vela_server::rate_limit::RECOVERY_INITIATE_PER_IP_USER_HOURLY {
        let resp = app.clone().oneshot(initiate(ATTACKER)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "attacker call {i}");
    }
    let resp = app.clone().oneshot(initiate(ATTACKER)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    // The victim, on a different IP, is unaffected — 404 because the account
    // does not exist, which is the answer they would get anyway.
    let resp = app
        .oneshot(initiate([198, 51, 100, 9]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// The other half of S-3: keying the cap on `(ip, user)` must not remove the
/// bound on *distributed* churn of one user's recovery state. Each source stays
/// under its own per-(ip, user) and per-IP budgets here, so the only limiter
/// that can fire is the global per-user backstop.
#[tokio::test]
async fn recovery_initiate_still_bounds_distributed_churn_per_user() {
    let app = vela_server::routes::build(helpers::test_state().await);
    let victim = Uuid::new_v4();
    let cap = vela_server::rate_limit::RECOVERY_INITIATE_PER_USER_HOURLY;

    // One request per source, so neither per-source limiter is in play.
    let initiate = |n: u64| {
        let mut req = Request::builder()
            .method("POST")
            .uri("/recovery/initiate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&json!({ "user_id": victim })).unwrap(),
            ))
            .unwrap();
        let ip = [10, 0, (n / 256) as u8, (n % 256) as u8];
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((ip, 44444))));
        req
    };

    for n in 0..cap {
        let resp = app.clone().oneshot(initiate(n)).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "call {n} should pass the limiters (404 = unknown account)"
        );
    }

    // One source past the cap, from an IP that has spent nothing itself.
    let resp = app.oneshot(initiate(cap)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn enroll_device_without_grant_returns_401() {
    let app = app().await;

    let body = serde_json::to_string(&json!({
        "user_id": Uuid::new_v4(),
        "recovery_grant": Uuid::new_v4(),
        "hybrid_ek": B64.encode(vec![0u8; 1600]),
        "hybrid_vk": B64.encode(vec![0u8; 2624]),
    }))
    .unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/recovery/enroll-device")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enroll_device_redeems_grant_exactly_once() {
    use vela_server::sqldb::{Db as _, TursoValue};

    let state = helpers::test_state().await;

    // Create the account this recovery grant is scoped to.
    let register_req = Request::builder()
        .method("POST")
        .uri("/account/register")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&json!({
                "hybrid_ek": B64.encode(vec![0u8; 1600]),
                "hybrid_vk": B64.encode(vec![0u8; 2624]),
            }))
            .unwrap(),
        ))
        .unwrap();
    let register_resp = vela_server::routes::build(state.clone())
        .oneshot(register_req)
        .await
        .unwrap();
    assert_eq!(register_resp.status(), StatusCode::OK);
    let register_body = axum::body::to_bytes(register_resp.into_body(), 1024)
        .await
        .unwrap();
    let register_json: serde_json::Value = serde_json::from_slice(&register_body).unwrap();
    let user_id = register_json["user_id"].as_str().unwrap().to_string();

    // Seed a grant the same way `/recovery/recover` would after a successful
    // WebAuthn assertion — this test exercises grant redemption directly
    // rather than driving a full WebAuthn ceremony.
    let grant = Uuid::new_v4();
    state
        .store
        .set_ex(
            &format!("recovery:enroll_grant:{user_id}:{grant}"),
            b"1",
            600,
        )
        .unwrap();

    let enroll_body = serde_json::to_string(&json!({
        "user_id": user_id,
        "recovery_grant": grant,
        "hybrid_ek": B64.encode(vec![1u8; 1600]),
        "hybrid_vk": B64.encode(vec![1u8; 2624]),
        "device_name": "Recovered Laptop",
    }))
    .unwrap();

    // A rotation conflict is retryable and must not spend the one-shot grant.
    state
        .sqldb
        .execute(
            "UPDATE users SET rekey_state = 'freezing' WHERE id = ?",
            vec![TursoValue::Text(user_id.clone())],
        )
        .await
        .unwrap();
    let paused_req = Request::builder()
        .method("POST")
        .uri("/recovery/enroll-device")
        .header("content-type", "application/json")
        .body(Body::from(enroll_body.clone()))
        .unwrap();
    let paused_resp = vela_server::routes::build(state.clone())
        .oneshot(paused_req)
        .await
        .unwrap();
    assert_eq!(paused_resp.status(), StatusCode::CONFLICT);
    assert!(state
        .store
        .exists(&format!("recovery:enroll_grant:{user_id}:{grant}"))
        .unwrap());
    state
        .sqldb
        .execute(
            "UPDATE users SET rekey_state = NULL WHERE id = ?",
            vec![TursoValue::Text(user_id.clone())],
        )
        .await
        .unwrap();

    let first_req = Request::builder()
        .method("POST")
        .uri("/recovery/enroll-device")
        .header("content-type", "application/json")
        .body(Body::from(enroll_body.clone()))
        .unwrap();
    let first_resp = vela_server::routes::build(state.clone())
        .oneshot(first_req)
        .await
        .unwrap();
    assert_eq!(first_resp.status(), StatusCode::OK);
    let first_json: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(first_resp.into_body(), 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(first_json["device_id"].is_string());

    // The same grant must not be redeemable twice.
    let second_req = Request::builder()
        .method("POST")
        .uri("/recovery/enroll-device")
        .header("content-type", "application/json")
        .body(Body::from(enroll_body))
        .unwrap();
    let second_resp = vela_server::routes::build(state.clone())
        .oneshot(second_req)
        .await
        .unwrap();
    assert_eq!(second_resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn recovery_enrollment_grant_is_invalid_after_key_rotation() {
    use vela_server::sqldb::{Db as _, TursoValue};

    let state = helpers::test_state().await;
    let user_id = Uuid::new_v4();
    let grant = Uuid::new_v4();
    state
        .sqldb
        .execute(
            "INSERT INTO users (id, created_at, key_epoch) VALUES (?, ?, 2)",
            vec![
                TursoValue::Text(user_id.to_string()),
                TursoValue::Text(chrono::Utc::now().to_rfc3339()),
            ],
        )
        .await
        .unwrap();
    // This grant was minted while the account was still at epoch 1.
    state
        .store
        .set_ex(
            &format!("recovery:enroll_grant:{user_id}:{grant}"),
            b"1",
            600,
        )
        .unwrap();

    let request = Request::builder()
        .method("POST")
        .uri("/recovery/enroll-device")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "user_id": user_id,
                "recovery_grant": grant,
                "hybrid_ek": B64.encode(vec![1u8; 1600]),
                "hybrid_vk": B64.encode(vec![1u8; 2624]),
            })
            .to_string(),
        ))
        .unwrap();
    let response = vela_server::routes::build(state.clone())
        .oneshot(request)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        body["message"],
        "recovery grant was invalidated by vault key rotation",
        "the request must reach the grant-epoch check"
    );
    let devices = state
        .sqldb
        .query(
            "SELECT id FROM devices WHERE user_id = ?",
            vec![TursoValue::Text(user_id.to_string())],
        )
        .await
        .unwrap();
    assert!(devices.is_empty(), "a stale grant must not enroll a device");
}

#[tokio::test]
async fn account_delete_without_token_returns_401() {
    let app = app().await;

    let req = Request::builder()
        .method("DELETE")
        .uri("/account")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn share_send_without_token_returns_401() {
    let app = app().await;

    let body = serde_json::to_string(&json!({
        "recipient_user_id": "00000000-0000-0000-0000-000000000000",
        "capsule": B64.encode(vec![0u8; 32])
    }))
    .unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/share/send")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn web_session_start_and_poll_pending() {
    // Build a clonable Router directly so both requests share one in-memory DB.
    let app = vela_server::routes::build(helpers::test_state().await);

    let body = serde_json::to_string(&json!({
        "ephemeral_pk": B64.encode(vec![0u8; 1600]),
        "link_nonce": B64.encode(vec![0u8; 32]),
        "approver_user_id": Uuid::new_v4(),
        "poll_secret_hash": poll_secret_hash(),
    }))
    .unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/web-session/start")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let session_id = v["session_id"].as_str().unwrap().to_string();

    // The browser polls; before any grant the session is pending.
    let resp = app.oneshot(web_session_poll_req(&session_id)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["status"], "pending");
    assert!(v.get("capsule").is_none());
}

#[tokio::test]
async fn web_session_start_rejects_bad_key_length() {
    let app = app().await;

    let body = serde_json::to_string(&json!({
        "ephemeral_pk": B64.encode(vec![0u8; 100]), // wrong length
        "link_nonce": B64.encode(vec![0u8; 32]),
        "approver_user_id": Uuid::new_v4(),
        "poll_secret_hash": poll_secret_hash(),
    }))
    .unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/web-session/start")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn web_session_grant_requires_auth() {
    let app = app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/web-session/{}/grant", Uuid::new_v4()))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "mode": "ro",
                        "capsule": B64.encode(vec![0u8; 64]),
                        "link_nonce": B64.encode(vec![0u8; 32]),
                        "key_epoch": 1,
                    })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Create a user + one enrolled device and return `(user_id, bearer token)`.
async fn seed_user_with_device(state: &vela_server::state::AppState) -> (Uuid, String) {
    use vela_server::sqldb::{Db as _, TursoValue};
    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let now = chrono::Utc::now();
    state
        .sqldb
        .execute(
            "INSERT INTO users (id, created_at) VALUES (?, ?)",
            vec![TursoValue::Text(user_id.to_string()), TursoValue::Text(now.to_rfc3339())],
        )
        .await
        .unwrap();
    state.sqldb.execute(
        "INSERT INTO devices
         (id, user_id, hybrid_ek, hybrid_vk, enrolled_by, rms_capsule, revoked, revoked_at, revoked_by, created_at)
         VALUES (?, ?, ?, ?, NULL, NULL, 0, NULL, NULL, ?)",
        vec![
            TursoValue::Text(device_id.to_string()),
            TursoValue::Text(user_id.to_string()),
            TursoValue::Text(B64.encode(vec![0u8; 1600])),
            TursoValue::Text(B64.encode(vec![0u8; 2624])),
            TursoValue::Text(now.to_rfc3339()),
        ],
    ).await.unwrap();
    let token = issue_token(state, user_id, device_id);
    (user_id, token)
}

/// The secret the browser keeps to collect its capsule, and the hash it commits
/// to at `start`.
const POLL_SECRET: [u8; 32] = [3u8; 32];

fn poll_secret_hash() -> String {
    use sha2::{Digest, Sha256};
    B64.encode(Sha256::digest(POLL_SECRET))
}

/// A `POST /web-session/start` request bound to `approver`.
fn web_session_start_req(approver: Uuid, link_nonce: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/web-session/start")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&json!({
                "ephemeral_pk": B64.encode(vec![0u8; 1600]),
                "web_vk": B64.encode(vec![0u8; 2624]),
                "link_nonce": link_nonce,
                "approver_user_id": approver,
                "poll_secret_hash": poll_secret_hash(),
            }))
            .unwrap(),
        ))
        .unwrap()
}

/// `GET /web-session/:id` as the browser that started it.
fn web_session_poll_req(session_id: &str) -> Request<Body> {
    Request::builder()
        .uri(format!("/web-session/{session_id}"))
        .header("x-web-session-secret", B64.encode(POLL_SECRET))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn web_session_grant_rejects_wrong_link_nonce() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());

    let (user_id, token) = seed_user_with_device(&state).await;

    let link_nonce = B64.encode(vec![7u8; 32]);
    let resp = app
        .clone()
        .oneshot(web_session_start_req(user_id, &link_nonce))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let session_id = v["session_id"].as_str().unwrap().to_string();

    let grant = |nonce: String| {
        Request::builder()
            .method("POST")
            .uri(format!("/web-session/{session_id}/grant"))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&json!({
                    "mode": "ro",
                    "capsule": B64.encode(vec![0u8; 64]),
                    "link_nonce": nonce,
                    "key_epoch": 1,
                }))
                .unwrap(),
            ))
            .unwrap()
    };

    // Wrong nonce → 401, session must remain pending.
    let resp = app
        .clone()
        .oneshot(grant(B64.encode(vec![9u8; 32])))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = app
        .clone()
        .oneshot(web_session_poll_req(&session_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["status"], "pending");

    // Correct nonce → grant succeeds.
    let resp = app.oneshot(grant(link_nonce)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn web_session_grant_rejects_a_capsule_from_an_old_key_epoch() {
    use vela_server::sqldb::{Db as _, TursoValue};

    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let (user_id, token) = seed_user_with_device(&state).await;
    state
        .sqldb
        .execute(
            "UPDATE users SET key_epoch = 2 WHERE id = ?",
            vec![TursoValue::Text(user_id.to_string())],
        )
        .await
        .unwrap();

    let link_nonce = B64.encode(vec![7u8; 32]);
    let resp = app
        .clone()
        .oneshot(web_session_start_req(user_id, &link_nonce))
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let session_id = body["session_id"].as_str().unwrap();

    let grant = |epoch| {
        Request::builder()
            .method("POST")
            .uri(format!("/web-session/{session_id}/grant"))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(
                json!({
                    "mode": "ro",
                    "capsule": B64.encode(vec![0u8; 64]),
                    "link_nonce": link_nonce,
                    "key_epoch": epoch,
                })
                .to_string(),
            ))
            .unwrap()
    };

    assert_eq!(
        app.clone().oneshot(grant(1)).await.unwrap().status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        app.oneshot(grant(2)).await.unwrap().status(),
        StatusCode::OK,
        "an epoch mismatch must leave the session pending and retryable"
    );
}

/// Audit S-1/S-4: the session is bound to the account the browser named at
/// `start`. Another authenticated user who knows the whole QR (session id +
/// link nonce) must not be able to read the browser's keys or grant the session.
#[tokio::test]
async fn web_session_is_bound_to_the_committed_approver() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());

    let (victim_id, victim_token) = seed_user_with_device(&state).await;
    let (_attacker_id, attacker_token) = seed_user_with_device(&state).await;

    let link_nonce = B64.encode(vec![7u8; 32]);
    let resp = app
        .clone()
        .oneshot(web_session_start_req(victim_id, &link_nonce))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let session_id = v["session_id"].as_str().unwrap().to_string();

    let keys_req = |token: &str| {
        Request::builder()
            .uri(format!("/web-session/{session_id}/keys"))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    let grant_req = |token: &str| {
        Request::builder()
            .method("POST")
            .uri(format!("/web-session/{session_id}/grant"))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::to_string(&json!({
                    "mode": "rw",
                    "capsule": B64.encode(vec![0u8; 64]),
                    "link_nonce": link_nonce,
                    "key_epoch": 1,
                }))
                .unwrap(),
            ))
            .unwrap()
    };

    // The attacker holds a valid token and the full QR — and still gets nothing.
    let resp = app.clone().oneshot(keys_req(&attacker_token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = app.clone().oneshot(grant_req(&attacker_token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // The failed grant must leave the session grantable by its real approver.
    let resp = app.clone().oneshot(keys_req(&victim_token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app.clone().oneshot(grant_req(&victim_token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // ...and the granted session belongs to the approver, not the attacker.
    let list_req = |token: &str| {
        Request::builder()
            .uri("/web-sessions")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    let listed_ids = |body: serde_json::Value| -> Vec<String> {
        body["sessions"]
            .as_array()
            .expect("sessions array")
            .iter()
            .map(|s| s["id"].as_str().unwrap_or_default().to_string())
            .collect()
    };

    let resp = app.clone().oneshot(list_req(&victim_token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
    let ids = listed_ids(serde_json::from_slice(&b).unwrap());
    assert!(ids.contains(&session_id), "approver sees their own session");

    // The attacker must not discover the session either: it is not in their
    // list, and revoking it is a 404 rather than a way to kill someone else's
    // browser session.
    let resp = app.clone().oneshot(list_req(&attacker_token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
    let ids = listed_ids(serde_json::from_slice(&b).unwrap());
    assert!(!ids.contains(&session_id), "attacker must not see the session");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/web-session/{session_id}"))
                .header("authorization", format!("Bearer {attacker_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // ...and the refused revoke left the session alive for its real owner.
    let resp = app.oneshot(list_req(&victim_token)).await.unwrap();
    let b = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
    let ids = listed_ids(serde_json::from_slice(&b).unwrap());
    assert!(ids.contains(&session_id), "session survives a refused revoke");
}

/// Audit S-2: the poll endpoint is unauthenticated by design, so possession of
/// the secret registered at `start` is what proves the caller is the browser.
/// Anyone who merely learns the `session_id` must not be able to collect — and
/// thereby destroy — the one-shot capsule.
#[tokio::test]
async fn web_session_poll_requires_the_browsers_secret() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());

    let (user_id, token) = seed_user_with_device(&state).await;
    let link_nonce = B64.encode(vec![7u8; 32]);
    let resp = app
        .clone()
        .oneshot(web_session_start_req(user_id, &link_nonce))
        .await
        .unwrap();
    let b = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let session_id = v["session_id"].as_str().unwrap().to_string();

    let capsule = B64.encode(vec![9u8; 64]);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/web-session/{session_id}/grant"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "mode": "ro",
                        "capsule": capsule,
                        "link_nonce": link_nonce,
                        "key_epoch": 1,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // No secret, and a wrong secret: both rejected, and neither may consume the
    // capsule.
    for header in [None, Some(B64.encode([9u8; 32]))] {
        let mut req = Request::builder().uri(format!("/web-session/{session_id}"));
        if let Some(value) = header {
            req = req.header("x-web-session-secret", value);
        }
        let resp = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // A session id that does not exist is indistinguishable from a wrong secret.
    let resp = app
        .clone()
        .oneshot(web_session_poll_req(&Uuid::new_v4().to_string()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // The real browser still gets its capsule, exactly once.
    let resp = app
        .clone()
        .oneshot(web_session_poll_req(&session_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["capsule"], capsule);

    let resp = app.oneshot(web_session_poll_req(&session_id)).await.unwrap();
    let b = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["status"], "granted");
    assert!(v.get("capsule").is_none(), "capsule is one-shot");
}

/// The committed approver may decline a session that is still pending — the
/// browser's poll then reports `revoked` instead of hanging until the 5-minute
/// reap. Before the binding existed there was no way to know who was entitled to
/// do this, so pending sessions could not be revoked at all.
#[tokio::test]
async fn committed_approver_can_decline_a_pending_session() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());

    let (victim_id, victim_token) = seed_user_with_device(&state).await;
    let (_attacker_id, attacker_token) = seed_user_with_device(&state).await;

    let link_nonce = B64.encode(vec![7u8; 32]);
    let resp = app
        .clone()
        .oneshot(web_session_start_req(victim_id, &link_nonce))
        .await
        .unwrap();
    let b = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let session_id = v["session_id"].as_str().unwrap().to_string();

    let delete_req = |token: &str| {
        Request::builder()
            .method("DELETE")
            .uri(format!("/web-session/{session_id}"))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };

    // Not for anyone else, even while it has no granting user yet.
    let resp = app.clone().oneshot(delete_req(&attacker_token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = app.clone().oneshot(delete_req(&victim_token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // The browser learns it was declined rather than waiting out the TTL.
    let resp = app
        .clone()
        .oneshot(web_session_poll_req(&session_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["status"], "revoked");

    // And a declined session cannot then be granted.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/web-session/{session_id}/grant"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {victim_token}"))
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "mode": "ro",
                        "capsule": B64.encode(vec![0u8; 64]),
                        "link_nonce": link_nonce,
                        "key_epoch": 1,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn web_session_start_requires_an_approver_account() {
    let app = vela_server::routes::build(helpers::test_state().await);

    let start = |body: serde_json::Value| {
        Request::builder()
            .method("POST")
            .uri("/web-session/start")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap()
    };

    // No approver — an unbound session could be granted by anyone.
    let resp = app
        .clone()
        .oneshot(start(json!({
            "ephemeral_pk": B64.encode(vec![0u8; 1600]),
            "link_nonce": B64.encode(vec![0u8; 32]),
            "poll_secret_hash": poll_secret_hash(),
        })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // No poll-secret commitment — the capsule could be collected by anyone who
    // learns the session id.
    let resp = app
        .clone()
        .oneshot(start(json!({
            "ephemeral_pk": B64.encode(vec![0u8; 1600]),
            "link_nonce": B64.encode(vec![0u8; 32]),
            "approver_user_id": Uuid::new_v4(),
        })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // A commitment that is not a SHA-256 digest is refused rather than stored.
    let resp = app
        .oneshot(start(json!({
            "ephemeral_pk": B64.encode(vec![0u8; 1600]),
            "link_nonce": B64.encode(vec![0u8; 32]),
            "approver_user_id": Uuid::new_v4(),
            "poll_secret_hash": B64.encode(vec![0u8; 16]),
        })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Red-team RT-4: a web-session token is not a device token ─────────────────

/// Mint a token of a given scope for an existing user, as the server would.
fn token_for(
    state: &vela_server::state::AppState,
    user_id: Uuid,
    device_id: Uuid,
    scope: vela_server::auth::token::TokenScope,
) -> String {
    let ts = vela_server::auth::token::TokenService::new(
        state.paseto_sk.clone(),
        state.paseto_pk.clone(),
    );
    ts.issue_scoped(user_id, device_id, None, scope).unwrap().0
}

/// Insert a user so the auth middleware's existence check passes.
async fn insert_user(state: &vela_server::state::AppState, user_id: Uuid) {
    use vela_server::sqldb::{Db as _, TursoValue};
    let now = chrono::Utc::now().to_rfc3339();
    state
        .sqldb
        .execute(
            "INSERT INTO users (id, created_at) VALUES (?, ?)",
            vec![TursoValue::Text(user_id.to_string()), TursoValue::Text(now)],
        )
        .await
        .unwrap();
}

/// The endpoints an ephemeral browser must not reach.
///
/// `EPHEMERAL_WEB_ACCESS_DESIGN.md` §2 promises a web session is temporary,
/// revocable, and enrolls no permanent device. Before the scope claim existed
/// its token was byte-for-byte as authoritative as a laptop's, so it could
/// rotate the recovery share, register the attacker's recovery passkey, revoke
/// the user's real devices, open an enrollment grant, and delete the account.
#[tokio::test]
async fn web_session_token_is_refused_on_permanent_power_routes() {
    use vela_server::auth::token::TokenScope;

    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let user_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    insert_user(&state, user_id).await;

    let web = token_for(&state, user_id, session_id, TokenScope::WebSession);

    let cases: Vec<(&str, &str, Option<serde_json::Value>)> = vec![
        ("PUT", "/recovery/share", Some(json!({ "share": B64.encode(b"x") }))),
        ("GET", "/recovery/share", None),
        ("DELETE", "/recovery/share", None),
        (
            "POST",
            "/recovery/webauthn/register/start",
            Some(json!({ "user_name": "attacker" })),
        ),
        ("POST", "/device/revoke", Some(json!({ "device_id": Uuid::new_v4() }))),
        ("POST", "/device/enrollment-grant", Some(json!({}))),
        ("DELETE", "/account", None),
        // RT-5 (HIGH): overwriting the account's share key let a borrowed
        // browser read every future share, and it survived revoking the
        // session.
        ("PUT", "/share/my-ek", Some(json!({ "share_ek": B64.encode([0u8; 1600]) }))),
        // RT-6: an RW token acting as approver minted fresh sessions with its
        // own keys, so revoking the visible one left a clone alive.
        (
            "POST",
            "/web-session/00000000-0000-0000-0000-000000000000/grant",
            Some(json!({ "mode": "rw", "capsule": B64.encode([0u8; 64]), "link_nonce": B64.encode([0u8; 32]), "key_epoch": 1 })),
        ),
        // The rest of the session-management surface, same class.
        ("GET", "/web-session/00000000-0000-0000-0000-000000000000/keys", None),
        ("DELETE", "/web-session/00000000-0000-0000-0000-000000000000", None),
        ("GET", "/web-sessions", None),
        ("GET", "/devices", None),
        ("GET", "/device/capsule", None),
    ];

    for (method, path, body) in cases {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("Authorization", format!("Bearer {web}"));
        let req = match body {
            Some(ref v) => {
                builder = builder.header("Content-Type", "application/json");
                builder.body(Body::from(serde_json::to_vec(v).unwrap())).unwrap()
            }
            None => builder.body(Body::empty()).unwrap(),
        };
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "{method} {path} must refuse a web-session token, got {}",
            resp.status()
        );
    }
}

/// The same routes still work for a real device token — the guard must refuse
/// web sessions, not everyone.
#[tokio::test]
async fn device_token_still_reaches_permanent_power_routes() {
    use vela_server::auth::token::TokenScope;

    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    insert_user(&state, user_id).await;

    let device = token_for(&state, user_id, device_id, TokenScope::Device);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/recovery/share")
                .header("Authorization", format!("Bearer {device}"))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({ "share": B64.encode(b"share-bytes") })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a real device must not be caught by the web-session guard"
    );
}

/// Renewal must carry the scope across.
///
/// The middleware re-issues a token when one is close to expiry. Issuing with
/// the default scope there would launder an ephemeral web-session token into a
/// device token roughly every ten minutes, silently undoing the guard above.
#[tokio::test]
async fn renewing_a_web_session_token_keeps_it_a_web_session_token() {
    use vela_server::auth::token::{TokenScope, TokenService};

    let state = helpers::test_state().await;
    let ts = TokenService::new(state.paseto_sk.clone(), state.paseto_pk.clone());
    let user_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();

    let (web, _) = ts
        .issue_scoped_at_epoch(user_id, session_id, None, TokenScope::WebSession, Some(7))
        .unwrap();
    let claims = ts.verify(&web).unwrap();
    assert_eq!(claims.scope, TokenScope::WebSession);
    assert_eq!(claims.key_epoch, Some(7));

    // What `AuthSession::from_request_parts` does on renewal.
    let (renewed, _) = ts
        .issue_scoped_at_epoch(
            claims.user_id,
            claims.device_id,
            Some(claims.hard_cap),
            claims.scope,
            claims.key_epoch,
        )
        .unwrap();
    let renewed = ts.verify(&renewed).unwrap();
    assert_eq!(renewed.scope, TokenScope::WebSession);
    assert_eq!(renewed.key_epoch, Some(7));
}

/// A token minted before the scope claim existed reads as a device token.
///
/// That is the permissive reading, chosen deliberately: the alternative would
/// have invalidated every device token in flight at deploy. The exposure is
/// bounded by the 15-minute token lifetime.
#[tokio::test]
async fn a_token_without_a_scope_claim_is_treated_as_a_device() {
    use vela_server::auth::token::{TokenScope, TokenService};

    let state = helpers::test_state().await;
    let ts = TokenService::new(state.paseto_sk.clone(), state.paseto_pk.clone());
    let (token, _) = ts.issue(Uuid::new_v4(), Uuid::new_v4(), None).unwrap();
    assert_eq!(ts.verify(&token).unwrap().scope, TokenScope::Device);
}

// ── Red-team RT-1: the consequence endpoints, keyed like initiate ────────────

/// A WebAuthn credential shaped well enough to deserialize.
///
/// It has to parse, or the handler rejects the body before the rate limit runs
/// and the test measures nothing at all.
fn parseable_credential() -> serde_json::Value {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    json!({
        "id": "abc",
        "rawId": B64URL.encode(b"abc"),
        "type": "public-key",
        "response": {
            "authenticatorData": B64URL.encode([0u8; 32]),
            "clientDataJSON": B64URL.encode(b"{}"),
            "signature": B64URL.encode([0u8; 64]),
        },
    })
}

/// `/recovery/recover` is the endpoint that releases the recovery share, and it
/// checked its budget before verifying anything — so a garbage body from any
/// address used to spend a victim's hourly allowance and lock them out of
/// recovery, which is the last resort after a lost device.
#[tokio::test]
async fn recovery_recover_limit_cannot_be_burned_for_someone_else() {
    let app = vela_server::routes::build(helpers::test_state().await);
    let victim = Uuid::new_v4();

    let recover = |ip: [u8; 4]| {
        let mut req = Request::builder()
            .method("POST")
            .uri("/recovery/recover")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(
                    &json!({ "user_id": victim, "credential": parseable_credential() }),
                )
                .unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((ip, 44444))));
        req
    };

    const ATTACKER: [u8; 4] = [203, 0, 113, 6];
    for i in 1..=vela_server::rate_limit::RECOVERY_CONSEQUENCE_PER_IP_USER_HOURLY {
        let resp = app.clone().oneshot(recover(ATTACKER)).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "attacker call {i} should spend budget, not be refused yet"
        );
    }
    let resp = app.clone().oneshot(recover(ATTACKER)).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the attacker must throttle themselves"
    );

    // The victim, elsewhere, is untouched.
    let resp = app.oneshot(recover([198, 51, 100, 7])).await.unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "one caller must not be able to lock another out of recovery"
    );
}

/// Same for `/recovery/enroll-device`, the step that re-enrols the recovered
/// device. Locking this is locking the user out just as effectively.
#[tokio::test]
async fn recovery_enroll_device_limit_cannot_be_burned_for_someone_else() {
    let app = vela_server::routes::build(helpers::test_state().await);
    let victim = Uuid::new_v4();

    let enroll = |ip: [u8; 4]| {
        let mut req = Request::builder()
            .method("POST")
            .uri("/recovery/enroll-device")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&json!({
                    "user_id": victim,
                    "recovery_grant": Uuid::new_v4(),
                    "hybrid_ek": "",
                    "hybrid_vk": "",
                    "device_name": "x",
                }))
                .unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((ip, 44444))));
        req
    };

    const ATTACKER: [u8; 4] = [203, 0, 113, 8];
    for i in 1..=vela_server::rate_limit::RECOVERY_CONSEQUENCE_PER_IP_USER_HOURLY {
        let resp = app.clone().oneshot(enroll(ATTACKER)).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "attacker call {i} should spend budget, not be refused yet"
        );
    }
    let resp = app.clone().oneshot(enroll(ATTACKER)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    let resp = app.oneshot(enroll([198, 51, 100, 11])).await.unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "one caller must not be able to lock another out of post-recovery enrollment"
    );
}

// ── Red-team RT-2: the RW token proof, scoped per caller ─────────────────────

/// The session id is in the QR and this endpoint does not require the poll
/// secret, so an onlooker can call it. With the budget keyed on the session
/// alone, an onlooker's attempts spent the browser's allowance.
///
/// This covers the per-caller *budget*. The exponential backoff — the other
/// half of RT-2, and the one the original exploit tripped — only engages once a
/// signature actually fails verification, which needs a granted session with a
/// real key; that half is exercised end to end against a live server rather
/// than here, and the scope string it uses is asserted below.
#[tokio::test]
async fn web_session_token_budget_cannot_be_burned_by_an_onlooker() {
    let app = vela_server::routes::build(helpers::test_state().await);
    let session_id = Uuid::new_v4();

    let attempt = |ip: [u8; 4]| {
        let mut req = Request::builder()
            .method("POST")
            .uri(format!("/web-session/{session_id}/token"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&json!({ "challenge": "AAAA", "signature": "AAAA" }))
                    .unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((ip, 44444))));
        req
    };

    // Spend the onlooker's own per-(ip, session) allowance (10/min).
    const ONLOOKER: [u8; 4] = [203, 0, 113, 12];
    for _ in 0..10 {
        let _ = app.clone().oneshot(attempt(ONLOOKER)).await.unwrap();
    }
    let resp = app.clone().oneshot(attempt(ONLOOKER)).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the onlooker must throttle themselves"
    );

    // The browser, elsewhere, still reaches the endpoint. Its proof is garbage
    // too, so "reached" means anything but 429.
    let resp = app.oneshot(attempt([198, 51, 100, 13])).await.unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "an onlooker must not be able to back off the legitimate browser"
    );
}

/// The guard must not break what a web session is *for*.
///
/// An RW browser session exists to read and write the vault it was granted.
/// Scoping the token is only correct if that still works — otherwise the fix
/// for RT-4 would have removed the feature rather than bounded it.
#[tokio::test]
async fn web_session_token_still_reaches_the_vault() {
    use vela_server::auth::token::TokenScope;

    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let user_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    insert_user(&state, user_id).await;

    // Vault endpoints only. `/devices` used to be in this list and is not any
    // more: it is account metadata rather than vault content, the web vault
    // never calls it, and it is now device-only alongside the rest of the
    // account-management surface (red-team RT-5/RT-6).
    let web = token_for(&state, user_id, session_id, TokenScope::WebSession);
    for (method, uri) in [("GET", "/vault/sync"), ("GET", "/share/inbox")] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("Authorization", format!("Bearer {web}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "{method} {uri} must stay reachable for a granted web session"
        );
    }
}

/// The capsule is one-shot even when polls arrive together.
///
/// The sequential case was already covered. This is the concurrent one: the
/// handler used to read the row, then clear it in a separate statement, so two
/// polls that both read before either cleared were both served the capsule.
/// Only the holder of the poll secret can reach this endpoint, so it was never
/// an attacker's race to win — but one-shot delivery exists to bound the damage
/// if that secret leaks, and a property that dissolves under concurrency bounds
/// nothing.
///
/// The assertion is deterministic — the conditional UPDATE makes exactly one
/// caller the winner whatever the interleaving. Its *detection* of a regression
/// is probabilistic: reverting the fix only fails this when the polls really do
/// overlap. That is worth saying out loud rather than trusting a green tick.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_capsule_is_delivered_once_even_under_concurrent_polls() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());

    let (user_id, token) = seed_user_with_device(&state).await;
    let link_nonce = B64.encode(vec![7u8; 32]);
    let resp = app
        .clone()
        .oneshot(web_session_start_req(user_id, &link_nonce))
        .await
        .unwrap();
    let b = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let session_id = v["session_id"].as_str().unwrap().to_string();

    let capsule = B64.encode(vec![9u8; 64]);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/web-session/{session_id}/grant"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "mode": "ro",
                        "capsule": capsule,
                        "link_nonce": link_nonce,
                        "key_epoch": 1,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let mut handles = Vec::new();
    for _ in 0..8 {
        let app = app.clone();
        let session_id = session_id.clone();
        handles.push(tokio::spawn(async move {
            let resp = app.oneshot(web_session_poll_req(&session_id)).await.unwrap();
            let b = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
            let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
            v.get("capsule")
                .and_then(|c| c.as_str())
                .map(|s| s.to_string())
        }));
    }

    let mut served = 0;
    for h in handles {
        if let Some(got) = h.await.unwrap() {
            assert_eq!(got, capsule, "a served capsule must be the real one");
            served += 1;
        }
    }
    assert_eq!(served, 1, "the capsule must be handed out exactly once, got {served}");
}

/// A device id that exists must be indistinguishable from one that does not.
///
/// Both `/auth/verify` and `/device/enroll` answered "no such device" and "wrong
/// signature" differently, so an anonymous caller could confirm whether a device
/// id was real. `/auth/verify` had already collapsed its not-found arm to one
/// message — the wording names all three possibilities deliberately — but the
/// signature arm returned the helper's own message and undid it. Half-applied
/// hardening reads as intentional to the next person, so this pins both arms of
/// both endpoints.
///
/// This covers the message channel only. A miss still returns after one lookup
/// while a hit runs an ML-DSA-87 verification, and that timing difference is
/// deliberately left: equalising it costs a signature verification per
/// unauthenticated request, to close an oracle that only confirms a UUIDv4 the
/// caller already holds.
#[tokio::test]
async fn device_existence_is_not_revealed_by_auth_failures() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let (_user_id, _token) = seed_user_with_device(&state).await;

    // The seeded device really exists; this id does not.
    let real = {
        use vela_server::sqldb::Db as _;
        let rows = state.sqldb.query("SELECT id FROM devices", vec![]).await.unwrap();
        rows.first()
            .and_then(|r| r.text(0))
            .unwrap()
            .to_string()
    };
    let absent = Uuid::new_v4().to_string();

    async fn probe(
        app: &axum::Router,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, String) {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let b = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap_or(json!({}));
        (status, v["message"].as_str().unwrap_or_default().to_string())
    }

    // A fresh challenge per probe: /device/enroll consumes it.
    async fn challenge(app: &axum::Router) -> String {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/challenge")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let b = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        v["challenge"].as_str().unwrap().to_string()
    }

    let bad_sig = B64.encode(vec![0u8; 4627 + 64]);

    for device_ids in [[real.clone(), absent.clone()]] {
        let mut verify_answers = Vec::new();
        let mut enroll_answers = Vec::new();
        for id in &device_ids {
            let ch = challenge(&app).await;
            verify_answers.push(
                probe(
                    &app,
                    "/auth/verify",
                    json!({ "device_id": id, "challenge": ch, "signature": bad_sig }),
                )
                .await,
            );

            let ch = challenge(&app).await;
            enroll_answers.push(
                probe(
                    &app,
                    "/device/enroll",
                    json!({
                        "enrolling_device_id": id,
                        "challenge": ch,
                        "auth_signature": bad_sig,
                        "new_device": {
                            "hybrid_ek": B64.encode(vec![0u8; 1600]),
                            "hybrid_vk": B64.encode(vec![0u8; 2624]),
                            "rms_capsule": B64.encode(vec![0u8; 64]),
                            "signature": bad_sig,
                        },
                    }),
                )
                .await,
            );
        }

        assert_eq!(
            verify_answers[0], verify_answers[1],
            "/auth/verify distinguishes an existing device id from an absent one"
        );
        assert_eq!(
            enroll_answers[0], enroll_answers[1],
            "/device/enroll distinguishes an existing device id from an absent one"
        );
    }
}

// ── Vault re-keying (docs/VAULT_REKEYING_DESIGN.md) ────────────────────────────

#[tokio::test]
async fn rekey_commit_replay_is_bound_to_the_completed_attempt() {
    use vela_server::sqldb::{Db as _, TursoValue};

    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let (user_id, token) = seed_user_with_device(&state).await;
    let completed_attempt = Uuid::new_v4().to_string();
    let stale_attempt = Uuid::new_v4().to_string();

    // This is the durable state after attempt A was aborted and a second
    // N -> N+1 attempt B committed. Only B may replay a lost commit response.
    state
        .sqldb
        .execute(
            "UPDATE users
             SET key_epoch = 2, last_rekey_id = ?, last_rekey_epoch = 2
             WHERE id = ?",
            vec![
                TursoValue::Text(completed_attempt.clone()),
                TursoValue::Text(user_id.to_string()),
            ],
        )
        .await
        .unwrap();

    let commit = |rotation_id: &str| {
        Request::builder()
            .method("POST")
            .uri("/vault/rekey/commit")
            .header("authorization", format!("Bearer {token}"))
            .header("x-vela-epoch", "2")
            .header("x-vela-rekey-id", rotation_id)
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        app.clone()
            .oneshot(commit(&stale_attempt))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        app.oneshot(commit(&completed_attempt)).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
}

/// One device drives a full rotation while a second device's stale write is
/// refused. Pins the whole epoch lifecycle: active → freezing → committed,
/// shadow-row isolation, the `vault_rekeyed` guard, capsule storage, and the
/// post-commit sweep of the superseded rows.
#[tokio::test]
async fn rekey_rotation_lifecycle_end_to_end() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());

    let user = Uuid::new_v4();
    let initiator = Uuid::new_v4();
    let other_device = Uuid::new_v4();
    let now = chrono::Utc::now();

    use vela_server::sqldb::{Db as _, TursoValue};
    state
        .sqldb
        .execute(
            "INSERT INTO users (id, recovery_share, created_at) VALUES (?, ?, ?)",
            vec![
                TursoValue::Text(user.to_string()),
                TursoValue::Text("retired-share".into()),
                TursoValue::Text(now.to_rfc3339()),
            ],
        )
        .await
        .unwrap();
    for device in [initiator, other_device] {
        state
            .sqldb
            .execute(
                "INSERT INTO devices (id, user_id, hybrid_ek, hybrid_vk, enrolled_by, rms_capsule, revoked, created_at)
                 VALUES (?, ?, ?, ?, NULL, NULL, 0, ?)",
                vec![
                    TursoValue::Text(device.to_string()),
                    TursoValue::Text(user.to_string()),
                    TursoValue::Text(B64.encode(vec![0u8; 1600])),
                    TursoValue::Text(B64.encode(vec![0u8; 2624])),
                    TursoValue::Text(now.to_rfc3339()),
                ],
            )
            .await
            .unwrap();
    }

    let token_initiator = issue_token(&state, user, initiator);
    let token_other = issue_token(&state, user, other_device);

    let attest = |token: &String| {
        Request::builder()
            .method("POST")
            .uri("/device/rekey-capable")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(attest(&token_initiator)).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );

    // Seed one chunk at the current epoch.
    let put = |token: &String, epoch: Option<i64>, if_match: &str, rotation_id: Option<&str>| {
        let mut b = Request::builder()
            .method("PUT")
            .uri("/vault/chunk/vault-main")
            .header("authorization", format!("Bearer {}", token))
            .header("if-match", if_match)
            .header("x-lamport-clock", "1");
        if let Some(e) = epoch {
            b = b.header("x-vela-epoch", e.to_string());
        }
        if let Some(id) = rotation_id {
            b = b.header("x-vela-rekey-id", id);
        }
        b.body(Body::from(vec![1u8, 2, 3])).unwrap()
    };

    let resp = app.clone().oneshot(put(&token_initiator, None, "0", None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // A malformed declaration must not silently become legacy/headerless.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/vault/chunk/bad-epoch")
                .header("authorization", format!("Bearer {token_initiator}"))
                .header("if-match", "0")
                .header("x-lamport-clock", "1")
                .header("x-vela-epoch", "not-an-integer")
                .body(Body::from(vec![1u8]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Rotation is unavailable until every active device has positively
    // attested that it retained its capsule private key.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/vault/rekey/start")
                .header("authorization", format!("Bearer {}", token_initiator))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(
        app.clone().oneshot(attest(&token_other)).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );

    // Start: returns the next epoch plus the inventory.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/vault/rekey/start")
                .header("authorization", format!("Bearer {}", token_initiator))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    assert_eq!(body["epoch"], 2);
    let rotation_id = body["rotation_id"].as_str().unwrap().to_string();
    assert_eq!(body["chunks"].as_array().unwrap().len(), 1);
    assert_eq!(body["chunks"][0]["chunk_id"], "vault-main");

    // Commit is structurally gated: the old row may not be swept until its
    // epoch-2 shadow exists.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/vault/rekey/commit")
                .header("authorization", format!("Bearer {}", token_initiator))
                .header("x-vela-rekey-id", &rotation_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // While freezing: a stale-epoch write from the offline device is refused
    // with the dedicated code — this is the guard that keeps an old-key blob
    // out of the new vault.
    let resp = app.clone().oneshot(put(&token_other, Some(1), "1", None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let err: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    assert_eq!(err["error"], "vault_rekeyed");

    // ...and even without an epoch header at all.
    let resp = app.clone().oneshot(put(&token_other, None, "1", None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/vault/chunk/vault-main")
                .header("authorization", format!("Bearer {token_other}"))
                .header("if-match", "1")
                .header("x-vela-epoch", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT, "freeze rejects deletes");

    // Knowing the target epoch does not authorize a sibling device to poison
    // the starter's shadow rows.
    let resp = app
        .clone()
        .oneshot(put(&token_other, Some(2), "0", Some(&rotation_id)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Nor may the temporary web-session authority rotation is intended to
    // retire populate a candidate row with attacker-chosen ciphertext.
    let web = token_for(
        &state,
        user,
        Uuid::new_v4(),
        vela_server::auth::token::TokenScope::WebSession,
    );
    let resp = app.clone().oneshot(put(&web, Some(2), "0", Some(&rotation_id))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // ORAM has no shadow migration protocol. Even a caller that knows the
    // target epoch must not create buckets which become authoritative at
    // commit without participating in the chunk completeness checks.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/vault/oram/tree/path/0")
                .header("authorization", format!("Bearer {web}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "height": 0,
                        "epoch": 2,
                        "buckets": [{
                            "bucket_index": 1,
                            "if_match": 0,
                            "lamport_clock": 1,
                            "ciphertext": B64.encode([1u8, 2, 3]),
                        }],
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let oram_rows = state
        .sqldb
        .query(
            "SELECT 1 FROM oram_buckets WHERE user_id = ?",
            vec![TursoValue::Text(user.to_string())],
        )
        .await
        .unwrap();
    assert!(oram_rows.is_empty(), "freeze must not create ORAM rows");

    // The initiator's re-keyed copy lands as a shadow row at epoch 2. Replays
    // must be tolerated (crash-resume), and successful progress refreshes the
    // inactivity deadline instead of imposing a fixed 15-minute wall clock.
    let old_activity = (chrono::Utc::now() - chrono::Duration::minutes(14)).to_rfc3339();
    state
        .sqldb
        .execute(
            "UPDATE users SET rekey_started_at = ? WHERE id = ?",
            vec![
                TursoValue::Text(old_activity.clone()),
                TursoValue::Text(user.to_string()),
            ],
        )
        .await
        .unwrap();
    for _ in 0..2 {
        let resp = app.clone().oneshot(put(
            &token_initiator,
            Some(2),
            "0",
            Some(&rotation_id),
        )).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let activity = state
        .sqldb
        .query(
            "SELECT rekey_started_at FROM users WHERE id = ?",
            vec![TursoValue::Text(user.to_string())],
        )
        .await
        .unwrap();
    assert_ne!(activity[0].text(0), Some(old_activity.as_str()));

    // Shadows alone are insufficient: every active device needs a capsule
    // minted for this exact target epoch before commit can strand nobody.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/vault/rekey/commit")
                .header("authorization", format!("Bearer {}", token_initiator))
                .header("x-vela-rekey-id", &rotation_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // Reads still serve the pre-rotation world until commit.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/vault/sync")
                .header("authorization", format!("Bearer {}", token_other))
                .header("x-vela-rekey-id", &rotation_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["epoch"], 1);
    assert_eq!(manifest["chunks"].as_array().unwrap().len(), 1);

    // Capsules: only the starter may store them, and only for real devices.
    let capsules = json!({
        "capsules": {
            initiator.to_string(): "Y2Fwc3VsZS1mb3ItaW5pdGlhdG9y",
            other_device.to_string(): "Y2Fwc3VsZS1mb3Itb3RoZXI=",
        }
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/vault/rekey/capsules")
                .header("authorization", format!("Bearer {}", token_other))
                .header("content-type", "application/json")
                .body(Body::from(capsules.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "non-starter refused");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/vault/rekey/capsules")
                .header("authorization", format!("Bearer {}", token_initiator))
                .header("x-vela-rekey-id", &rotation_id)
                .header("content-type", "application/json")
                .body(Body::from(capsules.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Commit flips the epoch and sweeps the superseded rows.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/vault/rekey/commit")
                .header("authorization", format!("Bearer {}", token_initiator))
                .header("x-vela-rekey-id", &rotation_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Commit retires both old recovery shares and outstanding browser grants.
    let recovery = state
        .sqldb
        .query(
            "SELECT recovery_share FROM users WHERE id = ?",
            vec![TursoValue::Text(user.to_string())],
        )
        .await
        .unwrap();
    assert!(matches!(recovery[0].get(0), None | Some(TursoValue::Null)));
    let resp = app
        .clone()
        .oneshot(put(&web, Some(2), "2", None))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "a pre-rotation web grant must lose write authority"
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/vault/epoch")
                .header("authorization", format!("Bearer {}", token_other))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    assert_eq!(body["epoch"], 2);
    assert_eq!(body["state"], "active");

    // A commit response may be lost after the CAS succeeds. Replaying with
    // the target epoch must report success rather than an ambiguous conflict.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/vault/rekey/commit")
                .header("authorization", format!("Bearer {token_initiator}"))
                .header("x-vela-rekey-id", &rotation_id)
                .header("x-vela-epoch", "2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // A legacy/offline client that omits X-Vela-Epoch must not have its
    // old-RMS ciphertext silently labelled as epoch 2 after commit.
    let resp = app
        .clone()
        .oneshot(put(&token_other, None, "2", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let err: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(err["error"], "vault_rekeyed");

    // Deletes are writes too: a stale headerless client must not be able to
    // delete the new epoch merely because its cached version happens to match.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/vault/chunk/vault-main")
                .header("authorization", format!("Bearer {token_other}"))
                .header("if-match", "2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // Exactly ONE row survives per chunk — the epoch-2 re-keyed copy.
    let rows = state
        .sqldb
        .query(
            "SELECT epoch FROM vault_chunks WHERE user_id = ?",
            vec![TursoValue::Text(user.to_string())],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "superseded rows must be swept at commit");

    let capsule_req = || {
        Request::builder()
            .uri("/device/capsule")
            .header("authorization", format!("Bearer {}", token_other))
            .body(Body::empty())
            .unwrap()
    };
    // Rekey capsules remain retryable until the device durably adopts and
    // explicitly acknowledges them.
    for _ in 0..2 {
        let resp = app.clone().oneshot(capsule_req()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["epoch"], 2);
    }
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/device/capsule/ack")
                .header("authorization", format!("Bearer {}", token_other))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "epoch": 2 }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = app.clone().oneshot(capsule_req()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // A concurrent abort and commit must have exactly one winner. In
    // particular, the loser must never sweep the epoch the winner made live.
    let start = Request::builder()
        .method("POST")
        .uri("/vault/rekey/start")
        .header("authorization", format!("Bearer {token_initiator}"))
        .body(Body::empty())
        .unwrap();
    let start = app.clone().oneshot(start).await.unwrap();
    assert_eq!(start.status(), StatusCode::OK);
    let start_body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(start.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let rotation_id3 = start_body["rotation_id"].as_str().unwrap().to_string();

    // A delayed upload from the previous N -> N+1 attempt must not be accepted
    // by this new attempt merely because it came from the same device.
    assert_eq!(
        app.clone()
            .oneshot(put(
                &token_initiator,
                Some(3),
                "0",
                Some(&rotation_id),
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(put(
                &token_initiator,
                Some(3),
                "0",
                Some(&rotation_id3),
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let capsules3 = json!({
        "capsules": {
            initiator.to_string(): "Y2Fwc3VsZS0zLWluaXQ=",
            other_device.to_string(): "Y2Fwc3VsZS0zLW90aGVy",
        }
    });
    let stale_capsules = Request::builder()
        .method("POST")
        .uri("/vault/rekey/capsules")
        .header("authorization", format!("Bearer {token_initiator}"))
        .header("x-vela-rekey-id", &rotation_id)
        .header("content-type", "application/json")
        .body(Body::from(capsules3.to_string()))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(stale_capsules).await.unwrap().status(),
        StatusCode::CONFLICT,
        "capsules from a prior attempt must not overwrite the current attempt"
    );
    assert_eq!(
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/vault/rekey/capsules")
                    .header("authorization", format!("Bearer {token_initiator}"))
                    .header("x-vela-rekey-id", &rotation_id3)
                    .header("content-type", "application/json")
                    .body(Body::from(capsules3.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    let commit = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/vault/rekey/commit")
            .header("authorization", format!("Bearer {token_initiator}"))
            .header("x-vela-rekey-id", &rotation_id3)
            .body(Body::empty())
            .unwrap(),
    );
    let abort = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/vault/rekey/abort")
            .header("authorization", format!("Bearer {token_initiator}"))
            .header("x-vela-rekey-id", &rotation_id3)
            .body(Body::empty())
            .unwrap(),
    );
    let (commit, abort) = tokio::join!(commit, abort);
    let commit = commit.unwrap();
    let abort = abort.unwrap();
    let statuses = [commit.status(), abort.status()];
    let details = [
        String::from_utf8_lossy(
            &axum::body::to_bytes(commit.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .into_owned(),
        String::from_utf8_lossy(
            &axum::body::to_bytes(abort.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .into_owned(),
    ];
    assert_eq!(
        statuses.iter().filter(|&&s| s == StatusCode::NO_CONTENT).count(),
        1,
        "exactly one state transition wins: {statuses:?} {details:?}"
    );
    assert_eq!(
        statuses.iter().filter(|&&s| s == StatusCode::CONFLICT).count(),
        1,
        "the losing transition reports a conflict"
    );
    let user_state = state
        .sqldb
        .query(
            "SELECT key_epoch FROM users WHERE id = ?",
            vec![TursoValue::Text(user.to_string())],
        )
        .await
        .unwrap();
    let winning_epoch = user_state[0].i64(0).unwrap();
    let chunks = state
        .sqldb
        .query(
            "SELECT epoch FROM vault_chunks WHERE user_id = ?",
            vec![TursoValue::Text(user.to_string())],
        )
        .await
        .unwrap();
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].i64(0), Some(winning_epoch));
}

#[tokio::test]
async fn rekey_start_refuses_accounts_with_oram_buckets() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let user = Uuid::new_v4();
    let device = Uuid::new_v4();
    let now = chrono::Utc::now().to_rfc3339();
    use vela_server::sqldb::{Db as _, TursoValue};

    state
        .sqldb
        .execute(
            "INSERT INTO users (id, created_at) VALUES (?, ?)",
            vec![TursoValue::Text(user.to_string()), TursoValue::Text(now.clone())],
        )
        .await
        .unwrap();
    state
        .sqldb
        .execute(
            "INSERT INTO devices
             (id, user_id, hybrid_ek, hybrid_vk, revoked, created_at)
             VALUES (?, ?, ?, ?, 0, ?)",
            vec![
                TursoValue::Text(device.to_string()),
                TursoValue::Text(user.to_string()),
                TursoValue::Text(B64.encode(vec![0u8; 1600])),
                TursoValue::Text(B64.encode(vec![0u8; 2624])),
                TursoValue::Text(now.clone()),
            ],
        )
        .await
        .unwrap();
    state
        .sqldb
        .execute(
            "INSERT INTO oram_buckets
             (user_id, tree_id, bucket_index, version, ciphertext, epoch, created_at, updated_at)
             VALUES (?, 'tree', 1, 1, 'Y3Q=', 1, ?, ?)",
            vec![
                TursoValue::Text(user.to_string()),
                TursoValue::Text(now.clone()),
                TursoValue::Text(now),
            ],
        )
        .await
        .unwrap();

    let token = issue_token(&state, user, device);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/vault/rekey/start")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn oram_writes_declare_and_accept_post_rotation_epoch() {
    let state = helpers::test_state().await;
    let app = vela_server::routes::build(state.clone());
    let user = Uuid::new_v4();
    let device = Uuid::new_v4();
    let now = chrono::Utc::now().to_rfc3339();
    use vela_server::sqldb::{Db as _, TursoValue};

    state
        .sqldb
        .execute(
            "INSERT INTO users (id, created_at, key_epoch) VALUES (?, ?, 2)",
            vec![
                TursoValue::Text(user.to_string()),
                TursoValue::Text(now.clone()),
            ],
        )
        .await
        .unwrap();
    state
        .sqldb
        .execute(
            "INSERT INTO devices
             (id, user_id, hybrid_ek, hybrid_vk, revoked, created_at)
             VALUES (?, ?, ?, ?, 0, ?)",
            vec![
                TursoValue::Text(device.to_string()),
                TursoValue::Text(user.to_string()),
                TursoValue::Text(B64.encode(vec![0u8; 1600])),
                TursoValue::Text(B64.encode(vec![0u8; 2624])),
                TursoValue::Text(now),
            ],
        )
        .await
        .unwrap();
    let token = issue_token(&state, user, device);
    let body = |epoch: Option<i64>| {
        json!({
            "height": 0,
            "epoch": epoch,
            "buckets": [{
                "bucket_index": 1,
                "if_match": 0,
                "lamport_clock": 1,
                "ciphertext": B64.encode([1u8, 2, 3]),
            }],
        })
    };
    let request = |body: serde_json::Value| {
        Request::builder()
            .method("PUT")
            .uri("/vault/oram/tree/path/0")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };

    assert_eq!(
        app.clone().oneshot(request(body(None))).await.unwrap().status(),
        StatusCode::CONFLICT,
        "headerless legacy writes remain forbidden after epoch 1"
    );
    assert_eq!(
        app.oneshot(request(body(Some(2)))).await.unwrap().status(),
        StatusCode::OK,
        "an ORAM write sealed for the active post-rotation epoch succeeds"
    );
}

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
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::json;
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
        "cyclo_pk": B64.encode(vec![0u8; 1024]),
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
        "cyclo_pk": B64.encode(vec![0u8; 1024]),
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

    for user_id in [user_a, user_b] {
        state
            .db
            .execute(
                "INSERT INTO users (id, created_at) VALUES ($1, $2)",
                stoolap::params![user_id.to_string(), now.to_rfc3339()],
            )
            .unwrap();
    }

    for (device_id, user_id) in [(device_a, user_a), (device_b, user_b)] {
        state.db.execute(
            "INSERT INTO devices
             (id, user_id, hybrid_ek, hybrid_vk, cyclo_pk, enrolled_by, rms_capsule, revoked, revoked_at, revoked_by, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE, $8, $9, $10)",
            stoolap::params![
                device_id.to_string(),
                user_id.to_string(),
                B64.encode(vec![0u8; 1600]),
                B64.encode(vec![0u8; 2624]),
                B64.encode(vec![0u8; 1024]),
                Option::<String>::None,
                Option::<String>::None,
                Option::<String>::None,
                Option::<String>::None,
                now.to_rfc3339(),
            ],
        ).unwrap();
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

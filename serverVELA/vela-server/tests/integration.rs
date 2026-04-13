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

    let body = axum::body::to_bytes(resp.into_body(), 1024)
        .await
        .unwrap();
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

    let body = axum::body::to_bytes(resp.into_body(), 1024)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["nonce"].is_string());
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

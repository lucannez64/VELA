use axum::Router;
use sqlx::PgPool;

use vela_server::{config, routes, state::AppStateInner, store::Store};

pub async fn test_app() -> Router {
    let _ = dotenvy::dotenv();

    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set for tests");

    let pool = PgPool::connect(&database_url)
        .await
        .expect("failed to connect to test database");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("failed to run migrations");

    let store = Store::open_temp().expect("failed to open temp sled store");

    let cfg = config::Config::from_env().expect("failed to load config");

    let state = std::sync::Arc::new(
        AppStateInner::new(pool, store, cfg).expect("failed to create state"),
    );

    routes::build(state)
}

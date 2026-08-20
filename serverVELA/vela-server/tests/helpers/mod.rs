use axum::Router;
use uuid::Uuid;

use vela_server::{
    config, db,
    routes,
    sqldb::{Db as _, TursoDb},
    state::{AppStateInner, DbPool},
    store::Store,
};

pub async fn test_state() -> vela_server::state::AppState {
    test_state_with_config(|_| {}).await
}

pub async fn test_state_with_config(
    configure: impl FnOnce(&mut config::Config),
) -> vela_server::state::AppState {
    let db_url = format!("memory://{}", Uuid::new_v4());
    let database = db::open_and_init(&db_url).expect("failed to open in-memory stoolap db");
    // Keep the stoolap handle available (some helpers/backfill still reference
    // the pool type), but all handlers now read/write turso.
    let db_pool = DbPool::new(database, 1);

    let turso_path = format!(
        "{}/vela-test-{}.db",
        std::env::temp_dir().display(),
        Uuid::new_v4()
    );
    let turso = std::sync::Arc::new(
        vela_server::sqldb::TursoDb::open(&turso_path, 1)
            .await
            .expect("failed to open temp turso db"),
    );

    let store = Store::open_temp().expect("failed to open temp sled store");

    let mut cfg = config::Config::from_env().expect("failed to load config");
    configure(&mut cfg);

    std::sync::Arc::new(
        AppStateInner::new(db_pool, turso, store, cfg)
            .await
            .expect("failed to create state"),
    )
}

pub async fn test_app() -> Router {
    routes::build(test_state().await)
}

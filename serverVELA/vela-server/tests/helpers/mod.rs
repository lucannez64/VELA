use axum::Router;
use uuid::Uuid;

use vela_server::{
    config,
    routes,
    sqldb::TursoDb,
    state::AppStateInner,
    store::Store,
};

pub async fn test_state() -> vela_server::state::AppState {
    test_state_with_config(|_| {}).await
}

pub async fn test_state_with_config(
    configure: impl FnOnce(&mut config::Config),
) -> vela_server::state::AppState {
    let turso_path = format!(
        "{}/vela-test-{}.db",
        std::env::temp_dir().display(),
        Uuid::new_v4()
    );
    let turso = std::sync::Arc::new(
        TursoDb::open(&turso_path, 1)
            .await
            .expect("failed to open temp turso db"),
    );

    let store = Store::open_temp().expect("failed to open temp sled store");

    let mut cfg = config::Config::from_env().expect("failed to load config");
    configure(&mut cfg);

    std::sync::Arc::new(
        AppStateInner::new(turso, store, cfg)
            .await
            .expect("failed to create state"),
    )
}

pub async fn test_app() -> Router {
    routes::build(test_state().await)
}

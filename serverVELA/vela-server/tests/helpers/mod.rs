use axum::Router;
use uuid::Uuid;

use vela_server::{config, db, routes, state::AppStateInner, store::Store};

pub async fn test_state() -> vela_server::state::AppState {
    test_state_with_config(|_| {}).await
}

pub async fn test_state_with_config(
    configure: impl FnOnce(&mut config::Config),
) -> vela_server::state::AppState {
    let db_url = format!("memory://{}", Uuid::new_v4());
    let database = db::open_and_init(&db_url).expect("failed to open in-memory stoolap db");

    let store = Store::open_temp().expect("failed to open temp sled store");

    let mut cfg = config::Config::from_env().expect("failed to load config");
    configure(&mut cfg);

    std::sync::Arc::new(AppStateInner::new(database, store, cfg).expect("failed to create state"))
}

pub async fn test_app() -> Router {
    routes::build(test_state().await)
}

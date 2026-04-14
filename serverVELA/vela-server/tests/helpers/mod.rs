use axum::Router;

use vela_server::{config, db, routes, state::AppStateInner, store::Store};

pub async fn test_app() -> Router {
    let database = db::open_and_init("memory://").expect("failed to open in-memory stoolap db");

    let store = Store::open_temp().expect("failed to open temp sled store");

    let cfg = config::Config::from_env().expect("failed to load config");

    let state = std::sync::Arc::new(
        AppStateInner::new(database, store, cfg).expect("failed to create state"),
    );

    routes::build(state)
}

use std::sync::Arc;

use pasetors::{
    keys::{AsymmetricPublicKey, AsymmetricSecretKey},
    version4::V4,
};
use stoolap::Database;

use crate::config::Config;
use crate::store::Store;

pub struct AppStateInner {
    pub db: Database,
    pub store: Store,
    pub paseto_sk: AsymmetricSecretKey<V4>,
    pub paseto_pk: AsymmetricPublicKey<V4>,
    pub config: Config,
}

pub type AppState = Arc<AppStateInner>;

impl AppStateInner {
    pub fn new(db: Database, store: Store, config: Config) -> anyhow::Result<Self> {
        let paseto_sk = AsymmetricSecretKey::<V4>::from(&config.paseto_secret_key)
            .map_err(|e| anyhow::anyhow!("invalid PASETO secret key: {e:?}"))?;
        let paseto_pk = AsymmetricPublicKey::<V4>::from(&config.paseto_public_key)
            .map_err(|e| anyhow::anyhow!("invalid PASETO public key: {e:?}"))?;

        Ok(Self {
            db,
            store,
            paseto_sk,
            paseto_pk,
            config,
        })
    }
}

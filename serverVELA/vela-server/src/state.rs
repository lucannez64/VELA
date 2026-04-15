use std::sync::Arc;

use pasetors::{
    keys::{AsymmetricPublicKey, AsymmetricSecretKey},
    version4::V4,
};
use stoolap::Database;
use webauthn_rs::prelude::{Url, Webauthn, WebauthnBuilder};

use crate::config::Config;
use crate::store::Store;

pub struct AppStateInner {
    pub db: Database,
    pub store: Store,
    pub webauthn: Webauthn,
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
        let rp_origin = Url::parse(&config.webauthn_rp_origin)
            .map_err(|e| anyhow::anyhow!("invalid WEBAUTHN_RP_ORIGIN: {e}"))?;
        let webauthn = WebauthnBuilder::new(&config.webauthn_rp_id, &rp_origin)
            .map_err(|e| anyhow::anyhow!("invalid WebAuthn configuration: {e:?}"))?
            .rp_name(&config.webauthn_rp_name)
            .allow_any_port(true)
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build WebAuthn verifier: {e:?}"))?;

        Ok(Self {
            db,
            store,
            webauthn,
            paseto_sk,
            paseto_pk,
            config,
        })
    }
}

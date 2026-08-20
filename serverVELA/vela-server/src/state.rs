use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use pasetors::{
    keys::{AsymmetricPublicKey, AsymmetricSecretKey},
    version4::V4,
};
use stoolap::Database;
use webauthn_rs::prelude::{Url, Webauthn, WebauthnBuilder};

use crate::config::Config;
use crate::store::Store;

/// A pool of cloned `stoolap::Database` handles sharing one `MVCCEngine`.
///
/// stoolap's `DatabaseInner` serializes every `query`/`execute` behind a single
/// `Mutex<Executor>` (stoolap-0.4.0 `api/database.rs`). Under concurrent load
/// that one lock is the binding throughput constraint for the whole auth path
/// (~8k SELECT/s on a 12-core box, regardless of CPU). `Database::clone()`
/// builds a *fresh* `Executor` over the same engine, so a pool of N handles
/// shards that lock across N independent mutexes — N× the SQL parallelism,
/// with no data-copy cost (the engine is `Arc`-shared).
///
/// `get()` round-robins a handle per call. For low-frequency work (startup
/// backfill, background cleanup tasks) `any()` returns a concrete clone.
pub struct DbPool {
    handles: Vec<Database>,
    idx: AtomicUsize,
}

impl Clone for DbPool {
    fn clone(&self) -> Self {
        // Cheap: shares the same `Arc<MVCCEngine>` handles (only the round-robin
        // counter is fresh — its starting offset is irrelevant).
        Self {
            handles: self.handles.clone(),
            idx: AtomicUsize::new(0),
        }
    }
}

impl DbPool {
    /// Build a pool of `size` cloned handles around `base`.
    ///
    /// `size` is clamped to at least 1. A good default is the machine's
    /// physical core count; cloning is cheap (shared `Arc<MVCCEngine>`).
    pub fn new(base: Database, size: usize) -> Self {
        let size = size.max(1);
        let mut handles = Vec::with_capacity(size);
        handles.push(base);
        for _ in 1..size {
            // Fresh executor with its own mutex, sharing the same engine.
            handles.push(handles[0].clone());
        }
        Self {
            handles,
            idx: AtomicUsize::new(0),
        }
    }

    /// Next handle (round-robin). Each handle has its own executor lock.
    pub fn get(&self) -> &Database {
        let i = self.idx.fetch_add(1, Ordering::Relaxed) % self.handles.len();
        &self.handles[i]
    }

    /// A concrete handle for handing to background tasks / one-shot startup work.
    pub fn any(&self) -> Database {
        self.get().clone()
    }
}

/// Deref to a round-robin `Database` so existing `state.db.query/execute` call
/// sites work unchanged and transparently pick a sharded executor handle.
impl Deref for DbPool {
    type Target = Database;
    fn deref(&self) -> &Database {
        self.get()
    }
}

pub struct AppStateInner {
    pub db: DbPool,
    pub sqldb: std::sync::Arc<crate::sqldb::TursoDb>,
    pub store: Store,
    pub webauthn: Webauthn,
    pub paseto_sk: AsymmetricSecretKey<V4>,
    pub paseto_pk: AsymmetricPublicKey<V4>,
    pub config: Config,
}

impl AppStateInner {
    /// Round-robin a pooled database handle for request-path SQL.
    pub fn db(&self) -> &Database {
        self.db.get()
    }
}

pub type AppState = Arc<AppStateInner>;

impl AppStateInner {
    pub async fn new(
        db: DbPool,
        sqldb: std::sync::Arc<crate::sqldb::TursoDb>,
        store: Store,
        config: Config,
    ) -> anyhow::Result<Self> {
        let paseto_sk = AsymmetricSecretKey::<V4>::from(&config.paseto_secret_key)
            .map_err(|e| anyhow::anyhow!("invalid PASETO secret key: {e:?}"))?;
        let paseto_pk = AsymmetricPublicKey::<V4>::from(&config.paseto_public_key)
            .map_err(|e| anyhow::anyhow!("invalid PASETO public key: {e:?}"))?;
        let rp_origin = Url::parse(&config.webauthn_rp_origin)
            .map_err(|e| anyhow::anyhow!("invalid WEBAUTHN_RP_ORIGIN: {e}"))?;
        let builder = WebauthnBuilder::new(&config.webauthn_rp_id, &rp_origin)
            .map_err(|e| anyhow::anyhow!("invalid WebAuthn configuration: {e:?}"))?
            .rp_name(&config.webauthn_rp_name);
        // Only relax RP origin port binding outside production (e.g. local dev
        // on a non-443 port). In production the origin port must match exactly,
        // since WebAuthn is the sole factor for account recovery.
        let builder = if config.production {
            builder
        } else {
            builder.allow_any_port(true)
        };
        let webauthn = builder
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build WebAuthn verifier: {e:?}"))?;

        if let Err(e) = crate::recovery::webauthn::backfill_webauthn_cred_ids(&sqldb).await {
            tracing::warn!(error = %e, "WebAuthn cred_id backfill failed; continuing startup");
        }

        Ok(Self {
            db,
            sqldb,
            store,
            webauthn,
            paseto_sk,
            paseto_pk,
            config,
        })
    }
}

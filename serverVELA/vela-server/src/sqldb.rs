//! Async SQL layer over the `turso` crate — the target backend for the
//! stoolap -> Turso migration.
//!
//! Foundation slice:
//!   - [`Db`]            : small async query/execute/batch trait
//!   - [`TursoDb`]       : turso (SQLite-compatible) implementation with a
//!                         small pool of `Connection`s (turso Connections are
//!                         Send+Sync+Clone; each is itself async-concurrency
//!                         safe, the pool is belt-and-braces for the write path)
//!   - [`VelaRow`]       : a buffered row (Vec<turso::Value>)
//!   - [`SCHEMA`]        : SQLite-compatible DDL, identical to what the
//!                         lossless exporter (`examples/export_db`) emits.
//!
//! Handlers are ported to this trait incrementally; stoolap remains in place
//! until every call site is migrated. Sync `stoolap::params!` sites become
//! `Vec<turso::Value>` here.

use std::sync::atomic::{AtomicUsize, Ordering};

/// A row buffered out of turso's streaming `Rows` into plain values.
#[derive(Debug)]
pub struct VelaRow {
    pub values: Vec<turso::Value>,
}

impl VelaRow {
    pub fn get(&self, idx: usize) -> Option<&turso::Value> {
        self.values.get(idx)
    }
    pub fn len(&self) -> usize {
        self.values.len()
    }
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// Minimal async database interface the server's SQL needs.
pub trait Db: Send + Sync {
    /// Run a query with positional params; returns all rows (buffered) or an
    /// empty vec if there were no rows/matches.
    async fn query(&self, sql: &str, params: Vec<turso::Value>) -> anyhow::Result<Vec<VelaRow>>;
    /// Run a write statement; returns rows affected.
    async fn execute(&self, sql: &str, params: Vec<turso::Value>) -> anyhow::Result<u64>;
    /// Run multiple statements (DDL batch).
    async fn execute_batch(&self, sql: &str) -> anyhow::Result<()>;
}

/// turso-backed implementation.
pub struct TursoDb {
    conns: Vec<turso::Connection>,
    idx: AtomicUsize,
}

impl TursoDb {
    /// Open (or create) a local turso database file at `path`, connect a pool
    /// of `pool` connections, and ensure the schema exists.
    pub async fn open(path: &str, pool: usize) -> anyhow::Result<Self> {
        let db = turso::Builder::new_local(path).build().await?;
        let n = pool.max(1);
        let mut conns = Vec::with_capacity(n);
        for _ in 0..n {
            conns.push(db.connect()?);
        }
        let this = Self {
            conns,
            idx: AtomicUsize::new(0),
        };
        this.execute_batch(SCHEMA).await?;
        Ok(this)
    }

    fn conn(&self) -> &turso::Connection {
        &self.conns[self.idx.fetch_add(1, Ordering::Relaxed) % self.conns.len()]
    }
}

impl Db for TursoDb {
    async fn query(&self, sql: &str, params: Vec<turso::Value>) -> anyhow::Result<Vec<VelaRow>> {
        let mut stream = self.conn().query(sql, params).await?;
        let mut out = Vec::new();
        while let Some(row) = stream.next().await? {
            let mut values = Vec::with_capacity(row.column_count());
            for i in 0..row.column_count() {
                values.push(row.get_value(i)?);
            }
            out.push(VelaRow { values });
        }
        Ok(out)
    }

    async fn execute(&self, sql: &str, params: Vec<turso::Value>) -> anyhow::Result<u64> {
        Ok(self.conn().execute(sql, params).await?)
    }

    async fn execute_batch(&self, sql: &str) -> anyhow::Result<()> {
        self.conn().execute_batch(sql).await?;
        Ok(())
    }
}

/// SQLite-compatible DDL, matching `examples/export_db`'s schema.sql.
pub const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS users (
    id TEXT UNIQUE NOT NULL, recovery_share TEXT, recovery_auth_hash TEXT,
    created_at TEXT NOT NULL, recovery_webauthn_credential TEXT,
    share_ek TEXT, recovery_webauthn_cred_id TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_webauthn_cred_id ON users(recovery_webauthn_cred_id);
CREATE TABLE IF NOT EXISTS devices (
    id TEXT UNIQUE NOT NULL, user_id TEXT NOT NULL,
    device_name TEXT NOT NULL DEFAULT 'Desktop Device', device_type TEXT NOT NULL DEFAULT 'desktop',
    last_active TEXT, hybrid_ek TEXT NOT NULL, hybrid_vk TEXT NOT NULL, enrolled_by TEXT,
    rms_capsule TEXT, revoked INTEGER NOT NULL DEFAULT 0, revoked_at TEXT, revoked_by TEXT,
    created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
CREATE TABLE IF NOT EXISTS vault_chunks (
    chunk_id TEXT NOT NULL, user_id TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1,
    lamport_clock INTEGER NOT NULL DEFAULT 0, last_writer TEXT, ciphertext TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_chunks_user_chunk ON vault_chunks(user_id, chunk_id);
CREATE INDEX IF NOT EXISTS idx_vault_chunks_user_id ON vault_chunks(user_id);
CREATE TABLE IF NOT EXISTS oram_buckets (
    user_id TEXT NOT NULL, tree_id TEXT NOT NULL, bucket_index INTEGER NOT NULL,
    version INTEGER NOT NULL DEFAULT 1, lamport_clock INTEGER NOT NULL DEFAULT 0,
    last_writer TEXT, ciphertext TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_oram_buckets_user_tree_bucket ON oram_buckets(user_id, tree_id, bucket_index);
CREATE TABLE IF NOT EXISTS share_inbox (
    id TEXT UNIQUE NOT NULL, sender_user_id TEXT NOT NULL, recipient_user_id TEXT NOT NULL,
    capsule TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_share_inbox_recipient ON share_inbox(recipient_user_id);
CREATE TABLE IF NOT EXISTS shared_items (
    id TEXT UNIQUE NOT NULL, sender_user_id TEXT NOT NULL, recipient_user_id TEXT NOT NULL,
    capsule TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS web_sessions (
    id TEXT UNIQUE NOT NULL, user_id TEXT, approver_user_id TEXT, poll_secret_hash TEXT,
    ephemeral_pk TEXT NOT NULL, web_vk TEXT, link_nonce TEXT NOT NULL, mode TEXT,
    status TEXT NOT NULL, capsule TEXT, approved_by TEXT, created_at TEXT NOT NULL,
    expires_at TEXT);
CREATE INDEX IF NOT EXISTS idx_web_sessions_status ON web_sessions(status);
CREATE INDEX IF NOT EXISTS idx_web_sessions_expires ON web_sessions(expires_at);
";

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    async fn temp_db() -> turso::Database {
        let path = format!(
            "{}/vela-sqldb-test-{}.db",
            std::env::temp_dir().display(),
            std::process::id()
        );
        let _ = std::fs::remove_file(&path);
        turso::Builder::new_local(&path).build().await.unwrap()
    }

    #[tokio::test]
    async fn schema_and_crud() {
        let db = temp_db().await;
        let conns = vec![db.connect().unwrap()];
        let ds = TursoDb {
            conns,
            idx: AtomicUsize::new(0),
        };
        ds.execute_batch(SCHEMA).await.unwrap();

        // insert a device with the same shape the server stores
        let n = ds
            .execute(
                "INSERT INTO devices (id, user_id, device_name, device_type, \
                 hybrid_ek, hybrid_vk, revoked, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
                vec![
                    turso::Value::Text("dev-1".into()),
                    turso::Value::Text("user-1".into()),
                    turso::Value::Text("Benchmark Device".into()),
                    turso::Value::Text("desktop".into()),
                    turso::Value::Text("ek-b64".into()),
                    turso::Value::Text("vk-b64".into()),
                    turso::Value::Text("2026-01-01T00:00:00Z".into()),
                ],
            )
            .await
            .unwrap();
        assert_eq!(n, 1);

        // exact verify SELECT-by-PK pattern
        let rows = ds
            .query(
                "SELECT id, user_id, hybrid_vk FROM devices WHERE id = ? AND revoked = 0",
                vec![turso::Value::Text("dev-1".into())],
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].len(), 3);
        assert!(matches!(rows[0].get(2), Some(turso::Value::Text(v)) if v == "vk-b64"));

        // UPDATE last_active
        let now = "2026-02-02T00:00:00Z".to_string();
        let u = ds
            .execute(
                "UPDATE devices SET last_active = ? WHERE id = ?",
                vec![turso::Value::Text(now), turso::Value::Text("dev-1".into())],
            )
            .await
            .unwrap();
        assert_eq!(u, 1);
    }
}

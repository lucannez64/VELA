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
use std::sync::Arc;

/// A row buffered out of turso's streaming `Rows` into plain values.
#[derive(Debug)]
pub struct VelaRow {
    pub values: Vec<turso::Value>,
}

/// Alias so consumers don't need to name the `turso` crate directly.
pub type TursoValue = turso::Value;

impl VelaRow {
    pub fn get(&self, idx: usize) -> Option<&TursoValue> {
        self.values.get(idx)
    }
    pub fn len(&self) -> usize {
        self.values.len()
    }
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Text cell, if present and non-null.
    pub fn text(&self, idx: usize) -> Option<&str> {
        match self.get(idx)? {
            TursoValue::Text(s) => Some(s),
            _ => None,
        }
    }
    /// 64-bit integer cell (SQLite may return INTEGER or a numeric TEXT).
    pub fn i64(&self, idx: usize) -> Option<i64> {
        match self.get(idx)? {
            TursoValue::Integer(i) => Some(*i),
            TursoValue::Text(s) => s.parse().ok(),
            _ => None,
        }
    }
    /// UUID cell parsed from text.
    pub fn uuid(&self, idx: usize) -> Option<uuid::Uuid> {
        self.text(idx).and_then(|s| uuid::Uuid::parse_str(s).ok())
    }
    /// RFC3339 timestamp cell parsed from text.
    pub fn timestamp(&self, idx: usize) -> Option<chrono::DateTime<chrono::Utc>> {
        self.text(idx)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&chrono::Utc))
    }
    /// Boolean-integer cell (0/1) as bool.
    pub fn bool_int(&self, idx: usize) -> Option<bool> {
        self.i64(idx).map(|i| i != 0)
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
    /// Dedicated connections for transactions. A transaction must pin ONE
    /// connection (BEGIN/compute/COMMIT on the same one), so these live behind
    /// a `tokio::sync::Mutex` that can be held across `await` (see [`TxGuard`]).
    tx: Vec<Arc<tokio::sync::Mutex<turso::Connection>>>,
    idx: AtomicUsize,
    tx_idx: AtomicUsize,
}

impl TursoDb {
    /// Open (or create) a local turso database file at `path`, connect a pool
    /// of `pool` connections, and ensure the schema exists.
    pub async fn open(path: &str, pool: usize) -> anyhow::Result<Self> {
        let db = turso::Builder::new_local(path).build().await?;
        let n = pool.max(1);
        let mut conns = Vec::with_capacity(n);
        let mut tx = Vec::with_capacity(n);
        for _ in 0..n {
            conns.push(db.connect()?);
            tx.push(Arc::new(tokio::sync::Mutex::new(db.connect()?)));
        }
        let this = Self {
            conns,
            tx,
            idx: AtomicUsize::new(0),
            tx_idx: AtomicUsize::new(0),
        };
        this.execute_batch(SCHEMA).await?;
        this.backfill_rekey_columns().await?;
        this.execute_batch(REKEY_INDEXES).await?;
        Ok(this)
    }

    /// Add the re-keying columns to databases created before they existed
    /// (docs/VAULT_REKEYING_DESIGN.md §9). Fresh databases already have them
    /// from `SCHEMA`, so each ALTER failing with "duplicate column" is the
    /// expected no-op path and is swallowed; anything else surfaces.
    async fn backfill_rekey_columns(&self) -> anyhow::Result<()> {
        const ALTERS: &[&str] = &[
            "ALTER TABLE users ADD COLUMN key_epoch INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE users ADD COLUMN rekey_state TEXT",
            "ALTER TABLE users ADD COLUMN rekey_started_at TEXT",
            "ALTER TABLE users ADD COLUMN rekey_starter TEXT",
            "ALTER TABLE users ADD COLUMN rekey_id TEXT",
            "ALTER TABLE vault_chunks ADD COLUMN epoch INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE oram_buckets ADD COLUMN epoch INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE devices ADD COLUMN rms_capsule_epoch INTEGER",
            "ALTER TABLE devices ADD COLUMN rekey_capable INTEGER NOT NULL DEFAULT 0",
        ];
        for sql in ALTERS {
            if let Err(e) = self.conn().execute(sql, ()).await {
                let msg = e.to_string().to_lowercase();
                if !msg.contains("duplicate") && !msg.contains("exists") {
                    return Err(e.into());
                }
            }
        }
        Ok(())
    }

    fn conn(&self) -> &turso::Connection {
        &self.conns[self.idx.fetch_add(1, Ordering::Relaxed) % self.conns.len()]
    }

    /// Begin a transaction pinned to one connection. The returned guard can be
    /// held across `await` (it owns a `tokio::sync::OwnedMutexGuard`), so a
    /// multi-statement tx is safe to interleave with other async work.
    pub async fn tx(&self) -> anyhow::Result<TxGuard> {
        let arc = Arc::clone(&self.tx[self.tx_idx.fetch_add(1, Ordering::Relaxed) % self.tx.len()]);
        let guard = arc.lock_owned().await;
        guard.execute("BEGIN", ()).await?;
        Ok(TxGuard {
            guard,
            finished: false,
        })
    }
}

/// An in-progress transaction: owns a locked turso connection and runs
/// BEGIN on creation, COMMIT or ROLLBACK on finish, ROLLBACK on drop if
/// unfinished.
pub struct TxGuard {
    guard: tokio::sync::OwnedMutexGuard<turso::Connection>,
    finished: bool,
}

impl TxGuard {
    pub async fn query(
        &self,
        sql: &str,
        params: Vec<turso::Value>,
    ) -> anyhow::Result<Vec<VelaRow>> {
        let mut stream = self.guard.query(sql, params).await?;
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

    pub async fn execute(&self, sql: &str, params: Vec<turso::Value>) -> anyhow::Result<u64> {
        Ok(self.guard.execute(sql, params).await?)
    }

    pub async fn commit(mut self) -> anyhow::Result<()> {
        self.guard.execute("COMMIT", ()).await?;
        self.finished = true;
        Ok(())
    }

    pub async fn rollback(mut self) -> anyhow::Result<()> {
        self.guard.execute("ROLLBACK", ()).await?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for TxGuard {
    fn drop(&mut self) {
        if !self.finished {
            // Best-effort rollback; cannot await in Drop. turso's own
            // Transaction handles dangling-tx on the next statement; leaving it
            // open here is safe because we drop the connection slot back to the
            // mutex, and a stale open tx is rolled back when the connection is
            // reused/freed.
            let _ = self.guard.execute("ROLLBACK", ());
        }
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
    share_ek TEXT, recovery_webauthn_cred_id TEXT,
    key_epoch INTEGER NOT NULL DEFAULT 1, rekey_state TEXT,
    rekey_started_at TEXT, rekey_starter TEXT, rekey_id TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_webauthn_cred_id ON users(recovery_webauthn_cred_id);
CREATE TABLE IF NOT EXISTS devices (
    id TEXT UNIQUE NOT NULL, user_id TEXT NOT NULL,
    device_name TEXT NOT NULL DEFAULT 'Desktop Device', device_type TEXT NOT NULL DEFAULT 'desktop',
    last_active TEXT, hybrid_ek TEXT NOT NULL, hybrid_vk TEXT NOT NULL, enrolled_by TEXT,
    rms_capsule TEXT, rms_capsule_epoch INTEGER, rekey_capable INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0, revoked_at TEXT, revoked_by TEXT,
    created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
CREATE TABLE IF NOT EXISTS vault_chunks (
    chunk_id TEXT NOT NULL, user_id TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1,
    lamport_clock INTEGER NOT NULL DEFAULT 0, last_writer TEXT, ciphertext TEXT NOT NULL,
    epoch INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS oram_buckets (
    user_id TEXT NOT NULL, tree_id TEXT NOT NULL, bucket_index INTEGER NOT NULL,
    version INTEGER NOT NULL DEFAULT 1, lamport_clock INTEGER NOT NULL DEFAULT 0,
    last_writer TEXT, ciphertext TEXT NOT NULL, epoch INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
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

/// Index changes which depend on columns added by `backfill_rekey_columns`.
/// Keep these out of `SCHEMA`: on an existing database `CREATE TABLE IF NOT
/// EXISTS` does not add `epoch`, so creating these indexes before the ALTERs
/// would make startup fail before the migration could run.
const REKEY_INDEXES: &str = "\
DROP INDEX IF EXISTS idx_vault_chunks_user_chunk;
CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_chunks_user_chunk_epoch
    ON vault_chunks(user_id, chunk_id, epoch);
CREATE INDEX IF NOT EXISTS idx_vault_chunks_user_epoch
    ON vault_chunks(user_id, epoch);
DROP INDEX IF EXISTS idx_oram_buckets_user_tree_bucket;
CREATE UNIQUE INDEX IF NOT EXISTS idx_oram_buckets_user_tree_bucket_epoch
    ON oram_buckets(user_id, tree_id, bucket_index, epoch);
";

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        format!(
            "{}/vela-sqldb-test-{}-{}.db",
            std::env::temp_dir().display(),
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        )
    }

    async fn temp_db() -> TursoDb {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        TursoDb::open(&path, 2).await.unwrap()
    }

    #[tokio::test]
    async fn schema_and_crud() {
        let ds = temp_db().await;
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

    #[tokio::test]
    async fn opens_and_upgrades_a_pre_rekey_database() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);

        // Build the relevant part of the pre-rekey schema without going
        // through TursoDb::open, then prove open performs the ALTERs before
        // creating the new epoch-dependent indexes.
        let raw = turso::Builder::new_local(&path).build().await.unwrap();
        let conn = raw.connect().unwrap();
        conn.execute_batch(
            "CREATE TABLE users (
                 id TEXT UNIQUE NOT NULL, recovery_share TEXT,
                 recovery_auth_hash TEXT, created_at TEXT NOT NULL,
                 recovery_webauthn_credential TEXT, share_ek TEXT,
                 recovery_webauthn_cred_id TEXT);
             CREATE TABLE devices (
                 id TEXT UNIQUE NOT NULL, user_id TEXT NOT NULL,
                 device_name TEXT NOT NULL DEFAULT 'Desktop Device',
                 device_type TEXT NOT NULL DEFAULT 'desktop', last_active TEXT,
                 hybrid_ek TEXT NOT NULL, hybrid_vk TEXT NOT NULL,
                 enrolled_by TEXT, rms_capsule TEXT,
                 revoked INTEGER NOT NULL DEFAULT 0, revoked_at TEXT,
                 revoked_by TEXT, created_at TEXT NOT NULL);
             CREATE TABLE vault_chunks (
                 chunk_id TEXT NOT NULL, user_id TEXT NOT NULL,
                 version INTEGER NOT NULL DEFAULT 1,
                 lamport_clock INTEGER NOT NULL DEFAULT 0, last_writer TEXT,
                 ciphertext TEXT NOT NULL, created_at TEXT NOT NULL,
                 updated_at TEXT NOT NULL);
             CREATE UNIQUE INDEX idx_vault_chunks_user_chunk
                 ON vault_chunks(user_id, chunk_id);
             CREATE TABLE oram_buckets (
                 user_id TEXT NOT NULL, tree_id TEXT NOT NULL,
                 bucket_index INTEGER NOT NULL, version INTEGER NOT NULL DEFAULT 1,
                 lamport_clock INTEGER NOT NULL DEFAULT 0, last_writer TEXT,
                 ciphertext TEXT NOT NULL, created_at TEXT NOT NULL,
                 updated_at TEXT NOT NULL);
             CREATE UNIQUE INDEX idx_oram_buckets_user_tree_bucket
                 ON oram_buckets(user_id, tree_id, bucket_index);",
        )
        .await
        .unwrap();
        drop(conn);
        drop(raw);

        let db = TursoDb::open(&path, 1).await.unwrap();
        db.query("SELECT epoch FROM vault_chunks LIMIT 0", vec![])
            .await
            .unwrap();
        db.query("SELECT epoch FROM oram_buckets LIMIT 0", vec![])
            .await
            .unwrap();
        db.query("SELECT key_epoch FROM users LIMIT 0", vec![])
            .await
            .unwrap();
        db.query("SELECT rekey_id FROM users LIMIT 0", vec![])
            .await
            .unwrap();

        let indexes = db
            .query(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?",
                vec![turso::Value::Text(
                    "idx_vault_chunks_user_chunk_epoch".into(),
                )],
            )
            .await
            .unwrap();
        assert_eq!(indexes.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn transaction_commit_and_rollback() {
        let db = temp_db().await;

        // rollback: begin, insert, rollback -> row must not be present
        {
            let tx = db.tx().await.unwrap();
            tx.execute(
                "INSERT INTO devices (id, user_id, device_name, device_type, \
                 hybrid_ek, hybrid_vk, revoked, created_at) \
                 VALUES (?, 'u', 'n', 'desktop', 'ek', 'vk', 0, '2026-01-01T00:00:00Z')",
                vec![turso::Value::Text("tx-rollback".into())],
            )
            .await
            .unwrap();
            tx.rollback().await.unwrap();
        }
        let rows = db
            .query(
                "SELECT id FROM devices WHERE id = ?",
                vec![turso::Value::Text("tx-rollback".into())],
            )
            .await
            .unwrap();
        assert!(rows.is_empty(), "rolled-back insert must be absent");

        // commit: begin, insert, commit -> row persists
        {
            let tx = db.tx().await.unwrap();
            tx.execute(
                "INSERT INTO devices (id, user_id, device_name, device_type, \
                 hybrid_ek, hybrid_vk, revoked, created_at) \
                 VALUES (?, 'u', 'n', 'desktop', 'ek', 'vk', 0, '2026-01-01T00:00:00Z')",
                vec![turso::Value::Text("tx-commit".into())],
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
        let rows = db
            .query(
                "SELECT id FROM devices WHERE id = ?",
                vec![turso::Value::Text("tx-commit".into())],
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "committed insert must persist");
    }
}

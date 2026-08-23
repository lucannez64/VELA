use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use stoolap::{Database, ResultRow, Value};
use uuid::Uuid;

use crate::error::AppError;

pub fn open_and_init(db_path: &str) -> anyhow::Result<Database> {
    let dsn = if db_path == "memory://" {
        db_path.to_string()
    } else if db_path.starts_with("memory://") || db_path.starts_with("file://") {
        db_path.to_string()
    } else {
        if let Some(parent) = std::path::Path::new(db_path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        format!("file://{}", db_path)
    };

    let db = Database::open(&dsn)?;
    init_schema(&db)?;
    Ok(db)
}

fn init_schema(db: &Database) -> anyhow::Result<()> {
    db.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id              TEXT UNIQUE NOT NULL,
            recovery_share  TEXT,
            recovery_auth_hash TEXT,
            created_at      TIMESTAMP NOT NULL,
            recovery_webauthn_credential TEXT,
            key_epoch       INTEGER NOT NULL DEFAULT 1
        )",
        (),
    )?;
    db.execute(
        "CREATE TABLE IF NOT EXISTS devices (
            id          TEXT UNIQUE NOT NULL,
            user_id     TEXT NOT NULL,
            device_name TEXT NOT NULL DEFAULT 'Desktop Device',
            device_type TEXT NOT NULL DEFAULT 'desktop',
            last_active TIMESTAMP,
            hybrid_ek   TEXT NOT NULL,
            hybrid_vk   TEXT NOT NULL,
            enrolled_by TEXT,
            rms_capsule TEXT,
            rms_capsule_epoch INTEGER,
            rekey_capable BOOLEAN NOT NULL DEFAULT FALSE,
            revoked     BOOLEAN NOT NULL DEFAULT FALSE,
            revoked_at  TIMESTAMP,
            revoked_by  TEXT,
            created_at  TIMESTAMP NOT NULL
        )",
        (),
    )?;
    db.execute(
        "CREATE TABLE IF NOT EXISTS vault_chunks (
            chunk_id      TEXT NOT NULL,
            user_id       TEXT NOT NULL,
            version       INTEGER NOT NULL DEFAULT 1,
            lamport_clock INTEGER NOT NULL DEFAULT 0,
            last_writer   TEXT,
            ciphertext    TEXT NOT NULL,
            epoch         INTEGER NOT NULL DEFAULT 1,
            created_at    TIMESTAMP NOT NULL,
            updated_at    TIMESTAMP NOT NULL
        )",
        (),
    )?;
    db.execute(
        "CREATE TABLE IF NOT EXISTS oram_buckets (
            user_id       TEXT NOT NULL,
            tree_id       TEXT NOT NULL,
            bucket_index  INTEGER NOT NULL,
            version       INTEGER NOT NULL DEFAULT 1,
            lamport_clock INTEGER NOT NULL DEFAULT 0,
            last_writer   TEXT,
            ciphertext    TEXT NOT NULL,
            epoch         INTEGER NOT NULL DEFAULT 1,
            created_at    TIMESTAMP NOT NULL,
            updated_at    TIMESTAMP NOT NULL
        )",
        (),
    )?;
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_oram_buckets_user_tree_bucket
         ON oram_buckets(user_id, tree_id, bucket_index)",
        (),
    )?;
    db.execute(
        "CREATE TABLE IF NOT EXISTS share_inbox (
            id                TEXT UNIQUE NOT NULL,
            sender_user_id    TEXT NOT NULL,
            recipient_user_id TEXT NOT NULL,
            capsule           TEXT NOT NULL,
            created_at        TIMESTAMP NOT NULL
        )",
        (),
    )?;
    db.execute(
        "CREATE TABLE IF NOT EXISTS shared_items (
            id                TEXT UNIQUE NOT NULL,
            sender_user_id    TEXT NOT NULL,
            recipient_user_id TEXT NOT NULL,
            capsule           TEXT NOT NULL,
            created_at        TIMESTAMP NOT NULL,
            updated_at        TIMESTAMP NOT NULL,
            revoked           BOOLEAN NOT NULL DEFAULT FALSE
        )",
        (),
    )?;
    let _ = db.execute(
        "ALTER TABLE devices ADD COLUMN device_name TEXT NOT NULL DEFAULT 'Desktop Device'",
        (),
    );
    let _ = db.execute(
        "ALTER TABLE devices ADD COLUMN device_type TEXT NOT NULL DEFAULT 'desktop'",
        (),
    );
    let _ = db.execute("ALTER TABLE devices ADD COLUMN last_active TIMESTAMP", ());
    migrate_devices_schema(db)?;
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id)",
        (),
    )?;
    let _ = db.execute("ALTER TABLE users ADD COLUMN recovery_auth_hash TEXT", ());
    let _ = db.execute(
        "ALTER TABLE users ADD COLUMN recovery_webauthn_credential TEXT",
        (),
    );
    let _ = db.execute("ALTER TABLE users ADD COLUMN share_ek TEXT", ());
    let _ = db.execute(
        "ALTER TABLE users ADD COLUMN recovery_webauthn_cred_id TEXT",
        (),
    );
    // Indexed alongside the credential JSON so cross-account duplicate-passkey
    // checks are a point lookup instead of a full table scan + per-row
    // deserialize. NULLs (no passkey registered) don't collide under UNIQUE.
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_webauthn_cred_id
         ON users(recovery_webauthn_cred_id)",
        (),
    )?;
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_share_inbox_recipient ON share_inbox(recipient_user_id)",
        (),
    )?;
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_share_inbox_created_at ON share_inbox(created_at)",
        (),
    )?;
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_shared_items_sender ON shared_items(sender_user_id, updated_at)",
        (),
    )?;
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_shared_items_recipient ON shared_items(recipient_user_id, updated_at)",
        (),
    )?;
    db.execute(
        "CREATE TABLE IF NOT EXISTS web_sessions (
            id                TEXT UNIQUE NOT NULL,
            user_id           TEXT,
            approver_user_id  TEXT,
            poll_secret_hash  TEXT,
            ephemeral_pk      TEXT NOT NULL,
            web_vk            TEXT,
            link_nonce        TEXT NOT NULL,
            mode              TEXT,
            status            TEXT NOT NULL,
            capsule           TEXT,
            approved_by       TEXT,
            created_at        TIMESTAMP NOT NULL,
            expires_at        TIMESTAMP
        )",
        (),
    )?;
    // The account the browser committed to at `start`; only that user may read
    // the session keys or grant it. Pre-existing pending rows have NULL here and
    // fail closed (they live at most 5 minutes).
    let _ = db.execute("ALTER TABLE web_sessions ADD COLUMN approver_user_id TEXT", ());
    // SHA-256 of the secret only the browser that started the session holds; it
    // must present the secret to collect the one-shot capsule. NULL on rows
    // written before the check existed, which fail closed.
    let _ = db.execute("ALTER TABLE web_sessions ADD COLUMN poll_secret_hash TEXT", ());
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_web_sessions_status ON web_sessions(status)",
        (),
    )?;
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_web_sessions_expires ON web_sessions(expires_at)",
        (),
    )?;
    migrate_vault_chunks_schema(db)?;
    migrate_rekey_schema(db)?;
    Ok(())
}

/// Vault re-keying schema (docs/VAULT_REKEYING_DESIGN.md §9): per-account key
/// epoch + rotation state, and an epoch column on both ciphertext tables.
///
/// Tolerant ALTERs follow the file's existing pattern: a fresh database already
/// has the columns from `CREATE TABLE` (the `let _ =` absorbs the duplicate-
/// column error), an upgraded one gets them here.
fn migrate_rekey_schema(db: &Database) -> anyhow::Result<()> {
    const ALTERS: &[&str] = &[
        "ALTER TABLE users ADD COLUMN key_epoch INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE users ADD COLUMN rekey_state TEXT",
        "ALTER TABLE users ADD COLUMN rekey_started_at TIMESTAMP",
        "ALTER TABLE users ADD COLUMN rekey_starter TEXT",
        "ALTER TABLE users ADD COLUMN rekey_id TEXT",
        "ALTER TABLE vault_chunks ADD COLUMN epoch INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE oram_buckets ADD COLUMN epoch INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE devices ADD COLUMN rms_capsule_epoch INTEGER",
        "ALTER TABLE devices ADD COLUMN rekey_capable BOOLEAN NOT NULL DEFAULT FALSE",
    ];
    for sql in ALTERS {
        if let Err(e) = db.execute(sql, ()) {
            let message = e.to_string().to_lowercase();
            if !message.contains("duplicate") && !message.contains("exists") {
                return Err(e.into());
            }
        }
    }

    // Shadow rows during a rotation coexist with the current-epoch rows for the
    // same chunk, so uniqueness moves from (user, chunk) to (user, chunk,
    // epoch). Commit sweeps the superseded rows; see the design doc, §5.
    let _ = db.execute("DROP INDEX IF EXISTS idx_vault_chunks_user_chunk", ());
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_chunks_user_chunk_epoch
         ON vault_chunks(user_id, chunk_id, epoch)",
        (),
    )?;
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_vault_chunks_user_epoch
         ON vault_chunks(user_id, epoch)",
        ())?;
    let _ = db.execute("DROP INDEX IF EXISTS idx_oram_buckets_user_tree_bucket", ());
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_oram_buckets_user_tree_bucket_epoch
         ON oram_buckets(user_id, tree_id, bucket_index, epoch)",
        (),
    )?;
    Ok(())
}

fn migrate_vault_chunks_schema(db: &Database) -> anyhow::Result<()> {
    if db
        .query(
            "SELECT version, lamport_clock, last_writer FROM vault_chunks LIMIT 0",
            (),
        )
        .is_ok()
    {
        return Ok(());
    }

    let _ = db.execute("DROP TABLE IF EXISTS vault_chunks_v2", ());
    db.execute(
        "CREATE TABLE vault_chunks_v2 (
            chunk_id      TEXT NOT NULL,
            user_id       TEXT NOT NULL,
            version       INTEGER NOT NULL DEFAULT 1,
            lamport_clock INTEGER NOT NULL DEFAULT 0,
            last_writer   TEXT,
            ciphertext    TEXT NOT NULL,
            epoch         INTEGER NOT NULL DEFAULT 1,
            created_at    TIMESTAMP NOT NULL,
            updated_at    TIMESTAMP NOT NULL
        )",
        (),
    )?;
    db.execute(
        "INSERT INTO vault_chunks_v2
         (chunk_id, user_id, version, lamport_clock, last_writer, ciphertext, created_at, updated_at)
         SELECT chunk_id, user_id, version, lamport_clock, last_writer, ciphertext, created_at, updated_at
         FROM vault_chunks",
        (),
    )?;
    db.execute("DROP TABLE vault_chunks", ())?;
    db.execute("ALTER TABLE vault_chunks_v2 RENAME TO vault_chunks", ())?;
    // Epoch-aware indexes, matching the rekey schema (§5): shadow rows make
    // uniqueness per (user, chunk, epoch), and readers filter by (user,
    // epoch). The legacy names are gone — migrate_rekey_schema only drops
    // them for databases indexed before this file was aligned.
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_chunks_user_chunk_epoch
         ON vault_chunks(user_id, chunk_id, epoch)",
        (),
    )?;
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_vault_chunks_user_epoch
         ON vault_chunks(user_id, epoch)",
        (),
    )?;
    Ok(())
}

fn migrate_devices_schema(db: &Database) -> anyhow::Result<()> {
    if db
        .query("SELECT cyclo_pk FROM devices LIMIT 0", ())
        .is_err()
    {
        return Ok(());
    }

    let _ = db.execute("DROP TABLE IF EXISTS devices_v2", ());
    db.execute(
        "CREATE TABLE devices_v2 (
            id          TEXT UNIQUE NOT NULL,
            user_id     TEXT NOT NULL,
            device_name TEXT NOT NULL DEFAULT 'Desktop Device',
            device_type TEXT NOT NULL DEFAULT 'desktop',
            last_active TIMESTAMP,
            hybrid_ek   TEXT NOT NULL,
            hybrid_vk   TEXT NOT NULL,
            enrolled_by TEXT,
            rms_capsule TEXT,
            rms_capsule_epoch INTEGER,
            rekey_capable BOOLEAN NOT NULL DEFAULT FALSE,
            revoked     BOOLEAN NOT NULL DEFAULT FALSE,
            revoked_at  TIMESTAMP,
            revoked_by  TEXT,
            created_at  TIMESTAMP NOT NULL
        )",
        (),
    )?;
    db.execute(
        "INSERT INTO devices_v2
         (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk,
          enrolled_by, rms_capsule, revoked, revoked_at, revoked_by, created_at)
         SELECT id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk,
                enrolled_by, rms_capsule, revoked, revoked_at, revoked_by, created_at
         FROM devices",
        (),
    )?;
    db.execute("DROP TABLE devices", ())?;
    db.execute("ALTER TABLE devices_v2 RENAME TO devices", ())?;
    Ok(())
}

pub fn encode_b64(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn decode_b64(s: &str) -> Result<Vec<u8>, AppError> {
    B64.decode(s)
        .map_err(|e| AppError::Internal(format!("base64 decode error: {e}")))
}

#[derive(Debug)]
pub struct UserRow {
    pub id: Uuid,
    pub recovery_share: Option<Vec<u8>>,
    pub recovery_auth_hash: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct DeviceRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_name: String,
    pub device_type: String,
    pub last_active: Option<DateTime<Utc>>,
    pub hybrid_ek: Vec<u8>,
    pub hybrid_vk: Vec<u8>,
    pub enrolled_by: Option<Uuid>,
    pub rms_capsule: Option<Vec<u8>>,
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct ChunkManifestRow {
    pub chunk_id: String,
    pub version: i64,
    pub lamport_clock: i64,
    pub last_writer: Option<Uuid>,
}

#[derive(Debug)]
pub struct ChunkRow {
    pub chunk_id: String,
    pub user_id: Uuid,
    pub version: i64,
    pub lamport_clock: i64,
    pub last_writer: Option<Uuid>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub struct SharedItemRow {
    pub id: String,
    pub sender_user_id: Uuid,
    pub recipient_user_id: Uuid,
    pub capsule: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revoked: bool,
}

fn val(row: &ResultRow, idx: usize) -> Result<Value, AppError> {
    row.get::<Value>(idx)
        .map_err(|e| AppError::Internal(e.to_string()))
}

fn uuid_from(row: &ResultRow, idx: usize) -> Result<Uuid, AppError> {
    let v = val(row, idx)?;
    v.as_str()
        .ok_or_else(|| AppError::Internal("expected text for uuid".into()))
        .and_then(|s| {
            Uuid::parse_str(s).map_err(|e| AppError::Internal(format!("uuid parse: {e}")))
        })
}

fn opt_uuid_from(row: &ResultRow, idx: usize) -> Result<Option<Uuid>, AppError> {
    let v = val(row, idx)?;
    if v.is_null() {
        return Ok(None);
    }
    v.as_str()
        .ok_or_else(|| AppError::Internal("expected text".into()))
        .and_then(|s| {
            Uuid::parse_str(s).map_err(|e| AppError::Internal(format!("uuid parse: {e}")))
        })
        .map(Some)
}

fn text_from(row: &ResultRow, idx: usize) -> Result<String, AppError> {
    let v = val(row, idx)?;
    v.as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Internal("expected text".into()))
}

fn opt_text_from(row: &ResultRow, idx: usize) -> Result<Option<String>, AppError> {
    let v = val(row, idx)?;
    if v.is_null() {
        return Ok(None);
    }
    Ok(Some(
        v.as_str()
            .ok_or_else(|| AppError::Internal("expected text".into()))?
            .to_string(),
    ))
}

fn int_from(row: &ResultRow, idx: usize) -> Result<i64, AppError> {
    let v = val(row, idx)?;
    v.as_int64()
        .ok_or_else(|| AppError::Internal("expected integer".into()))
}

fn bool_from(row: &ResultRow, idx: usize) -> Result<bool, AppError> {
    let v = val(row, idx)?;
    v.as_boolean()
        .ok_or_else(|| AppError::Internal("expected boolean".into()))
}

fn ts_from(row: &ResultRow, idx: usize) -> Result<DateTime<Utc>, AppError> {
    let v = val(row, idx)?;
    v.as_timestamp()
        .ok_or_else(|| AppError::Internal("expected timestamp".into()))
}

fn opt_ts_from(row: &ResultRow, idx: usize) -> Result<Option<DateTime<Utc>>, AppError> {
    let v = val(row, idx)?;
    if v.is_null() {
        return Ok(None);
    }
    Ok(v.as_timestamp())
}

pub fn parse_user_row(row: &ResultRow) -> Result<UserRow, AppError> {
    Ok(UserRow {
        id: uuid_from(row, 0)?,
        recovery_share: opt_text_from(row, 1)?.map(|s| decode_b64(&s)).transpose()?,
        recovery_auth_hash: opt_text_from(row, 2)?.map(|s| decode_b64(&s)).transpose()?,
        created_at: ts_from(row, 3)?,
    })
}

pub fn parse_device_row(row: &ResultRow) -> Result<DeviceRow, AppError> {
    Ok(DeviceRow {
        id: uuid_from(row, 0)?,
        user_id: uuid_from(row, 1)?,
        device_name: text_from(row, 2)?,
        device_type: text_from(row, 3)?,
        last_active: opt_ts_from(row, 4)?,
        hybrid_ek: decode_b64(&text_from(row, 5)?)?,
        hybrid_vk: decode_b64(&text_from(row, 6)?)?,
        enrolled_by: opt_uuid_from(row, 7)?,
        rms_capsule: opt_text_from(row, 8)?.map(|s| decode_b64(&s)).transpose()?,
        revoked: bool_from(row, 9)?,
        revoked_at: opt_ts_from(row, 10)?,
        revoked_by: opt_uuid_from(row, 11)?,
        created_at: ts_from(row, 12)?,
    })
}

pub fn parse_chunk_manifest_row(row: &ResultRow) -> Result<ChunkManifestRow, AppError> {
    Ok(ChunkManifestRow {
        chunk_id: text_from(row, 0)?,
        version: int_from(row, 1)?,
        lamport_clock: int_from(row, 2)?,
        last_writer: opt_uuid_from(row, 3)?,
    })
}

pub fn parse_chunk_row(row: &ResultRow) -> Result<ChunkRow, AppError> {
    Ok(ChunkRow {
        chunk_id: text_from(row, 0)?,
        user_id: uuid_from(row, 1)?,
        version: int_from(row, 2)?,
        lamport_clock: int_from(row, 3)?,
        last_writer: opt_uuid_from(row, 4)?,
        ciphertext: decode_b64(&text_from(row, 5)?)?,
    })
}

pub fn parse_shared_item_row(row: &ResultRow) -> Result<SharedItemRow, AppError> {
    Ok(SharedItemRow {
        id: text_from(row, 0)?,
        sender_user_id: uuid_from(row, 1)?,
        recipient_user_id: uuid_from(row, 2)?,
        capsule: decode_b64(&text_from(row, 3)?)?,
        created_at: ts_from(row, 4)?,
        updated_at: ts_from(row, 5)?,
        revoked: bool_from(row, 6)?,
    })
}

pub fn row_val(row: &ResultRow, idx: usize) -> Result<Value, AppError> {
    val(row, idx)
}

// ── turso-backed parsing (migration): read from a buffered VelaRow ────────────
// stoolap's row parsers above read `stoolap::ResultRow`; these read
// `crate::sqldb::VelaRow` (Vec<turso::Value>). Kept separate while endpoints
// are ported one at a time; the two families are ported together at the end.

fn tv_as_str(v: &crate::sqldb::TursoValue) -> Option<&str> {
    match v {
        crate::sqldb::TursoValue::Text(s) => Some(s),
        _ => None,
    }
}

fn tv_as_i64(v: &crate::sqldb::TursoValue) -> Option<i64> {
    match v {
        crate::sqldb::TursoValue::Integer(i) => Some(*i),
        crate::sqldb::TursoValue::Text(s) => s.parse().ok(),
        _ => None,
    }
}

fn tv_as_bool(v: &crate::sqldb::TursoValue) -> Option<bool> {
    tv_as_i64(v).map(|i| i != 0)
}

fn tv_is_null(v: &crate::sqldb::TursoValue) -> bool {
    matches!(v, crate::sqldb::TursoValue::Null)
}

fn turso_uuid(v: &crate::sqldb::TursoValue) -> Option<Uuid> {
    tv_as_str(v).and_then(|s| Uuid::parse_str(s).ok())
}

fn turso_text(v: &crate::sqldb::TursoValue) -> Option<String> {
    tv_as_str(v).map(|s| s.to_string())
}

fn turso_ts(v: &crate::sqldb::TursoValue) -> Option<DateTime<Utc>> {
    tv_as_str(v).and_then(|s| DateTime::parse_from_rfc3339(s).ok()).map(|d| d.with_timezone(&Utc))
}

fn cell<'a>(row: &'a crate::sqldb::VelaRow, idx: usize) -> Result<&'a crate::sqldb::TursoValue, AppError> {
    row.get(idx).ok_or_else(|| AppError::Internal(format!("row missing column {idx}")))
}

/// Parse a `shared_items` row buffered from turso (migration target).
pub fn parse_shared_item_row_turso(row: &crate::sqldb::VelaRow) -> Result<SharedItemRow, AppError> {
    let text = |i: usize| {
        row.text(i)
            .map(String::from)
            .ok_or_else(|| AppError::Internal("missing cell".into()))
    };
    let uuid = |i: usize| {
        row.uuid(i)
            .ok_or_else(|| AppError::Internal("missing/malformed uuid".into()))
    };
    let ts = |i: usize| {
        row.timestamp(i)
            .ok_or_else(|| AppError::Internal("missing/malformed timestamp".into()))
    };
    Ok(SharedItemRow {
        id: text(0)?,
        sender_user_id: uuid(1)?,
        recipient_user_id: uuid(2)?,
        capsule: B64
            .decode(text(3)?)
            .map_err(|e| AppError::Internal(format!("capsule decode: {e}")))?,
        created_at: ts(4)?,
        updated_at: ts(5)?,
        revoked: row.bool_int(6).unwrap_or(false),
    })
}

/// Parse a `devices` row buffered from turso (migration target).
pub fn parse_device_row_turso(row: &crate::sqldb::VelaRow) -> Result<DeviceRow, AppError> {
    Ok(DeviceRow {
        id: turso_uuid(cell(row, 0)?)
            .ok_or_else(|| AppError::Internal("device id missing/malformed".into()))?,
        user_id: turso_uuid(cell(row, 1)?)
            .ok_or_else(|| AppError::Internal("device user_id missing/malformed".into()))?,
        device_name: turso_text(cell(row, 2)?).unwrap_or_default(),
        device_type: turso_text(cell(row, 3)?).unwrap_or_default(),
        last_active: turso_ts(cell(row, 4)?),
        hybrid_ek: B64
            .decode(turso_text(cell(row, 5)?).unwrap_or_default())
            .map_err(|e| AppError::Internal(format!("hybrid_ek decode: {e}")))?,
        hybrid_vk: B64
            .decode(turso_text(cell(row, 6)?).unwrap_or_default())
            .map_err(|e| AppError::Internal(format!("hybrid_vk decode: {e}")))?,
        enrolled_by: turso_uuid(cell(row, 7)?),
        rms_capsule: turso_text(cell(row, 8)?).map(|s| B64.decode(s)).transpose()
            .map_err(|e| AppError::Internal(format!("rms_capsule decode: {e}")))?,
        revoked: tv_as_bool(cell(row, 9)?).unwrap_or(false),
        revoked_at: turso_ts(cell(row, 10)?),
        revoked_by: turso_uuid(cell(row, 11)?),
        created_at: turso_ts(cell(row, 12)?)
            .ok_or_else(|| AppError::Internal("device created_at missing/malformed".into()))?,
    })
}


/// Parse a `vault_chunks` row buffered from turso (migration target).
pub fn parse_chunk_row_turso(row: &crate::sqldb::VelaRow) -> Result<ChunkRow, AppError> {
    let text = |i: usize| {
        row.text(i)
            .map(String::from)
            .ok_or_else(|| AppError::Internal("missing cell".into()))
    };
    let uuid = |i: usize| {
        row.uuid(i)
            .ok_or_else(|| AppError::Internal("missing/malformed uuid".into()))
    };
    Ok(ChunkRow {
        chunk_id: text(0)?,
        user_id: uuid(1)?,
        version: row
            .i64(2)
            .ok_or_else(|| AppError::Internal("missing version".into()))?,
        lamport_clock: row
            .i64(3)
            .ok_or_else(|| AppError::Internal("missing lamport_clock".into()))?,
        last_writer: row.uuid(4),
        ciphertext: B64
            .decode(text(5)?)
            .map_err(|e| AppError::Internal(format!("ciphertext decode: {e}")))?,
    })
}

// ── One-time bootstrap: stoolap -> turso ───────────────────────────────────────
// Migrates an existing stoolap database into an (empty) turso database, so a
// server upgraded to the turso backend serves its pre-existing users/devices/
// vaults/shares/sessions. Idempotent and per-table: a table in turso that
// already has rows is left untouched, so it is safe on restart and never
// clobbers a partially-filled turso DB. Full-scan based (does not trust
// stoolap's COUNT(*), which we measured returning 1 for 10000 rows).

const BOOTSTRAP_TABLES: &[(&str, &[&str])] = &[
    (
        "users",
        &[
            "id", "recovery_share", "recovery_auth_hash", "created_at",
            "recovery_webauthn_credential", "share_ek", "recovery_webauthn_cred_id",
        ],
    ),
    (
        "devices",
        &[
            "id", "user_id", "device_name", "device_type", "last_active",
            "hybrid_ek", "hybrid_vk", "enrolled_by", "rms_capsule", "revoked",
            "revoked_at", "revoked_by", "created_at",
        ],
    ),
    (
        "vault_chunks",
        &[
            "chunk_id", "user_id", "version", "lamport_clock", "last_writer",
            "ciphertext", "created_at", "updated_at",
        ],
    ),
    (
        "oram_buckets",
        &[
            "user_id", "tree_id", "bucket_index", "version", "lamport_clock",
            "last_writer", "ciphertext", "created_at", "updated_at",
        ],
    ),
    (
        "share_inbox",
        &["id", "sender_user_id", "recipient_user_id", "capsule", "created_at"],
    ),
    (
        "shared_items",
        &[
            "id", "sender_user_id", "recipient_user_id", "capsule", "created_at",
            "updated_at", "revoked",
        ],
    ),
    (
        "web_sessions",
        &[
            "id", "user_id", "approver_user_id", "poll_secret_hash", "ephemeral_pk",
            "web_vk", "link_nonce", "mode", "status", "capsule", "approved_by",
            "created_at", "expires_at",
        ],
    ),
];

fn stoolap_to_turso_value(v: &stoolap::Value) -> crate::sqldb::TursoValue {
    use crate::sqldb::TursoValue;
    match v {
        stoolap::Value::Null(_) => TursoValue::Null,
        stoolap::Value::Integer(i) => TursoValue::Integer(*i),
        stoolap::Value::Float(f) => TursoValue::Real(*f),
        stoolap::Value::Text(s) => TursoValue::Text(s.to_string()),
        stoolap::Value::Boolean(b) => TursoValue::Integer(if *b { 1 } else { 0 }),
        stoolap::Value::Timestamp(ts) => TursoValue::Text(ts.to_rfc3339()),
        stoolap::Value::Extension(bytes) => TursoValue::Text(format!("\\x{}", encode_b64(bytes))),
    }
}

/// Copy every non-empty stoolap table into turso (per-table, only where turso
/// is still empty). Returns the total number of rows copied.
pub async fn bootstrap_stoolap_into_turso(
    stoolap: &Database,
    turso: &crate::sqldb::TursoDb,
) -> anyhow::Result<u64> {
    use crate::sqldb::Db as _;
    let mut total = 0u64;
    for (table, cols) in BOOTSTRAP_TABLES {
        let existing = turso
            .query(&format!("SELECT 1 FROM {table} LIMIT 1"), vec![])
            .await?;
        if !existing.is_empty() {
            // turso already has rows for this table; never clobber.
            continue;
        }

        let col_list = cols.join(", ");
        let rows = stoolap
            .query(&format!("SELECT {col_list} FROM {table}"), ())
            .map_err(|e| anyhow::anyhow!("bootstrap read {table}: {e}"))?;

        let placeholders = cols.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
        let table_turso = table.to_string();
        let mut count = 0u64;

        // Whole-table copy in one transaction so a partial failure rolls back
        // and a restart re-attempts cleanly.
        let tx = turso.tx().await?;
        for r in rows {
            let r = r.map_err(|e| anyhow::anyhow!("bootstrap row {table}: {e}"))?;
            let mut params = Vec::with_capacity(cols.len());
            for i in 0..cols.len() {
                let cell = r
                    .get::<stoolap::Value>(i)
                    .map_err(|e| anyhow::anyhow!("bootstrap cell {table}:{i}: {e}"))?;
                params.push(stoolap_to_turso_value(&cell));
            }
            tx.execute(
                &format!("INSERT INTO {table_turso} ({col_list}) VALUES ({placeholders})"),
                params,
            )
            .await
            .map_err(|e| anyhow::anyhow!("bootstrap insert {table}: {e}"))?;
            count += 1;
        }
        tx.commit().await?;

        if count > 0 {
            tracing::info!(table = %table_turso, copied = count, "bootstrap: stoolap rows copied to turso");
            total += count;
        }
    }
    Ok(total)
}

/// Parse a `vault_chunks` manifest row buffered from turso (migration target).
pub fn parse_chunk_manifest_row_turso(row: &crate::sqldb::VelaRow) -> Result<ChunkManifestRow, AppError> {
    Ok(ChunkManifestRow {
        chunk_id: row
            .text(0)
            .map(String::from)
            .ok_or_else(|| AppError::Internal("missing chunk_id".into()))?,
        version: row
            .i64(1)
            .ok_or_else(|| AppError::Internal("missing version".into()))?,
        lamport_clock: row
            .i64(2)
            .ok_or_else(|| AppError::Internal("missing lamport_clock".into()))?,
        last_writer: row.uuid(3),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrades_a_pre_rekey_stoolap_schema_before_creating_epoch_indexes() {
        let db = Database::open(&format!("memory://{}", Uuid::new_v4())).unwrap();
        db.execute(
            "CREATE TABLE vault_chunks (
                chunk_id TEXT NOT NULL, user_id TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                lamport_clock INTEGER NOT NULL DEFAULT 0, last_writer TEXT,
                ciphertext TEXT NOT NULL, created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL
            )",
            (),
        )
        .unwrap();
        db.execute(
            "CREATE UNIQUE INDEX idx_vault_chunks_user_chunk
             ON vault_chunks(user_id, chunk_id)",
            (),
        )
        .unwrap();

        init_schema(&db).expect("epoch columns must be added before epoch indexes");
        db.query("SELECT epoch FROM vault_chunks LIMIT 0", ()).unwrap();
        db.query("SELECT key_epoch, rekey_state, rekey_id FROM users LIMIT 0", ())
            .unwrap();
    }

    #[tokio::test]
    async fn bootstrap_stoolap_into_turso_copies_once_and_is_idempotent() {
        use crate::sqldb::{Db as _, TursoDb};

        let stoolap = open_and_init(&format!("memory://{}", Uuid::new_v4())).unwrap();
        let now = Utc::now().to_rfc3339();
        let user_id = Uuid::new_v4().to_string();
        let device_id = Uuid::new_v4().to_string();
        stoolap
            .execute(
                "INSERT INTO users (id, created_at) VALUES ($1, $2)",
                stoolap::params![user_id.clone(), now.clone()],
            )
            .unwrap();
        stoolap
            .execute(
                "INSERT INTO devices (id, user_id, hybrid_ek, hybrid_vk, revoked, created_at) \
                 VALUES ($1, $2, $3, $4, FALSE, $5)",
                stoolap::params![device_id.clone(), user_id.clone(), "ek".to_string(), "vk".to_string(), now.clone()],
            )
            .unwrap();

        let path = format!(
            "{}/vela-bootstrap-test-{}.db",
            std::env::temp_dir().display(),
            Uuid::new_v4()
        );
        let _ = std::fs::remove_file(&path);
        let turso = TursoDb::open(&path, 2).await.unwrap();

        // First run copies.
        let copied = bootstrap_stoolap_into_turso(&stoolap, &turso).await.unwrap();
        assert!(copied >= 2, "expected >=2 rows copied, got {copied}");

        let devs = turso
            .query(
                "SELECT id FROM devices WHERE id = ? AND revoked = 0",
                vec![crate::sqldb::TursoValue::Text(device_id.clone())],
            )
            .await
            .unwrap();
        assert_eq!(devs.len(), 1, "device should be visible in turso after bootstrap");
        let users = turso
            .query("SELECT id FROM users", vec![])
            .await
            .unwrap();
        assert_eq!(users.len(), 1, "user should be visible in turso after bootstrap");

        // Second run is a no-op (turso already populated).
        let copied_again = bootstrap_stoolap_into_turso(&stoolap, &turso).await.unwrap();
        assert_eq!(copied_again, 0, "bootstrap must be idempotent");

        let _ = std::fs::remove_file(&path);
    }
    #[test]
    fn webauthn_cred_id_unique_index_rejects_cross_account_duplicates() {
        let db = open_and_init("memory://").unwrap();
        let now = Utc::now().to_rfc3339();
        let user_a = Uuid::new_v4().to_string();
        let user_b = Uuid::new_v4().to_string();
        let user_c = Uuid::new_v4().to_string();
        for id in [&user_a, &user_b, &user_c] {
            db.execute(
                "INSERT INTO users (id, created_at) VALUES ($1, $2)",
                stoolap::params![id.clone(), now.clone()],
            )
            .unwrap();
        }

        db.execute(
            "UPDATE users SET recovery_webauthn_cred_id = $1 WHERE id = $2",
            stoolap::params!["cred-abc".to_string(), user_a.clone()],
        )
        .unwrap();

        // Same cred_id for a different user must be rejected by the unique index.
        let err = db
            .execute(
                "UPDATE users SET recovery_webauthn_cred_id = $1 WHERE id = $2",
                stoolap::params!["cred-abc".to_string(), user_b.clone()],
            )
            .unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("unique")
                || err.to_string().to_lowercase().contains("duplicate"),
            "expected a unique-constraint error, got: {err}"
        );

        // user_b and user_c both still have a NULL recovery_webauthn_cred_id —
        // NULLs must not collide under the unique index.
        let rows = db
            .query(
                "SELECT id FROM users WHERE recovery_webauthn_cred_id IS NULL",
                (),
            )
            .unwrap();
        let null_count = rows.into_iter().filter(|r| r.is_ok()).count();
        assert_eq!(null_count, 2);
    }
}

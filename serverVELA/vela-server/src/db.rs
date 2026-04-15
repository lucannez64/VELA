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
            recovery_webauthn_credential TEXT
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
            cyclo_pk    TEXT NOT NULL,
            enrolled_by TEXT,
            rms_capsule TEXT,
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
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_chunks_user_chunk
         ON vault_chunks(user_id, chunk_id)",
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
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id)",
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
    let _ = db.execute("ALTER TABLE users ADD COLUMN recovery_auth_hash TEXT", ());
    let _ = db.execute(
        "ALTER TABLE users ADD COLUMN recovery_webauthn_credential TEXT",
        (),
    );
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_vault_chunks_user_id ON vault_chunks(user_id)",
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
    migrate_vault_chunks_schema(db)?;
    Ok(())
}

fn migrate_vault_chunks_schema(db: &Database) -> anyhow::Result<()> {
    let _ = db.execute("DROP TABLE IF EXISTS vault_chunks_v2", ());
    db.execute(
        "CREATE TABLE vault_chunks_v2 (
            chunk_id      TEXT NOT NULL,
            user_id       TEXT NOT NULL,
            version       INTEGER NOT NULL DEFAULT 1,
            lamport_clock INTEGER NOT NULL DEFAULT 0,
            last_writer   TEXT,
            ciphertext    TEXT NOT NULL,
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
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_chunks_user_chunk
         ON vault_chunks(user_id, chunk_id)",
        (),
    )?;
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_vault_chunks_user_id ON vault_chunks(user_id)",
        (),
    )?;
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
    pub cyclo_pk: Vec<u8>,
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
        cyclo_pk: decode_b64(&text_from(row, 7)?)?,
        enrolled_by: opt_uuid_from(row, 8)?,
        rms_capsule: opt_text_from(row, 9)?.map(|s| decode_b64(&s)).transpose()?,
        revoked: bool_from(row, 10)?,
        revoked_at: opt_ts_from(row, 11)?,
        revoked_by: opt_uuid_from(row, 12)?,
        created_at: ts_from(row, 13)?,
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

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use stoolap::{params, Database, ResultRow};
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
            id         TEXT PRIMARY KEY,
            recovery_share TEXT,
            recovery_auth_hash TEXT,
            created_at TIMESTAMP NOT NULL
        )",
        (),
    )?;

    db.execute(
        "CREATE TABLE IF NOT EXISTS devices (
            id          TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL,
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
            chunk_id      TEXT PRIMARY KEY,
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
        "CREATE TABLE IF NOT EXISTS share_inbox (
            id                TEXT PRIMARY KEY,
            sender_user_id    TEXT NOT NULL,
            recipient_user_id TEXT NOT NULL,
            capsule           TEXT NOT NULL,
            created_at        TIMESTAMP NOT NULL
        )",
        (),
    )?;

    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id)",
        (),
    )?;
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

    Ok(())
}

pub fn encode_b64(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn decode_b64(s: &str) -> Result<Vec<u8>, AppError> {
    B64.decode(s)
        .map_err(|e| AppError::Internal(format!("base64 decode error: {e}")))
}

// ─── Row types ────────────────────────────────────────────────────────────────

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
    pub chunk_id: Uuid,
    pub version: i64,
    pub lamport_clock: i64,
    pub last_writer: Option<Uuid>,
}

#[derive(Debug)]
pub struct ChunkRow {
    pub chunk_id: Uuid,
    pub user_id: Uuid,
    pub version: i64,
    pub lamport_clock: i64,
    pub last_writer: Option<Uuid>,
    pub ciphertext: Vec<u8>,
}

// ─── Row parsers ──────────────────────────────────────────────────────────────

pub fn parse_user_row(row: &ResultRow) -> Result<UserRow, AppError> {
    let id_str: String = row.get("id").map_err(db_err)?;
    let recovery_share_str: Option<String> = row.get("recovery_share").map_err(db_err)?;
    let recovery_auth_hash_str: Option<String> = row.get("recovery_auth_hash").map_err(db_err)?;
    let created_at: DateTime<Utc> = row.get("created_at").map_err(db_err)?;

    Ok(UserRow {
        id: Uuid::parse_str(&id_str).map_err(|e| AppError::Internal(format!("uuid parse: {e}")))?,
        recovery_share: recovery_share_str.map(|s| decode_b64(&s)).transpose()?,
        recovery_auth_hash: recovery_auth_hash_str.map(|s| decode_b64(&s)).transpose()?,
        created_at,
    })
}

pub fn parse_device_row(row: &ResultRow) -> Result<DeviceRow, AppError> {
    let id_str: String = row.get("id").map_err(db_err)?;
    let user_id_str: String = row.get("user_id").map_err(db_err)?;
    let hybrid_ek_str: String = row.get("hybrid_ek").map_err(db_err)?;
    let hybrid_vk_str: String = row.get("hybrid_vk").map_err(db_err)?;
    let cyclo_pk_str: String = row.get("cyclo_pk").map_err(db_err)?;
    let enrolled_by_str: Option<String> = row.get("enrolled_by").map_err(db_err)?;
    let rms_capsule_str: Option<String> = row.get("rms_capsule").map_err(db_err)?;
    let revoked: bool = row.get("revoked").map_err(db_err)?;
    let revoked_at: Option<DateTime<Utc>> = row.get("revoked_at").map_err(db_err)?;
    let revoked_by_str: Option<String> = row.get("revoked_by").map_err(db_err)?;
    let created_at: DateTime<Utc> = row.get("created_at").map_err(db_err)?;

    Ok(DeviceRow {
        id: Uuid::parse_str(&id_str).map_err(|e| AppError::Internal(format!("uuid parse: {e}")))?,
        user_id: Uuid::parse_str(&user_id_str)
            .map_err(|e| AppError::Internal(format!("uuid parse: {e}")))?,
        hybrid_ek: decode_b64(&hybrid_ek_str)?,
        hybrid_vk: decode_b64(&hybrid_vk_str)?,
        cyclo_pk: decode_b64(&cyclo_pk_str)?,
        enrolled_by: enrolled_by_str
            .map(|s| {
                Uuid::parse_str(&s).map_err(|e| AppError::Internal(format!("uuid parse: {e}")))
            })
            .transpose()?,
        rms_capsule: rms_capsule_str.map(|s| decode_b64(&s)).transpose()?,
        revoked,
        revoked_at,
        revoked_by: revoked_by_str
            .map(|s| {
                Uuid::parse_str(&s).map_err(|e| AppError::Internal(format!("uuid parse: {e}")))
            })
            .transpose()?,
        created_at,
    })
}

pub fn parse_chunk_manifest_row(row: &ResultRow) -> Result<ChunkManifestRow, AppError> {
    let chunk_id_str: String = row.get("chunk_id").map_err(db_err)?;
    let version: i64 = row.get("version").map_err(db_err)?;
    let lamport_clock: i64 = row.get("lamport_clock").map_err(db_err)?;
    let last_writer_str: Option<String> = row.get("last_writer").map_err(db_err)?;

    Ok(ChunkManifestRow {
        chunk_id: Uuid::parse_str(&chunk_id_str)
            .map_err(|e| AppError::Internal(format!("uuid parse: {e}")))?,
        version,
        lamport_clock,
        last_writer: last_writer_str
            .map(|s| {
                Uuid::parse_str(&s).map_err(|e| AppError::Internal(format!("uuid parse: {e}")))
            })
            .transpose()?,
    })
}

pub fn parse_chunk_row(row: &ResultRow) -> Result<ChunkRow, AppError> {
    let chunk_id_str: String = row.get("chunk_id").map_err(db_err)?;
    let user_id_str: String = row.get("user_id").map_err(db_err)?;
    let version: i64 = row.get("version").map_err(db_err)?;
    let lamport_clock: i64 = row.get("lamport_clock").map_err(db_err)?;
    let last_writer_str: Option<String> = row.get("last_writer").map_err(db_err)?;
    let ciphertext_str: String = row.get("ciphertext").map_err(db_err)?;

    Ok(ChunkRow {
        chunk_id: Uuid::parse_str(&chunk_id_str)
            .map_err(|e| AppError::Internal(format!("uuid parse: {e}")))?,
        user_id: Uuid::parse_str(&user_id_str)
            .map_err(|e| AppError::Internal(format!("uuid parse: {e}")))?,
        version,
        lamport_clock,
        last_writer: last_writer_str
            .map(|s| {
                Uuid::parse_str(&s).map_err(|e| AppError::Internal(format!("uuid parse: {e}")))
            })
            .transpose()?,
        ciphertext: decode_b64(&ciphertext_str)?,
    })
}

fn db_err(e: stoolap::Error) -> AppError {
    AppError::Internal(e.to_string())
}

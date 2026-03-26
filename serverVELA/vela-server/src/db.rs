//! Database helpers — pool construction and typed row structs.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, postgres::PgPoolOptions};
use uuid::Uuid;

pub async fn connect(url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(url)
        .await?;
    Ok(pool)
}

/// Run all pending SQLx migrations from the `migrations/` directory.
pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

// ─── Row types ────────────────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
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

#[derive(Debug, sqlx::FromRow)]
pub struct ChunkManifestRow {
    pub chunk_id: Uuid,
    pub version: i64,
    pub lamport_clock: i64,
    pub last_writer: Option<Uuid>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct ChunkRow {
    pub chunk_id: Uuid,
    pub user_id: Uuid,
    pub version: i64,
    pub lamport_clock: i64,
    pub last_writer: Option<Uuid>,
    pub ciphertext: Vec<u8>,
}

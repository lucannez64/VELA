//! Server configuration loaded from environment variables (`.env` supported).

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

/// Runtime configuration for vela-server.
#[derive(Clone, Debug)]
pub struct Config {
    /// `HOST:PORT` the server listens on.  Default: `0.0.0.0:8443`.
    pub listen_addr: String,

    /// PostgreSQL connection URL, e.g. `postgres://vela:secret@localhost/vela`.
    pub database_url: String,

    /// Redis connection URL, e.g. `redis://localhost:6379`.
    pub redis_url: String,

    /// Ed25519 secret key for PASETO v4 public tokens.
    /// Stored as standard base64 (64 raw bytes: 32-byte seed ‖ 32-byte pubkey).
    pub paseto_secret_key: Vec<u8>,

    /// Ed25519 public key for PASETO v4 public tokens (32 bytes, derived from
    /// paseto_secret_key if not given explicitly).
    pub paseto_public_key: Vec<u8>,

    /// Maximum request body size in bytes.  Default: 2 MiB.
    pub max_body_bytes: usize,

    /// Max vault chunk size accepted by PUT /vault/chunk/{id}.  Default: 1 MiB.
    pub max_chunk_bytes: usize,
}

impl Config {
    /// Load configuration from the process environment.
    /// Call `dotenvy::dotenv()` beforehand to source a `.env` file.
    pub fn from_env() -> Result<Self> {
        let database_url = std::env::var("DATABASE_URL")
            .context("DATABASE_URL not set")?;
        let redis_url = std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let listen_addr = std::env::var("LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8443".into());

        let (sk_bytes, pk_bytes) = load_or_generate_paseto_key()?;

        let max_body_bytes = std::env::var("MAX_BODY_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2 * 1024 * 1024); // 2 MiB

        let max_chunk_bytes = std::env::var("MAX_CHUNK_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1024 * 1024); // 1 MiB

        Ok(Self {
            listen_addr,
            database_url,
            redis_url,
            paseto_secret_key: sk_bytes,
            paseto_public_key: pk_bytes,
            max_body_bytes,
            max_chunk_bytes,
        })
    }
}

/// Load the PASETO Ed25519 keypair from `PASETO_SECRET_KEY` (base64-encoded
/// 64-byte value) or generate a fresh one and print instructions.
///
/// Returns `(secret_key_bytes_64, public_key_bytes_32)`.
fn load_or_generate_paseto_key() -> Result<(Vec<u8>, Vec<u8>)> {
    use pasetors::keys::{AsymmetricKeyPair, Generate};
    use pasetors::version4::V4;

    if let Ok(b64) = std::env::var("PASETO_SECRET_KEY") {
        let raw = B64.decode(b64.trim()).context("PASETO_SECRET_KEY is not valid base64")?;
        anyhow::ensure!(
            raw.len() == 64,
            "PASETO_SECRET_KEY must be 64 bytes (got {})",
            raw.len()
        );
        let pk = raw[32..].to_vec();
        return Ok((raw, pk));
    }

    // No key configured — generate one and log it so the operator can persist it.
    tracing::warn!(
        "PASETO_SECRET_KEY not set — generating an ephemeral keypair. \
         Tokens will be invalidated on restart. \
         Set PASETO_SECRET_KEY=<base64> to persist sessions across restarts."
    );

    let kp = AsymmetricKeyPair::<V4>::generate()
        .map_err(|e| anyhow::anyhow!("PASETO key generation failed: {e:?}"))?;
    let sk_bytes = kp.secret.as_bytes().to_vec();
    let pk_bytes = kp.public.as_bytes().to_vec();

    tracing::info!(
        paseto_secret_key = %B64.encode(&sk_bytes),
        "Generated ephemeral PASETO keypair — add to .env to persist"
    );

    Ok((sk_bytes, pk_bytes))
}

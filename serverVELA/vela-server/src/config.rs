use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

#[derive(Clone, Debug)]
pub struct Config {
    pub listen_addr: String,
    pub db_path: String,
    pub sled_path: String,
    pub paseto_secret_key: Vec<u8>,
    pub paseto_public_key: Vec<u8>,
    pub max_body_bytes: usize,
    pub max_chunk_bytes: usize,
    pub cors_origins: Vec<String>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let db_path = std::env::var("DB_PATH").unwrap_or_else(|_| "./data/vela.db".into());
        let sled_path = std::env::var("SLED_PATH").unwrap_or_else(|_| "./data/sled".into());
        let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8443".into());

        let (sk_bytes, pk_bytes) = load_or_generate_paseto_key()?;

        let max_body_bytes = std::env::var("MAX_BODY_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2 * 1024 * 1024);

        let max_chunk_bytes = std::env::var("MAX_CHUNK_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1024 * 1024);

        let cors_origins = std::env::var("CORS_ORIGINS")
            .unwrap_or_else(|_| "*".into())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Ok(Self {
            listen_addr,
            db_path,
            sled_path,
            paseto_secret_key: sk_bytes,
            paseto_public_key: pk_bytes,
            max_body_bytes,
            max_chunk_bytes,
            cors_origins,
        })
    }
}

fn load_or_generate_paseto_key() -> Result<(Vec<u8>, Vec<u8>)> {
    use pasetors::keys::{AsymmetricKeyPair, Generate};
    use pasetors::version4::V4;

    if let Ok(b64) = std::env::var("PASETO_SECRET_KEY") {
        let raw = B64
            .decode(b64.trim())
            .context("PASETO_SECRET_KEY is not valid base64")?;
        anyhow::ensure!(
            raw.len() == 64,
            "PASETO_SECRET_KEY must be 64 bytes (got {})",
            raw.len()
        );
        let pk = raw[32..].to_vec();
        return Ok((raw, pk));
    }

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

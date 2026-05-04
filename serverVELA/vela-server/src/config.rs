use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

#[derive(Clone, Debug)]
pub struct Config {
    pub listen_addr: String,
    pub db_path: String,
    pub sled_path: String,
    pub webauthn_rp_id: String,
    pub webauthn_rp_origin: String,
    pub webauthn_rp_name: String,
    pub paseto_secret_key: Vec<u8>,
    pub paseto_public_key: Vec<u8>,
    pub max_body_bytes: usize,
    pub max_chunk_bytes: usize,
    pub cors_origins: Vec<String>,
    pub allow_wildcard_cors: bool,
    pub allow_insecure_lan: bool,
    pub production: bool,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let production = env_flag("VELA_PRODUCTION") || env_is_production();
        let db_path = std::env::var("DB_PATH").unwrap_or_else(|_| "./data/vela.db".into());
        let sled_path = std::env::var("SLED_PATH").unwrap_or_else(|_| "./data/sled".into());
        let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8443".into());
        let webauthn_rp_id = std::env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".into());
        let webauthn_rp_origin =
            std::env::var("WEBAUTHN_RP_ORIGIN").unwrap_or_else(|_| "http://localhost:1420".into());
        let webauthn_rp_name = std::env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| "VELA".into());

        let allow_insecure_lan = env_flag("ALLOW_INSECURE_LAN");

        if production && webauthn_rp_origin.starts_with("http://") {
            anyhow::ensure!(
                allow_insecure_lan,
                "WEBAUTHN_RP_ORIGIN must use https in production unless ALLOW_INSECURE_LAN=true"
            );
        }

        let (sk_bytes, pk_bytes) = load_paseto_key(production)?;

        let max_body_bytes = std::env::var("MAX_BODY_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2 * 1024 * 1024);

        let max_chunk_bytes = std::env::var("MAX_CHUNK_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1024 * 1024);

        let cors_origins: Vec<String> = std::env::var("CORS_ORIGINS")
            .unwrap_or_else(|_| webauthn_rp_origin.clone())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let allow_wildcard_cors = env_flag("ALLOW_WILDCARD_CORS");

        if production {
            anyhow::ensure!(
                cors_origins.iter().all(|origin| origin != "*"),
                "CORS_ORIGINS='*' is not allowed in production"
            );
        }
        if cors_origins.iter().any(|origin| origin == "*") {
            anyhow::ensure!(
                allow_wildcard_cors,
                "CORS_ORIGINS='*' requires ALLOW_WILDCARD_CORS=true"
            );
        }

        Ok(Self {
            listen_addr,
            db_path,
            sled_path,
            webauthn_rp_id,
            webauthn_rp_origin,
            webauthn_rp_name,
            paseto_secret_key: sk_bytes,
            paseto_public_key: pk_bytes,
            max_body_bytes,
            max_chunk_bytes,
            cors_origins,
            allow_wildcard_cors,
            allow_insecure_lan,
            production,
        })
    }
}

fn load_paseto_key(production: bool) -> Result<(Vec<u8>, Vec<u8>)> {
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

    anyhow::ensure!(
        !production,
        "PASETO_SECRET_KEY must be set when VELA_PRODUCTION=true or VELA_ENV=production"
    );

    tracing::warn!(
        "PASETO_SECRET_KEY not set — generating an ephemeral keypair. \
         Tokens will be invalidated on restart. \
         Set PASETO_SECRET_KEY=<base64> to persist sessions across restarts."
    );

    let kp = AsymmetricKeyPair::<V4>::generate()
        .map_err(|e| anyhow::anyhow!("PASETO key generation failed: {e:?}"))?;
    let sk_bytes = kp.secret.as_bytes().to_vec();
    let pk_bytes = kp.public.as_bytes().to_vec();

    Ok((sk_bytes, pk_bytes))
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn env_is_production() -> bool {
    std::env::var("VELA_ENV")
        .map(|value| value.eq_ignore_ascii_case("production") || value.eq_ignore_ascii_case("prod"))
        .unwrap_or(false)
}

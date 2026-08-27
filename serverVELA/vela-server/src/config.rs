use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use std::net::IpAddr;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct Config {
    pub listen_addr: String,
    pub tls_listen_addr: Option<String>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub http3_enabled: bool,
    pub http3_listen_addr: Option<String>,
    pub http3_alt_svc_max_age: u64,
    pub db_path: String,
    pub sled_path: String,
    pub webauthn_rp_id: String,
    pub webauthn_rp_origin: String,
    pub webauthn_rp_name: String,
    pub paseto_secret_key: Vec<u8>,
    pub paseto_public_key: Vec<u8>,
    pub max_body_bytes: usize,
    pub max_chunk_bytes: usize,
    /// Hard ceiling on registered accounts, or `None` for no ceiling.
    ///
    /// Registration is rate-limited per IP, which bounds one source but not a
    /// botnet: rotating addresses could fill the disk with accounts on a server
    /// whose operator only ever wanted to serve their own household. Unset by
    /// default, because a public deployment should not silently stop accepting
    /// users — this is opt-in for the self-hosted case (audit, server
    /// hardening).
    pub max_accounts: Option<u64>,
    pub cors_origins: Vec<String>,
    pub allow_wildcard_cors: bool,
    pub allow_insecure_lan: bool,
    pub trust_proxy_headers: bool,
    pub trusted_proxy_cidrs: Vec<String>,
    pub production: bool,
    /// Accept legacy v1 (32-byte keyed-hash) possession commitments during
    /// the hybrid redesign migration. A v1 commitment is itself the proof
    /// key, so while this is on, a database reader can forge proofs for any
    /// account still holding a v1 row. Operators should flip it to `false`
    /// (VELA_ALLOW_LEGACY_POSSESSION_V1=0) once all staged commitments are
    /// known to be hybrid v2 — verification then fails closed for v1 rows.
    pub allow_legacy_possession_v1: bool,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let production = env_flag("VELA_PRODUCTION") || env_is_production();
        let data_dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "./data".into());
        let db_path =
            std::env::var("DB_PATH").unwrap_or_else(|_| path_join_string(&data_dir, "vela.db"));
        let sled_path =
            std::env::var("SLED_PATH").unwrap_or_else(|_| path_join_string(&data_dir, "sled"));
        let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8443".into());
        let tls_listen_addr = env_optional("TLS_LISTEN_ADDR");
        let tls_cert_path = env_optional("TLS_CERT_PATH");
        let tls_key_path = env_optional("TLS_KEY_PATH");
        let http3_enabled = env_flag("HTTP3_ENABLED");
        let http3_listen_addr = env_optional("HTTP3_LISTEN_ADDR").or_else(|| {
            if http3_enabled {
                tls_listen_addr.clone()
            } else {
                None
            }
        });
        let http3_alt_svc_max_age = std::env::var("HTTP3_ALT_SVC_MAX_AGE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(86_400);
        let webauthn_rp_id = std::env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".into());
        let webauthn_rp_origin =
            std::env::var("WEBAUTHN_RP_ORIGIN").unwrap_or_else(|_| "http://localhost:1420".into());
        let webauthn_rp_name = std::env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| "VELA".into());

        let allow_insecure_lan = env_flag("ALLOW_INSECURE_LAN");
        let trust_proxy_headers = env_flag("TRUST_PROXY_HEADERS");

        // VELA serves cleartext on LISTEN_ADDR, which must face only a trusted
        // TLS-terminating proxy. That's satisfied when it's bound to loopback
        // (a same-host proxy) OR when TRUST_PROXY_HEADERS is set — the latter
        // covers reverse-proxy / container deployments (Cloudflare Tunnel,
        // Coolify/Docker) where the process must bind the container interface
        // (0.0.0.0) because loopback isn't reachable across network namespaces.
        // Either way, `enforce_https` still rejects any direct cleartext client
        // that isn't a trusted proxy (per TRUSTED_PROXY_CIDRS), so a non-loopback
        // bind never accepts a bearer token in the clear.
        if production
            && !allow_insecure_lan
            && !trust_proxy_headers
            && !listen_addr_is_loopback(&listen_addr)
        {
            anyhow::bail!(
                "LISTEN_ADDR={listen_addr} binds a non-loopback interface in production without \
                 TRUST_PROXY_HEADERS. Either bind loopback (e.g. 127.0.0.1:8443) behind a same-host \
                 proxy, or set TRUST_PROXY_HEADERS=true with TRUSTED_PROXY_CIDRS scoped to your \
                 proxy/container network (Cloudflare Tunnel, Coolify/Docker), or set \
                 ALLOW_INSECURE_LAN=true to override."
            );
        }

        if tls_listen_addr.is_some() || http3_enabled {
            anyhow::ensure!(
                tls_cert_path.is_some() && tls_key_path.is_some(),
                "TLS_CERT_PATH and TLS_KEY_PATH are required when TLS_LISTEN_ADDR is set or HTTP3_ENABLED=true"
            );
        }
        if http3_enabled {
            anyhow::ensure!(
                http3_listen_addr.is_some(),
                "HTTP3_LISTEN_ADDR is required when HTTP3_ENABLED=true unless TLS_LISTEN_ADDR is set"
            );
        }

        // Misconfiguration must never lock the operator out of their own server
        // (e.g. a Coolify redeploy where WEBAUTHN_RP_ORIGIN was never set):
        // degrade passkey recovery with a loud warning instead of refusing to start.
        if production && webauthn_rp_origin.starts_with("http://") && !allow_insecure_lan {
            tracing::warn!(
                origin = %webauthn_rp_origin,
                "WEBAUTHN_RP_ORIGIN uses cleartext http in production — passkey (WebAuthn) \
                 recovery will not work until this is set to your https origin"
            );
        }

        let (sk_bytes, pk_bytes) = load_paseto_key(&data_dir)?;

        let max_body_bytes = std::env::var("MAX_BODY_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2 * 1024 * 1024);

        let max_chunk_bytes = std::env::var("MAX_CHUNK_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1024 * 1024);

        // 0 and empty both read as "no limit", so MAX_ACCOUNTS=0 does not
        // accidentally lock everyone out.
        let max_accounts = std::env::var("MAX_ACCOUNTS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0);

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

        let trusted_proxy_cidrs: Vec<String> = std::env::var("TRUSTED_PROXY_CIDRS")
            .unwrap_or_else(|_| "127.0.0.1/32,::1/128".into())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        for cidr in &trusted_proxy_cidrs {
            validate_proxy_cidr(cidr)?;
        }

        Ok(Self {
            listen_addr,
            tls_listen_addr,
            tls_cert_path,
            tls_key_path,
            http3_enabled,
            http3_listen_addr,
            http3_alt_svc_max_age,
            db_path,
            sled_path,
            webauthn_rp_id,
            webauthn_rp_origin,
            webauthn_rp_name,
            paseto_secret_key: sk_bytes,
            paseto_public_key: pk_bytes,
            max_body_bytes,
            max_chunk_bytes,
            max_accounts,
            cors_origins,
            allow_wildcard_cors,
            allow_insecure_lan,
            trust_proxy_headers,
            trusted_proxy_cidrs,
            production,
            // Migration default: v1 commitments still verify so accounts set
            // up before the hybrid redesign can finish recovery. Operators
            // opt out once migration completes.
            allow_legacy_possession_v1: !env_flag("VELA_ALLOW_LEGACY_POSSESSION_V1_OFF"),
        })
    }
}

fn path_join_string(base: &str, leaf: &str) -> String {
    Path::new(base).join(leaf).to_string_lossy().into_owned()
}

/// Whether `addr` (a `host:port` socket address) binds a loopback interface.
/// Non-parseable or hostname-based addresses are treated as non-loopback so the
/// production guard fails closed.
fn listen_addr_is_loopback(addr: &str) -> bool {
    addr.parse::<std::net::SocketAddr>()
        .map(|s| s.ip().is_loopback())
        .unwrap_or(false)
}

fn env_optional(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Load the PASETO keypair, in priority order:
/// 1. `PASETO_SECRET_KEY` env var (explicit operator configuration), or
/// 2. a key persisted at `{data_dir}/paseto.key` from a previous run, or
/// 3. a freshly generated keypair, persisted to that path (0600) so sessions
///    survive restarts with zero operator action.
///
/// Only if persisting fails (e.g. read-only filesystem) does the server fall
/// back to an ephemeral in-memory key — never refusing to start, so a redeploy
/// can never lock the operator out of an otherwise healthy server.
fn load_paseto_key(data_dir: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    use pasetors::keys::{AsymmetricKeyPair, Generate};
    use pasetors::version4::V4;

    let parse_key = |raw: Vec<u8>, source: &str| -> Result<(Vec<u8>, Vec<u8>)> {
        anyhow::ensure!(
            raw.len() == 64,
            "{source} must be 64 bytes (got {})",
            raw.len()
        );
        let pk = raw[32..].to_vec();
        Ok((raw, pk))
    };

    if let Ok(b64) = std::env::var("PASETO_SECRET_KEY") {
        let raw = B64
            .decode(b64.trim())
            .context("PASETO_SECRET_KEY is not valid base64")?;
        return parse_key(raw, "PASETO_SECRET_KEY");
    }

    let key_path = Path::new(data_dir).join("paseto.key");
    match std::fs::read_to_string(&key_path) {
        Ok(contents) => {
            let raw = B64
                .decode(contents.trim())
                .context(format!("{} is not valid base64", key_path.display()))?;
            return parse_key(raw, "paseto.key");
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            // Unreadable but present — do NOT silently rotate the key (that
            // would invalidate every live session). Fail loudly instead.
            anyhow::bail!("cannot read {}: {e}", key_path.display());
        }
    }

    let kp = AsymmetricKeyPair::<V4>::generate()
        .map_err(|e| anyhow::anyhow!("PASETO key generation failed: {e:?}"))?;
    let sk_bytes = kp.secret.as_bytes().to_vec();
    let pk_bytes = kp.public.as_bytes().to_vec();

    match persist_paseto_key(&key_path, &sk_bytes) {
        Ok(()) => tracing::info!(
            path = %key_path.display(),
            "generated and persisted PASETO keypair (sessions survive restarts)"
        ),
        Err(e) => tracing::warn!(
            path = %key_path.display(),
            error = %e,
            "could not persist PASETO keypair — using an ephemeral key; \
             tokens will be invalidated on restart"
        ),
    }

    Ok((sk_bytes, pk_bytes))
}

/// Write the PASETO secret key to `path` as base64 with owner-only permissions.
fn persist_paseto_key(path: &Path, sk_bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(B64.encode(sk_bytes).as_bytes())?;
    file.sync_all()?;
    Ok(())
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

/// Narrowest CIDR breadth accepted for `TRUSTED_PROXY_CIDRS`.
///
/// /8 still covers a whole private cloud network (10.0.0.0/8), which is the
/// broadest thing a real deployment legitimately needs; /32 for v6 is likewise
/// far wider than any proxy fleet. Below these, "trusted proxy" has stopped
/// meaning anything and X-Forwarded-For becomes attacker-controlled.
const MIN_TRUSTED_PROXY_PREFIX_V4: u8 = 8;
const MIN_TRUSTED_PROXY_PREFIX_V6: u8 = 32;

fn validate_proxy_cidr(cidr: &str) -> Result<()> {
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("TRUSTED_PROXY_CIDRS entry must be CIDR: {cidr}"))?;
    let ip: IpAddr = addr
        .parse()
        .with_context(|| format!("TRUSTED_PROXY_CIDRS has invalid IP: {cidr}"))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("TRUSTED_PROXY_CIDRS has invalid prefix: {cidr}"))?;
    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    anyhow::ensure!(
        prefix <= max_prefix,
        "TRUSTED_PROXY_CIDRS prefix too large for {cidr}"
    );
    // Refuse a range so broad that anyone may forge their own address.
    //
    // This validated syntax only, so `0.0.0.0/0` passed — and that single
    // setting quietly undoes the per-IP keying every rate limit depends on. It
    // is worse than "limits can be evaded": the recovery and web-session budgets
    // are keyed on (ip, target), so an attacker who chooses their own
    // `X-Forwarded-For` can name the *victim's* address and burn exactly the
    // victim's bucket — RT-1 and RT-2 restored in full, with the regression
    // suite still green because it runs against a correctly configured server.
    //
    // A warning in a log would not do. Nobody reads one before shipping, and
    // the failure it precedes is silent. Refusing to start is the only signal
    // that arrives in time.
    //
    // The floor still admits the ranges a real deployment uses: a single
    // proxy (/32), a subnet, or a whole private cloud network like
    // 10.0.0.0/8. What it rejects is the class where "trusted proxy" has
    // stopped meaning anything.
    let min_prefix = match ip {
        IpAddr::V4(_) => MIN_TRUSTED_PROXY_PREFIX_V4,
        IpAddr::V6(_) => MIN_TRUSTED_PROXY_PREFIX_V6,
    };
    anyhow::ensure!(
        prefix >= min_prefix,
        "TRUSTED_PROXY_CIDRS entry {cidr} is too broad: /{prefix} lets {} forge \
         X-Forwarded-For, which makes every per-IP rate limit attacker-controlled \
         (an attacker can spend a victim's budget by claiming the victim's address). \
         Use /{min_prefix} or narrower — the address range of your actual proxies.",
        if prefix == 0 { "anyone" } else { "a large part of the internet" }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An over-broad trusted-proxy range must stop the server, not warn.
    ///
    /// `TRUSTED_PROXY_CIDRS=0.0.0.0/0` makes `X-Forwarded-For` attacker-supplied,
    /// and every per-IP limit is keyed on that value. It does not merely let an
    /// attacker dodge their own budget: the recovery and web-session limits are
    /// keyed on (ip, target), so a forged address spends the *victim's*
    /// allowance — RT-1 and RT-2 in full, against a build whose regression suite
    /// still passes because CI runs it configured correctly.
    #[test]
    fn an_over_broad_trusted_proxy_range_is_refused() {
        for cidr in ["0.0.0.0/0", "0.0.0.0/4", "::/0", "::/16"] {
            let err = validate_proxy_cidr(cidr)
                .expect_err(&format!("{cidr} is broad enough to forge any client address"));
            assert!(
                err.to_string().contains("too broad"),
                "{cidr} should be refused for breadth, got: {err}"
            );
        }
    }

    /// The floor must not break real deployments: a single proxy, a Docker
    /// bridge network, a private cloud range, an IPv6 site prefix.
    #[test]
    fn ordinary_proxy_ranges_are_still_accepted() {
        for cidr in [
            "127.0.0.1/32",
            "::1/128",
            "10.0.0.0/8",
            "172.17.0.0/16",
            "192.168.1.0/24",
            "2001:db8::/48",
        ] {
            validate_proxy_cidr(cidr)
                .unwrap_or_else(|e| panic!("{cidr} is a normal proxy range but was refused: {e}"));
        }
    }

    /// Syntax checks still apply.
    #[test]
    fn malformed_proxy_ranges_are_still_refused() {
        for cidr in ["10.0.0.0", "not-an-ip/24", "10.0.0.0/33", "::1/129"] {
            assert!(validate_proxy_cidr(cidr).is_err(), "{cidr} should be refused");
        }
    }
}

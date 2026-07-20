use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Cursor, Read},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

use crate::data_lock::DataDirLock;

const MAGIC: &[u8; 11] = b"VELA-MIGRAT";
const FORMAT_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const ARGON_M_COST: u32 = 64 * 1024;
const ARGON_T_COST: u32 = 3;
const ARGON_P_COST: u32 = 1;

#[derive(Debug, Clone)]
pub struct ExportOptions {
    pub out: PathBuf,
    pub env_file: PathBuf,
    pub data_dir: PathBuf,
    pub include_secrets: bool,
    pub include_deployment_config: Vec<PathBuf>,
    pub passphrase: PassphraseSource,
}

#[derive(Debug, Clone)]
pub struct ImportOptions {
    pub bundle: PathBuf,
    pub target_data_dir: PathBuf,
    pub target_env_file: PathBuf,
    pub replace: bool,
    pub passphrase: PassphraseSource,
}

#[derive(Debug, Clone)]
pub struct InspectOptions {
    pub bundle: PathBuf,
    pub passphrase: PassphraseSource,
}

#[derive(Debug, Clone)]
pub enum PassphraseSource {
    Prompt,
    Env(String),
    Value(String),
}

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    format: String,
    format_version: u8,
    created_at: String,
    source: SourceManifest,
    storage: StorageManifest,
    identity: IdentityManifest,
    deployment_config: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SourceManifest {
    server_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct StorageManifest {
    db_relative_path: String,
    sled_relative_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdentityManifest {
    webauthn_rp_id: Option<String>,
    webauthn_rp_origin: Option<String>,
    webauthn_rp_name: Option<String>,
    cors_origins: Option<String>,
    paseto_public_key_b64: Option<String>,
    includes_secret_key: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Checksums {
    algorithm: String,
    files: BTreeMap<String, String>,
}

pub fn export_bundle(options: ExportOptions) -> Result<()> {
    let passphrase = load_passphrase(&options.passphrase, true)?;
    let env = read_env_file(&options.env_file)?;
    let _lock = DataDirLock::try_acquire(&options.data_dir)?;

    let db_path = options.data_dir.join("vela.db");
    let sled_path = options.data_dir.join("sled");
    // stoolap stores `vela.db` as a directory; older/embedded modes may use a
    // single file. Accept either.
    ensure_exists(&db_path, "database")?;
    ensure_dir(&sled_path, "sled store")?;

    let root = TempDir::new().context("failed to create migration staging dir")?;
    let payload_root = root.path().join("payload");
    fs::create_dir(&payload_root)?;
    let data_root = payload_root.join("data");
    fs::create_dir(&data_root)?;

    copy_path(&db_path, &data_root.join("vela.db"))
        .with_context(|| format!("failed to copy {}", db_path.display()))?;
    copy_dir_all(&sled_path, &data_root.join("sled"))?;

    let identity_env = build_identity_env(&env, options.include_secrets)?;
    write_identity_env(&payload_root.join("identity.env"), &identity_env)?;

    let mut deployment_entries = Vec::new();
    if !options.include_deployment_config.is_empty() {
        let deploy_root = payload_root.join("deployment");
        fs::create_dir(&deploy_root)?;
        for path in &options.include_deployment_config {
            ensure_file(path, "deployment config")?;
            let name = path
                .file_name()
                .ok_or_else(|| {
                    anyhow!(
                        "deployment config path has no file name: {}",
                        path.display()
                    )
                })?
                .to_string_lossy()
                .to_string();
            let rel = format!("deployment/{name}");
            fs::copy(path, payload_root.join(&rel))
                .with_context(|| format!("failed to copy {}", path.display()))?;
            deployment_entries.push(rel);
        }
    }

    let manifest = Manifest {
        format: "vela.migration.bundle".to_string(),
        format_version: FORMAT_VERSION,
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        source: SourceManifest {
            server_version: env!("CARGO_PKG_VERSION").to_string(),
        },
        storage: StorageManifest {
            db_relative_path: "data/vela.db".to_string(),
            sled_relative_path: "data/sled".to_string(),
        },
        identity: IdentityManifest {
            webauthn_rp_id: env.get("WEBAUTHN_RP_ID").cloned(),
            webauthn_rp_origin: env.get("WEBAUTHN_RP_ORIGIN").cloned(),
            webauthn_rp_name: env.get("WEBAUTHN_RP_NAME").cloned(),
            cors_origins: env.get("CORS_ORIGINS").cloned(),
            paseto_public_key_b64: env
                .get("PASETO_SECRET_KEY")
                .and_then(|secret| paseto_public_key_b64(secret).ok()),
            includes_secret_key: options.include_secrets,
        },
        deployment_config: deployment_entries,
    };
    fs::write(
        payload_root.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;

    let checksums = checksums_for_tree(&payload_root)?;
    fs::write(
        payload_root.join("checksums.json"),
        serde_json::to_vec_pretty(&checksums)?,
    )?;

    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        builder.append_dir_all(".", &payload_root)?;
        builder.finish()?;
    }
    let compressed = zstd::stream::encode_all(Cursor::new(tar_bytes), 10)?;
    let encrypted = encrypt_payload(&passphrase, &compressed)?;

    if let Some(parent) = options.out.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    fs::write(&options.out, encrypted)
        .with_context(|| format!("failed to write {}", options.out.display()))?;
    Ok(())
}

pub fn import_bundle(options: ImportOptions) -> Result<()> {
    let passphrase = load_passphrase(&options.passphrase, false)?;
    let _lock = DataDirLock::try_acquire(&options.target_data_dir)?;

    if options.target_data_dir.exists() && dir_has_payload(&options.target_data_dir)? {
        if !options.replace {
            bail!(
                "target data dir {} is not empty; pass --replace to overwrite",
                options.target_data_dir.display()
            );
        }
        remove_if_exists(&options.target_data_dir.join("vela.db"))?;
        remove_if_exists(&options.target_data_dir.join("sled"))?;
    }

    let payload_root = decrypt_bundle_to_temp(&options.bundle, &passphrase)?;
    verify_payload(payload_root.path())?;

    fs::create_dir_all(&options.target_data_dir)?;
    copy_path(
        &payload_root.path().join("data/vela.db"),
        &options.target_data_dir.join("vela.db"),
    )?;
    copy_dir_all(
        &payload_root.path().join("data/sled"),
        &options.target_data_dir.join("sled"),
    )?;

    if let Some(parent) = options
        .target_env_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let identity = fs::read_to_string(payload_root.path().join("identity.env"))?;
    fs::write(&options.target_env_file, identity)?;
    Ok(())
}

pub fn inspect_bundle(options: InspectOptions) -> Result<String> {
    let passphrase = load_passphrase(&options.passphrase, false)?;
    let payload_root = decrypt_bundle_to_temp(&options.bundle, &passphrase)?;
    verify_payload(payload_root.path())?;
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(payload_root.path().join("manifest.json"))?)?;
    Ok(serde_json::to_string_pretty(&manifest)?)
}

pub fn verify_bundle(options: InspectOptions) -> Result<()> {
    let passphrase = load_passphrase(&options.passphrase, false)?;
    let payload_root = decrypt_bundle_to_temp(&options.bundle, &passphrase)?;
    verify_payload(payload_root.path())
}

fn encrypt_payload(passphrase: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt)
        .map_err(|e| anyhow!("failed to generate migration salt: {e}"))?;
    let key = derive_key(passphrase, &salt)?;
    let ciphertext = vela_crypto::aead::encrypt(&key, payload)
        .map_err(|e| anyhow!("failed to encrypt migration bundle: {e}"))?;
    let mut out = Vec::with_capacity(MAGIC.len() + 1 + SALT_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_bundle_to_temp(bundle: &Path, passphrase: &str) -> Result<TempDir> {
    let raw = fs::read(bundle).with_context(|| format!("failed to read {}", bundle.display()))?;
    if raw.len() <= MAGIC.len() + 1 + SALT_LEN || &raw[..MAGIC.len()] != MAGIC {
        bail!("not a VELA migration bundle");
    }
    let version = raw[MAGIC.len()];
    if version != FORMAT_VERSION {
        bail!("unsupported migration bundle version {version}");
    }
    let salt_start = MAGIC.len() + 1;
    let salt_end = salt_start + SALT_LEN;
    let key = derive_key(passphrase, &raw[salt_start..salt_end])?;
    let plaintext = vela_crypto::aead::decrypt(&key, &raw[salt_end..]).map_err(|_| {
        anyhow!("failed to decrypt migration bundle; wrong passphrase or corrupted bundle")
    })?;
    let tar_bytes = zstd::stream::decode_all(Cursor::new(plaintext.as_slice()))
        .context("failed to decompress migration bundle")?;
    let temp = TempDir::new().context("failed to create import staging dir")?;
    let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
    archive.unpack(temp.path())?;
    Ok(temp)
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(ARGON_M_COST, ARGON_T_COST, ARGON_P_COST, Some(32))
        .map_err(|e| anyhow!("invalid Argon2 parameters: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("failed to derive migration key: {e}"))?;
    Ok(key)
}

fn verify_payload(root: &Path) -> Result<()> {
    ensure_file(&root.join("manifest.json"), "manifest")?;
    ensure_file(&root.join("checksums.json"), "checksums")?;
    ensure_file(&root.join("identity.env"), "identity env")?;
    ensure_exists(&root.join("data/vela.db"), "database")?;
    ensure_dir(&root.join("data/sled"), "sled store")?;
    let checksums: Checksums = serde_json::from_slice(&fs::read(root.join("checksums.json"))?)?;
    let actual = checksums_for_tree(root)?;
    let actual_without_checksum = actual
        .files
        .into_iter()
        .filter(|(path, _)| path != "checksums.json")
        .collect::<BTreeMap<_, _>>();
    let expected_without_checksum = checksums
        .files
        .into_iter()
        .filter(|(path, _)| path != "checksums.json")
        .collect::<BTreeMap<_, _>>();
    if actual_without_checksum != expected_without_checksum {
        bail!("migration bundle checksum verification failed");
    }
    Ok(())
}

fn checksums_for_tree(root: &Path) -> Result<Checksums> {
    let mut files = BTreeMap::new();
    collect_checksums(root, root, &mut files)?;
    Ok(Checksums {
        algorithm: "blake3".to_string(),
        files,
    })
}

fn collect_checksums(root: &Path, dir: &Path, files: &mut BTreeMap<String, String>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_checksums(root, &path, files)?;
        } else if path.is_file() {
            let rel = path
                .strip_prefix(root)?
                .to_string_lossy()
                .replace('\\', "/");
            let mut hasher = blake3::Hasher::new();
            let mut file = File::open(&path)?;
            let mut buf = [0u8; 64 * 1024];
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            files.insert(rel, hasher.finalize().to_hex().to_string());
        }
    }
    Ok(())
}

/// Write identity.env with owner-only permissions: it may carry the PASETO
/// secret, so it must never be created world/group-readable by umask.
fn write_identity_env(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn build_identity_env(env: &BTreeMap<String, String>, include_secrets: bool) -> Result<String> {
    let mut out = String::new();
    out.push_str(
        "# Restored VELA server identity. Review machine-specific settings before start.\n",
    );
    if include_secrets {
        let secret = env
            .get("PASETO_SECRET_KEY")
            .ok_or_else(|| anyhow!("--include-secrets requires PASETO_SECRET_KEY in --env-file"))?;
        validate_paseto_secret(secret)?;
        push_env(&mut out, "PASETO_SECRET_KEY", secret);
    }
    for key in [
        "WEBAUTHN_RP_ID",
        "WEBAUTHN_RP_ORIGIN",
        "WEBAUTHN_RP_NAME",
        "CORS_ORIGINS",
        "TRUST_PROXY_HEADERS",
        "TRUSTED_PROXY_CIDRS",
    ] {
        if let Some(value) = env.get(key) {
            push_env(&mut out, key, value);
        }
    }
    out.push_str("DATA_DIR=/var/lib/vela\n");
    out.push_str("LISTEN_ADDR=127.0.0.1:8443\n");
    Ok(out)
}

fn push_env(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push('=');
    out.push_str(value);
    out.push('\n');
}

fn read_env_file(path: &Path) -> Result<BTreeMap<String, String>> {
    let iter = dotenvy::from_path_iter(path)
        .with_context(|| format!("failed to read env file {}", path.display()))?;
    let mut env = BTreeMap::new();
    for item in iter {
        let (key, value) = item?;
        env.insert(key, value);
    }
    Ok(env)
}

fn paseto_public_key_b64(secret: &str) -> Result<String> {
    let raw = validate_paseto_secret(secret)?;
    Ok(B64.encode(&raw[32..]))
}

fn validate_paseto_secret(secret: &str) -> Result<Vec<u8>> {
    let raw = B64
        .decode(secret.trim())
        .context("PASETO_SECRET_KEY is not valid base64")?;
    if raw.len() != 64 {
        bail!("PASETO_SECRET_KEY must be 64 bytes");
    }
    Ok(raw)
}

fn load_passphrase(source: &PassphraseSource, confirm: bool) -> Result<String> {
    let passphrase = match source {
        PassphraseSource::Prompt => {
            let first = rpassword::prompt_password("Migration passphrase: ")?;
            if confirm {
                let second = rpassword::prompt_password("Confirm migration passphrase: ")?;
                if first != second {
                    bail!("migration passphrases do not match");
                }
            }
            first
        }
        PassphraseSource::Env(name) => std::env::var(name)
            .with_context(|| format!("environment variable {name} is not set"))?,
        PassphraseSource::Value(value) => value.clone(),
    };
    if passphrase.len() < 12 {
        bail!("migration passphrase must be at least 12 characters");
    }
    Ok(passphrase)
}

fn ensure_file(path: &Path, label: &str) -> Result<()> {
    if !path.is_file() {
        bail!("{label} not found at {}", path.display());
    }
    Ok(())
}

fn ensure_dir(path: &Path, label: &str) -> Result<()> {
    if !path.is_dir() {
        bail!("{label} not found at {}", path.display());
    }
    Ok(())
}

/// Like [`ensure_file`]/[`ensure_dir`] but accepts either — `vela.db` is a
/// directory under stoolap but may be a single file in other modes.
fn ensure_exists(path: &Path, label: &str) -> Result<()> {
    if !path.exists() {
        bail!("{label} not found at {}", path.display());
    }
    Ok(())
}

/// Copy a path that may be a file or a directory.
fn copy_path(src: &Path, dst: &Path) -> Result<()> {
    if src.is_dir() {
        copy_dir_all(src, dst)
    } else {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(src, dst).with_context(|| format!("failed to copy {}", src.display()))?;
        Ok(())
    }
}

fn dir_has_payload(path: &Path) -> Result<bool> {
    Ok(path.join("vela.db").exists() || path.join("sled").exists())
}

fn remove_if_exists(path: &Path) -> Result<()> {
    if path.is_dir() {
        fs::remove_dir_all(path)?;
    } else if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    if dst.exists() {
        fs::remove_dir_all(dst)?;
    }
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let target = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &target)?;
        } else if ty.is_file() {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &str = "correct horse battery staple";

    #[test]
    fn export_import_roundtrip_restores_data_and_identity() {
        let temp = TempDir::new().unwrap();
        let source_data = temp.path().join("source-data");
        let target_data = temp.path().join("target-data");
        fs::create_dir_all(source_data.join("sled/tree")).unwrap();
        fs::write(source_data.join("vela.db"), b"db bytes").unwrap();
        fs::write(source_data.join("sled/tree/file"), b"sled bytes").unwrap();
        let env_file = temp.path().join("vela.env");
        let secret = B64.encode([0u8; 64]);
        fs::write(
            &env_file,
            format!(
                "PASETO_SECRET_KEY={secret}\nWEBAUTHN_RP_ID=vault.example.com\nWEBAUTHN_RP_ORIGIN=https://vault.example.com\nWEBAUTHN_RP_NAME=VELA\nCORS_ORIGINS=https://vault.example.com\n"
            ),
        )
        .unwrap();
        let bundle = temp.path().join("bundle.vela-migrate");
        let target_env = temp.path().join("restored.env");

        export_bundle(ExportOptions {
            out: bundle.clone(),
            env_file,
            data_dir: source_data,
            include_secrets: true,
            include_deployment_config: Vec::new(),
            passphrase: PassphraseSource::Value(PASSPHRASE.to_string()),
        })
        .unwrap();
        import_bundle(ImportOptions {
            bundle,
            target_data_dir: target_data.clone(),
            target_env_file: target_env.clone(),
            replace: false,
            passphrase: PassphraseSource::Value(PASSPHRASE.to_string()),
        })
        .unwrap();

        assert_eq!(fs::read(target_data.join("vela.db")).unwrap(), b"db bytes");
        assert_eq!(
            fs::read(target_data.join("sled/tree/file")).unwrap(),
            b"sled bytes"
        );
        let restored_env = fs::read_to_string(target_env).unwrap();
        assert!(restored_env.contains("PASETO_SECRET_KEY="));
        assert!(restored_env.contains("WEBAUTHN_RP_ORIGIN=https://vault.example.com"));
    }

    #[test]
    fn export_import_roundtrip_with_directory_db() {
        // stoolap stores vela.db as a directory; the bundle must carry it whole.
        let temp = TempDir::new().unwrap();
        let source_data = temp.path().join("source-data");
        fs::create_dir_all(source_data.join("vela.db/wal")).unwrap();
        fs::write(source_data.join("vela.db/db.lock"), b"").unwrap();
        fs::write(source_data.join("vela.db/wal/seg-1.log"), b"wal bytes").unwrap();
        fs::create_dir_all(source_data.join("sled")).unwrap();
        fs::write(source_data.join("sled/conf"), b"sled conf").unwrap();
        let env_file = temp.path().join("vela.env");
        fs::write(&env_file, "WEBAUTHN_RP_ID=vault.example.com\n").unwrap();
        let bundle = temp.path().join("bundle.vela-migrate");
        let target_data = temp.path().join("target-data");
        let target_env = temp.path().join("restored.env");

        export_bundle(ExportOptions {
            out: bundle.clone(),
            env_file,
            data_dir: source_data,
            include_secrets: false,
            include_deployment_config: Vec::new(),
            passphrase: PassphraseSource::Value(PASSPHRASE.to_string()),
        })
        .unwrap();
        import_bundle(ImportOptions {
            bundle,
            target_data_dir: target_data.clone(),
            target_env_file: target_env,
            replace: false,
            passphrase: PassphraseSource::Value(PASSPHRASE.to_string()),
        })
        .unwrap();

        assert_eq!(
            fs::read(target_data.join("vela.db/wal/seg-1.log")).unwrap(),
            b"wal bytes"
        );
        assert_eq!(
            fs::read(target_data.join("sled/conf")).unwrap(),
            b"sled conf"
        );
    }

    #[test]
    fn wrong_passphrase_fails_verification() {
        let temp = TempDir::new().unwrap();
        let source_data = temp.path().join("source-data");
        fs::create_dir_all(source_data.join("sled")).unwrap();
        fs::write(source_data.join("vela.db"), b"db bytes").unwrap();
        let env_file = temp.path().join("vela.env");
        let secret = B64.encode([0u8; 64]);
        fs::write(&env_file, format!("PASETO_SECRET_KEY={secret}\n")).unwrap();
        let bundle = temp.path().join("bundle.vela-migrate");

        export_bundle(ExportOptions {
            out: bundle.clone(),
            env_file,
            data_dir: source_data,
            include_secrets: true,
            include_deployment_config: Vec::new(),
            passphrase: PassphraseSource::Value(PASSPHRASE.to_string()),
        })
        .unwrap();

        let err = verify_bundle(InspectOptions {
            bundle,
            passphrase: PassphraseSource::Value("wrong horse battery staple".to_string()),
        })
        .unwrap_err();
        assert!(err.to_string().contains("failed to decrypt"));
    }

    #[test]
    fn export_can_include_deployment_config_explicitly() {
        let temp = TempDir::new().unwrap();
        let source_data = temp.path().join("source-data");
        fs::create_dir_all(source_data.join("sled")).unwrap();
        fs::write(source_data.join("vela.db"), b"db bytes").unwrap();
        let env_file = temp.path().join("vela.env");
        let secret = B64.encode([0u8; 64]);
        fs::write(&env_file, format!("PASETO_SECRET_KEY={secret}\n")).unwrap();
        let cloudflared = temp.path().join("config.yml");
        fs::write(&cloudflared, b"tunnel: test\n").unwrap();
        let bundle = temp.path().join("bundle.vela-migrate");

        export_bundle(ExportOptions {
            out: bundle.clone(),
            env_file,
            data_dir: source_data,
            include_secrets: true,
            include_deployment_config: vec![cloudflared],
            passphrase: PassphraseSource::Value(PASSPHRASE.to_string()),
        })
        .unwrap();

        let manifest = inspect_bundle(InspectOptions {
            bundle,
            passphrase: PassphraseSource::Value(PASSPHRASE.to_string()),
        })
        .unwrap();
        assert!(manifest.contains("deployment/config.yml"));
    }
}

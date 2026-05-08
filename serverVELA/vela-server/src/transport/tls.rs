use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig,
};

#[derive(Debug, Clone)]
pub struct TlsConfigPaths {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl TlsConfigPaths {
    pub fn from_strings(cert_path: &str, key_path: &str) -> Self {
        Self {
            cert_path: PathBuf::from(cert_path),
            key_path: PathBuf::from(key_path),
        }
    }
}

pub fn load_rustls_server_config(paths: &TlsConfigPaths, alpn: &[&[u8]]) -> Result<ServerConfig> {
    let cert_chain = load_cert_chain(&paths.cert_path)?;
    let private_key = load_private_key(&paths.key_path)?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("failed to build rustls server config from certificate and key")?;
    config.alpn_protocols = alpn.iter().map(|value| value.to_vec()).collect();

    Ok(config)
}

fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open TLS certificate PEM: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to read TLS certificate PEM: {}", path.display()))?;

    anyhow::ensure!(
        !certs.is_empty(),
        "TLS certificate PEM contains no certificate chain: {}",
        path.display()
    );
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open TLS private key PEM: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("failed to read TLS private key PEM: {}", path.display()))?
        .with_context(|| {
            format!(
                "TLS private key PEM contains no supported private key: {}",
                path.display()
            )
        })
}

//! Unlocking the vault from the CLI.
//!
//! The vault is sealed under the master password (Argon2id) — the same blob
//! the desktop app verifies against — so the CLI unlocks directly, like
//! `bw unlock`. There is no second daemon: the printed session key is the
//! vault's own key material, hex-encoded, exactly as Bitwarden's CLI prints
//! its derived key. That is also why it must be treated as a secret.

use std::collections::{HashMap, HashSet};

use vela_desktop_core::crypto::Crypto;
use vela_desktop_core::store::Store;
use vela_desktop_core::vault::VaultStore;

use crate::Cli;

pub struct UnlockedVault {
    pub vault: VaultStore,
}

/// The store the desktop app uses, or `--store DIR` for a portable vault.
pub fn open_store(cli: &Cli) -> Result<Store, String> {
    match cli.opt("store") {
        Some(dir) => Store::new_at(std::path::PathBuf::from(dir)).map_err(|e| e.to_string()),
        None => Store::new().map_err(|e| e.to_string()),
    }
}

fn session_key(cli: &Cli) -> Option<String> {
    cli.opt("session")
        .map(str::to_string)
        .or_else(|| std::env::var("VELA_SESSION").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Open the vault under an explicit session key. Without one this is a
/// locked vault — say so, and how to fix it.
pub fn open_vault(cli: &Cli) -> Result<UnlockedVault, String> {
    let store = open_store(cli)?;

    let Some(key_hex) = session_key(cli) else {
        return Err(
            "The vault is locked. Run `vela unlock` and set the printed key as \
             VELA_SESSION (or pass --session)."
                .to_string(),
        );
    };

    let rms = decode_hex_key(&key_hex)?;
    let crypto = Crypto::new(&rms);
    let vault = store.load_vault(&crypto).map_err(|_| {
        "The session key does not unlock this vault (wrong key or wrong vault)".to_string()
    })?;

    Ok(UnlockedVault { vault })
}

/// `vela unlock`: verify the master password and print the session key.
///
/// The key is the vault's own key material. The output says so, because the
/// failure mode of a convenience export like this is a user pasting it into
/// a shell that lands in `.bash_history`.
pub fn unlock_and_print() -> Result<(), String> {
    let cli = Cli {
        command: vec![],
        options: HashMap::new(),
        flags: HashSet::new(),
    };
    let store = open_store(&cli)?;
    if !store.has_existing_vault() {
        return Err(
            "No VELA vault exists on this device. Create one in the desktop app first.".to_string(),
        );
    }

    let password = rpassword::prompt_password("Master password: ")
        .map_err(|e| format!("No password entered: {e}"))?;

    let Some(rms) = vela_desktop_core::biometric::authenticate_with_password(&password) else {
        return Err("Invalid master password".to_string());
    };

    let key = hex_encode(&rms);
    println!();
    println!("Session key (this IS the vault key — treat it like a password):");
    println!();
    println!("  export VELA_SESSION={key}");
    println!();
    println!("Then run commands as `vela list items`, or pass --session. The key works until");
    println!("the vault's master password is changed; clear it from your shell history.");
    Ok(())
}

fn decode_hex_key(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(
            "The session key must be 64 hex characters (as printed by `vela unlock`)".to_string(),
        );
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err("The session key must be hex".to_string()),
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::items::find_item;
    use vela_desktop_core::crypto::Crypto;
    use vela_desktop_core::vault::{VaultItem, VaultMeta};

    fn cli_for(dir: &std::path::Path, session: Option<&str>) -> Cli {
        let mut options = HashMap::new();
        if let Some(hex) = session {
            options.insert("session".to_string(), hex.to_string());
        }
        options.insert("store".to_string(), dir.to_string_lossy().to_string());
        Cli {
            command: vec![],
            options,
            flags: HashSet::new(),
        }
    }

    fn seed_vault() -> (tempfile::TempDir, [u8; 32]) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new_at(dir.path().to_path_buf()).unwrap();
        let rms = Crypto::generate_rms();
        let crypto = Crypto::new(&rms);
        let now = chrono::Utc::now();
        let mut vault = vela_desktop_core::vault::VaultStore::default();
        vault.add_item(VaultItem::Login {
            meta: VaultMeta {
                id: "item-1".into(),
                name: "GitHub".into(),
                notes: Some("work account".into()),
                created_at: now,
                updated_at: now,
                last_modified_device: None,
                favorite: false,
                shared: false,
                share_recipient: None,
            },
            url: "https://github.com".into(),
            username: "octo".into(),
            pass: "hunter2".into(),
            totp: None,
            app_ids: Vec::new(),
            credential_change_needs_reauth: None,
            allow_second_factor_downgrade: None,
        });
        store.save_vault(&vault, &crypto).unwrap();
        (dir, rms)
    }

    #[test]
    fn session_key_roundtrip_unlocks_the_vault() {
        let (dir, rms) = seed_vault();
        let hex = hex_encode(&rms);
        let cli = cli_for(dir.path(), Some(&hex));
        let vault = open_vault(&cli).unwrap();
        assert_eq!(vault.vault.items.len(), 1);

        // A wrong key is refused with the session error, not a crypto dump.
        let bad = cli_for(dir.path(), Some(&hex_encode(&[0u8; 32])));
        let err = match open_vault(&bad) {
            Err(e) => e,
            Ok(_) => panic!("a wrong session key must be refused"),
        };
        assert!(err.contains("does not unlock"), "{err}");

        // Hex decode/encode is lossless.
        assert_eq!(decode_hex_key(&hex).unwrap(), rms);
    }

    #[test]
    fn locked_vault_says_how_to_unlock() {
        let (dir, _rms) = seed_vault();
        let cli = cli_for(dir.path(), None);
        let err = match open_vault(&cli) {
            Err(e) => e,
            Ok(_) => panic!("no session key must mean locked"),
        };
        assert!(err.contains("vela unlock"), "{err}");
    }

    #[test]
    fn item_lookup_matches_id_name_and_unique_substring() {
        let (dir, rms) = seed_vault();
        let cli = cli_for(dir.path(), Some(&hex_encode(&rms)));
        let vault = open_vault(&cli).unwrap();

        assert_eq!(find_item(&vault.vault, "item-1").unwrap().name(), "GitHub");
        assert_eq!(find_item(&vault.vault, "github").unwrap().id(), "item-1");
        assert_eq!(find_item(&vault.vault, "GITHUB").unwrap().id(), "item-1");
        assert_eq!(find_item(&vault.vault, "git").unwrap().id(), "item-1");
        assert!(find_item(&vault.vault, "nomatch").is_err());
    }
}

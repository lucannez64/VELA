//! End-to-end vault lifecycle against the real desktop backend modules:
//! create a vault, add items, encrypt+persist, reload+decrypt, search/update/
//! delete, and the master-password unlock crypto.
//!
//! Hermetic by design — it drives `Crypto`/`VaultStore` and the password key
//! derivation directly and NEVER touches the OS keychain or the app data dir,
//! so it's safe to run on a developer's real machine as well as in CI.

use crate::biometric::derive_key_from_password;
use crate::crypto::Crypto;
use crate::vault::{ItemType, VaultItem, VaultMeta, VaultStore};
use chrono::Utc;

fn meta(id: &str, name: &str) -> VaultMeta {
    let now = Utc::now();
    VaultMeta {
        id: id.into(),
        name: name.into(),
        notes: None,
        created_at: now,
        updated_at: now,
        last_modified_device: None,
        favorite: false,
        shared: false,
        share_recipient: None,
    }
}

fn login(id: &str, name: &str, url: &str, user: &str, pass: &str) -> VaultItem {
    VaultItem::Login {
        meta: meta(id, name),
        url: url.into(),
        username: user.into(),
        pass: pass.into(),
        totp: None,
    }
}

#[test]
fn create_vault_add_items_persist_reload_decrypt() {
    // "Create a new vault": fresh root seed + crypto (what setup does).
    let rms = Crypto::generate_rms();
    let crypto = Crypto::new(&rms);

    // "Create items" of several types.
    let mut vault = VaultStore::new();
    vault.add_item(login("1", "GitHub", "https://github.com", "alice", "hunter2pw"));
    vault.add_item(VaultItem::SecureNote {
        meta: meta("2", "Recovery codes"),
        title: "codes".into(),
        content: "1234-5678".into(),
    });
    vault.add_item(VaultItem::CreditCard {
        meta: meta("3", "Visa"),
        number: "4111111111111111".into(),
        exp: "12/30".into(),
        cvv: "123".into(),
        pin: None,
        cardholder_name: Some("Alice".into()),
    });
    assert_eq!(vault.items.len(), 3);

    // "Save vault": exactly what Store::save_vault does — serialize then encrypt.
    let plaintext = serde_json::to_vec(&vault).unwrap();
    let ciphertext = crypto.encrypt_vault(&plaintext).unwrap();
    assert_ne!(ciphertext, plaintext, "vault must be encrypted at rest");
    assert!(
        !ciphertext.windows(6).any(|w| w == b"hunter"),
        "plaintext secret must not appear in ciphertext"
    );

    // "Reload vault": decrypt then deserialize.
    let decrypted = crypto.decrypt_vault(&ciphertext).unwrap();
    let reloaded: VaultStore = serde_json::from_slice(&decrypted).unwrap();

    assert_eq!(reloaded.items.len(), 3);
    let gh = reloaded.get_item("1").expect("login present after reload");
    assert_eq!(gh.username(), Some("alice"));
    assert_eq!(gh.password(), Some("hunter2pw"));
    assert_eq!(
        reloaded.get_item("3").unwrap().item_type(),
        ItemType::CreditCard
    );
}

#[test]
fn wrong_master_seed_cannot_decrypt_vault() {
    let crypto = Crypto::new(&Crypto::generate_rms());
    let mut vault = VaultStore::new();
    vault.add_item(login("1", "Site", "https://x.com", "u", "p"));
    let ciphertext = crypto
        .encrypt_vault(&serde_json::to_vec(&vault).unwrap())
        .unwrap();

    let attacker = Crypto::new(&Crypto::generate_rms());
    assert!(
        attacker.decrypt_vault(&ciphertext).is_err(),
        "a different root seed must not decrypt the vault"
    );
}

#[test]
fn search_update_delete_items() {
    let mut vault = VaultStore::new();
    vault.add_item(login("1", "GitHub", "https://github.com", "alice", "p1"));
    vault.add_item(login("2", "GitLab", "https://gitlab.com", "bob", "p2"));

    assert_eq!(vault.search("git").len(), 2);
    assert_eq!(vault.search("alice").len(), 1);

    vault.update_item(login("1", "GitHub", "https://github.com", "alice2", "p1b"));
    assert_eq!(vault.get_item("1").unwrap().username(), Some("alice2"));

    vault.delete_item("1", Some("device-x"));
    assert!(vault.get_item("1").is_none());
    assert_eq!(vault.items.len(), 1);
    assert_eq!(vault.tombstones.len(), 1);
}

#[test]
fn master_password_unlock_roundtrip() {
    // The master-password path derives a key from password+salt and AEAD-seals
    // the RMS. Verify the round-trip and that a wrong password fails — without
    // touching the OS keychain/files (safe on any dev machine).
    let rms = Crypto::generate_rms();
    let salt = [7u8; 16];

    let key = derive_key_from_password("correct horse battery staple", &salt);
    let sealed = vela_crypto::aead::encrypt(&key, &rms).unwrap();

    let key_again = derive_key_from_password("correct horse battery staple", &salt);
    let opened = vela_crypto::aead::decrypt(&key_again, &sealed).unwrap();
    assert_eq!(&opened[..32], &rms, "correct password unlocks the RMS");

    let wrong = derive_key_from_password("wrong password", &salt);
    assert!(
        vela_crypto::aead::decrypt(&wrong, &sealed).is_err(),
        "wrong password must not unlock the RMS"
    );
}

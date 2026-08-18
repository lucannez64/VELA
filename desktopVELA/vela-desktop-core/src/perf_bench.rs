//! Timing harness for the hot paths of the shared desktop core.
//!
//! Not a correctness test: every case is `#[ignore]`d so `cargo test` stays
//! quiet, and the numbers only mean anything in a release build.
//!
//!     cargo test --release -p vela-desktop-core perf_bench -- --ignored --nocapture

use std::time::Instant;

use chrono::Utc;

use crate::audit::{record_audit_event, AuditAction};
use crate::crypto::Crypto;
use crate::vault::{VaultItem, VaultMeta, VaultStore};
use crate::AppState;

const N: usize = 2000;

fn login(i: usize, device: Option<&str>) -> VaultItem {
    let now = Utc::now();
    VaultItem::Login {
        meta: VaultMeta {
            id: format!("item-{i:06}"),
            name: format!("Account number {i} at example{}.com", i % 97),
            notes: Some("some notes about this account".to_string()),
            created_at: now,
            updated_at: now,
            last_modified_device: device.map(|s| s.to_string()),
            favorite: i % 11 == 0,
            shared: false,
            share_recipient: None,
        },
        url: format!("https://www.example{}.com/login/path", i % 97),
        username: format!("user{i}@mail.example.com"),
        pass: format!("Correct-Horse-Battery-Staple-{i}!"),
        totp: if i % 5 == 0 { Some("JBSWY3DPEHPK3PXP".to_string()) } else { None },
        app_ids: Vec::new(),
    }
}

fn vault_with(n: usize, device: Option<&str>) -> VaultStore {
    let mut store = VaultStore::new();
    for i in 0..n {
        store.add_item(login(i, device));
    }
    store
}

fn unlocked() -> (tempfile::TempDir, AppState) {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::for_test(dir.path());
    state.unlock_for_test(&Crypto::generate_rms());
    (dir, state)
}

fn bench<T>(label: &str, iters: u32, mut f: impl FnMut() -> T) {
    // Warm up, so the first allocation / page fault is not in the measurement.
    std::hint::black_box(f());
    let start = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(f());
    }
    let per = start.elapsed().as_secs_f64() / f64::from(iters) * 1e6;
    println!("{label:<38} {per:>10.1} µs");
}

#[test]
#[ignore = "timing harness"]
fn bench_audit() {
    let (_dir, state) = unlocked();
    for i in 0..1000 {
        record_audit_event(&state, AuditAction::ItemAdded { item_type: format!("login{i}") });
    }
    bench("record_audit_event (1000-entry log)", 200, || {
        record_audit_event(&state, AuditAction::ItemUpdated { item_type: "login".into() })
    });
}

#[test]
#[ignore = "timing harness"]
fn bench_store() {
    let (_dir, state) = unlocked();
    let vault = vault_with(N, Some("test-device"));
    let plaintext = serde_json::to_vec(&vault).unwrap();
    println!("vault: {N} items, {} bytes serialized", plaintext.len());

    let crypto_guard = state.crypto.read();
    let crypto = crypto_guard.as_ref().unwrap();
    bench("save_vault", 100, || state.store.save_vault(&vault, crypto).unwrap());
    bench("load_vault", 100, || state.store.load_vault(crypto).unwrap());
    bench("serde_json::to_vec(vault)", 200, || serde_json::to_vec(&vault).unwrap());
    bench("VaultStore::clone", 200, || vault.clone());
    bench("encrypt_vault", 100, || crypto.encrypt_vault(&plaintext).unwrap());
    bench("chunk_key", 5000, || crypto.chunk_key(b"vault-data-0"));
}

#[test]
#[ignore = "timing harness"]
fn bench_merge() {
    let local = vault_with(N, Some("test-device"));
    let server = vault_with(N, Some("other-device"));
    bench("merge_server_vaults", 50, || {
        let mut local = local.clone();
        crate::sync::merge_server_vaults(&mut local, server.clone(), "test-device").len()
    });
}

#[test]
#[ignore = "timing harness"]
fn bench_lookup() {
    let (_dir, state) = unlocked();
    *state.vault.write() = vault_with(N, Some("test-device"));
    bench("get_items (clone all)", 200, || state.vault.read().items.clone());
    bench("get_item x1000", 50, || {
        let vault = state.vault.read();
        (0..1000).filter(|i| vault.get_item(&format!("item-{i:06}")).is_some()).count()
    });
    bench("search_by_domain", 500, || state.vault.read().search_by_domain("example42.com").len());
    bench("search", 200, || state.vault.read().search("account number 1234").len());
}

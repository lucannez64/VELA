//! End-to-end: the real provider binary against a real desktop IPC server
//! over the real well-known pipe.
//!
//! Everything in the middle is production code: the desktop's connection
//! gate (which must admit `vela-passkey-provider.exe` on identity alone —
//! no browser ancestry exists for a COM-launched process), the framed JSON
//! protocol, and the vault metadata read. The one faked part is the vault:
//! `AppState::for_test` + a directly constructed `VaultItem::Passkey`, since
//! minting a real credential would need a human.
//!
//! One test, sequential, Windows-only: the endpoint is a fixed per-user pipe
//! name and the provider crate does not build elsewhere.

#![cfg(windows)]

use std::process::{Command, Stdio};
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use vela_desktop_core::host::Host;
use vela_desktop_core::vault::{VaultItem, VaultMeta};
use vela_desktop_core::AppState;

/// Minimal host callbacks: the sync path reads the vault and reports state;
/// it must never surface the window or prompt.
struct NopHost(Arc<AppState>);

impl Host for NopHost {
    fn state(&self) -> &Arc<AppState> {
        &self.0
    }
    fn focus_main_window(&self) {
        panic!("provider sync must not surface the window");
    }
    fn app_identifier(&self) -> String {
        "com.vela.test".into()
    }
    fn open_quick_search(&self) {
        panic!("provider sync must not open quick search");
    }
    fn notify_vault_items_changed(&self) {}
    fn show_toast(&self, _message: &str) {}
    fn confirm_presence(&self, _title: &str, _prompt: &str) -> Option<bool> {
        panic!("credential metadata sync must never prompt");
    }
}

/// A valid (but throwaway) P-256 scalar, base64url — the vault stores the
/// raw secret, so anything below the curve order parses.
const TEST_SCALAR: &[u8] = &[
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
    0x3c, 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
    0x4f, 0x3c,
];

/// Any desktop front end running means the per-user pipe already has a
/// server we cannot distinguish ours from.
fn foreign_desktop_running() -> bool {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut found = false;
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry.szExeFile.iter().position(|c| *c == 0).unwrap_or(0)],
                );
                if name.eq_ignore_ascii_case("vela-desktop.exe")
                    || name.eq_ignore_ascii_case("vela-desktop-gpui.exe")
                {
                    found = true;
                    break;
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = windows::Win32::Foundation::CloseHandle(snapshot);
        found
    }
}

fn seed_passkey(state: &AppState, rp_id: &str) {
    let now = chrono::Utc::now();
    state.vault.write().add_item(VaultItem::Passkey {
        meta: VaultMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: rp_id.to_string(),
            notes: None,
            created_at: now,
            updated_at: now,
            last_modified_device: None,
            favorite: false,
            tags: Vec::new(),
            tag_tombstones: Vec::new(),
            custom_fields: Vec::new(),
            folder: None,
            shared: false,
            share_recipient: None,
        },
        rp_id: rp_id.to_string(),
        rp_name: format!("{rp_id} Test Site"),
        credential_id: B64URL.encode([7u8; 32]),
        user_handle: B64URL.encode(b"handle"),
        user_name: "alice@example.com".to_string(),
        user_display_name: "Alice".to_string(),
        private_key: B64URL.encode(TEST_SCALAR),
        sign_count: 1,
    });
}

#[test]
#[ignore = "binds the fixed per-user pipe; run explicitly and alone"]
fn the_real_provider_meets_the_real_desktop() {
    // A desktop already running owns the well-known pipe, and extra server
    // instances on the same name share connects unpredictably — this test's
    // child could be answered by the *installed* desktop (whose gate predates
    // the provider rule) instead of this test's server. Skip rather than
    // produce a confusing failure; close the desktop to run the test.
    if foreign_desktop_running() {
        eprintln!("skipping: a vela-desktop process is running and owns the IPC pipe");
        return;
    }
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG)
        .with_test_writer()
        .try_init();
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(AppState::for_test(dir.path()));
    state.unlock_for_test(&vela_desktop_core::crypto::Crypto::generate_rms());
    seed_passkey(&state, "example.com");
    let host: Arc<dyn Host> = Arc::new(NopHost(state));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    {
        let host = host.clone();
        std::thread::spawn(move || {
            rt.block_on(async move {
                vela_desktop_core::ipc::server::IpcServer::new().start(host).await;
            });
        });
    }

    // Wait for the pipe the same way the native messaging host does.
    {
        let pipe = vela_nm_host::desktop_endpoint();
        let mut waited = 0;
        loop {
            if std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&pipe)
                .is_ok()
            {
                break;
            }
            waited += 1;
            assert!(waited < 100, "desktop pipe never appeared at {pipe}");
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    // The gate admits the *provider binary* on exe identity alone. The child
    // here is the real provider exe, so the real gate decision is exercised.
    let output = Command::new(env!("CARGO_BIN_EXE_vela-passkey-provider"))
        .arg("--sync-credentials")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .expect("spawn provider exe");
    assert!(
        output.status.success(),
        "sync failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Synced 1 passkey"),
        "expected one synced credential, got: {stdout}"
    );
}

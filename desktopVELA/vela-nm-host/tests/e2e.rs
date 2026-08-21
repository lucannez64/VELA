//! End-to-end: the real native messaging host binary against a real desktop
//! IPC server over the real well-known socket.
//!
//! This is the option-B smoke test. Everything in the middle is production
//! code: the browser framing, endpoint discovery, the desktop's connection
//! gate (`ipc_gate`), and ping/pong. The only faked part is *browser
//! ancestry* — the gate admits a host whose ancestor executable is named in
//! `VELA_NM_BROWSER_NAMES`, and this test puts its own executable name there,
//! because arranging an actual Firefox process tree inside CI is not a thing.
//! The gate's decision logic itself is covered exhaustively (and without any
//! escape hatch) by `ipc_gate`'s own unit tests.
//!
//! One test, sequentially, because the endpoint is a fixed per-user name (a
//! second server cannot bind while the first listens) and the escape hatch is
//! process-global state the gate reads.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;

use serde_json::{json, Value};
use vela_desktop_core::host::Host;
use vela_desktop_core::AppState;

/// Minimal host callbacks: nothing here should be reached by a ping.
struct NopHost(Arc<AppState>);

impl Host for NopHost {
    fn state(&self) -> &Arc<AppState> {
        &self.0
    }
    fn focus_main_window(&self) {
        panic!("ping must not surface the window");
    }
    fn app_identifier(&self) -> String {
        "com.vela.test".into()
    }
    fn open_quick_search(&self) {
        panic!("ping must not open quick search");
    }
    fn notify_vault_items_changed(&self) {}
    fn show_toast(&self, _message: &str) {}
    fn confirm_presence(&self, _prompt: &str) -> Option<bool> {
        panic!("ping must not prompt");
    }
}

fn frame(obj: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(obj).unwrap();
    let mut out = (body.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

fn read_frame(stream: &mut impl Read) -> Option<Value> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).ok()?;
    let length = u32::from_le_bytes(len_bytes) as usize;
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload).ok()?;
    serde_json::from_slice(&payload).ok()
}

fn endpoint_path() -> std::path::PathBuf {
    let uid = unsafe { libc::getuid() };
    match std::env::var("XDG_RUNTIME_DIR") {
        Ok(d) if !d.is_empty() => {
            std::path::PathBuf::from(d).join(format!("vela-{uid}")).join("desktop.sock")
        }
        _ => std::env::temp_dir().join(format!("vela-{uid}")).join("desktop.sock"),
    }
}

fn spawn_host(browser_ancestor_name: Option<&str>) -> (std::process::Child, std::process::ChildStdin, std::process::ChildStdout) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vela-native-messaging-host"));
    // The gate walks the host's ancestry looking for a named spawner. This
    // test process *is* the ancestor, so naming ourselves makes us count.
    if let Some(name) = browser_ancestor_name {
        cmd.env("VELA_NM_BROWSER_NAMES", name);
    } else {
        cmd.env_remove("VELA_NM_BROWSER_NAMES");
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn native messaging host");
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    (child, stdin, stdout)
}

#[test]
fn the_real_host_meets_the_real_gate() {
    // Desktop side: hermetic store, vault unlocked, IPC server listening on
    // the well-known per-user endpoint.
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(AppState::for_test(dir.path()));
    state.unlock_for_test(&vela_desktop_core::crypto::Crypto::generate_rms());
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

    let endpoint = endpoint_path();
    let mut waited = 0;
    while !endpoint.exists() && waited < 100 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        waited += 1;
    }
    assert!(endpoint.exists(), "desktop socket never appeared at {}", endpoint.display());

    let own_name =
        std::env::current_exe().unwrap().file_name().unwrap().to_string_lossy().to_string();

    // ── Phase 1: no browser anywhere in the host's ancestry ─────────────
    // The gate refuses; from the extension's side that reads as "not
    // connected", never as success or a hang.
    {
        let (_child, mut stdin, mut stdout) = spawn_host(None);
        stdin.write_all(&frame(&json!({ "action": "ping" }))).unwrap();
        let response =
            read_frame(&mut stdout).expect("host should answer even when the desktop refuses");
        assert_eq!(response["success"], false, "{response}");
        assert_eq!(response["connected"], false, "{response}");
    }

    // ── Phase 2: this test process stands in for the browser ────────────
    // Same transport, same gate, admitted ancestry: full round trip.
    // Note the escape hatch is read by the *desktop* process (the gate runs
    // there), so it is this process's env, not the spawned host's.
    {
        std::env::set_var("VELA_NM_BROWSER_NAMES", &own_name);
        let (mut child, mut stdin, mut stdout) = spawn_host(Some(&own_name));
        stdin.write_all(&frame(&json!({ "action": "ping" }))).unwrap();
        let response = read_frame(&mut stdout).expect("no response within the socket timeout");
        assert_eq!(response["success"], true, "{response}");
        assert_eq!(response["connected"], true, "{response}");

        // And a second exchange over the same host process, since the browser
        // keeps one host alive for many requests.
        stdin.write_all(&frame(&json!({ "action": "getStatus" }))).unwrap();
        let response = read_frame(&mut stdout).expect("second exchange");
        assert_eq!(response["success"], false, "{response}");
        assert_eq!(response["error"], "Not implemented");

        drop(stdin);
        let _ = child.wait();
        std::env::remove_var("VELA_NM_BROWSER_NAMES");
    }
}

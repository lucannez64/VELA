//! Discover and drive a real browser for the browser-driven login tier.
//!
//! The core spawns a disposable browser (Chrome/Chromium/Edge) with a fresh
//! temp profile and a CDP debug port, attaches over WebSocket, and tears the
//! whole thing down afterwards — profile deleted, process killed. See
//! `security/browser-driven-login-design.md`.
//!
//! Process isolation: on Linux the browser's child processes are readable by
//! any same-UID process, so a co-resident process can read the substituted
//! password out of the browser during a login. `VELA_BROWSER_SANDBOX` routes
//! the spawn through a setuid launcher that drops the whole browser to a
//! dedicated unprivileged UID (see `vela-browser-sandbox/`), closing that.
//! `spawn()` fails closed if the sandbox is requested but not effecting a
//! distinct UID, and warns when the tier runs without it.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// A running disposable browser. Dropping it kills the process and wipes the
/// profile.
pub struct Browser {
    child: Option<Child>,
    profile_dir: PathBuf,
    debug_port: u16,
}

impl Browser {
    /// The port the browser's debug endpoint listens on.
    pub fn debug_port(&self) -> u16 {
        self.debug_port
    }
}

impl Drop for Browser {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.profile_dir);
    }
}

/// The browser binaries we look for, best first, per platform.
fn candidates() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    #[cfg(target_os = "linux")]
    {
        for name in [
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
            "microsoft-edge",
            "microsoft-edge-stable",
        ] {
            if let Some(path) = which(name) {
                out.push(path);
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        for name in [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        ] {
            let path = PathBuf::from(name);
            if path.exists() {
                out.push(path);
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        let program_files = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
        let program_files_x86 =
            std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| r"C:\Program Files (x86)".into());
        for root in [&program_files, &program_files_x86] {
            for relative in [
                r"Google\Chrome\Application\chrome.exe",
                r"Microsoft\Edge\Application\msedge.exe",
            ] {
                let path = PathBuf::from(root).join(relative);
                if path.exists() {
                    out.push(path);
                }
            }
        }
    }
    out
}

/// Find an executable on PATH.
fn which(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Reserve a free TCP port for the browser's debug endpoint.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .map(|listener| listener.local_addr().map(|a| a.port()).unwrap_or(0))
        .unwrap_or(0)
}

/// Path to the setuid launcher that runs the disposable browser under a
/// dedicated, unprivileged UID (Linux only).
///
/// Why this is needed: Chromium's child processes — the ones that move the
/// login request, and the renderers — are left readable by any *same-UID*
/// process on a default `kernel.yama.ptrace_scope=1` kernel. Verified
/// empirically: a co-resident same-user process can recover the substituted
/// password from the disposable browser's memory during a login (see
/// `security/exploits/test_browser_tier_memleak.py`). The core process is not
/// affected — a plain process is gated against unrelated same-UID reads — but
/// the browser's process tree is open to them.
///
/// Running the whole disposable browser under a *different*, unprivileged UID
/// closes that: cross-UID `process_vm_readv` and `/proc/<pid>/mem` reads are
/// refused by the kernel unless the reader is root. Turning a user-spawned
/// subprocess into a different UID needs a privileged bootstrap, so this is
/// done with a small setuid helper (`desktopVELA/vela-browser-sandbox/`),
/// which an operator installs `setuid root` (one-time, see its README).
///
/// Opt-in via `VELA_BROWSER_SANDBOX`: either a path to the launcher, or `1`
/// to use the launcher installed next to the app's own binary. When it is
/// configured we fail closed; when it is absent we keep the legacy same-UID
/// behaviour but warn loudly that the documented residual is reachable.
#[cfg(target_os = "linux")]
fn sandbox_launcher() -> Option<PathBuf> {
    let value = std::env::var_os("VELA_BROWSER_SANDBOX")?;
    let empty = std::ffi::OsStr::new("");
    if value == empty {
        return None;
    }
    if value == "1" {
        // The launcher installed alongside the running binary.
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("vela-browser-sandbox")))
    } else {
        Some(PathBuf::from(value))
    }
}

/// A process's effective UID, from `/proc/<pid>/status` (Linux). `None` if the
/// process is gone or the file is unreadable.
#[cfg(target_os = "linux")]
fn euid_of(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    // Uid:	real	effective	saved	fs  (effective is the 3rd token)
    line.split_whitespace().nth(2)?.parse().ok()
}

/// Spawn a disposable browser and wait for its CDP endpoint to answer.
pub async fn spawn() -> Result<Browser, String> {
    // Test seam: lets a unit test prove the fallback wiring without opening a
    // real browser window (which would sit on a mock 403 page doing nothing).
    if std::env::var("VELA_BROWSER_LOGIN_DISABLED").is_ok() {
        return Err(
            "the disposable browser tier is disabled in this environment \
             (VELA_BROWSER_LOGIN_DISABLED is set)"
                .to_string(),
        );
    }
    let binary = candidates()
        .into_iter()
        .next()
        .ok_or_else(|| "no Chrome, Chromium or Edge browser was found on this machine".to_string())?;
    let profile_dir = std::env::temp_dir().join(format!(
        "vela-browser-{}-{}",
        std::process::id(),
        rand_hex(8)
    ));
    std::fs::create_dir_all(&profile_dir).map_err(|e| format!("could not create the browser profile: {e}"))?;

    let debug_port = free_port();
    let mut browser_args: Vec<String> = vec![
        format!("--remote-debugging-port={debug_port}"),
        format!("--user-data-dir={}", profile_dir.display()),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        "--disable-background-networking".into(),
        "--disable-component-update".into(),
        "--disable-default-apps".into(),
        "--window-size=1280,800".into(),
    ];

    #[cfg(target_os = "linux")]
    let sandbox = sandbox_launcher();
    #[cfg(not(target_os = "linux"))]
    let sandbox: Option<PathBuf> = None;

    // When a setuid launcher is configured, the browser is spawned *through*
    // it: `launcher <binary> <profile-dir> <browser-args…>`. The launcher drops
    // the whole browser to a dedicated unprivileged UID and wraps its lifetime
    // (chowning the profile back to us when it exits, so we can wipe it).
    let mut command = match &sandbox {
        Some(launcher) => {
            let mut c = Command::new(launcher);
            c.arg(&binary).arg(&profile_dir).args(&browser_args);
            c
        }
        None => {
            let mut c = Command::new(&binary);
            c.args(&browser_args);
            c
        }
    };
    // Visible by default: a real, human-visible window is both harder for bot
    // checks to reject and lets the user finish a second factor.
    let mut child = command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("could not start {binary:?}: {e}"))?;

    // Sandbox self-check. When isolation was explicitly requested, the browser
    // *must* actually be running under a different UID than the app; otherwise
    // the isolation is not effecting anything and we fail closed rather than
    // proceed as if the residual were mitigated.
    #[cfg(target_os = "linux")]
    if let Some(_launcher) = &sandbox {
        let isolated = match (euid_of(child.id()), euid_of(std::process::id())) {
            (Some(browser_euid), Some(app_euid)) => browser_euid != app_euid,
            _ => false,
        };
        if !isolated {
            let _ = child.kill();
            let _ = child.wait();
            return Err(
                "the browser sandbox (VELA_BROWSER_SANDBOX) was requested but the \
                 disposable browser is not running under a distinct UID — the \
                 vela-browser-sandbox launcher may not be installed setuid-root, so \
                 refusing to continue with an ineffective sandbox"
                    .to_string(),
            );
        }
    }

    // Without a sandbox the disposable browser runs as the user's own UID, and
    // the documented residual (a co-resident same-user process reading the
    // substituted password from the browser's memory) is empirically reachable.
    // Say so once, loudly, instead of letting it pass silently.
    #[cfg(target_os = "linux")]
    if sandbox.is_none() {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                "the disposable login browser runs as your own UID: a co-resident \
                 same-user process can read its memory during the login (the \
                 substituted password). Enable process isolation with VELA_BROWSER_SANDBOX \
                 and the vela-browser-sandbox setuid launcher (see \
                 desktopVELA/vela-browser-sandbox/)."
            );
        });
    }

    let browser = Browser {
        child: Some(child),
        profile_dir,
        debug_port,
    };

    // The debug endpoint is up once /json/version answers.
    let endpoint = format!("http://127.0.0.1:{debug_port}/json/version");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        if let Ok(response) = reqwest::get(&endpoint).await {
            if response.status().is_success() {
                return Ok(browser);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    drop(browser);
    Err("the browser did not open its debug port in time".to_string())
}

/// Fetch the browser-level CDP WebSocket URL from `/json/version`.
pub async fn websocket_url(debug_port: u16) -> Result<String, String> {
    let endpoint = format!("http://127.0.0.1:{debug_port}/json/version");
    let response = reqwest::get(&endpoint)
        .await
        .map_err(|e| format!("could not reach the browser's debug endpoint: {e}"))?;
    let value: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("the browser's debug endpoint did not answer JSON: {e}"))?;
    value
        .get("webSocketDebuggerUrl")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "the browser's debug endpoint did not advertise a WebSocket URL".to_string())
}

fn rand_hex(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    getrandom::getrandom(&mut bytes).unwrap_or_default();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn sandbox_launcher_uses_the_configured_path() {
        std::env::set_var("VELA_BROWSER_SANDBOX", "/opt/vela/libexec/vela-browser-sandbox");
        assert_eq!(
            sandbox_launcher(),
            Some(PathBuf::from("/opt/vela/libexec/vela-browser-sandbox"))
        );
        std::env::remove_var("VELA_BROWSER_SANDBOX");
    }

    #[test]
    fn sandbox_launcher_is_absent_when_not_configured() {
        std::env::remove_var("VELA_BROWSER_SANDBOX");
        assert_eq!(sandbox_launcher(), None);
    }

    #[test]
    fn euid_of_self_reads_the_effective_uid() {
        let uid = euid_of(std::process::id()).expect("self /proc status is readable");
        // We must be running as some uid; cross-check against /proc/self.
        let self_status = std::fs::read_to_string("/proc/self/status").unwrap();
        let expected = self_status
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2))
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap();
        assert_eq!(uid, expected);
    }
}


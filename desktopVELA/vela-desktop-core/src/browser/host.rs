//! Discover and drive a real browser for the browser-driven login tier.
//!
//! The core spawns a disposable browser (Chrome/Chromium/Edge) with a fresh
//! temp profile and a CDP debug port, attaches over WebSocket, and tears the
//! whole thing down afterwards — profile deleted, process killed. See
//! `security/browser-driven-login-design.md`.

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
    let child = Command::new(&binary)
        .arg(format!("--remote-debugging-port={debug_port}"))
        .arg(format!("--user-data-dir={}", profile_dir.display()))
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--disable-background-networking")
        .arg("--disable-component-update")
        .arg("--disable-default-apps")
        .arg("--window-size=1280,800")
        // Visible by default: a real, human-visible window is both harder for
        // bot checks to reject and lets the user finish a second factor.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("could not start {binary:?}: {e}"))?;

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

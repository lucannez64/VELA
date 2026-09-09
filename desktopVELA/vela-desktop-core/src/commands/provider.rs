//! Windows system-wide passkey provider: toolkit-agnostic control surface.
//!
//! Both front ends call these: `src-tauri` wraps them in `#[tauri::command]`,
//! `src-gpui` calls them from Settings actions.
//!
//! These all shell out to `vela-passkey-provider.exe` rather than calling the
//! crate in-process, deliberately: `WebAuthNPluginAddAuthenticator` (and the
//! autofill-cache writes) are accepted only from a process with **package
//! identity**, which the provider exe carries (embedded manifest + registered
//! identity package) and the desktop process does not. The CLI answers with
//! JSON (`--json`), so the desktop parses a verdict instead of scraping text.

#[cfg(windows)]
pub use windows_impl::{
    register, schedule_autofill_sync, status, sync_credentials, unregister, ProviderSummary,
};

#[cfg(not(windows))]
pub use fallback::{
    register, schedule_autofill_sync, status, sync_credentials, unregister, ProviderSummary,
};

#[cfg(windows)]
mod windows_impl {
    use crate::AppState;
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    use std::sync::Arc;

    /// What the front ends render: registration state.
    #[derive(Debug, Clone, serde::Serialize)]
    pub struct ProviderSummary {
        pub com_registered: bool,
        pub os_registered: bool,
        pub enabled: bool,
    }

    /// Locate the provider exe: installed layout ships it under
    /// `passkey-provider/` next to the desktop; the dev flat layout puts
    /// both exes in the same target directory.
    fn provider_exe() -> Result<std::path::PathBuf, String> {
        let exe = std::env::current_exe().map_err(|e| format!("cannot resolve exe: {e}"))?;
        let dir = exe.parent().ok_or_else(|| "exe has no directory".to_string())?;
        for candidate in [
            dir.join("passkey-provider").join("vela-passkey-provider.exe"),
            dir.join("vela-passkey-provider.exe"),
        ] {
            if candidate.exists() {
                return Ok(candidate);
            }
        }
        Err(
            "vela-passkey-provider.exe not found next to the desktop app \
             (reinstall, or build vela-win-passkey for development)"
                .to_string(),
        )
    }

    /// Run one provider CLI command and parse its `--json` verdict.
    fn run_provider(command: &str) -> Result<serde_json::Value, String> {
        let output = Command::new(provider_exe()?)
            .args([command, "--json"])
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .output()
            .map_err(|e| format!("could not run the passkey provider: {e}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let verdict: serde_json::Value = serde_json::from_str(stdout.trim())
            .map_err(|e| {
                format!(
                    "unreadable provider response ({e}): {}{}",
                    stdout.trim(),
                    String::from_utf8_lossy(&output.stderr)
                )
            })?;
        if verdict.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            return Err(verdict
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("the passkey provider reported an unspecified failure")
                .to_string());
        }
        Ok(verdict)
    }

    fn summary_of(verdict: &serde_json::Value) -> ProviderSummary {
        ProviderSummary {
            com_registered: verdict.get("com_registered").and_then(|v| v.as_bool()).unwrap_or(false),
            os_registered: verdict.get("os_registered").and_then(|v| v.as_bool()).unwrap_or(false),
            enabled: verdict.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false),
        }
    }

    pub fn register() -> Result<ProviderSummary, String> {
        // The CLI's own autofill sync covers new installs; the front ends
        // call sync_credentials() separately for an explicit refresh.
        Ok(summary_of(&run_provider("--register")?))
    }

    pub fn unregister() -> Result<(), String> {
        run_provider("--unregister").map(|_| ())
    }

    pub fn status() -> Option<ProviderSummary> {
        Some(summary_of(&run_provider("--status").ok()?))
    }

    /// Push the vault's passkey metadata into the OS autofill cache. The
    /// provider reads it over the pipe itself, so this requires an unlocked
    /// vault exactly like every other vault reader.
    pub fn sync_credentials(_state: &Arc<AppState>) -> Result<usize, String> {
        let verdict = run_provider("--sync-credentials")?;
        Ok(verdict.get("synced").and_then(|v| v.as_u64()).unwrap_or(0) as usize)
    }

    /// Debounced automatic refresh of the OS autofill cache.
    ///
    /// Called on every vault-change notification (and unlock), from whatever
    /// thread raised it: coalesces a burst of changes into one provider run
    /// 1.5 s later. Failures are deliberately silent — a cache that lags
    /// until the next manual sync or unlock is a cosmetic issue, while a
    /// background task that could surface errors or prompts would be a
    /// behavior change. The provider's own sync re-checks the session and
    /// refuses a locked vault, which is the correct outcome after auto-lock.
    pub fn schedule_autofill_sync(state: &Arc<AppState>) {
        static PENDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if PENDING.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return; // a refresh is already scheduled
        }
        let state = state.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(1500));
            PENDING.store(false, std::sync::atomic::Ordering::SeqCst);
            let unlocked = {
                let session = state.session.read();
                session.active && !session.is_expired()
            };
            if !unlocked {
                return;
            }
            match run_provider("--sync-credentials") {
                Ok(verdict) => tracing::debug!(
                    "OS autofill cache refreshed: {} passkey(s)",
                    verdict.get("synced").and_then(|v| v.as_u64()).unwrap_or(0)
                ),
                Err(e) => tracing::debug!("OS autofill cache refresh skipped: {e}"),
            }
        });
    }
}

#[cfg(not(windows))]
mod fallback {
    use crate::AppState;
    use std::sync::Arc;

    #[derive(Debug, Clone, serde::Serialize)]
    pub struct ProviderSummary {
        pub com_registered: bool,
        pub os_registered: bool,
        pub enabled: bool,
    }

    pub fn register() -> Result<ProviderSummary, String> {
        Err("System-wide passkey provider is Windows-only".to_string())
    }

    pub fn unregister() -> Result<(), String> {
        Err("System-wide passkey provider is Windows-only".to_string())
    }

    pub fn status() -> Option<ProviderSummary> {
        None
    }

    pub fn sync_credentials(_state: &Arc<AppState>) -> Result<usize, String> {
        Err("System-wide passkey provider is Windows-only".to_string())
    }

    pub fn schedule_autofill_sync(_state: &Arc<AppState>) {}
}

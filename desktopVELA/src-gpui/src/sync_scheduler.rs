//! Automatic sync scheduling — the port of `App.tsx`'s two effects:
//!
//! ```ts
//! // sync on unlock when sync_on_startup is set
//! useEffect(() => { if (session?.active && settings?.sync_on_startup) doSync(); }, ...);
//! // and every background_sync_minutes while unlocked
//! useEffect(() => { const t = setInterval(doSync, syncMinutes * 60_000); ... });
//! ```
//!
//! In the Tauri build the renderer owns that scheduling, so the gpui port
//! (which has no renderer) dropped it entirely — only the manual "Sync now"
//! paths (`SettingsScreen::sync_now`, tray menu) remained, and the vault
//! never synced on its own. This module restores both behaviors.
//!
//! The returned [`Task`] runs until dropped: [`AppShell`] holds it for its
//! lifetime, and `AppShell` is created on unlock and destroyed on lock, so
//! background sync stops exactly when the session does — matching the
//! original's `if (!session?.active) return` guard.

use std::sync::Arc;
use std::time::{Duration, Instant};

use gpui::{AsyncApp, Context, Task};

use vela_desktop_core::settings::Settings;
use vela_desktop_core::AppState;

/// How often the loop wakes to check whether a sync is due. A short fixed
/// tick (instead of sleeping the whole configured interval) means a changed
/// `background_sync_minutes` takes effect within a tick — same net result as
/// the original's useEffect re-running on settings change, without needing
/// a settings-change subscription.
const TICK: Duration = Duration::from_secs(30);

/// Start the scheduler. `cx` is AppShell's context; the task outlives the
/// call and must be held by the caller.
pub fn start(app_state: Arc<AppState>, cx: &mut Context<'_, crate::views::app_shell::AppShell>) -> Task<()> {
    cx.spawn(async move |_this, cx| {
        // Startup sync, mirroring
        // `if (session?.active && settings?.sync_on_startup) doSync()`.
        if load_settings(&app_state).sync_on_startup {
            run_sync(&app_state, cx, "startup").await;
        }

        let mut last_sync = Instant::now();
        loop {
            cx.background_executor().timer(TICK).await;

            let minutes = load_settings(&app_state).background_sync_minutes;
            // The original treats 0 as "Never" (`if (syncMinutes <= 0) return`).
            if minutes == 0 {
                continue;
            }
            if last_sync.elapsed() >= Duration::from_secs(minutes as u64 * 60) {
                run_sync(&app_state, cx, "background").await;
                last_sync = Instant::now();
            }
        }
    })
}

/// Fresh read from disk on every call: cheap at tick granularity and always
/// reflects the latest Settings save, with no change-notification plumbing.
fn load_settings(app_state: &AppState) -> Settings {
    app_state.store.load_settings().unwrap_or_default()
}

/// Fire one sync. Background syncs are silent — the original's interval
/// `doSync()` doesn't toast either; failures are only logged (a manual
/// "Sync now" reports through the UI as before). Overlap with a manual sync
/// is fine: core serializes runs on `AppState::sync_mutex`.
async fn run_sync(app_state: &Arc<AppState>, cx: &AsyncApp, why: &'static str) {
    // Real network I/O (chunk upload/download, server auth) — must run on
    // the tokio runtime via gpui_tokio's bridge, exactly like
    // `SettingsScreen::sync_now`, never on `cx.background_spawn`'s pool.
    let result = gpui_tokio::Tokio::spawn(cx, {
        let app_state = app_state.clone();
        async move { vela_desktop_core::sync::trigger_sync(&app_state).await }
    })
    .await;

    match result {
        Ok(Ok(status)) => {
            if let Some(err) = &status.error {
                tracing::warn!("{why} sync reported an error: {err}");
            } else if !status.conflicts.is_empty() {
                tracing::warn!("{why} sync: {} conflict(s) detected", status.conflicts.len());
            } else {
                tracing::info!("{why} sync completed");
            }
        }
        Ok(Err(e)) => tracing::warn!("{why} sync failed: {e}"),
        Err(e) => tracing::warn!("{why} sync task failed: {e}"),
    }
}

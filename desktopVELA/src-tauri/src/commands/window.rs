use tauri::{command, AppHandle, Emitter, Manager, WebviewUrl, WebviewWindowBuilder, WindowEvent};

pub const QUICK_SEARCH_LABEL: &str = "quick-search";

/// Disable WebKit subsystems VELA's UI never touches (no canvas/WebGL, no
/// audio/video, no camera/mic, no WebRTC, no Java/NPAPI plugins). Wry enables
/// WebGL and WebAudio by default for every webview regardless of whether the
/// app uses them; each of these subsystems otherwise reserves memory (shader
/// compiler contexts, media pipeline registries, ICE/DTLS stacks, ...) just
/// by being enabled. Also disables the back/forward page cache, which is
/// dead weight for a single-page app that never navigates away from
/// index.html.
#[cfg(target_os = "linux")]
pub fn trim_unused_webkit_subsystems<R: tauri::Runtime>(window: &tauri::WebviewWindow<R>) {
    let _ = window.with_webview(|w| {
        use webkit2gtk::{SettingsExt, WebViewExt};
        let webview = w.inner();
        if let Some(settings) = WebViewExt::settings(&webview) {
            settings.set_enable_webgl(false);
            settings.set_enable_webaudio(false);
            settings.set_enable_media(false);
            settings.set_enable_media_stream(false);
            settings.set_enable_webrtc(false);
            settings.set_enable_mediasource(false);
            settings.set_enable_encrypted_media(false);
            settings.set_enable_java(false);
            settings.set_enable_plugins(false);
            settings.set_enable_page_cache(false);
        }
    });
}

/// Show the quick-search popup as its own small always-on-top window instead
/// of surfacing the whole main window: a freshly mapped window appears on the
/// compositor's active workspace, so the popup opens over whatever the user
/// is doing while the main app stays wherever it lives. Closed (not just
/// hidden) on Escape/blur so every reopen maps on the then-active workspace
/// again and the idle app isn't carrying a second full WebKit process (and
/// its ~100+ MB) for a popup that's used for a few seconds at a time.
pub fn open_quick_search_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(QUICK_SEARCH_LABEL) {
        let _ = window.show();
        let _ = window.set_focus();
        let _ = window.emit("quick-search-shown", ());
        return;
    }

    let built = WebviewWindowBuilder::new(
        app,
        QUICK_SEARCH_LABEL,
        WebviewUrl::App("index.html".into()),
    )
    .title("VELA Quick Search")
    .inner_size(640.0, 440.0)
    .resizable(false)
    .maximizable(false)
    .minimizable(false)
    .decorations(false)
    .always_on_top(true)
    .skip_taskbar(true)
    .center()
    .focused(true)
    .build();

    match built {
        Ok(window) => {
            #[cfg(target_os = "linux")]
            trim_unused_webkit_subsystems(&window);
            let window_for_events = window.clone();
            window.on_window_event(move |event| {
                if let WindowEvent::Focused(false) = event {
                    let _ = window_for_events.close();
                }
            });
        }
        Err(e) => tracing::error!("Failed to create quick search window: {e}"),
    }
}

#[command]
pub async fn hide_quick_search(app: AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window(QUICK_SEARCH_LABEL) {
        window.close().map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Called from the quick-search popup when the user picks a result (or asks
/// to open the app): hides the popup, surfaces the main window, and — when a
/// vault item was selected — forwards it for the main window to display. The
/// item payload is the frontend's own item shape, passed through untouched.
#[command]
pub async fn quick_search_open_item(
    app: AppHandle,
    item: Option<serde_json::Value>,
) -> Result<(), String> {
    if let Some(window) = app.get_webview_window(QUICK_SEARCH_LABEL) {
        let _ = window.close();
    }
    if let Some(main) = app.get_webview_window("main") {
        main.show().map_err(|e| e.to_string())?;
        let _ = main.set_focus();
        if let Some(item) = item {
            main.emit("open-item", item).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

#[command]
pub async fn minimize_window(app: AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        window.minimize().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[command]
pub async fn maximize_window(app: AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        if window.is_maximized().unwrap_or(false) {
            window.unmaximize().map_err(|e| e.to_string())?;
        } else {
            window.maximize().map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

#[command]
pub async fn close_window(app: AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        window.hide().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[command]
pub async fn toggle_always_on_top(app: AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        let is_always_on_top = window.is_always_on_top().unwrap_or(false);
        window
            .set_always_on_top(!is_always_on_top)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

//! Native system tray, via `ksni` (StatusNotifierItem over D-Bus). Uses
//! ksni's `async-io` backend (`zbus/async-io`), matching this app's existing
//! zbus-executor choice for `ashpd`/`secret-service` (see
//! `vela-desktop-core/Cargo.toml`'s comments on that fix) — async-io's
//! reactor self-initializes lazily regardless of what polls it, so calling
//! `.spawn().await` from gpui's own foreground executor (a plain
//! single-threaded cooperative scheduler, neither tokio nor async-io itself)
//! works the same way the secret-service fix already proved out.
//!
//! Menu matches the shipped Tauri app's tray 1:1 (Open VELA / Lock Now /
//! Sync Now / Quit). One deliberate behavior difference: left-click
//! activation always raises+focuses the window rather than the original's
//! hide/show toggle. gpui-ce's `Window` has no hide/is-visible primitive on
//! Linux (`activate_window`/`minimize_window` are the only lifecycle
//! methods) — Wayland has no client-side "hide" concept the way X11 does,
//! only minimize, which Hyprland's scrolling-tiling model doesn't
//! meaningfully support either. Raising is the closest available
//! equivalent, and the shipped app never hides the window any other way
//! (no close-to-tray interception exists there either — closing the window
//! quits, same as this port).

use std::sync::mpsc::Sender;
use std::sync::Arc;

use ksni::menu::{MenuItem, StandardItem};
use ksni::{Icon, ToolTip};
use vela_desktop_core::AppState;

pub enum TrayCommand {
    /// Raise and focus the main window ("Open VELA" menu item, or left-click
    /// on the tray icon itself).
    Activate,
    Quit,
}

pub struct VelaTray {
    app_state: Arc<AppState>,
    runtime: tokio::runtime::Handle,
    cmd_tx: Sender<TrayCommand>,
    icon: Icon,
}

impl VelaTray {
    pub fn new(app_state: Arc<AppState>, runtime: tokio::runtime::Handle, cmd_tx: Sender<TrayCommand>) -> Self {
        Self { app_state, runtime, cmd_tx, icon: load_icon() }
    }
}

/// Same bundled icon the shipped Tauri app's tray uses. `ksni::Icon` wants
/// ARGB32 in network (big-endian) byte order; `image` gives RGBA8, so the
/// channels are reordered per-pixel.
fn load_icon() -> Icon {
    let bytes = include_bytes!("../../src-tauri/icons/icon.png");
    let img = image::load_from_memory(bytes).expect("bundled tray icon must decode").to_rgba8();
    let (width, height) = img.dimensions();
    let mut data = img.into_raw();
    for px in data.chunks_exact_mut(4) {
        let (r, g, b, a) = (px[0], px[1], px[2], px[3]);
        px[0] = a;
        px[1] = r;
        px[2] = g;
        px[3] = b;
    }
    Icon { width: width as i32, height: height as i32, data }
}

impl ksni::Tray for VelaTray {
    fn id(&self) -> String {
        "com.vela.vault.desktop".into()
    }

    fn title(&self) -> String {
        "VELA".into()
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        vec![self.icon.clone()]
    }

    fn tool_tip(&self) -> ToolTip {
        ToolTip { title: "VELA — Zero-Knowledge Vault".into(), ..Default::default() }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        let _ = self.cmd_tx.send(TrayCommand::Activate);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        vec![
            StandardItem {
                label: "Open VELA".into(),
                activate: Box::new(|this: &mut Self| {
                    let _ = this.cmd_tx.send(TrayCommand::Activate);
                }),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Lock Now".into(),
                activate: Box::new(|this: &mut Self| {
                    vela_desktop_core::commands::session::lock_session(&this.app_state);
                    tracing::info!("Session locked via tray");
                }),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Sync Now".into(),
                activate: Box::new(|this: &mut Self| {
                    let app_state = this.app_state.clone();
                    this.runtime.spawn(async move {
                        match vela_desktop_core::sync::trigger_sync(&app_state).await {
                            Ok(status) => {
                                if let Some(err) = status.error {
                                    tracing::warn!("Manual sync via tray finished with an error: {err}");
                                } else {
                                    tracing::info!("Manual sync via tray complete");
                                }
                            }
                            Err(e) => tracing::warn!("Manual sync via tray failed: {e}"),
                        }
                    });
                    tracing::info!("Manual sync triggered via tray");
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit".into(),
                activate: Box::new(|this: &mut Self| {
                    tracing::info!("Application quit requested via tray");
                    let _ = this.cmd_tx.send(TrayCommand::Quit);
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}

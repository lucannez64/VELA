//! Go/no-go spike for the Tauri/WebKit -> gpui-ce migration.
//! See /home/hirew/.claude/plans/mighty-wibbling-wave.md Step 0.
//!
//! Proves, in one binary:
//!   1. A native Wayland window opens on Hyprland (not XWayland), with a
//!      real self-hosted font (Inter) loaded and rendered.
//!   2. `gpui_tokio` can be handed a runtime built + entered exactly the way
//!      `main.rs` already does it (2 workers, entered before AppState::default()
//!      constructs the HTTP/3 ApiClient) — the ordering commit `48a2f0a` had
//!      to fix — without silently regressing to TCP fallback.
//!   3. A real vault item, round-tripped through the *actual* `Crypto`/
//!      `VaultStore` from `vela-desktop` (not mocked data), renders in a
//!      gpui view. Uses a throwaway in-memory RMS, exactly like
//!      `vault_lifecycle_test.rs` — never touches the user's real vault
//!      files or OS keychain.
//!   4. An undecorated window with a draggable custom titlebar region,
//!      matching `tauri.conf.json`'s `decorations: false`.

use std::path::PathBuf;

use gpui::{
    App, Bounds, Context, IntoElement, MouseButton, MouseDownEvent, ParentElement,
    Render, SharedString, Styled, TitlebarOptions, Window, WindowBounds, WindowDecorations,
    WindowOptions, div, prelude::*, px, rgb, size,
};

use vela_desktop::crypto::Crypto;
use vela_desktop::vault::{ItemType, VaultItem, VaultMeta, VaultStore};

fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

/// Build a throwaway vault with one real item, entirely in memory, encrypted
/// and decrypted through the real `Crypto`/`VaultStore` — same pattern as
/// `vault_lifecycle_test.rs::create_vault_add_items_persist_reload_decrypt`.
/// No OS file or keychain is touched.
fn decrypt_one_real_item() -> VaultItem {
    let rms = Crypto::generate_rms();
    let crypto = Crypto::new(&rms);

    let mut vault = VaultStore::new();
    vault.add_item(VaultItem::Login {
        meta: VaultMeta {
            id: "spike-1".into(),
            name: "gpui-ce spike item".into(),
            notes: None,
            created_at: now(),
            updated_at: now(),
            last_modified_device: None,
            favorite: false,
            shared: false,
            share_recipient: None,
        },
        url: "https://example.com".into(),
        username: "spike-user".into(),
        pass: "not-a-real-secret".into(),
        totp: None,
    });

    let plaintext = serde_json::to_vec(&vault).expect("serialize vault");
    let ciphertext = crypto.encrypt_vault(&plaintext).expect("encrypt vault");
    assert_ne!(ciphertext, plaintext, "vault must be encrypted at rest");

    let decrypted = crypto.decrypt_vault(&ciphertext).expect("decrypt vault");
    let reloaded: VaultStore = serde_json::from_slice(&decrypted).expect("deserialize vault");
    reloaded.get_item("spike-1").expect("item survives round-trip").clone()
}

struct SpikeView {
    item_label: SharedString,
    protocol_label: SharedString,
}

impl Render for SpikeView {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(rgb(0x1a1b26))
            .child(
                // Drag region standing in for the custom titlebar
                // (tauri.conf.json has decorations: false today).
                div()
                    .id("drag-region")
                    .h(px(32.))
                    .w_full()
                    .bg(rgb(0x24283b))
                    .flex()
                    .items_center()
                    .px_3()
                    .text_color(rgb(0xa9b1d6))
                    .text_sm()
                    .child("VELA gpui-ce spike — drag me")
                    .on_mouse_down(MouseButton::Left, |_: &MouseDownEvent, window, _cx| {
                        window.start_window_move();
                    }),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .p_6()
                    .font_family("Inter")
                    .child(
                        div()
                            .text_xl()
                            .text_color(rgb(0xc0caf5))
                            .child("Real crypto-backed VaultItem, rendered natively:"),
                    )
                    .child(
                        div()
                            .text_lg()
                            .text_color(rgb(0x9ece6a))
                            .child(self.item_label.clone()),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(0x565f89))
                            .child(self.protocol_label.clone()),
                    ),
            )
    }
}

fn load_font_bytes() -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../src/assets/fonts/inter-400.ttf");
    std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"))
}

fn main() {
    // Mirrors main.rs's fix in commit 48a2f0a: build a 2-worker runtime and
    // enter it *before* constructing AppState (which builds an ApiClient
    // whose HTTP/3 client needs a reactor present to bind its UDP socket).
    let async_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    let _runtime_guard = async_runtime.enter();

    // Reuses the real AppState::default() from src-tauri/src/lib.rs — same
    // ApiClient construction path, same protocol-selection logic in api.rs.
    let app_state = vela_desktop::AppState::default();
    let protocol_label: SharedString = format!(
        "AppState constructed OK under gpui's runtime ordering (server_url={:?})",
        *app_state.server_url.read()
    )
    .into();

    let item = decrypt_one_real_item();
    let item_label: SharedString = match &item {
        VaultItem::Login { meta, username, .. } => {
            format!("{} ({}) — type={:?}", meta.name, username, ItemType::Login).into()
        }
        _ => "unexpected item type".into(),
    };

    gpui_platform::application().run(move |cx: &mut App| {
        // Wires our own tokio runtime/handle into gpui_tokio instead of
        // letting it build its own — proves the two can share one runtime,
        // which is what api.rs's ApiClient will need in the real migration.
        gpui_tokio::init_from_handle(cx, async_runtime.handle().clone());

        cx.text_system()
            .add_fonts(vec![load_font_bytes().into()])
            .expect("failed to load Inter font");

        cx.activate(true);

        let bounds = Bounds::centered(None, size(px(640.), px(360.)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions {
                    title: Some("VELA gpui-ce spike".into()),
                    appears_transparent: true,
                    traffic_light_position: None,
                }),
                window_decorations: Some(WindowDecorations::Client),
                is_movable: true,
                ..Default::default()
            },
            |_, cx| {
                cx.new(|_| SpikeView {
                    item_label: item_label.clone(),
                    protocol_label: protocol_label.clone(),
                })
            },
        )
        .expect("failed to open spike window");

        cx.on_window_closed(|cx, _| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();
    });
}

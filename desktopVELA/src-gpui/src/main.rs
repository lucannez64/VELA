//! VELA desktop, native gpui-ce build. See
//! /home/hirew/.claude/plans/mighty-wibbling-wave.md Step 2.

#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(target_os = "linux")]
#[allow(non_upper_case_globals)]
#[export_name = "malloc_conf"]
pub static malloc_conf: &[u8] =
    b"background_thread:true,narenas:2,dirty_decay_ms:2000,muzzy_decay_ms:2000\0";

mod animation;
mod background;
mod clipboard;
mod favicon_ui;
mod fonts;
mod host;
mod icon;
mod keyboard;
mod qr;
mod quick_search;
mod sidebar;
mod sync_scheduler;
mod theme;
mod titlebar;
mod toast;
mod tray;
mod views;

use std::sync::Arc;

use gpui::{
    div, prelude::*, px, rgba, size, App, Bounds, Context, Entity, IntoElement, MouseButton,
    Render, Subscription, TitlebarOptions, Window, WindowBounds, WindowDecorations, WindowOptions,
};
use ksni::TrayMethods;

use crate::icon::icon;
use theme::{ActiveTheme, Palette, ThemeId};
use titlebar::{TitleBar, TitleBarEvent};
use vela_desktop_core::{commands::session, AppState};
use views::app_shell::{AppShell, AppShellEvent};
use views::biometric_gate::{BiometricGate, BiometricGateEvent};
use views::setup_screen::{SetupScreen, SetupScreenEvent};
use views::welcome::{WelcomeEvent, WelcomeScreen};

enum Screen {
    Welcome(Entity<WelcomeScreen>),
    Setup(Entity<SetupScreen>),
    BiometricGate(Entity<BiometricGate>),
    App(Entity<AppShell>),
}

struct RootView {
    app_state: Arc<AppState>,
    screen: Screen,
    title_bar: Entity<TitleBar>,
    _subscriptions: Vec<Subscription>,
}

impl RootView {
    fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<ActiveTheme>(|_, cx| cx.notify()).detach();
        cx.observe_global::<toast::ToastGlobal>(|_, cx| cx.notify()).detach();
        // A presence confirmation (in-core login, passkey use) arrives from a
        // background thread and is parked in a global; render it as a modal.
        cx.observe_global::<host::PresencePromptGlobal>(|_, cx| cx.notify()).detach();
        // The quick-search popup lives in its own window, so it can't reach
        // this view through `cx.subscribe` (that needs both entities in one
        // window's tree). It publishes the picked item as a global instead,
        // and this is where the main window acts on it.
        cx.observe_global::<quick_search::QuickSearchSelection>(|this, cx| {
            let picked = cx.global::<quick_search::QuickSearchSelection>().0.clone();
            let Some(item) = picked else { return };
            // A pick against a locked vault carries no item — the popup's
            // "press Enter to open VELA" path — and just raising the window
            // (already done by the popup) is the whole action there.
            if let Screen::App(app) = &this.screen {
                let id = item.id().to_string();
                app.update(cx, |app, cx| app.open_item(id, cx));
                // The popup just closed itself; without this the main window
                // stays behind whatever the user was actually looking at when
                // they hit the shortcut.
                cx.activate(true);
            }
        })
        .detach();
        let title_bar = cx.new({
            let app_state = app_state.clone();
            move |cx| TitleBar::new(app_state, cx)
        });
        let mut this = Self {
            app_state: app_state.clone(),
            // Placeholder until show_welcome/show_biometric_gate below sets
            // the real first screen — both always run before this value is
            // ever rendered.
            screen: Screen::Welcome(cx.new({
                let app_state = app_state.clone();
                move |cx| WelcomeScreen::new(app_state, cx)
            })),
            title_bar,
            _subscriptions: Vec::new(),
        };
        let title_bar_sub = cx.subscribe(&this.title_bar, |this, _title_bar, event, cx| match event {
            TitleBarEvent::Locked => {
                tracing::info!("Locked via titlebar — showing BiometricGate");
                this.show_biometric_gate(cx);
            }
        });
        this._subscriptions.push(title_bar_sub);
        // Mirrors App.tsx's `isFirstLaunch` check: an existing on-disk vault
        // means we're a returning user (show the unlock gate), otherwise
        // first-launch (show Welcome). Same on-disk store as the shipped
        // Tauri app — this reads/unlocks the real vault, not a fixture.
        if session::check_vault_exists(&app_state) {
            this.show_biometric_gate(cx);
        } else {
            this.show_welcome(cx);
        }
        this
    }

    fn show_welcome(&mut self, cx: &mut Context<Self>) {
        let welcome = cx.new({
            let app_state = self.app_state.clone();
            move |cx| WelcomeScreen::new(app_state, cx)
        });
        let subscription = cx.subscribe(&welcome, |this, _welcome, event, cx| match event {
            WelcomeEvent::CreateVault | WelcomeEvent::AddExistingDevice => {
                this.show_setup(cx);
            }
            // Both of these end with the vault present *and* the session
            // already unlocked, so they go straight to the shell — routing
            // via BiometricGate would ask the user to unlock something that
            // is already unlocked.
            WelcomeEvent::ImportComplete => {
                tracing::info!("Enrollment import complete — showing app shell");
                this.show_app(cx);
            }
            WelcomeEvent::AccountRecovered => {
                tracing::info!("Account recovery complete — showing app shell");
                this.show_app(cx);
            }
        });
        self.screen = Screen::Welcome(welcome);
        self._subscriptions.push(subscription);
        cx.notify();
    }

    fn show_setup(&mut self, cx: &mut Context<Self>) {
        let setup = cx.new({
            let app_state = self.app_state.clone();
            move |cx| SetupScreen::new(app_state, cx)
        });
        let subscription = cx.subscribe(&setup, |this, _setup, event, cx| match event {
            SetupScreenEvent::Complete => this.show_biometric_gate(cx),
        });
        self.screen = Screen::Setup(setup);
        self._subscriptions.push(subscription);
        cx.notify();
    }

    fn show_biometric_gate(&mut self, cx: &mut Context<Self>) {
        let gate = cx.new({
            let app_state = self.app_state.clone();
            move |cx| BiometricGate::new(app_state, cx)
        });
        let subscription = cx.subscribe(&gate, |this, _gate, event, cx| match event {
            BiometricGateEvent::Unlocked => {
                tracing::info!("Unlocked — showing app shell");
                this.show_app(cx);
            }
            BiometricGateEvent::VaultReset => {
                tracing::info!("Vault reset — showing Welcome");
                this.show_welcome(cx);
            }
        });
        self.screen = Screen::BiometricGate(gate);
        self._subscriptions.push(subscription);
        cx.notify();
    }

    fn show_app(&mut self, cx: &mut Context<Self>) {
        let app = cx.new({
            let app_state = self.app_state.clone();
            move |cx| AppShell::new(app_state, cx)
        });
        let subscription = cx.subscribe(&app, |this, _app, event, cx| match event {
            AppShellEvent::ThemeChanged(theme_id) => {
                cx.set_global(ActiveTheme(*theme_id));
            }
            AppShellEvent::Locked => {
                tracing::info!("Locked — showing BiometricGate");
                this.show_biometric_gate(cx);
            }
            AppShellEvent::VaultDeleted => {
                tracing::info!("Vault deleted — showing Welcome");
                this.show_welcome(cx);
            }
        });
        self.screen = Screen::App(app);
        self._subscriptions.push(subscription);
        cx.notify();
    }
}

impl Render for RootView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = theme::current_palette(cx);

        let content: gpui::AnyElement = match &self.screen {
            Screen::Welcome(welcome) => welcome.clone().into_any_element(),
            Screen::Setup(setup) => setup.clone().into_any_element(),
            Screen::BiometricGate(gate) => gate.clone().into_any_element(),
            Screen::App(app) => app.clone().into_any_element(),
        };

        div()
            .relative()
            .size_full()
            .flex()
            .flex_col()
            .bg(palette.surface)
            .font_family(fonts::LABEL)
            // Window-wide Tab / Shift-Tab focus movement. It lives at the root
            // because the tab order is a property of the window, not of any
            // one screen, and because a key listener only sees keystrokes on
            // the focused element's dispatch path — anything shallower than
            // the root would miss fields rendered outside its subtree.
            .on_key_down(keyboard::navigate_on_tab)
            .child(self.title_bar.clone())
            .child(
                // `.overflow_hidden()` is load-bearing, not decorative: without
                // it, a tall child (e.g. AppShell with a long VaultBrowser
                // list) can grow this flex-1 wrapper past the window's real
                // height instead of being clipped to it — and since AppShell's
                // Sidebar sizes itself via `h_full()` off this same ancestor
                // chain, an overflowing content area silently stretches the
                // sidebar too, pushing its footer (Add Item / Lock Session)
                // below the visible viewport.
                div().flex_1().overflow_hidden().child(content),
            )
            .children(toast::render(&palette, cx))
            .when_some(
                cx.try_global::<host::PresencePromptGlobal>()
                    .and_then(|g| g.0.clone()),
                |el, prompt| el.child(presence_modal(&palette, prompt)),
            )
    }
}

/// The modal that asks "Sign in to X by sending your saved password…?" —
/// the gpui build's answer to the Tauri app's confirmation dialog. It answers
/// through the reply channel the requesting thread is blocked on, then
/// dismisses itself.
fn presence_modal(palette: &Palette, prompt: host::PresencePrompt) -> gpui::AnyElement {
    let approve = prompt.reply.clone();
    let deny = prompt.reply.clone();
    let (site, requester) = parse_presence_prompt(&prompt.prompt);
    let details = if let Some(requester) = &requester {
        format!("Requested by {requester}")
    } else {
        prompt.prompt.clone()
    };

    div()
        .id("presence-scrim")
        .absolute()
        .inset_0()
        .bg(rgba(0x0000_00a8))
        // `occlude()` is the whole fix: it sets this hitbox to
        // `HitboxBehavior::BlockMouse`, which stops the window's hit-test loop
        // at this element. Without it, gpui's hit-test only *stops* on
        // BlockMouse hitboxes — handlers on this div don't prevent hits from
        // reaching the vault behind, so clicks and hover both fall through.
        .occlude()
        .flex()
        .items_center()
        .justify_center()
        .child(
            div()
                .w_full()
                .max_w(px(460.))
                .mx_6()
                .rounded_2xl()
                .bg(palette.surface_container)
                .p_6()
                .flex()
                .flex_col()
                .gap_5()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .child(
                            div()
                                .size(px(40.))
                                .flex()
                                .items_center()
                                .justify_center()
                                .rounded_full()
                                .bg(palette.primary_dim)
                                .child(icon("shield_lock", px(22.), palette.surface)),
                        )
                        .child(
                            div()
                                .flex_col()
                                .child(
                                    div()
                                        .font_family(fonts::LABEL)
                                        .text_color(palette.on_surface)
                                        .font_weight(gpui::FontWeight::BOLD)
                                        .child("Approve sign in"),
                                )
                                .child(
                                    div()
                                        .font_family(fonts::BODY)
                                        .text_color(palette.on_surface_variant)
                                        .text_size(px(12.))
                                        .child(details),
                                ),
                        ),
                )
                .child(
                    div()
                        .rounded_lg()
                        .bg(palette.surface_container_highest)
                        .px_4()
                        .py_3()
                        .child(
                            div()
                                .font_family(fonts::BODY)
                                .text_color(palette.on_surface_variant)
                                .text_size(px(12.))
                                .child("VELA would sign you in to"),
                        )
                        .child(
                            div()
                                .font_family(fonts::BODY)
                                .text_color(palette.on_surface)
                                .font_weight(gpui::FontWeight::BOLD)
                                .child(site),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .justify_end()
                        .gap_2()
                        .child(
                            div()
                                .px_5()
                                .py_2()
                                .rounded_lg()
                                .bg(palette.surface_container_high)
                                .text_color(palette.on_surface)
                                .cursor_pointer()
                                .on_mouse_down(MouseButton::Left, move |_, _, cx| {
                                    let _ = deny.send(Some(false));
                                    cx.set_global(host::PresencePromptGlobal(None));
                                })
                                .child("Deny"),
                        )
                        .child(
                            div()
                                .px_5()
                                .py_2()
                                .rounded_lg()
                                .bg(palette.primary)
                                .text_color(palette.on_primary)
                                .font_weight(gpui::FontWeight::BOLD)
                                .cursor_pointer()
                                .on_mouse_down(MouseButton::Left, move |_, _, cx| {
                                    let _ = approve.send(Some(true));
                                    cx.set_global(host::PresencePromptGlobal(None));
                                })
                                .child("Approve"),
                        ),
                ),
        )
        .into_any_element()
}

/// Pull the site name and requester out of the presence prompt text
/// ("Sign in to {site} by sending your saved password to that site, at the
/// request of {requester}") so the modal can show them cleanly instead of the
/// raw sentence.
fn parse_presence_prompt(prompt: &str) -> (String, Option<String>) {
    let site = prompt
        .strip_prefix("Sign in to ")
        .and_then(|s| s.split(" by sending").next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(prompt)
        .to_string();
    let requester = prompt
        .split("at the request of ")
        .nth(1)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    (site, requester)
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Same 2-worker runtime construction/entry order as src-tauri/src/main.rs
    // (commit 48a2f0a) — required before AppState::default() constructs an
    // ApiClient whose HTTP/3 client needs a reactor present to bind its UDP
    // socket.
    let async_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    let _runtime_guard = async_runtime.enter();

    let app_state = Arc::new(AppState::default());

    // Claim our portal app id *before* gpui starts. This ordering is
    // load-bearing, not cosmetic: `ashpd` caches one process-wide session-bus
    // connection, xdg-desktop-portal binds an app id to that connection
    // exactly once, and `gpui_linux`'s `xdg_desktop_portal.rs` opens
    // `org.freedesktop.portal.Settings` (color-scheme/cursor-theme watcher)
    // during platform init — i.e. before anything inside the `run(...)`
    // closure executes. Registering from the shortcut task, as this used to,
    // always lost that race and failed with "Connection already associated
    // with an application ID", which then made the GlobalShortcuts session
    // fail with "An app id is required".
    //
    // Blocking here is fine and deliberate: it's one short D-Bus round trip
    // before any window exists. `futures::executor::block_on` (rather than
    // the tokio runtime above) because ashpd is pinned to the `async-io`
    // zbus backend workspace-wide, and async-io self-starts its own reactor
    // thread on first use regardless of which executor polls it.
    #[cfg(target_os = "linux")]
    if vela_desktop_core::wayland_shortcut::is_wayland_session() {
        futures::executor::block_on(vela_desktop_core::wayland_shortcut::register_app_id(
            host::APP_IDENTIFIER,
        ));
    }

    // Real settings read (plain sync fs read, no unlock required) so the
    // window opens in the user's actually-saved theme from frame one,
    // rather than always starting on Vela and only picking up the real
    // theme once something happens to touch the global later.
    let initial_settings = vela_desktop_core::commands::settings::get_settings(&app_state).ok();
    let initial_theme = initial_settings
        .as_ref()
        .map(|s| ThemeId::from_setting(&s.theme))
        .unwrap_or(ThemeId::Vela);
    let initial_clipboard_clear_seconds = initial_settings.as_ref().map(|s| s.clipboard_clear_seconds);
    let quick_search_shortcut = initial_settings
        .as_ref()
        .map(|s| s.quick_search_shortcut.clone())
        .unwrap_or_else(|| "Ctrl+Alt+V".to_string());

    // Only a cheap Handle is moved into the one-shot startup closure below —
    // `.run(...)` invokes it once and drops it right after, so moving the
    // actual `Runtime` in there would drop (and shut down) the runtime
    // itself the moment the window finished opening. Keeping `async_runtime`
    // here, in `main()`'s own frame, keeps its worker/blocking-pool threads
    // alive for as long as `.run()` blocks (i.e. the whole app lifetime) —
    // without this, any unlock attempt made after startup submits its
    // `tokio::task::spawn_blocking` work to an already-dead runtime and gets
    // an immediate "task was cancelled" error.
    let runtime_handle = async_runtime.handle().clone();

    gpui_platform::application().run(move |cx: &mut App| {
        let tray_runtime_handle = runtime_handle.clone();
        gpui_tokio::init_from_handle(cx, runtime_handle);
        cx.set_global(ActiveTheme(initial_theme));
        if let Some(seconds) = initial_clipboard_clear_seconds {
            clipboard::set_clear_seconds(cx, seconds);
        }

        cx.bind_keys(
            gpui_elements::editable_text::actions::default_bindings()
                .as_keybindings(Some(gpui_elements::editable_text::actions::DEFAULT_INPUT_CONTEXT)),
        );

        for (font_file, font_bytes) in fonts::FONT_FILES {
            cx.text_system()
                .add_fonts(vec![std::borrow::Cow::Borrowed(*font_bytes)])
                .unwrap_or_else(|e| panic!("failed to load font {font_file}: {e}"));
        }

        cx.activate(true);

        let bounds = Bounds::centered(None, size(px(1024.), px(720.)), cx);
        let app_state_for_tray = app_state.clone();
        let app_state_for_auto_lock = app_state.clone();
        let app_state_for_ipc = app_state.clone();
        let app_state_for_quick_search = app_state.clone();
        let app_state = app_state.clone();
        let window_handle = cx
            .open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(bounds)),
                    titlebar: Some(TitlebarOptions {
                        title: Some("VELA".into()),
                        appears_transparent: true,
                        traffic_light_position: None,
                    }),
                    window_decorations: Some(WindowDecorations::Client),
                    is_movable: true,
                    ..Default::default()
                },
                move |_, cx| cx.new(|cx| RootView::new(app_state, cx)),
            )
            .expect("failed to open main window");

        cx.on_window_closed(|cx, _| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();

        // System tray: registers a real StatusNotifierItem over D-Bus (see
        // tray.rs's module doc for why the async-io-backed `.spawn().await`
        // is safe to run from gpui's own foreground executor here). The
        // returned `Handle` is intentionally dropped — the tray's own
        // service-loop task holds its own strong reference and keeps
        // running independently (confirmed via ksni's source: `Service::
        // run`'s future captures its own `Arc` clone, not tied to `Handle`).
        let (tray_tx, tray_rx) = std::sync::mpsc::channel::<tray::TrayCommand>();

        // Enforce auto-lock on the clock, not on the next user action: an idle
        // app used to keep the RMS, crypto context, decrypted vault and last
        // copied secret in RAM long past the deadline (audit D-1). Reuses the
        // tray's `Locked` command, so an expiry clears the clipboard and toasts
        // through exactly the same path as "Lock Now".
        {
            let lock_tx = tray_tx.clone();
            vela_desktop_core::commands::session::spawn_auto_lock_watchdog(
                app_state_for_auto_lock,
                move || {
                    tracing::info!("Session expired — auto-locking");
                    let _ = lock_tx.send(tray::TrayCommand::Locked);
                },
            );
        }

        cx.spawn(async move |_cx| {
            let vela_tray = tray::VelaTray::new(app_state_for_tray, tray_runtime_handle, tray_tx);
            match vela_tray.spawn().await {
                Ok(handle) => {
                    tracing::info!("System tray registered");
                    std::mem::forget(handle);
                }
                Err(e) => tracing::warn!("Failed to register system tray (continuing without it): {e}"),
            }
        })
        .detach();

        // Autofill IPC bridge (browser extension) + Wayland portal global
        // shortcut. Both are written against `vela_desktop_core::host::Host`
        // and run on their own threads, so they reach the UI through the same
        // channel-plus-poll-loop hop the tray uses — see `host.rs`.
        let (host_tx, host_rx) = std::sync::mpsc::channel::<host::HostCommand>();
        let ipc_host: Arc<dyn vela_desktop_core::host::Host> =
            Arc::new(host::GpuiHost::new(app_state_for_ipc.clone(), host_tx.clone()));
        let ipc_capability = app_state_for_ipc.ipc_capability.clone();
        std::thread::spawn(move || {
            // Its own single-threaded runtime, exactly as `src-tauri/src/
            // main.rs` does — this server owns a long-lived listener and
            // shouldn't share the app's main worker pool.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create IPC tokio runtime");
            rt.block_on(async {
                vela_desktop_core::ipc::server::IpcServer::new(ipc_capability)
                    .start(ipc_host)
                    .await;
            });
        });
        tracing::info!("Autofill IPC server started");

        if vela_desktop_core::wayland_shortcut::is_wayland_session() {
            let trigger = vela_desktop_core::wayland_shortcut::to_portal_trigger(&quick_search_shortcut);
            let shortcut_host: Arc<dyn vela_desktop_core::host::Host> =
                Arc::new(host::GpuiHost::new(app_state_for_ipc.clone(), host_tx));
            // `wayland_shortcut` talks to the XDG portal over zbus's
            // *async-io* backend (the executor this whole workspace
            // standardized on — see vela-desktop-core/Cargo.toml), so it
            // must not be driven by the tokio runtime the IPC server uses.
            // gpui's own foreground executor drives it fine, same as the
            // ksni tray's `.spawn().await` above.
            cx.spawn(async move |_cx| {
                vela_desktop_core::wayland_shortcut::run(shortcut_host, trigger).await;
            })
            .detach();
            tracing::info!("Wayland portal global shortcut registered");
        } else {
            tracing::info!(
                "Not a Wayland session — global quick-search shortcut not registered \
                 (the X11 plugin path the Tauri build uses isn't ported)"
            );
        }

        // Polls for tray + host commands (plain `std::sync::mpsc::Receiver`s,
        // since ksni's `Tray` impl and the IPC/portal threads all run on their
        // own background threads and can't reach gpui's window/App state
        // directly — gpui-ce has no public cross-thread "run this on the main
        // thread" primitive to bridge that gap safely, so this reuses the same
        // poll-loop idiom already proven throughout this codebase, e.g.
        // TitleBar's 1s session poll).
        cx.spawn(async move |cx| loop {
            while let Ok(cmd) = tray_rx.try_recv() {
                match cmd {
                    tray::TrayCommand::Activate => {
                        window_handle.update(cx, |_, window, _| window.activate_window()).ok();
                    }
                    tray::TrayCommand::SyncFinished { message, kind } => {
                        cx.update(|cx| toast::show(cx, message, kind));
                    }
                    tray::TrayCommand::Locked => {
                        cx.update(|cx| {
                            clipboard::clear(cx);
                            toast::show(cx, "Session locked", toast::ToastKind::Info);
                        });
                    }
                    tray::TrayCommand::Quit => {
                        cx.update(|cx| cx.quit());
                    }
                }
            }
            while let Ok(cmd) = host_rx.try_recv() {
                match cmd {
                    host::HostCommand::FocusMainWindow => {
                        window_handle.update(cx, |_, window, _| window.activate_window()).ok();
                    }
                    host::HostCommand::OpenQuickSearch => {
                        cx.update(|cx| quick_search::toggle(cx, app_state_for_quick_search.clone()));
                    }
                    host::HostCommand::VaultItemsChanged => {
                        cx.update(host::notify_vault_items_changed);
                    }
                    host::HostCommand::ConfirmPresence { prompt, reply } => {
                        cx.update(|cx| {
                            cx.set_global(host::PresencePromptGlobal(Some(host::PresencePrompt {
                                prompt,
                                reply,
                            })));
                        });
                    }
                }
            }
            cx.background_executor().timer(std::time::Duration::from_millis(200)).await;
        })
        .detach();
    });
}

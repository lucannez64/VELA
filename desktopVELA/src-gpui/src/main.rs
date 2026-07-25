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
mod clipboard;
mod favicon_ui;
mod fonts;
mod icon;
mod qr;
mod sidebar;
mod theme;
mod titlebar;
mod tray;
mod views;

use std::path::PathBuf;
use std::sync::Arc;

use gpui::{
    div, prelude::*, px, size, App, Bounds, Context, Entity, IntoElement, Render, Subscription,
    TitlebarOptions, Window, WindowBounds, WindowDecorations, WindowOptions,
};
use ksni::TrayMethods;

use theme::{ActiveTheme, ThemeId};
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
            .size_full()
            .flex()
            .flex_col()
            .bg(palette.surface)
            .font_family(fonts::LABEL)
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
    }
}

fn load_font_bytes(file_name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../src/assets/fonts")
        .join(file_name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"))
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

    // Real settings read (plain sync fs read, no unlock required) so the
    // window opens in the user's actually-saved theme from frame one,
    // rather than always starting on Vela and only picking up the real
    // theme once something happens to touch the global later.
    let initial_theme = vela_desktop_core::commands::settings::get_settings(&app_state)
        .map(|s| ThemeId::from_setting(&s.theme))
        .unwrap_or(ThemeId::Vela);

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

        cx.bind_keys(
            gpui_elements::editable_text::actions::default_bindings()
                .as_keybindings(Some(gpui_elements::editable_text::actions::DEFAULT_INPUT_CONTEXT)),
        );

        for font_file in fonts::FONT_FILES {
            cx.text_system()
                .add_fonts(vec![load_font_bytes(font_file).into()])
                .unwrap_or_else(|e| panic!("failed to load font {font_file}: {e}"));
        }

        cx.activate(true);

        let bounds = Bounds::centered(None, size(px(1024.), px(720.)), cx);
        let app_state_for_tray = app_state.clone();
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

        // Polls for tray commands (a plain `std::sync::mpsc::Receiver`, since
        // ksni's `Tray` impl runs on its own background thread and can't
        // reach gpui's window/App state directly — gpui-ce has no public
        // cross-thread "run this on the main thread" primitive to bridge
        // that gap safely, so this reuses the same poll-loop idiom already
        // proven throughout this codebase, e.g. TitleBar's 1s session poll).
        cx.spawn(async move |cx| loop {
            while let Ok(cmd) = tray_rx.try_recv() {
                match cmd {
                    tray::TrayCommand::Activate => {
                        window_handle.update(cx, |_, window, _| window.activate_window()).ok();
                    }
                    tray::TrayCommand::Quit => {
                        cx.update(|cx| cx.quit());
                    }
                }
            }
            cx.background_executor().timer(std::time::Duration::from_millis(200)).await;
        })
        .detach();
    });
}

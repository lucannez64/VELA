//! Port of `desktopVELA/src/views/WelcomeScreen.tsx` — first-launch screen:
//! create a new vault or add an existing device. Import/recover modals from
//! the original aren't ported yet (follow-up); this proves the primary
//! action path end-to-end: button click -> real
//! `vela_desktop_core::biometric::check_enrollment()` call -> state update ->
//! re-render, with no IPC hop at all (a plain background-thread function
//! call, unlike the original's `invoke('check_enrollment')`).
//!
//! The "VELA" wordmark is clickable (`title="Click to reset everything"` in
//! the original) and opens a real typed-DELETE confirmation calling the
//! real `reset_vault` — same backend call as Settings' Delete Vault and
//! BiometricGate's reset link — then proceeds straight to vault creation on
//! success, matching the original's `onReset={() => { ...; handleCreateVault(); }}`.

use std::sync::Arc;

use gpui::{
    div, prelude::*, px, App, Context, EventEmitter, IntoElement, MouseButton, MouseDownEvent, Render,
    SharedString, Task, Window,
};
use gpui_elements::editable_text::{text_input, EditableTextState, StringStorage};

use vela_desktop_core::AppState;

use crate::background::GuardedSpawn;
use crate::animation;
use crate::fonts;
use crate::icon::icon;
use crate::theme::Palette;

pub enum WelcomeEvent {
    CreateVault,
    AddExistingDevice,
    /// An enrollment code was imported for real — the vault is now present
    /// *and* the session is already unlocked (`import_enrollment_code` ends
    /// by unlocking), so the app goes straight to the shell, not to the
    /// unlock gate. Mirrors the original's `onImportComplete`.
    ImportComplete,
    /// Account recovery finished — same "vault now exists and is unlocked"
    /// situation as `ImportComplete` (`onAccountRecovered` in the original).
    AccountRecovered,
}

impl EventEmitter<WelcomeEvent> for WelcomeScreen {}

/// `max-w-4xl` on the original's card.
const CARD_MAX_WIDTH: f32 = 896.;

pub struct WelcomeScreen {
    app_state: Arc<AppState>,
    /// `None` while the initial `check_enrollment()` background call is in
    /// flight (mirrors the original's `biometricAvailable === null` state).
    biometric_available: Option<bool>,
    show_reset_modal: bool,
    reset_confirm_state: gpui::Entity<EditableTextState>,
    resetting: bool,
    reset_error: Option<SharedString>,
    show_import_modal: bool,
    import_code_state: gpui::Entity<EditableTextState>,
    import_password_state: gpui::Entity<EditableTextState>,
    import_password_visible: bool,
    /// Out-of-band code the user compares against their other device. Derived
    /// from the pasted enrollment code, recomputed whenever it changes.
    import_verification_code: Option<SharedString>,
    /// Confirmation that the verification code matched. Reset on every code
    /// change — the whole point is that it attests to *this* code.
    import_code_confirmed: bool,
    importing: bool,
    import_error: Option<SharedString>,
    /// A v3 enrollment this device has claimed and is waiting on (audit P-1).
    ///
    /// The fingerprint in here comes from `begin_enrollment_join`, which
    /// computes it in-process from the keypair it has just generated. It must
    /// stay that way: rendering one that arrived over the network would turn
    /// the user's comparison from "two devices agree about a key" into "two
    /// devices agree about a number".
    join_v3: Option<JoinV3>,
    _join_v3_task: Option<Task<()>>,
    /// Whether the pasted code is a v3 one. Recomputed with the verification
    /// code, and what decides which of the two flows "Continue" runs.
    import_is_v3: bool,
    show_recover_modal: bool,
    recover: RecoverState,
    _pulse_task: Task<()>,
    _import_code_subscription: gpui::Subscription,
}

/// A v3 enrollment in flight on the joining side.
#[derive(Clone)]
struct JoinV3 {
    grant_id: String,
    /// This device's own fingerprint, computed locally from the key it just
    /// generated. Displayed for the user to find on the primary's screen.
    fingerprint: SharedString,
    /// True once the primary has confirmed and the vault is coming down.
    finishing: bool,
}

/// Mirrors `RecoverAccountModal.tsx`'s `Step` union.
#[derive(PartialEq, Clone, Copy)]
enum RecoverStep {
    /// Pick the rclone remote holding Share 1.
    Remote,
    /// The remote holds backups for several accounts — pick one.
    Account,
    /// Share 1 downloaded — confirm the account, then verify with the
    /// security key.
    Confirm,
    /// Assertion passed and Share 2 released — name the device and set a
    /// local vault password.
    Device,
}

struct RecoverState {
    step: RecoverStep,
    remotes: Option<Vec<SharedString>>,
    selected_remote: Option<SharedString>,
    loading_remotes: bool,
    fetching_share: bool,
    /// All Share 1 envelopes found on the selected remote. Usually one; a
    /// remote shared by several VELA accounts carries one per account.
    shares: Vec<vela_desktop_core::recovery::CloudRecoveryShare>,
    share: Option<vela_desktop_core::recovery::CloudRecoveryShare>,
    verifying: bool,
    /// Share 2 + the enrollment grant, both released by the server only after
    /// the WebAuthn assertion verified.
    recover_response: Option<vela_desktop_core::api::RecoveryRecoverResponse>,
    /// Security-key PIN. The browser build never sees this (the browser's own
    /// WebAuthn UI collects it); driving CTAP2 directly means collecting it
    /// ourselves — same as Settings' security-key registration modal.
    pin_state: gpui::Entity<EditableTextState>,
    device_name_state: gpui::Entity<EditableTextState>,
    password_state: gpui::Entity<EditableTextState>,
    confirm_password_state: gpui::Entity<EditableTextState>,
    finishing: bool,
    error: Option<SharedString>,
}

impl WelcomeScreen {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        cx.spawn(async move |this, cx| {
            let status = cx
                .background_spawn_guarded("welcome enrollment check", async {
                    vela_desktop_core::biometric::check_enrollment()
                })
                .await
                // A backend that can't answer is not a backend that enrolled
                // us: fall through to the password path.
                .unwrap_or_default();
            let has_real_biometric = status.enrolled
                && !matches!(
                    status.provider,
                    vela_desktop_core::biometric::BiometricProvider::None
                        | vela_desktop_core::biometric::BiometricProvider::MasterPassword
                );
            this.update(cx, |this, cx| {
                this.biometric_available = Some(has_real_biometric);
                cx.notify();
            })
            .ok();
        })
        .detach();

        let import_code_state = cx.new(|cx| EditableTextState::new(StringStorage::default(), cx));
        // Recompute the verification code (and drop any prior confirmation)
        // whenever the pasted code changes — same `useEffect([importCode])`
        // the original runs, and the reason the checkbox can't be sticky.
        let import_code_subscription = cx.observe(&import_code_state, |this: &mut Self, _, cx| {
            this.refresh_verification_code(cx);
        });

        Self {
            app_state,
            biometric_available: None,
            show_reset_modal: false,
            reset_confirm_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
            resetting: false,
            reset_error: None,
            show_import_modal: false,
            import_code_state,
            import_password_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
            import_password_visible: false,
            import_verification_code: None,
            import_code_confirmed: false,
            importing: false,
            import_error: None,
            join_v3: None,
            _join_v3_task: None,
            import_is_v3: false,
            show_recover_modal: false,
            recover: RecoverState {
                step: RecoverStep::Remote,
                remotes: None,
                selected_remote: None,
                loading_remotes: false,
                fetching_share: false,
                shares: Vec::new(),
                share: None,
                verifying: false,
                recover_response: None,
                pin_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
                device_name_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
                password_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
                confirm_password_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
                finishing: false,
                error: None,
            },
            _pulse_task: animation::spawn_pulse_ticker(cx),
            _import_code_subscription: import_code_subscription,
        }
    }

    fn open_recover_modal(&mut self, cx: &mut Context<Self>) {
        self.recover.step = RecoverStep::Remote;
        self.recover.remotes = None;
        self.recover.selected_remote = None;
        self.recover.shares = Vec::new();
        self.recover.share = None;
        self.recover.recover_response = None;
        self.recover.error = None;
        self.recover.loading_remotes = true;
        self.recover.pin_state.update(cx, |s, cx| s.emplace("", cx));
        self.recover.device_name_state.update(cx, |s, cx| s.emplace("", cx));
        self.recover.password_state.update(cx, |s, cx| s.emplace("", cx));
        self.recover.confirm_password_state.update(cx, |s, cx| s.emplace("", cx));
        self.show_recover_modal = true;
        cx.notify();

        cx.spawn(async move |this, cx| {
            // Shells out to `rclone listremotes` — blocking process I/O, no
            // tokio reactor needed, so the background pool is the right home.
            let result = cx
                .background_spawn_guarded("list cloud recovery remotes", async {
                    vela_desktop_core::recovery::list_cloud_backup_remotes().await
                })
                .await
                .unwrap_or_else(|| Err("Listing cloud remotes failed unexpectedly".to_string()));
            this.update(cx, |this, cx| {
                this.recover.loading_remotes = false;
                match result {
                    Ok(remotes) => {
                        let remotes: Vec<SharedString> =
                            remotes.into_iter().map(SharedString::from).collect();
                        this.recover.selected_remote = remotes.first().cloned();
                        this.recover.remotes = Some(remotes);
                    }
                    Err(e) => this.recover.error = Some(e.into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn close_recover_modal(&mut self, cx: &mut Context<Self>) {
        self.show_recover_modal = false;
        cx.notify();
    }

    fn fetch_recovery_share(&mut self, cx: &mut Context<Self>) {
        let Some(remote) = self.recover.selected_remote.clone() else { return };
        self.recover.fetching_share = true;
        self.recover.error = None;
        cx.notify();

        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn_guarded("fetch cloud recovery share", async move {
                    vela_desktop_core::recovery::fetch_cloud_recovery_shares(
                        remote.to_string(),
                    )
                    .await
                })
                .await
                .unwrap_or_else(|| Err("Downloading the recovery share failed unexpectedly".to_string()));
            this.update(cx, |this, cx| {
                this.recover.fetching_share = false;
                match result {
                    Ok(shares) if shares.len() == 1 => {
                        this.recover.share = Some(shares.into_iter().next().unwrap());
                        this.recover.step = RecoverStep::Confirm;
                    }
                    Ok(shares) => {
                        // A remote shared by several VELA accounts: let the
                        // user pick whose backup to recover.
                        this.recover.shares = shares;
                        this.recover.step = RecoverStep::Account;
                    }
                    Err(e) => {
                        this.recover.error =
                            Some(format!("Failed to download Share 1 from this remote: {e}").into())
                    }
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn verify_with_security_key(&mut self, cx: &mut Context<Self>) {
        let Some(share) = self.recover.share.clone() else { return };
        let pin = self.recover.pin_state.read(cx).as_str().to_string();
        self.recover.verifying = true;
        self.recover.error = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            // Real network I/O *and* blocking USB HID access to the security
            // key — must run on the real tokio runtime via gpui_tokio, not
            // `background_spawn`.
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                vela_desktop_core::webauthn::recover_account_with_security_key(
                    &app_state,
                    &share.user_id,
                    pin,
                )
                .await
            })
            .await;
            this.update(cx, |this, cx| {
                this.recover.verifying = false;
                match result {
                    Ok(Ok(resp)) => {
                        this.recover.recover_response = Some(resp);
                        this.recover.step = RecoverStep::Device;
                    }
                    Ok(Err(e)) => this.recover.error = Some(e.into()),
                    Err(e) => this.recover.error = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn finish_recovery(&mut self, cx: &mut Context<Self>) {
        let Some(share) = self.recover.share.clone() else { return };
        let Some(recover_response) = self.recover.recover_response.clone() else { return };
        let password = self.recover.password_state.read(cx).as_str().to_string();
        let confirm = self.recover.confirm_password_state.read(cx).as_str().to_string();
        let device_name = self.recover.device_name_state.read(cx).as_str().trim().to_string();

        // Same two validations, same messages, as the original's `handleFinish`.
        if password.len() < 8 {
            self.recover.error = Some("Password must be at least 8 characters".into());
            cx.notify();
            return;
        }
        if password != confirm {
            self.recover.error = Some("Passwords do not match".into());
            cx.notify();
            return;
        }

        self.recover.finishing = true;
        self.recover.error = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                vela_desktop_core::recovery::complete_account_recovery(
                    &app_state,
                    share.user_id.clone(),
                    share.share_b64.clone(),
                    recover_response,
                    password,
                    (!device_name.is_empty()).then_some(device_name),
                )
                .await
            })
            .await;
            this.update(cx, |this, cx| {
                this.recover.finishing = false;
                match result {
                    Ok(Ok(())) => {
                        this.show_recover_modal = false;
                        crate::toast::show(cx, "Account recovered", crate::toast::ToastKind::Success);
                        cx.emit(WelcomeEvent::AccountRecovered);
                    }
                    Ok(Err(e)) => this.recover.error = Some(e.into()),
                    Err(e) => this.recover.error = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn open_import_modal(&mut self, cx: &mut Context<Self>) {
        self.import_code_state.update(cx, |s, cx| s.emplace("", cx));
        self.import_password_state.update(cx, |s, cx| s.emplace("", cx));
        self.import_password_visible = false;
        self.import_verification_code = None;
        self.import_code_confirmed = false;
        self.import_error = None;
        self.show_import_modal = true;
        cx.notify();
    }

    fn close_import_modal(&mut self, cx: &mut Context<Self>) {
        self.show_import_modal = false;
        cx.notify();
    }

    fn refresh_verification_code(&mut self, cx: &mut Context<Self>) {
        let code = self.import_code_state.read(cx).as_str().trim().to_string();
        self.import_code_confirmed = false;
        // A v3 code has nothing to verify at this point: the value the user
        // compares is derived from a key this device has not generated yet, and
        // will not until it claims the grant. Showing a v2-style digest of a v3
        // code would be a number that means nothing, confirmed by a checkbox
        // that attests to nothing.
        self.import_is_v3 =
            vela_desktop_core::commands::enrollment_v3::is_v3_enrollment_code(&code);
        self.import_verification_code = if code.is_empty() || self.import_is_v3 {
            None
        } else {
            // Pure local hash of the code — no network, no vault access — so
            // it's fine to compute inline per keystroke.
            Some(
                vela_desktop_core::commands::devices::enrollment_verification_code(&code).into(),
            )
        };
        cx.notify();
    }

    /// Claim a v3 grant with a freshly generated keypair, then wait for the
    /// primary's user to pick this device's fingerprint.
    fn begin_join_v3(&mut self, code: String, cx: &mut Context<Self>) {
        self.importing = true;
        self.import_error = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                vela_desktop_core::commands::enrollment_v3::begin_enrollment_join(&app_state, &code)
                    .await
            })
            .await;

            this.update(cx, |this, cx| {
                this.importing = false;
                match result {
                    Ok(Ok(request)) => {
                        this.join_v3 = Some(JoinV3 {
                            grant_id: request.grant_id,
                            fingerprint: request.fingerprint.into(),
                            finishing: false,
                        });
                        this.spawn_join_poll(cx);
                    }
                    Ok(Err(e)) => this.import_error = Some(e.into()),
                    Err(e) => this.import_error = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn spawn_join_poll(&mut self, cx: &mut Context<Self>) {
        let Some(join) = self.join_v3.clone() else { return };
        let app_state = self.app_state.clone();
        let grant_id = join.grant_id.clone();

        self._join_v3_task = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_spawn(async {
                    std::thread::sleep(std::time::Duration::from_secs(2))
                })
                .await;

                let app_state = app_state.clone();
                let gid = grant_id.clone();
                let result = gpui_tokio::Tokio::spawn(cx, async move {
                    vela_desktop_core::commands::enrollment_v3::poll_enrollment_join(&app_state, &gid)
                        .await
                })
                .await;

                match result {
                    Ok(Ok(vela_desktop_core::commands::enrollment_v3::JoinStatus::Waiting)) => {
                        continue
                    }
                    Ok(Ok(vela_desktop_core::commands::enrollment_v3::JoinStatus::Enrolled)) => {
                        this.update(cx, |this, cx| this.finish_join_v3(cx)).ok();
                        break;
                    }
                    // The grant is gone — expired, or the primary cancelled.
                    // There is nothing left to wait for.
                    Ok(Err(e)) => {
                        this.update(cx, |this, cx| {
                            this.join_v3 = None;
                            this.import_error = Some(e.into());
                            cx.notify();
                        })
                        .ok();
                        break;
                    }
                    Err(e) => {
                        this.update(cx, |this, cx| {
                            this.join_v3 = None;
                            this.import_error = Some(format!("Task failed: {e}").into());
                            cx.notify();
                        })
                        .ok();
                        break;
                    }
                }
            }
        }));
    }

    fn finish_join_v3(&mut self, cx: &mut Context<Self>) {
        let Some(join) = self.join_v3.clone() else { return };
        let password = self.import_password_state.read(cx).as_str().to_string();
        let grant_id = join.grant_id.clone();

        if let Some(state) = self.join_v3.as_mut() {
            state.finishing = true;
        }
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                vela_desktop_core::commands::enrollment_v3::finish_enrollment_join(
                    &app_state, &grant_id, password,
                )
                .await
            })
            .await;

            this.update(cx, |this, cx| {
                match result {
                    Ok(Ok(())) => {
                        this.join_v3 = None;
                        this.show_import_modal = false;
                        crate::toast::show(cx, "Device joined", crate::toast::ToastKind::Success);
                        cx.emit(WelcomeEvent::ImportComplete);
                    }
                    Ok(Err(e)) => {
                        this.join_v3 = None;
                        this.import_error = Some(e.into());
                    }
                    Err(e) => {
                        this.join_v3 = None;
                        this.import_error = Some(format!("Task failed: {e}").into());
                    }
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn cancel_join_v3(&mut self, cx: &mut Context<Self>) {
        vela_desktop_core::commands::enrollment_v3::cancel_enrollment_join(&self.app_state);
        self.join_v3 = None;
        self._join_v3_task = None;
        cx.notify();
    }

    fn do_import(&mut self, cx: &mut Context<Self>) {
        let code = self.import_code_state.read(cx).as_str().trim().to_string();
        let password = self.import_password_state.read(cx).as_str().to_string();
        // Same three guards, same messages, same order as the original's
        // `handleImport`.
        if code.is_empty() {
            self.import_error = Some("Please paste the enrollment code.".into());
            cx.notify();
            return;
        }
        if password.is_empty() {
            self.import_error =
                Some("Please set a password to protect the vault on this device.".into());
            cx.notify();
            return;
        }
        // A v3 code takes the other path entirely: this device generates its own
        // keys and claims the grant, and what the user compares only exists
        // after that. There is no v2 digest here to have confirmed.
        if self.import_is_v3 {
            self.begin_join_v3(code, cx);
            return;
        }

        if !self.import_code_confirmed {
            self.import_error =
                Some("Confirm the verification code matches your other device first.".into());
            cx.notify();
            return;
        }

        self.importing = true;
        self.import_error = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            // Real network I/O (server challenge, capsule + vault download)
            // plus a `spawn_blocking` signature — must go through gpui_tokio's
            // bridge onto the actual tokio runtime, not `background_spawn`.
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                vela_desktop_core::commands::devices::import_enrollment_code(
                    &app_state, code, password,
                )
                .await
            })
            .await;
            this.update(cx, |this, cx| {
                this.importing = false;
                match result {
                    Ok(Ok(())) => {
                        this.show_import_modal = false;
                        crate::toast::show(cx, "Device joined", crate::toast::ToastKind::Success);
                        cx.emit(WelcomeEvent::ImportComplete);
                    }
                    Ok(Err(e)) => this.import_error = Some(e.into()),
                    Err(e) => this.import_error = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn create_vault_label(&self) -> SharedString {
        match self.biometric_available {
            None => "Checking…".into(),
            Some(_) => "Create new vault".into(),
        }
    }

    fn open_reset_modal(&mut self, cx: &mut Context<Self>) {
        self.reset_confirm_state.update(cx, |s, cx| s.emplace("", cx));
        self.reset_error = None;
        self.show_reset_modal = true;
        cx.notify();
    }

    fn close_reset_modal(&mut self, cx: &mut Context<Self>) {
        self.show_reset_modal = false;
        cx.notify();
    }

    fn confirm_reset(&mut self, cx: &mut Context<Self>) {
        let confirm_text = self.reset_confirm_state.read(cx).as_str().to_string();
        self.resetting = true;
        self.reset_error = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            // `reset_vault` may perform a real server auth challenge (when
            // unlocked with a server configured) — must run via gpui_tokio's
            // bridge onto the actual tokio runtime, not `cx.background_spawn`
            // (a separate thread pool that never entered that runtime and
            // panics on real reactor I/O).
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                vela_desktop_core::commands::session::reset_vault(&app_state, Some(confirm_text), None).await
            })
            .await;
            this.update(cx, |this, cx| {
                this.resetting = false;
                match result {
                    Ok(Ok(())) => {
                        this.show_reset_modal = false;
                        // Matches the original: reset, then immediately
                        // proceed to vault creation.
                        cx.emit(WelcomeEvent::CreateVault);
                    }
                    Ok(Err(e)) => this.reset_error = Some(format!("Failed to reset vault: {e}").into()),
                    Err(e) => this.reset_error = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }
}

impl Render for WelcomeScreen {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = crate::theme::current_palette(cx);
        let checking = self.biometric_available.is_none();

        // The original is a 12-column grid inside `max-w-4xl`: the branding
        // column is `hidden md:flex md:col-span-5`, the action column is
        // `md:col-span-7 p-6 sm:p-10 md:p-16` with a `max-w-md` content
        // block, and the headline steps `text-3xl sm:text-4xl md:text-5xl`.
        // gpui has neither media queries nor grid, so the breakpoints come
        // from the live viewport (same idiom as `sidebar.rs` and
        // `item_detail.rs`) and the 5/12 split is computed here — a
        // percentage width would be measured against a stretched parent and
        // silently fall back to the content size.
        let viewport = window.viewport_size().width;
        let sm_up = viewport >= px(640.);
        let md_up = viewport >= px(768.);
        let card_width = (f32::from(viewport) - 64.).clamp(0., CARD_MAX_WIDTH);
        let branding_width = px(card_width * 5. / 12.);
        let pane_padding = if md_up {
            px(64.)
        } else if sm_up {
            px(40.)
        } else {
            px(24.)
        };
        let headline_size = if md_up {
            px(48.)
        } else if sm_up {
            px(36.)
        } else {
            px(30.)
        };
        // `mb-8 sm:mb-12` on the header, `mt-10 sm:mt-16` on the footer.
        let header_gap = if sm_up { px(48.) } else { px(32.) };
        let footer_gap = if sm_up { px(64.) } else { px(40.) };

        div()
            .id("welcome")
            .relative()
            .size_full()
            .overflow_y_scroll()
            .bg(palette.surface)
            .font_family(fonts::LABEL)
            .child(
                // `min-h-screen ... my-auto` in the original: centred while the
                // card fits, growing (and scrolling) instead of centring once
                // it doesn't. Centring directly on the scroll container would
                // push the headline off the top with no way to reach it.
                div()
                    .min_h_full()
                    .w_full()
                    .flex()
                    .items_center()
                    .justify_center()
                    .p_8()
                    .child(
                        div()
                            .flex()
                            .w_full()
                            .max_w(px(CARD_MAX_WIDTH))
                            .min_w_0()
                            .rounded_xl()
                            .overflow_hidden()
                            .bg(palette.surface_container_low)
                            .when(md_up, |el| el.child(
                                // Left branding panel — `hidden md:flex` in the
                                // original, so it drops out entirely below 768px
                                // rather than squeezing the actions.
                                div()
                                    .w(branding_width)
                                    .flex_shrink_0()
                                    .p_12()
                                    .flex()
                                    .flex_col()
                                    .justify_between()
                                    .bg(palette.surface_container)
                                    .child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .gap_4()
                                            .child({
                                                let hover_t = animation::hover_transition("welcome-reset", window, cx);
                                                let t = *hover_t.evaluate(window, cx);
                                                let color = animation::lerp_hsla(
                                                    palette.primary,
                                                    gpui::Hsla { a: 0.8, ..palette.primary },
                                                    t,
                                                );
                                                div()
                                                    .id("welcome-reset")
                                                    .cursor_pointer()
                                                    .on_hover(move |is_hovered, _, cx| {
                                                        hover_t.update(cx, |v, cx| {
                                                            *v = *is_hovered as u8 as f32;
                                                            cx.notify();
                                                        });
                                                    })
                                                    .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                                        this.open_reset_modal(cx);
                                                    }))
                                                    .child(
                                                        fonts::tracked_text("VELA", px(24.), 0.2)
                                                            .font_family(fonts::HEADLINE)
                                                            .font_weight(gpui::FontWeight::BOLD)
                                                            .text_color(color)
                                                            .text_xl(),
                                                    )
                                            })
                                            .child(
                                                div()
                                                    .flex()
                                                    .items_center()
                                                    .gap_2()
                                                    .text_xs()
                                                    .text_color(palette.secondary)
                                                    .child(icon("verified_user", px(14.), palette.secondary))
                                                    .child(fonts::tracked_text("POST-QUANTUM READY", px(12.), 0.1)),
                                            )
                                            .child(
                                                div()
                                                    .font_family(fonts::HEADLINE)
                                                    .font_weight(gpui::FontWeight::LIGHT)
                                                    .text_size(px(30.))
                                                    .line_height(px(30.) * 1.25)
                                                    .text_color(palette.on_surface)
                                                    .child("Secure your identity in the void."),
                                            ),
                                    )
                                    .child(
                                        // `.security-pulse` (`index.css`: 4s pulse)
                                        // wraps this whole card in the original.
                                        div()
                                            .p_3()
                                            .rounded_lg()
                                            .bg(palette.surface_container_high)
                                            .opacity(animation::pulse_alpha(4.0))
                                            .flex()
                                            .items_center()
                                            .gap_3()
                                            .child(icon("security", px(20.), palette.primary))
                                            .child(
                                                div()
                                                    .flex()
                                                    .flex_col()
                                                    .child(
                                                        div()
                                                            .font_family(fonts::HEADLINE)
                                                            .font_weight(gpui::FontWeight::BOLD)
                                                            .text_sm()
                                                            .text_color(palette.primary)
                                                            .child("Active Protection"),
                                                    )
                                                    .child(
                                                        div()
                                                            .text_xs()
                                                            .text_color(palette.on_surface_variant)
                                                            .child("Zero-Knowledge Protocol Engaged"),
                                                    ),
                                            ),
                                    ),
                            ))
                            .child(
                                div()
                                    .flex_1()
                                    // Without this the column's min-content width —
                                    // the unwrapped subtitle — wins over `flex_1`, so
                                    // the panel grows past the card and everything
                                    // right of the fold is clipped, padding included.
                                    .min_w_0()
                                    .p(pane_padding)
                                    .flex()
                                    .flex_col()
                                    .justify_center()
                                    .items_center()
                                    .child(
                                        div()
                                            .w_full()
                                            // `max-w-md mx-auto` in the original.
                                            .max_w(px(448.))
                                            .flex()
                                            .flex_col()
                                            .child(
                                                div()
                                                    .flex()
                                                    .flex_col()
                                                    .gap_4()
                                                    .child(
                                                        div()
                                                            .flex()
                                                            .flex_col()
                                                            .font_family(fonts::HEADLINE)
                                                            .font_weight(gpui::FontWeight::BOLD)
                                                            // `tracked_text` only spaces the
                                                            // glyphs; the size is inherited.
                                                            .text_size(headline_size)
                                                            // `leading-tight`.
                                                            .line_height(headline_size * 1.25)
                                                            .text_color(palette.on_surface)
                                                            .child(fonts::tracked_text("Your vault.", headline_size, -0.025))
                                                            .child(fonts::tracked_text("No passwords.", headline_size, -0.025)),
                                                    )
                                                    .child(
                                                        div()
                                                            .font_family(fonts::BODY)
                                                            .text_lg()
                                                            .text_color(palette.on_surface_variant)
                                                            .child(
                                                                "Access your secrets through device-native \
                                                                 biometrics and post-quantum encryption.",
                                                            ),
                                                    ),
                                            )
                                            .child(
                                                div()
                                                    .flex()
                                                    .flex_col()
                                                    // `space-y-4`, below a `mb-8 sm:mb-12` header.
                                                    .gap_4()
                                                    .mt(header_gap)
                                                    .child(primary_action_button(
                                                        &palette,
                                                        "create-vault",
                                                        self.create_vault_label(),
                                                        "add_circle",
                                                        !checking,
                                                        window,
                                                        cx,
                                                        cx.listener(|_this, _, _, cx| {
                                                            cx.emit(WelcomeEvent::CreateVault);
                                                        }),
                                                    ))
                                                    .child(action_button(
                                                        &palette,
                                                        "add-existing",
                                                        "Add existing device",
                                                        "devices",
                                                        !checking,
                                                        window,
                                                        cx,
                                                        cx.listener(|_this, _, _, cx| {
                                                            cx.emit(WelcomeEvent::AddExistingDevice);
                                                        }),
                                                    ))
                                                    .child(action_button(
                                                        &palette,
                                                        "join-account",
                                                        "Join existing account",
                                                        "vpn_key",
                                                        true,
                                                        window,
                                                        cx,
                                                        cx.listener(|this, _event, _window, cx| {
                                                            this.open_import_modal(cx);
                                                        }),
                                                    ))
                                                    .child(action_button(
                                                        &palette,
                                                        "recover-account",
                                                        "Recover my account",
                                                        "restore",
                                                        true,
                                                        window,
                                                        cx,
                                                        cx.listener(|this, _event, _window, cx| {
                                                            this.open_recover_modal(cx);
                                                        }),
                                                    )),
                                            )
                                            .child(trust_footer(&palette, footer_gap)),
                                ),
                        ),
                    ),
            )
            .when(self.show_reset_modal, |el| el.child(reset_confirm_modal(&palette, self, window, cx)))
            .when(self.show_import_modal, |el| el.child(import_code_modal(&palette, self, window, cx)))
            .when(self.show_recover_modal, |el| el.child(recover_account_modal(&palette, self, window, cx)))
    }
}

/// Port of `RecoverAccountModal.tsx` — the "every enrolled device is gone"
/// path. Three steps, same order and same copy as the original: pick the
/// rclone remote holding Share 1, confirm the account it identifies and pass
/// a security-key assertion (which is what makes the server release Share 2),
/// then set a local password for the recovered vault.
///
/// One real difference from the original, unavoidable outside a browser: the
/// security-key PIN is collected here. The web build hands the ceremony to
/// `navigator.credentials.get`, and the *browser* prompts for the PIN; this
/// build drives CTAP2 over USB HID itself, so the PIN field is ours — the
/// same trade already made by Settings' security-key registration modal.
fn recover_account_modal(
    palette: &Palette,
    screen: &WelcomeScreen,
    window: &mut Window,
    cx: &mut Context<WelcomeScreen>,
) -> impl IntoElement {
    let state = &screen.recover;

    let cancel_hover = animation::hover_transition("welcome-recover-cancel", window, cx);
    let cancel_t = *cancel_hover.evaluate(window, cx);
    let cancel_bg = animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, cancel_t);

    let body = div()
        .id("welcome-recover-modal-body")
        .map(|el| crate::keyboard::trap_tab(el, "welcome-recover-modal-trap", window, cx))
        .w(px(460.))
        .max_h(px(660.))
        .overflow_y_scroll()
        .p_8()
        .rounded_2xl()
        .bg(palette.surface_container)
        .border_1()
        .border_color(gpui::Hsla { a: 0.2, ..palette.outline_variant })
        .flex()
        .flex_col()
        .gap_4()
        .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
        // Enter runs whichever step's primary button is on screen. The Remote
        // step has no field to type Enter into (it's a remote picker), so it
        // can never reach here.
        .on_key_down(crate::keyboard::submit_on_enter(cx, |this, _window, cx| {
            match this.recover.step {
                RecoverStep::Remote | RecoverStep::Account => {}
                RecoverStep::Confirm => {
                    if !this.recover.verifying {
                        this.verify_with_security_key(cx);
                    }
                }
                RecoverStep::Device => {
                    if !this.recover.finishing {
                        this.finish_recovery(cx);
                    }
                }
            }
        }))
        .child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .child(icon("restore", px(24.), palette.primary))
                .child(
                    div()
                        .font_family(fonts::HEADLINE)
                        .font_weight(gpui::FontWeight::BOLD)
                        .text_xl()
                        .text_color(palette.on_surface)
                        .child("Recover my account"),
                ),
        );

    let body = match state.step {
        RecoverStep::Remote => body
            .child(
                div().text_sm().text_color(palette.on_surface_variant).child(
                    "Pick the cloud remote where Share 1 of your recovery backup was uploaded.",
                ),
            )
            .map(|el| {
                if state.loading_remotes {
                    return el.child(
                        div()
                            .text_sm()
                            .text_color(palette.on_surface_variant)
                            .child("Checking configured rclone remotes..."),
                    );
                }
                match state.remotes.as_ref() {
                    Some(remotes) if !remotes.is_empty() => el
                        .child(
                            // gpui has no `<select>`; a clickable list, the
                            // same substitution Settings' theme picker and
                            // SharingScreen's item picker already use.
                            div()
                                .id("welcome-recover-remotes")
                                .max_h(px(180.))
                                .overflow_y_scroll()
                                .rounded_xl()
                                .border_1()
                                .border_color(gpui::Hsla { a: 0.3, ..palette.outline_variant })
                                .bg(palette.surface_bright)
                                .flex()
                                .flex_col()
                                .children(remotes.iter().enumerate().map(|(index, remote)| {
                                    let is_selected = state.selected_remote.as_ref() == Some(remote);
                                    let remote_for_click = remote.clone();
                                    div()
                                        .id(("welcome-recover-remote", index))
                                        .px_4()
                                        .py_3()
                                        .flex()
                                        .items_center()
                                        .gap_3()
                                        .cursor_pointer()
                                        .when(is_selected, |el| {
                                            el.bg(gpui::Hsla { a: 0.1, ..palette.primary })
                                        })
                                        .child(icon(
                                            if is_selected { "radio_button_checked" } else { "radio_button_unchecked" },
                                            px(16.),
                                            if is_selected { palette.primary } else { palette.outline },
                                        ))
                                        .child(
                                            div()
                                                .text_sm()
                                                .text_color(palette.on_surface)
                                                .child(remote.clone()),
                                        )
                                        .on_mouse_down(
                                            MouseButton::Left,
                                            cx.listener(move |this, _, _, cx| {
                                                this.recover.selected_remote =
                                                    Some(remote_for_click.clone());
                                                cx.notify();
                                            }),
                                        )
                                })),
                        )
                        .child(primary_modal_button(
                            palette,
                            "welcome-recover-continue",
                            if state.fetching_share { "Downloading..." } else { "Continue" },
                            !state.fetching_share,
                            cx.listener(|this, _, _, cx| this.fetch_recovery_share(cx)),
                        )),
                    _ => el.child(
                        div().text_sm().text_color(palette.on_surface_variant).child(
                            "No configured rclone remotes found. Install rclone and configure \
                             the same remote used during recovery setup, then come back here.",
                        ),
                    ),
                }
            }),

        RecoverStep::Account => body
            .child(
                div().text_sm().text_color(palette.on_surface_variant).child(
                    "This remote holds recovery backups for more than one account. Pick the one \
                     you are recovering:",
                ),
            )
            .child(
                div()
                    .id("welcome-recover-accounts")
                    .max_h(px(180.))
                    .overflow_y_scroll()
                    .rounded_xl()
                    .border_1()
                    .border_color(gpui::Hsla { a: 0.3, ..palette.outline_variant })
                    .bg(palette.surface_bright)
                    .flex()
                    .flex_col()
                    .children(state.shares.iter().enumerate().map(|(index, share)| {
                        // Clone out of the borrowed `state` before the
                        // 'static listener closure captures it.
                        let share_for_click = share.clone();
                        let user_id = SharedString::from(share.user_id.clone());
                        div()
                            .id(("welcome-recover-account", index))
                            .px_4()
                            .py_3()
                            .flex()
                            .items_center()
                            .gap_3()
                            .cursor_pointer()
                            .hover(|el| el.bg(gpui::Hsla { a: 0.06, ..palette.primary }))
                            .child(
                                div()
                                    .font_family(fonts::MONO)
                                    .text_xs()
                                    .text_color(palette.on_surface)
                                    .child(user_id),
                            )
                            .on_mouse_down(
                                MouseButton::Left,
                                cx.listener(move |this, _, _, cx| {
                                    this.recover.share = Some(share_for_click.clone());
                                    this.recover.step = RecoverStep::Confirm;
                                    cx.notify();
                                }),
                            )
                    })),
            ),

        RecoverStep::Confirm => body
            .child(
                div()
                    .text_sm()
                    .text_color(palette.on_surface_variant)
                    .child("Found a recovery backup for account:"),
            )
            .when_some(state.share.as_ref(), |el, share| {
                el.child(
                    div()
                        .font_family(fonts::MONO)
                        .text_xs()
                        .px_4()
                        .py_3()
                        .rounded_lg()
                        .bg(palette.surface_bright)
                        .text_color(palette.on_surface)
                        .child(SharedString::from(share.user_id.clone())),
                )
            })
            .child(
                div().text_sm().text_color(palette.on_surface_variant).child(
                    "Next, verify with the security key (passkey) you registered for recovery.",
                ),
            )
            .child(field_label(palette, "Security key PIN"))
            .child(
                text_input("welcome-recover-pin")
                    .state(state.pin_state.downgrade())
                    .placeholder("PIN")
                    .caret_blink_interval_500ms()
                    .mask_char(Some('*'))
                    .bg(palette.surface_bright)
                    .text_color(palette.on_surface)
                    .rounded_xl()
                    .p_3()
                    .w_full()
                    .min_h_auto()
                    .whitespace_nowrap()
                    .overflow_x_scroll(),
            )
            .child(primary_modal_button(
                palette,
                "welcome-recover-verify",
                if state.verifying { "Waiting for security key..." } else { "Verify with security key" },
                !state.verifying,
                cx.listener(|this, _, _, cx| this.verify_with_security_key(cx)),
            )),

        RecoverStep::Device => body
            .child(
                div().text_sm().text_color(palette.on_surface_variant).child(
                    "Set a password to protect the vault on this device, and optionally name it.",
                ),
            )
            .child(field_label(palette, "Device name (optional)"))
            .child(
                text_input("welcome-recover-device-name")
                    .state(state.device_name_state.downgrade())
                    .placeholder("This device")
                    .caret_blink_interval_500ms()
                    .bg(palette.surface_bright)
                    .text_color(palette.on_surface)
                    .rounded_xl()
                    .p_3()
                    .w_full()
                    .min_h_auto()
                    .whitespace_nowrap()
                    .overflow_x_scroll(),
            )
            .child(field_label(palette, "Vault password (this device)"))
            .child(
                text_input("welcome-recover-password")
                    .state(state.password_state.downgrade())
                    .placeholder("Set a password for this device")
                    .caret_blink_interval_500ms()
                    .mask_char(Some('*'))
                    .bg(palette.surface_bright)
                    .text_color(palette.on_surface)
                    .rounded_xl()
                    .p_3()
                    .w_full()
                    .min_h_auto()
                    .whitespace_nowrap()
                    .overflow_x_scroll(),
            )
            .child(field_label(palette, "Confirm password"))
            .child(
                text_input("welcome-recover-confirm-password")
                    .state(state.confirm_password_state.downgrade())
                    .placeholder("Confirm password")
                    .caret_blink_interval_500ms()
                    .mask_char(Some('*'))
                    .bg(palette.surface_bright)
                    .text_color(palette.on_surface)
                    .rounded_xl()
                    .p_3()
                    .w_full()
                    .min_h_auto()
                    .whitespace_nowrap()
                    .overflow_x_scroll(),
            )
            .child(primary_modal_button(
                palette,
                "welcome-recover-finish",
                if state.finishing { "Recovering vault..." } else { "Recover vault" },
                !state.finishing,
                cx.listener(|this, _, _, cx| this.finish_recovery(cx)),
            )),
    };

    let body = body
        .when_some(state.error.clone(), |el, error| {
            el.child(div().text_sm().text_color(palette.error).child(error))
        })
        .child(
            div()
                .id("welcome-recover-cancel")
                .w_full()
                .py_2()
                .rounded_xl()
                .flex()
                .items_center()
                .justify_center()
                .bg(cancel_bg)
                .text_sm()
                .text_color(palette.on_surface)
                .cursor_pointer()
                .child("Cancel")
                .on_hover(move |is_hovered, _, cx| {
                    cancel_hover.update(cx, |v, cx| {
                        *v = *is_hovered as u8 as f32;
                        cx.notify();
                    });
                })
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _, _, cx| this.close_recover_modal(cx)),
                ),
        );

    div()
        .id("welcome-recover-modal-backdrop")
        .absolute()
        .inset_0()
        .bg(gpui::Hsla { a: 0.6, h: 0., s: 0., l: 0. })
        .flex()
        .items_center()
        .justify_center()
        .p_4()
        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| this.close_recover_modal(cx)))
        .child(body)
}

fn primary_modal_button(
    palette: &Palette,
    id: &'static str,
    label: &'static str,
    enabled: bool,
    on_click: impl Fn(&MouseDownEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    div()
        .id(id)
        .w_full()
        .py_3()
        .rounded_xl()
        .flex()
        .items_center()
        .justify_center()
        .bg(if enabled { palette.primary } else { gpui::Hsla { a: 0.5, ..palette.primary } })
        .text_color(palette.on_primary)
        .font_weight(gpui::FontWeight::MEDIUM)
        .when(enabled, |el| el.cursor_pointer())
        .child(label)
        .when(enabled, |el| el.on_mouse_down(MouseButton::Left, on_click))
}

/// Port of `WelcomeScreen.tsx`'s inline "Join existing account" modal: paste
/// the enrollment code generated on a peer device, compare the derived
/// verification code out of band, then set a local vault password.
///
/// The verification step is the security-critical part and is reproduced
/// exactly: the code is derived locally from what was pasted, the checkbox
/// resets on every edit, and "Import & join" stays disabled until it's
/// checked — an attacker-substituted code produces a different verification
/// code, which is the only thing standing between the user and enrolling
/// against someone else's account.
fn import_code_modal(
    palette: &Palette,
    screen: &WelcomeScreen,
    window: &mut Window,
    cx: &mut Context<WelcomeScreen>,
) -> gpui::AnyElement {
    // Once this device has claimed a grant there is nothing left to fill in —
    // it is waiting on the other device's user, and all it has to do is show
    // the fingerprint of the key it generated.
    if let Some(join) = screen.join_v3.clone() {
        return join_waiting_modal(palette, join, screen.import_error.clone(), window, cx)
            .into_any_element();
    }

    let importing = screen.importing;
    let confirmed = screen.import_code_confirmed;
    // A v3 code has nothing to confirm at this point — the comparison happens
    // after this device has claimed the grant — so requiring the v2 checkbox
    // would leave the button permanently dead.
    let can_import = (confirmed || screen.import_is_v3) && !importing;
    let password_visible = screen.import_password_visible;
    let amber = gpui::rgb(0xf59e0b).into();

    let cancel_hover = animation::hover_transition("welcome-import-cancel", window, cx);
    let cancel_t = *cancel_hover.evaluate(window, cx);
    let cancel_bg = animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, cancel_t);

    div()
        .id("welcome-import-modal-backdrop")
        .absolute()
        .inset_0()
        .bg(gpui::Hsla { a: 0.6, h: 0., s: 0., l: 0. })
        .flex()
        .items_center()
        .justify_center()
        .p_4()
        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| this.close_import_modal(cx)))
        .child(
            div()
                .id("welcome-import-modal-body")
                .map(|el| crate::keyboard::trap_tab(el, "welcome-import-modal-trap", window, cx))
                .w(px(460.))
                .max_h(px(640.))
                .overflow_y_scroll()
                .p_8()
                .rounded_2xl()
                .bg(palette.surface_container)
                .border_1()
                .border_color(gpui::Hsla { a: 0.2, ..palette.outline_variant })
                .flex()
                .flex_col()
                .gap_4()
                .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                // Enter from the password field imports. It can't fire from
                // the enrollment-code box above — that's a `text_area`, where
                // Enter inserts a newline and never reaches us.
                .on_key_down(crate::keyboard::submit_on_enter(cx, |this, _window, cx| {
                    if (this.import_code_confirmed || this.import_is_v3) && !this.importing {
                        this.do_import(cx);
                    }
                }))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .child(icon("vpn_key", px(24.), palette.primary))
                        .child(
                            div()
                                .font_family(fonts::HEADLINE)
                                .font_weight(gpui::FontWeight::BOLD)
                                .text_xl()
                                .text_color(palette.on_surface)
                                .child("Join existing account"),
                        ),
                )
                .child(
                    div().text_sm().text_color(palette.on_surface_variant).child(
                        "Paste the enrollment code generated on your other device, then set a \
                         password to protect the vault on this device.",
                    ),
                )
                .child(field_label(palette, "Enrollment code"))
                .child(
                    gpui_elements::editable_text::text_area("welcome-import-code")
                        .state(screen.import_code_state.downgrade())
                        .placeholder("Paste enrollment code here…")
                        .caret_blink_interval_500ms()
                        .bg(palette.surface_bright)
                        .text_color(palette.on_surface)
                        .font_family(fonts::MONO)
                        .text_xs()
                        .rounded_xl()
                        .p_3()
                        .w_full()
                        .max_h(px(96.))
                        .overflow_y_scroll(),
                )
                .when_some(screen.import_verification_code.clone(), |el, code| {
                    el.child(
                        div()
                            .p_4()
                            .rounded_xl()
                            .bg(gpui::Hsla { a: 0.1, ..amber })
                            .border_1()
                            .border_color(gpui::Hsla { a: 0.3, ..amber })
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(icon("verified_user", px(18.), amber))
                                    .child(
                                        div()
                                            .font_family(fonts::LABEL)
                                            .font_weight(gpui::FontWeight::BOLD)
                                            .text_sm()
                                            .text_color(amber)
                                            .child("Verify this code"),
                                    ),
                            )
                            .child(
                                div().text_xs().text_color(palette.on_surface_variant).child(
                                    "Compare this against the verification code shown on your \
                                     other device's \"Enrollment Code\" dialog. If it doesn't \
                                     match, stop — do not proceed, the code may have been \
                                     tampered with.",
                                ),
                            )
                            .child(
                                fonts::tracked_text(&code, px(20.), 0.15)
                                    .font_family(fonts::MONO)
                                    .font_weight(gpui::FontWeight::BOLD)
                                    .text_color(palette.on_surface)
                                    .justify_center()
                                    .py_1(),
                            )
                            .child(
                                div()
                                    .id("welcome-import-confirm-check")
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .cursor_pointer()
                                    .child(
                                        // gpui has no checkbox widget (same
                                        // gap `password_generator.rs` works
                                        // around) — a bordered box with a
                                        // check glyph when set.
                                        div()
                                            .w(px(16.))
                                            .h(px(16.))
                                            .rounded_sm()
                                            .border_1()
                                            .border_color(if confirmed {
                                                palette.primary
                                            } else {
                                                palette.outline_variant
                                            })
                                            .when(confirmed, |el| el.bg(palette.primary))
                                            .flex()
                                            .items_center()
                                            .justify_center()
                                            .when(confirmed, |el| {
                                                el.child(icon("check", px(12.), palette.on_primary))
                                            }),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(palette.on_surface)
                                            .child("It matches the code on my other device"),
                                    )
                                    .on_mouse_down(
                                        MouseButton::Left,
                                        cx.listener(|this, _, _, cx| {
                                            this.import_code_confirmed = !this.import_code_confirmed;
                                            cx.notify();
                                        }),
                                    ),
                            ),
                    )
                })
                .child(field_label(palette, "Vault password (this device)"))
                .child(
                    div()
                        .relative()
                        .w_full()
                        .child(
                            text_input("welcome-import-password")
                                .state(screen.import_password_state.downgrade())
                                .placeholder("Set a password for this device")
                                .caret_blink_interval_500ms()
                                .mask_char((!password_visible).then_some('*'))
                                .bg(palette.surface_bright)
                                .text_color(palette.on_surface)
                                .rounded_xl()
                                .py_3()
                                .pl_4()
                                .pr(px(48.))
                                .w_full()
                                .min_h_auto()
                                .whitespace_nowrap()
                                .overflow_x_scroll(),
                        )
                        .child(
                            div()
                                .id("welcome-import-password-toggle")
                                .absolute()
                                .right_3()
                                .top_0()
                                .bottom_0()
                                .flex()
                                .items_center()
                                .cursor_pointer()
                                .child(icon(
                                    if password_visible { "visibility_off" } else { "visibility" },
                                    px(20.),
                                    palette.on_surface_variant,
                                ))
                                .on_mouse_down(
                                    MouseButton::Left,
                                    cx.listener(|this, _, _, cx| {
                                        this.import_password_visible = !this.import_password_visible;
                                        cx.notify();
                                    }),
                                ),
                        ),
                )
                .when_some(screen.import_error.clone(), |el, error| {
                    el.child(div().text_sm().text_color(palette.error).child(error))
                })
                .child(
                    div()
                        .flex()
                        .gap_3()
                        .child(
                            div()
                                .id("welcome-import-cancel")
                                .flex_1()
                                .py_3()
                                .rounded_xl()
                                .flex()
                                .items_center()
                                .justify_center()
                                .bg(cancel_bg)
                                .text_color(palette.on_surface)
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .cursor_pointer()
                                .child("Cancel")
                                .on_hover(move |is_hovered, _, cx| {
                                    cancel_hover.update(cx, |v, cx| {
                                        *v = *is_hovered as u8 as f32;
                                        cx.notify();
                                    });
                                })
                                .on_mouse_down(
                                    MouseButton::Left,
                                    cx.listener(|this, _, _, cx| this.close_import_modal(cx)),
                                ),
                        )
                        .child(
                            div()
                                .id("welcome-import-submit")
                                .flex_1()
                                .py_3()
                                .rounded_xl()
                                .flex()
                                .items_center()
                                .justify_center()
                                .bg(if can_import {
                                    palette.primary
                                } else {
                                    gpui::Hsla { a: 0.4, ..palette.primary }
                                })
                                .text_color(palette.on_primary)
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .when(can_import, |el| el.cursor_pointer())
                                .child(if importing {
                                    "Working…"
                                } else if screen.import_is_v3 {
                                    "Continue"
                                } else {
                                    "Import & join"
                                })
                                .when(can_import, |el| {
                                    el.on_mouse_down(
                                        MouseButton::Left,
                                        cx.listener(|this, _, _, cx| this.do_import(cx)),
                                    )
                                }),
                        ),
                ),
        )
        .into_any_element()
}

/// Waiting for the other device's user to pick this device's fingerprint.
///
/// The value rendered here is `JoinV3::fingerprint`, which
/// `begin_enrollment_join` computed in-process from the keypair it had just
/// generated. It must never be replaced by one read from a response: the point
/// of the comparison is that the two devices agree about a *key*, and a number
/// off the wire would let them agree about nothing at all (audit P-1).
fn join_waiting_modal(
    palette: &Palette,
    join: JoinV3,
    error: Option<SharedString>,
    window: &mut Window,
    cx: &mut Context<WelcomeScreen>,
) -> impl IntoElement {
    let finishing = join.finishing;
    let cancel_hover = animation::hover_transition("welcome-join-cancel", window, cx);
    let cancel_t = *cancel_hover.evaluate(window, cx);
    let cancel_bg =
        animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, cancel_t);

    div()
        .id("welcome-join-modal-backdrop")
        .absolute()
        .inset_0()
        .bg(gpui::Hsla { a: 0.6, h: 0., s: 0., l: 0. })
        .flex()
        .items_center()
        .justify_center()
        .p_4()
        .child(
            div()
                .id("welcome-join-modal-body")
                .w(px(460.))
                .p_8()
                .rounded_2xl()
                .bg(palette.surface_container)
                .border_1()
                .border_color(gpui::Hsla { a: 0.2, ..palette.outline_variant })
                .flex()
                .flex_col()
                .gap_4()
                .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .child(icon("vpn_key", px(24.), palette.primary))
                        .child(
                            div()
                                .font_family(fonts::HEADLINE)
                                .font_weight(gpui::FontWeight::BOLD)
                                .text_xl()
                                .text_color(palette.on_surface)
                                .child("Join existing account"),
                        ),
                )
                .child(
                    div().text_sm().text_color(palette.on_surface_variant).child(
                        "Your other device is now showing several codes. Pick this one on it:",
                    ),
                )
                .child(
                    div()
                        .py_6()
                        .rounded_xl()
                        .bg(palette.surface_bright)
                        .flex()
                        .justify_center()
                        .child(
                            fonts::tracked_text(&join.fingerprint, px(24.), 0.15)
                                .font_family(fonts::MONO)
                                .font_weight(gpui::FontWeight::BOLD)
                                .text_color(palette.on_surface),
                        ),
                )
                .child(
                    div().text_xs().text_color(palette.on_surface_variant).child(
                        "This code is computed on this device from the key it just generated for \
                         itself. Nobody else can produce it, which is what makes picking it on \
                         your other device mean something.",
                    ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_center()
                        .gap_2()
                        .text_sm()
                        .text_color(palette.on_surface_variant)
                        .child(
                            icon("sync", px(16.), palette.on_surface_variant)
                                .opacity(animation::pulse_alpha(1.0)),
                        )
                        .child(if finishing {
                            "Confirmed — downloading your vault…"
                        } else {
                            "Waiting for confirmation…"
                        }),
                )
                .when_some(error, |el, error| {
                    el.child(div().text_sm().text_color(palette.error).child(error))
                })
                .child(
                    div()
                        .id("welcome-join-cancel")
                        .w_full()
                        .py_3()
                        .rounded_xl()
                        .flex()
                        .items_center()
                        .justify_center()
                        .bg(cancel_bg)
                        .text_color(palette.on_surface)
                        .font_weight(gpui::FontWeight::MEDIUM)
                        .when(!finishing, |el| el.cursor_pointer())
                        .child("Cancel")
                        .on_hover(move |is_hovered, _, cx| {
                            cancel_hover.update(cx, |v, cx| {
                                *v = *is_hovered as u8 as f32;
                                cx.notify();
                            });
                        })
                        .when(!finishing, |el| {
                            el.on_mouse_down(
                                MouseButton::Left,
                                cx.listener(|this, _, _, cx| {
                                    this.cancel_join_v3(cx);
                                    this.close_import_modal(cx);
                                }),
                            )
                        }),
                ),
        )
}

fn field_label(palette: &Palette, text: &'static str) -> impl IntoElement {
    div()
        .font_family(fonts::LABEL)
        .font_weight(gpui::FontWeight::MEDIUM)
        .text_xs()
        .text_color(palette.on_surface_variant)
        .child(text)
}

/// Port of `ConfirmResetModal.tsx`. Same real backend call and modal shape
/// as `BiometricGate`'s `reset_confirm_modal` (deliberately not shared as a
/// generic component across these two independent view types — see this
/// codebase's established per-screen-modal convention, e.g. `revoke_modal`/
/// `delete_modal`).
fn reset_confirm_modal(palette: &Palette, screen: &WelcomeScreen, window: &mut Window, cx: &mut Context<WelcomeScreen>) -> impl IntoElement {
    let confirm_text = screen.reset_confirm_state.read(cx).as_str().to_string();
    let can_reset = confirm_text == "DELETE";
    let resetting = screen.resetting;

    let cancel_hover = animation::hover_transition("welcome-reset-cancel", window, cx);
    let cancel_t = *cancel_hover.evaluate(window, cx);
    let cancel_bg = animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, cancel_t);

    div()
        .id("welcome-reset-modal-backdrop")
        .absolute()
        .inset_0()
        .bg(gpui::Hsla { a: 0.6, h: 0., s: 0., l: 0. })
        .flex()
        .items_center()
        .justify_center()
        .p_4()
        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| this.close_reset_modal(cx)))
        .child(
            div()
                .id("welcome-reset-modal-body")
                .map(|el| crate::keyboard::trap_tab(el, "welcome-reset-modal-trap", window, cx))
                .w(px(420.))
                .p_8()
                .rounded_2xl()
                .bg(palette.surface_container)
                .border_1()
                .border_color(gpui::Hsla { a: 0.3, ..palette.error })
                .flex()
                .flex_col()
                .gap_4()
                .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                // Enter confirms, but only once DELETE has actually been
                // typed — the same guard the button carries.
                .on_key_down(crate::keyboard::submit_on_enter(cx, |this, _window, cx| {
                    if !this.resetting && this.reset_confirm_state.read(cx).as_str() == "DELETE" {
                        this.confirm_reset(cx);
                    }
                }))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .child(icon("warning", px(24.), palette.error))
                        .child(
                            div()
                                .font_family(fonts::HEADLINE)
                                .font_weight(gpui::FontWeight::BOLD)
                                .text_xl()
                                .text_color(palette.on_surface)
                                .child("Reset vault?"),
                        ),
                )
                .child(
                    div()
                        .text_sm()
                        .text_color(palette.on_surface_variant)
                        .child(
                            "This action is irreversible. All vault data and credentials on \
                             this device will be permanently deleted. Type DELETE to confirm.",
                        ),
                )
                .when_some(screen.reset_error.clone(), |el, error| {
                    el.child(div().text_sm().text_color(palette.error).child(error))
                })
                .child(
                    text_input("welcome-reset-confirm-input")
                        .state(screen.reset_confirm_state.downgrade())
                        .placeholder("Type DELETE")
                        .caret_blink_interval_500ms()
                        .bg(palette.surface_container_highest)
                        .text_color(palette.on_surface)
                        .rounded_xl()
                        .p_3()
                        .w_full()
                        .min_h_auto()
                        .whitespace_nowrap()
                        .overflow_x_scroll(),
                )
                .child(
                    div()
                        .flex()
                        .gap_4()
                        .child(
                            div()
                                .id("welcome-cancel-reset")
                                .flex_1()
                                .py_3()
                                .rounded_xl()
                                .flex()
                                .items_center()
                                .justify_center()
                                .bg(cancel_bg)
                                .text_color(palette.on_surface)
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .cursor_pointer()
                                .child("Cancel")
                                .on_hover(move |is_hovered, _, cx| {
                                    cancel_hover.update(cx, |v, cx| {
                                        *v = *is_hovered as u8 as f32;
                                        cx.notify();
                                    });
                                })
                                .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                    this.close_reset_modal(cx);
                                })),
                        )
                        .child(
                            div()
                                .id("welcome-confirm-reset")
                                .flex_1()
                                .py_3()
                                .rounded_xl()
                                .flex()
                                .items_center()
                                .justify_center()
                                .bg(if can_reset { palette.error } else { gpui::Hsla { a: 0.4, ..palette.error } })
                                .text_color(gpui::white())
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .when(can_reset, |el| el.cursor_pointer())
                                .child(if resetting { "Resetting…" } else { "Reset forever" })
                                .when(can_reset, |el| {
                                    el.on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                        this.confirm_reset(cx);
                                    }))
                                }),
                        ),
                ),
        )
}

/// The original's closing `<footer>`: three overlapping credential avatars
/// (`-space-x-2`) beside the "trusted by" line, above a hairline rule.
fn trust_footer(palette: &Palette, top_margin: gpui::Pixels) -> impl IntoElement {
    let avatar = |name: &'static str, overlap: bool| {
        div()
            .size(px(32.))
            .rounded_full()
            .border_2()
            .border_color(palette.surface_container_low)
            .bg(palette.surface_bright)
            .flex()
            .items_center()
            .justify_center()
            .when(overlap, |el| el.ml(px(-8.)))
            .child(icon(name, px(14.), palette.on_surface_variant))
    };

    div()
        .mt(top_margin)
        .pt_8()
        .border_t_1()
        .border_color(gpui::Hsla {
            a: 0.1,
            ..palette.outline_variant
        })
        .flex()
        .items_center()
        .gap_6()
        .child(
            div()
                .flex()
                .child(avatar("key", false))
                .child(avatar("fingerprint", true))
                .child(avatar("face", true)),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .text_xs()
                .text_color(palette.on_surface_variant)
                .child("Trusted by individuals requiring")
                .child(
                    div()
                        .text_color(palette.secondary)
                        .child("sovereign data control."),
                ),
        )
}

fn action_button(
    palette: &Palette,
    id: &'static str,
    label: impl Into<SharedString>,
    icon_name: &'static str,
    enabled: bool,
    window: &mut Window,
    cx: &mut Context<WelcomeScreen>,
    on_click: impl Fn(&MouseDownEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    let label = label.into();
    let bg = palette.surface_container_highest;
    let text = palette.on_surface;
    let hover_t = animation::hover_transition(format!("welcome-{id}"), window, cx);
    let t = *hover_t.evaluate(window, cx);
    let bg = animation::lerp_hsla(bg, palette.surface_bright, t);

    let mut el = div()
        .id(id)
        .w_full()
        .flex()
        .items_center()
        .justify_between()
        // `py-4 px-6` in the original.
        .py_4()
        .px_6()
        .rounded_xl()
        .bg(bg)
        .text_color(text)
        .font_family(fonts::HEADLINE)
        .font_weight(gpui::FontWeight::MEDIUM)
        .child(fonts::tracked_text(&label, px(16.), 0.025))
        .child(icon(icon_name, px(20.), palette.primary));

    if enabled {
        el = el
            .cursor_pointer()
            .on_hover(move |is_hovered, _, cx| {
                hover_t.update(cx, |v, cx| {
                    *v = *is_hovered as u8 as f32;
                    cx.notify();
                });
            })
            .on_mouse_down(MouseButton::Left, on_click);
    } else {
        el = el.opacity(0.5);
    }

    el
}

/// The primary "Create new vault" button — port of the original's
/// gradient-border trick (`bg-gradient-to-r ... p-[1px]` outer +
/// `bg-surface-container-lowest` inner that fades to transparent on hover,
/// revealing the full gradient behind it). Distinct from `action_button`
/// (used by the other 3 buttons, which are flat `bg-surface-container-
/// highest`) — this is the one button in the group with real gradient
/// treatment in the original.
fn primary_action_button(
    palette: &Palette,
    id: &'static str,
    label: impl Into<SharedString>,
    icon_name: &'static str,
    enabled: bool,
    window: &mut Window,
    cx: &mut Context<WelcomeScreen>,
    on_click: impl Fn(&MouseDownEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    let label = label.into();
    let hover_t = animation::hover_transition(format!("welcome-{id}"), window, cx);
    let t = *hover_t.evaluate(window, cx);
    let inner_bg = animation::lerp_hsla(palette.surface_container_lowest, gpui::transparent_black(), t);
    let icon_color = animation::lerp_hsla(palette.primary, palette.on_primary, t);
    let gradient = gpui::linear_gradient(
        90.,
        gpui::linear_color_stop(palette.primary, 0.),
        gpui::linear_color_stop(palette.primary_dim, 1.),
    );

    // The inner fill has to be a *flex child* that grows: a percentage width
    // resolved against this stretched parent falls back to the content size,
    // which leaves the gradient showing as a slab beside a shrink-wrapped
    // pill instead of reading as a 1px border.
    let mut outer = div().id(id).w_full().flex().rounded_xl().p(px(1.)).bg(gradient).child(
        div()
            .flex_1()
            .min_w_0()
            .bg(inner_bg)
            .rounded(px(11.))
            .py_4()
            .px_6()
            .flex()
            .items_center()
            .justify_between()
            .child(fonts::tracked_text(&label, px(16.), 0.025).font_family(fonts::HEADLINE).font_weight(gpui::FontWeight::BOLD).text_color(palette.on_surface))
            .child(icon(icon_name, px(20.), icon_color)),
    );

    if enabled {
        outer = outer
            .cursor_pointer()
            .on_hover(move |is_hovered, _, cx| {
                hover_t.update(cx, |v, cx| {
                    *v = *is_hovered as u8 as f32;
                    cx.notify();
                });
            })
            .on_mouse_down(MouseButton::Left, on_click);
    } else {
        outer = outer.opacity(0.5);
    }

    outer
}

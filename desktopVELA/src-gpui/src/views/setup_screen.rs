//! Port of `desktopVELA/src/views/SetupScreen.tsx` — first-run onboarding
//! wizard: welcome -> biometric or password -> recovery -> complete.
//!
//! The password step creates a real vault (`create_vault_with_password`),
//! and the biometric step runs the real enrollment probe and unlock — same
//! backend calls as the Tauri build. Because that backend will overwrite an
//! existing vault without asking and there is no undo, both paths refuse
//! outright when `check_vault_exists` says one is already there.
//!
//! All three recovery methods call the real backend: cloud backup (rclone),
//! security key (WebAuthn/CTAP2), and trusted contact (Share 3, handed to
//! the user to deliver out of band). Leaving the step also runs
//! `finalize_recovery_setup`, which drops the locally cached shares — the
//! split is pointless while all three still sit on this device.
//!
//! The "Skip for now" button is a deliberate addition the original lacks:
//! the 2-of-3 Continue gate can still be unreachable (no rclone remote, no
//! FIDO2 key), and nobody should be stuck in the wizard unable to finish
//! creating a vault. Recovery stays configurable from Settings.

use std::sync::Arc;

use gpui::{
    div, prelude::*, px, App, Context, EventEmitter, IntoElement, MouseButton, MouseDownEvent,
    Render, SharedString, Window,
};
use gpui_elements::editable_text::{text_input, EditableTextState, StringStorage};

use vela_desktop_core::biometric::BiometricProvider;
use vela_desktop_core::commands::session;
use vela_desktop_core::AppState;

use crate::background::GuardedSpawn;
use crate::animation;
use crate::fonts;
use crate::icon::icon;
use crate::theme::Palette;

#[derive(Clone, Copy, PartialEq)]
enum Step {
    Welcome,
    Biometric,
    Password,
    Recovery,
    Complete,
}

pub enum SetupScreenEvent {
    Complete,
}
impl EventEmitter<SetupScreenEvent> for SetupScreen {}

pub struct SetupScreen {
    _app_state: Arc<AppState>,
    step: Step,
    biometric_available: Option<bool>,
    password_state: gpui::Entity<EditableTextState>,
    confirm_state: gpui::Entity<EditableTextState>,
    password_visible: bool,
    password_error: Option<SharedString>,
    is_working: bool,
    cloud_backup_done: bool,
    security_key_done: bool,
    trusted_contact_done: bool,
    /// Security-key registration (the real WebAuthn/CTAP2 ceremony, shared
    /// with Settings' Recovery section) needs a PIN, so it opens a modal
    /// rather than acting straight from the row.
    show_security_key_modal: bool,
    security_key_pin_state: gpui::Entity<EditableTextState>,
    registering_security_key: bool,
    security_key_error: Option<SharedString>,
    show_cloud_backup_modal: bool,
    cloud_remotes: Option<Vec<SharedString>>,
    selected_cloud_remote: Option<SharedString>,
    loading_cloud_remotes: bool,
    uploading_cloud_backup: bool,
    cloud_backup_error: Option<SharedString>,
    /// Share 3 has no VELA-operated channel — it is shown to the user to
    /// deliver however they like — so the modal holds it in memory only,
    /// for as long as it is on screen.
    show_trusted_contact_modal: bool,
    trusted_contact_share: Option<SharedString>,
    contact_key_state: gpui::Entity<EditableTextState>,
    loading_trusted_contact: bool,
    acknowledging_trusted_contact: bool,
    trusted_contact_error: Option<SharedString>,
}

impl SetupScreen {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        cx.spawn(async move |this, cx| {
            let status = cx
                .background_spawn_guarded("setup enrollment check", async {
                    vela_desktop_core::biometric::check_enrollment()
                })
                .await
                .unwrap_or_default();
            let available = !matches!(
                status.provider,
                BiometricProvider::None | BiometricProvider::MasterPassword
            );
            this.update(cx, |this, cx| {
                this.biometric_available = Some(available);
                cx.notify();
            })
            .ok();
        })
        .detach();

        Self {
            _app_state: app_state,
            step: Step::Welcome,
            biometric_available: None,
            password_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
            confirm_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
            password_visible: false,
            password_error: None,
            is_working: false,
            cloud_backup_done: false,
            security_key_done: false,
            trusted_contact_done: false,
            show_security_key_modal: false,
            security_key_pin_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
            registering_security_key: false,
            security_key_error: None,
            show_cloud_backup_modal: false,
            cloud_remotes: None,
            selected_cloud_remote: None,
            loading_cloud_remotes: false,
            uploading_cloud_backup: false,
            cloud_backup_error: None,
            show_trusted_contact_modal: false,
            trusted_contact_share: None,
            contact_key_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
            loading_trusted_contact: false,
            acknowledging_trusted_contact: false,
            trusted_contact_error: None,
        }
    }

    fn open_security_key_modal(&mut self, cx: &mut Context<Self>) {
        self.security_key_pin_state.update(cx, |s, cx| s.emplace("", cx));
        self.security_key_error = None;
        self.show_security_key_modal = true;
        cx.notify();
    }

    fn close_security_key_modal(&mut self, cx: &mut Context<Self>) {
        self.show_security_key_modal = false;
        cx.notify();
    }

    fn register_security_key(&mut self, cx: &mut Context<Self>) {
        let pin = self.security_key_pin_state.read(cx).as_str().to_string();
        self.registering_security_key = true;
        self.security_key_error = None;
        cx.notify();

        let app_state = self._app_state.clone();
        cx.spawn(async move |this, cx| {
            // Real network I/O plus blocking USB HID access to the key —
            // gpui_tokio's bridge, not `background_spawn`.
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                vela_desktop_core::webauthn::register_security_key(&app_state, pin).await
            })
            .await;
            this.update(cx, |this, cx| {
                this.registering_security_key = false;
                match result {
                    Ok(Ok(())) => {
                        this.show_security_key_modal = false;
                        this.security_key_done = true;
                        crate::toast::show(
                            cx,
                            "Security key registered",
                            crate::toast::ToastKind::Success,
                        );
                    }
                    Ok(Err(e)) => this.security_key_error = Some(e.into()),
                    Err(e) => this.security_key_error = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn open_cloud_backup_modal(&mut self, cx: &mut Context<Self>) {
        self.cloud_backup_error = None;
        self.cloud_remotes = None;
        self.selected_cloud_remote = None;
        self.loading_cloud_remotes = true;
        self.show_cloud_backup_modal = true;
        cx.notify();

        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn_guarded("list cloud backup remotes", async {
                    vela_desktop_core::recovery::list_cloud_backup_remotes().await
                })
                .await
                .unwrap_or_else(|| Err("Listing cloud remotes failed unexpectedly".to_string()));
            this.update(cx, |this, cx| {
                this.loading_cloud_remotes = false;
                match result {
                    Ok(remotes) => {
                        let remotes: Vec<SharedString> =
                            remotes.into_iter().map(SharedString::from).collect();
                        this.selected_cloud_remote = remotes.first().cloned();
                        this.cloud_remotes = Some(remotes);
                    }
                    Err(e) => this.cloud_backup_error = Some(e.into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn close_cloud_backup_modal(&mut self, cx: &mut Context<Self>) {
        self.show_cloud_backup_modal = false;
        cx.notify();
    }

    fn upload_cloud_backup(&mut self, cx: &mut Context<Self>) {
        let Some(remote) = self.selected_cloud_remote.clone() else { return };
        self.uploading_cloud_backup = true;
        self.cloud_backup_error = None;
        cx.notify();

        let app_state = self._app_state.clone();
        cx.spawn(async move |this, cx| {
            // `rclone` upload is blocking process I/O, but `ensure_shares_split`
            // ahead of it touches the vault — both are fine off the reactor.
            let result = cx
                .background_spawn_guarded("upload cloud backup share", async move {
                    vela_desktop_core::recovery::setup_cloud_backup_recovery(
                        &app_state,
                        remote.to_string(),
                    )
                    .await
                })
                .await
                .unwrap_or_else(|| Err("Uploading the recovery share failed unexpectedly".to_string()));
            this.update(cx, |this, cx| {
                this.uploading_cloud_backup = false;
                match result {
                    Ok(()) => {
                        this.show_cloud_backup_modal = false;
                        this.cloud_backup_done = true;
                        crate::toast::show(
                            cx,
                            "Recovery share uploaded",
                            crate::toast::ToastKind::Success,
                        );
                    }
                    Err(e) => this.cloud_backup_error = Some(e.into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn open_trusted_contact_modal(&mut self, cx: &mut Context<Self>) {
        self.trusted_contact_error = None;
        self.trusted_contact_share = None;
        self.loading_trusted_contact = false;
        self.show_trusted_contact_modal = true;
        cx.notify();
    }

    /// Seal Share 3 into an authenticated, recipient-bound envelope for the
    /// pasted contact public key (M18).
    fn seal_trusted_contact_envelope(&mut self, cx: &mut Context<Self>) {
        let contact_key = self.contact_key_state.read(cx).as_str().trim().to_string();
        if contact_key.is_empty() {
            self.trusted_contact_error = Some("Paste your contact's public key first".into());
            cx.notify();
            return;
        }
        self.trusted_contact_error = None;
        self.loading_trusted_contact = true;
        cx.notify();

        let app_state = self._app_state.clone();
        cx.spawn(async move |this, cx| {
            // Splitting the RMS touches the vault and writes the pending-share
            // file, so it goes off the main thread like the other two methods.
            let result = cx
                .background_spawn_guarded("seal trusted contact envelope", async move {
                    vela_desktop_core::recovery::seal_trusted_contact_share(
                        &app_state,
                        &contact_key,
                    )
                    .await
                })
                .await
                .unwrap_or_else(|| Err("Sealing the recovery envelope failed unexpectedly".to_string()));
            this.update(cx, |this, cx| {
                this.loading_trusted_contact = false;
                match result {
                    Ok(handoff) => {
                        this.trusted_contact_share = Some(
                            serde_json::to_string(&handoff)
                                .unwrap_or_else(|_| "{}".into())
                                .into(),
                        );
                    }
                    Err(e) => this.trusted_contact_error = Some(e.into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn close_trusted_contact_modal(&mut self, cx: &mut Context<Self>) {
        self.show_trusted_contact_modal = false;
        // Don't leave a recovery share sitting in the view after it closes.
        self.trusted_contact_share = None;
        cx.notify();
    }

    fn copy_trusted_contact_share(&mut self, cx: &mut Context<Self>) {
        let Some(share) = self.trusted_contact_share.clone() else { return };
        // A share is key material: copy it as a secret so it stays out of
        // clipboard history, exactly like the enrollment code.
        crate::clipboard::copy(cx, "Recovery share", share.as_ref());
    }

    fn acknowledge_trusted_contact(&mut self, cx: &mut Context<Self>) {
        self.acknowledging_trusted_contact = true;
        cx.notify();

        let app_state = self._app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn_guarded("acknowledge trusted contact share", async move {
                    vela_desktop_core::recovery::acknowledge_trusted_contact_share(&app_state).await
                })
                .await
                .unwrap_or_else(|| Err("Recording the handover failed unexpectedly".to_string()));
            this.update(cx, |this, cx| {
                this.acknowledging_trusted_contact = false;
                // Best-effort bookkeeping: the share was generated and shown
                // either way, so a failure here must not strand the user.
                if let Err(e) = result {
                    tracing::warn!("Could not record trusted-contact handover: {e}");
                }
                this.trusted_contact_done = true;
                this.show_trusted_contact_modal = false;
                this.trusted_contact_share = None;
                crate::toast::show(cx, "Trusted contact share delivered", crate::toast::ToastKind::Success);
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    /// Commit the exact server/cloud publication before leaving recovery setup.
    fn finalize_recovery(&mut self, cx: &mut Context<Self>) {
        let app_state = self._app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn_guarded("finalize recovery setup", async move {
                    vela_desktop_core::recovery::finalize_recovery_setup(&app_state).await
                })
                .await;
            this.update(cx, |this, cx| {
                match result {
                    Some(Ok(())) => this.step = Step::Complete,
                    Some(Err(e)) => crate::toast::show(
                        cx,
                        &format!("Recovery publication failed: {e}"),
                        crate::toast::ToastKind::Error,
                    ),
                    None => tracing::warn!("Recovery finalization task was cancelled"),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn discard_recovery(&mut self, cx: &mut Context<Self>) {
        if let Err(e) =
            vela_desktop_core::recovery::discard_recovery_setup(&self._app_state)
        {
            tracing::warn!("Could not discard incomplete recovery setup: {e}");
        }
        self.step = Step::Complete;
        cx.notify();
    }

    fn submit_password(&mut self, cx: &mut Context<Self>) {
        let password = self.password_state.read(cx).as_str().to_string();
        let confirm = self.confirm_state.read(cx).as_str().to_string();
        if password.len() < 8 {
            self.password_error = Some("Password must be at least 8 characters".into());
            cx.notify();
            return;
        }
        if password != confirm {
            self.password_error = Some("Passwords do not match".into());
            cx.notify();
            return;
        }
        self.password_error = None;

        // The guard the backend doesn't have: `create_vault_with_password`
        // will happily overwrite an existing vault, and there is no undo for
        // that. Refuse rather than trust the wizard to never be reachable
        // with a vault present.
        if session::check_vault_exists(&self._app_state) {
            self.password_error =
                Some("A vault already exists on this device. Unlock it instead of creating a new one.".into());
            cx.notify();
            return;
        }

        self.is_working = true;
        cx.notify();

        let app_state = self._app_state.clone();
        cx.spawn(async move |this, cx| {
            // Vault creation touches the keyring/TPM and, when a server is
            // configured, registers the device — real I/O, off the main
            // thread.
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                session::create_vault_with_password(&app_state, password).await
            })
            .await;
            this.update(cx, |this, cx| {
                this.is_working = false;
                match result {
                    Ok(Ok(())) => {
                        tracing::info!("Vault created with a master password");
                        this.step = Step::Recovery;
                    }
                    Ok(Err(e)) => this.password_error = Some(e.into()),
                    Err(e) => this.password_error = Some(format!("Vault creation failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    /// Port of the original's `handleBiometricEnroll`. Note what it does
    /// *not* do: create a vault. Enrolling here proves the existing
    /// device-bound key still unlocks; a first-run machine has no key to
    /// prove, so it falls through to the password step, which is where the
    /// vault is actually created (and where the RMS gets sealed into the TPM
    /// or keyring on the way).
    fn enroll_biometric(&mut self, cx: &mut Context<Self>) {
        self.is_working = true;
        self.password_error = None;
        cx.notify();

        let app_state = self._app_state.clone();
        cx.spawn(async move |this, cx| {
            let status = cx
                .background_spawn_guarded("setup enrollment probe", async {
                    vela_desktop_core::biometric::check_enrollment()
                })
                .await
                .unwrap_or_default();
            let usable = status.enrolled
                && !matches!(
                    status.provider,
                    BiometricProvider::None | BiometricProvider::MasterPassword
                );
            if !usable || !session::check_vault_exists(&app_state) {
                this.update(cx, |this, cx| {
                    this.is_working = false;
                    this.step = Step::Password;
                    cx.notify();
                })
                .ok();
                return;
            }

            let result = cx
                .background_spawn_guarded("setup biometric authenticate", async {
                    vela_desktop_core::biometric::authenticate()
                })
                .await;
            this.update(cx, |this, cx| {
                this.is_working = false;
                match result {
                    Some(result) if result.success => this.step = Step::Recovery,
                    Some(result) => {
                        this.password_error = Some(
                            result
                                .error_message
                                .unwrap_or_else(|| {
                                    "Authentication failed - use password instead".to_string()
                                })
                                .into(),
                        );
                    }
                    // The original's `catch` arm: a ceremony that fails
                    // outright drops to the password path rather than
                    // dead-ending on the biometric step.
                    None => this.step = Step::Password,
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }
}

impl Render for SetupScreen {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = crate::theme::current_palette(cx);

        let content = match self.step {
            Step::Welcome => welcome_step(self, &palette, window, cx),
            Step::Biometric => biometric_step(self, &palette, window, cx),
            Step::Password => password_step(self, &palette, window, cx),
            Step::Recovery => recovery_step(self, &palette, window, cx),
            Step::Complete => complete_step(&palette, window, cx),
        };

        // `max-w-lg w-full` on every step except Recovery, which is
        // `max-w-xl` because it carries three option cards. The original's
        // `<main>` is `p-6 overflow-y-auto` with `my-auto` on the content, so
        // a step taller than the window scrolls instead of being clipped —
        // Recovery is routinely taller than 720px.
        let content_max_width = match self.step {
            Step::Recovery => px(576.),
            _ => px(512.),
        };
        // The original pins Back to the *screen* corner, outside the step's
        // own column. gpui resolves `absolute` against the parent, not the
        // nearest positioned ancestor, so it has to be mounted at the root.
        let back_target = match self.step {
            Step::Biometric | Step::Password => Some(Step::Welcome),
            Step::Recovery => Some(Step::Password),
            Step::Welcome | Step::Complete => None,
        };

        div()
            .id("setup")
            .relative()
            .size_full()
            .overflow_y_scroll()
            .bg(palette.surface)
            .font_family(fonts::LABEL)
            .child(
                div()
                    .min_h_full()
                    .w_full()
                    .flex()
                    .items_center()
                    .justify_center()
                    .p_6()
                    // `flex_col` so the step stretches to the block's width:
                    // the steps' own `w_full` buttons measure against it, and
                    // a shrink-to-fit step would leave them content-sized.
                    .child(
                        div()
                            .w_full()
                            .max_w(content_max_width)
                            .flex()
                            .flex_col()
                            .child(content),
                    ),
            )
            .when_some(back_target, |el, target| {
                el.child(back_button(target, cx))
            })
            // Modals mount at the top level, not inside `recovery_step` —
            // the same fix already applied across the other screens, so an
            // `.absolute().inset_0()` backdrop resolves against the real
            // viewport rather than a nested (possibly scrolling) container.
            .when(self.show_security_key_modal, |el| {
                el.child(security_key_modal(&palette, self, window, cx))
            })
            .when(self.show_trusted_contact_modal, |el| {
                el.child(trusted_contact_modal(&palette, self, window, cx))
            })
            .when(self.show_cloud_backup_modal, |el| {
                el.child(cloud_backup_modal(&palette, self, window, cx))
            })
    }
}

/// PIN prompt for the real FIDO2 registration ceremony. Same shape and same
/// backend call as Settings' Recovery section — the SetupScreen wizard and
/// Settings are two entry points to one flow, so a key registered here counts
/// toward the same 2-of-3 gate.
/// Share 3 of the 2-of-3 split, shown for the user to deliver themselves.
///
/// A lone share below the threshold is information-theoretically
/// indistinguishable from random bytes, so displaying it here reveals nothing
/// about the vault — it only becomes meaningful next to a second share.
fn trusted_contact_modal(
    palette: &Palette,
    screen: &SetupScreen,
    window: &mut Window,
    cx: &mut Context<SetupScreen>,
) -> impl IntoElement {
    let has_share = screen.trusted_contact_share.is_some();
    let acknowledging = screen.acknowledging_trusted_contact;

    let body = modal_body(palette, "setup-trusted-contact")
        .child(modal_header(palette, "person_add", "Trusted contact"))
        .child(
            div().text_sm().text_color(palette.on_surface_variant).child(
                "One of three recovery pieces. Paste your contact's public key to seal this \
                 recovery share into an envelope only they can open — they only need to hand \
                 it back if you lose every device.",
            ),
        )
        .when(screen.trusted_contact_share.is_none(), |el| {
            el.child(
                text_input("setup-contact-public-key-input")
                    .state(screen.contact_key_state.downgrade())
                    .placeholder("Base64 contact public key")
                    .caret_blink_interval_500ms()
                    .font_family(fonts::MONO)
                    .bg(palette.surface_container_highest)
                    .text_color(palette.on_surface)
                    .caret_color(palette.on_surface)
                    .rounded_lg()
                    .p_3()
                    .w_full()
                    .min_h_auto(),
            )
            .child(modal_primary_button(
                palette,
                "setup-trusted-contact-seal",
                "Seal envelope",
                !screen.loading_trusted_contact,
                cx.listener(|this, _, _, cx| this.seal_trusted_contact_envelope(cx)),
            ))
        })
        .map(|el| {
            if screen.loading_trusted_contact {
                return el.child(
                    div()
                        .text_sm()
                        .text_color(palette.on_surface_variant)
                        .child("Sealing recovery envelope…"),
                );
            }
            match screen.trusted_contact_share.as_ref() {
                Some(share) => el.child(
                    div()
                        .id("setup-trusted-contact-share")
                        .max_h(px(160.))
                        .overflow_y_scroll()
                        .p_3()
                        .rounded_xl()
                        .border_1()
                        .border_color(gpui::Hsla { a: 0.3, ..palette.outline_variant })
                        .bg(palette.surface_bright)
                        .font_family(fonts::MONO)
                        .text_xs()
                        .text_color(palette.on_surface)
                        .child(share.clone()),
                ),
                None => el,
            }
        })
        .when_some(screen.trusted_contact_error.clone(), |el, error| {
            el.child(div().text_sm().text_color(palette.error).child(error))
        })
        .when(has_share, |el| {
            el.child(modal_primary_button(
                palette,
                "setup-trusted-contact-copy",
                "Copy envelope",
                !acknowledging,
                cx.listener(|this, _, _, cx| this.copy_trusted_contact_share(cx)),
            ))
        })
        .child(modal_primary_button(
            palette,
            "setup-trusted-contact-done",
            if acknowledging { "Saving…" } else { "I've sent it" },
            has_share && !acknowledging,
            cx.listener(|this, _, _, cx| this.acknowledge_trusted_contact(cx)),
        ))
        .child(modal_cancel_button(
            palette,
            "setup-trusted-contact-cancel",
            window,
            cx,
            cx.listener(|this, _, _, cx| this.close_trusted_contact_modal(cx)),
        ));

    modal_backdrop("setup-trusted-contact", cx, |this, cx| this.close_trusted_contact_modal(cx))
        .child(body)
}

fn security_key_modal(
    palette: &Palette,
    screen: &SetupScreen,
    window: &mut Window,
    cx: &mut Context<SetupScreen>,
) -> impl IntoElement {
    let registering = screen.registering_security_key;

    modal_backdrop("setup-security-key", cx, |this, cx| this.close_security_key_modal(cx)).child(
        modal_body(palette, "setup-security-key")
            .map(|el| crate::keyboard::trap_tab(el, "setup-security-key-trap", window, cx))
            .on_key_down(crate::keyboard::submit_on_enter(cx, |this, _window, cx| {
                if !this.registering_security_key {
                    this.register_security_key(cx);
                }
            }))
            .child(modal_header(palette, "key", "Register security key"))
            .child(
                div().text_sm().text_color(palette.on_surface_variant).child(
                    "Insert your FIDO2 security key and enter its PIN. VELA will register a \
                     passkey and hand the server your recovery share, gated behind that key.",
                ),
            )
            .child(
                text_input("setup-security-key-pin")
                    .state(screen.security_key_pin_state.downgrade())
                    .placeholder("Security key PIN")
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
            .when_some(screen.security_key_error.clone(), |el, error| {
                el.child(div().text_sm().text_color(palette.error).child(error))
            })
            .child(modal_primary_button(
                palette,
                "setup-security-key-submit",
                if registering { "Waiting for security key…" } else { "Register" },
                !registering,
                cx.listener(|this, _, _, cx| this.register_security_key(cx)),
            ))
            .child(modal_cancel_button(
                palette,
                "setup-security-key-cancel",
                window,
                cx,
                cx.listener(|this, _, _, cx| this.close_security_key_modal(cx)),
            )),
    )
}

/// Remote picker for uploading Share 1 (recovery method 1). Replaces what was
/// previously a stub that flipped the row to "done" without uploading
/// anything — which would have left the user believing they had a recovery
/// share in the cloud that did not exist.
fn cloud_backup_modal(
    palette: &Palette,
    screen: &SetupScreen,
    window: &mut Window,
    cx: &mut Context<SetupScreen>,
) -> impl IntoElement {
    let uploading = screen.uploading_cloud_backup;
    let has_remote = screen.selected_cloud_remote.is_some();

    let body = modal_body(palette, "setup-cloud-backup")
        .child(modal_header(palette, "cloud_upload", "Cloud backup"))
        .child(
            div().text_sm().text_color(palette.on_surface_variant).child(
                "Pick the rclone remote to upload recovery Share 1 to. You'll need this same \
                 remote configured on any device you later recover onto.",
            ),
        )
        .map(|el| {
        if screen.loading_cloud_remotes {
            return el.child(
                div()
                    .text_sm()
                    .text_color(palette.on_surface_variant)
                    .child("Checking configured rclone remotes…"),
            );
        }
        match screen.cloud_remotes.as_ref() {
            Some(remotes) if !remotes.is_empty() => el.child(
                div()
                    .id("setup-cloud-remotes")
                    .max_h(px(180.))
                    .overflow_y_scroll()
                    .rounded_xl()
                    .border_1()
                    .border_color(gpui::Hsla { a: 0.3, ..palette.outline_variant })
                    .bg(palette.surface_bright)
                    .flex()
                    .flex_col()
                    .children(remotes.iter().enumerate().map(|(index, remote)| {
                        let is_selected = screen.selected_cloud_remote.as_ref() == Some(remote);
                        let remote_for_click = remote.clone();
                        div()
                            .id(("setup-cloud-remote", index))
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
                                if is_selected {
                                    "radio_button_checked"
                                } else {
                                    "radio_button_unchecked"
                                },
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
                                    this.selected_cloud_remote = Some(remote_for_click.clone());
                                    cx.notify();
                                }),
                            )
                    })),
            ),
            _ => el.child(
                div().text_sm().text_color(palette.on_surface_variant).child(
                    "No configured rclone remotes found. Install rclone and configure a remote, \
                     then come back here.",
                ),
            ),
        }
    })
        .when_some(screen.cloud_backup_error.clone(), |el, error| {
            el.child(div().text_sm().text_color(palette.error).child(error))
        })
        .child(modal_primary_button(
            palette,
            "setup-cloud-backup-submit",
            if uploading { "Uploading…" } else { "Upload share" },
            has_remote && !uploading,
            cx.listener(|this, _, _, cx| this.upload_cloud_backup(cx)),
        ))
        .child(modal_cancel_button(
            palette,
            "setup-cloud-backup-cancel",
            window,
            cx,
            cx.listener(|this, _, _, cx| this.close_cloud_backup_modal(cx)),
        ));

    modal_backdrop("setup-cloud-backup", cx, |this, cx| this.close_cloud_backup_modal(cx))
        .child(body)
}

// ── Shared modal chrome for this screen's two recovery modals ──────────────

fn modal_backdrop(
    id: &'static str,
    cx: &mut Context<SetupScreen>,
    on_dismiss: impl Fn(&mut SetupScreen, &mut Context<SetupScreen>) + 'static,
) -> gpui::Stateful<gpui::Div> {
    div()
        .id(id)
        .absolute()
        .inset_0()
        .bg(gpui::Hsla { a: 0.6, h: 0., s: 0., l: 0. })
        .flex()
        .items_center()
        .justify_center()
        .p_4()
        .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| on_dismiss(this, cx)))
}

fn modal_body(palette: &Palette, id: &'static str) -> gpui::Stateful<gpui::Div> {
    div()
        .id(id)
        .w(px(440.))
        .max_h(px(600.))
        .overflow_y_scroll()
        .p_8()
        .rounded_2xl()
        .bg(palette.surface_container)
        .border_1()
        .border_color(gpui::Hsla { a: 0.2, ..palette.outline_variant })
        .flex()
        .flex_col()
        .gap_4()
        // Swallow clicks so they don't reach the backdrop's dismiss handler.
        .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
}

fn modal_header(palette: &Palette, icon_name: &'static str, title: &'static str) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .gap_3()
        .child(icon(icon_name, px(24.), palette.primary))
        .child(
            div()
                .font_family(fonts::HEADLINE)
                .font_weight(gpui::FontWeight::BOLD)
                .text_xl()
                .text_color(palette.on_surface)
                .child(title),
        )
}

fn modal_primary_button(
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

fn modal_cancel_button(
    palette: &Palette,
    id: &'static str,
    window: &mut Window,
    cx: &mut Context<SetupScreen>,
    on_click: impl Fn(&MouseDownEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    let hover = animation::hover_transition(id, window, cx);
    let t = *hover.evaluate(window, cx);
    let bg = animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, t);

    div()
        .id(id)
        .w_full()
        .py_2()
        .rounded_xl()
        .flex()
        .items_center()
        .justify_center()
        .bg(bg)
        .text_sm()
        .text_color(palette.on_surface)
        .cursor_pointer()
        .child("Cancel")
        .on_hover(move |is_hovered, _, cx| {
            hover.update(cx, |v, cx| {
                *v = *is_hovered as u8 as f32;
                cx.notify();
            });
        })
        .on_mouse_down(MouseButton::Left, on_click)
}

fn back_button(target: Step, cx: &mut Context<SetupScreen>) -> impl IntoElement {
    let palette = crate::theme::current_palette(cx);
    div()
        .id("back")
        // `absolute top-4 left-4 sm:top-6 sm:left-6` — pinned to the screen
        // corner, not stacked above the step's own content.
        .absolute()
        .top_6()
        .left_6()
        .flex()
        .items_center()
        .gap_2()
        .text_sm()
        .text_color(palette.on_surface_variant)
        .cursor_pointer()
        .child(icon("arrow_back", px(16.), palette.on_surface_variant))
        .child("Back")
        .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
            this.step = target;
            cx.notify();
        }))
}

fn step_icon(palette: &Palette, name: &'static str) -> impl IntoElement {
    // `w-24 h-24 mx-auto rounded-2xl` around a `text-6xl` symbol — the
    // wrapper is what makes `mx-auto` work on steps that don't centre their
    // children themselves.
    div().w_full().flex().justify_center().child(
        div()
            .w(px(96.))
            .h(px(96.))
            .flex_shrink_0()
            .rounded_2xl()
            .bg(palette.surface_container)
            .flex()
            .items_center()
            .justify_center()
            .child(icon(name, px(56.), palette.primary)),
    )
}

fn step_title(palette: &Palette, title: &'static str) -> impl IntoElement {
    div()
        .font_family(fonts::HEADLINE)
        .font_weight(gpui::FontWeight::BOLD)
        .text_size(px(30.))
        .text_center()
        .text_color(palette.on_surface)
        .child(title)
}

fn step_body(palette: &Palette, body: &'static str) -> impl IntoElement {
    div()
        .font_family(fonts::BODY)
        .text_center()
        .text_color(palette.on_surface_variant)
        .child(body)
}

fn welcome_step(
    screen: &SetupScreen,
    palette: &Palette,
    window: &mut Window,
    cx: &mut Context<SetupScreen>,
) -> gpui::AnyElement {
    let checking = screen.biometric_available.is_none();
    let label: SharedString = if checking { "Checking…".into() } else { "Create new vault".into() };

    div()
        .flex()
        .flex_col()
        .items_center()
        .gap_6()
        .child(step_icon(palette, "lock"))
        .child(step_title(palette, "Welcome to VELA"))
        .child(step_body(
            palette,
            "Your passwordless, zero-knowledge vault with post-quantum security.",
        ))
        .child(
            div()
                .w_full()
                .flex()
                .flex_col()
                .gap_3()
                .child(primary_button("create-vault", label, !checking, window, cx, |this, cx| {
                    this.step = if this.biometric_available == Some(true) {
                        Step::Biometric
                    } else {
                        Step::Password
                    };
                    cx.notify();
                }))
                .child(secondary_button("existing-vault", "I have an existing vault", !checking, cx, |this, cx| {
                    this.step = Step::Password;
                    cx.notify();
                })),
        )
        .into_any_element()
}

fn biometric_step(
    screen: &SetupScreen,
    palette: &Palette,
    window: &mut Window,
    cx: &mut Context<SetupScreen>,
) -> gpui::AnyElement {
    let working = screen.is_working;
    div()
        .flex()
        .flex_col()
        .gap_4()
        .child(step_icon(palette, "fingerprint"))
        .child(step_title(palette, "Set up biometrics"))
        .child(step_body(
            palette,
            "Your fingerprint or face will be the primary way to unlock VELA.",
        ))
        .child(primary_button(
            "enroll",
            if working { "Setting up…" } else { "Enable biometric unlock" },
            !working,
            window,
            cx,
            |this, cx| this.enroll_biometric(cx),
        ))
        .child(
            div()
                .p_3()
                .rounded_lg()
                .bg(gpui::rgb(0x2a2410))
                .flex()
                .items_start()
                .gap_2()
                .child(icon("info", px(18.), gpui::rgb(0xf59e0b).into()))
                .child(
                    div()
                        .font_family(fonts::BODY)
                        .text_sm()
                        .text_color(palette.on_surface_variant)
                        .child("You'll also set up a master password as a backup in the next step."),
                ),
        )
        .into_any_element()
}

fn password_step(
    screen: &SetupScreen,
    palette: &Palette,
    window: &mut Window,
    cx: &mut Context<SetupScreen>,
) -> gpui::AnyElement {
    let error = screen.password_error.clone();
    div()
        .flex()
        .flex_col()
        .gap_4()
        // Enter from either password box creates the vault, so the whole step
        // can be completed without reaching for the mouse.
        .on_key_down(crate::keyboard::submit_on_enter(cx, |this, _window, cx| {
            this.submit_password(cx);
        }))
        .child(step_icon(palette, "password"))
        .child(step_title(palette, "Set up master password"))
        .child(step_body(
            palette,
            "Create a strong master password to protect your vault.",
        ))
        .child(masked_password_field(
            "setup-password",
            &screen.password_state,
            "Master password (min 8 characters)",
            screen.password_visible,
            palette,
            cx,
        ))
        .child(masked_password_field(
            "setup-confirm",
            &screen.confirm_state,
            "Confirm password",
            screen.password_visible,
            palette,
            cx,
        ))
        .when_some(error, |el, error| {
            el.child(
                div()
                    .font_family(fonts::BODY)
                    .text_sm()
                    .text_color(palette.error)
                    .child(error),
            )
        })
        .child(primary_button("submit-password", "Create Vault", true, window, cx, |this, cx| {
            this.submit_password(cx);
        }))
        .into_any_element()
}

/// A real masked password field — port of the original's shared
/// `passwordVisible` toggle covering both the master-password and confirm-
/// password inputs on this step. Uses the vendored `gpui_elements` patch's
/// `.mask_char()` (see its doc comment in `editable_text/element.rs`).
fn masked_password_field(
    id: &'static str,
    state: &gpui::Entity<EditableTextState>,
    placeholder: &'static str,
    visible: bool,
    palette: &Palette,
    cx: &mut Context<SetupScreen>,
) -> impl IntoElement {
    div()
        .relative()
        .child(
            text_input(id)
                .state(state.downgrade())
                .placeholder(placeholder)
                .caret_blink_interval_500ms()
                // Single-byte ASCII mask char — see biometric_gate.rs's
                // `mask_char` comment for why '•' (multi-byte in UTF-8)
                // misplaces the caret against ordinary ASCII passwords.
                .mask_char((!visible).then_some('*'))
                .font_family(fonts::MONO)
                .bg(palette.surface_container)
                .text_color(palette.on_surface)
                .caret_color(palette.on_surface)
                .rounded_lg()
                .p_3()
                .pr(px(44.))
                .w_full()
                .min_h_auto()
                .whitespace_nowrap()
                .overflow_x_scroll(),
        )
        .child(
            div()
                .id(SharedString::from(format!("{id}-toggle-visible")))
                .absolute()
                .right_3()
                .top_0()
                .bottom_0()
                .flex()
                .items_center()
                .cursor_pointer()
                .child(icon(if visible { "visibility_off" } else { "visibility" }, px(18.), palette.on_surface_variant))
                .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                    this.password_visible = !this.password_visible;
                    cx.notify();
                })),
        )
}

fn recovery_step(
    screen: &SetupScreen,
    palette: &Palette,
    window: &mut Window,
    cx: &mut Context<SetupScreen>,
) -> gpui::AnyElement {
    let required_completed =
        u32::from(screen.cloud_backup_done) + u32::from(screen.security_key_done);
    let can_continue = required_completed == 2;

    div()
        .flex()
        .flex_col()
        .gap_4()
        .child(step_title(palette, "Set up recovery"))
        .child(step_body(
            palette,
            "Publish the cloud and security-key shares together; a trusted contact is optional but recommended.",
        ))
        .child(recovery_row(
            palette,
            "1",
            "Cloud backup",
            "Upload a recovery share via rclone",
            screen.cloud_backup_done,
            true,
            cx,
            |this, cx| this.open_cloud_backup_modal(cx),
        ))
        .child(recovery_row(
            palette,
            "2",
            "Security Key",
            "Passkey recovery enabled",
            screen.security_key_done,
            true,
            cx,
            |this, cx| this.open_security_key_modal(cx),
        ))
        .child(recovery_row(
            palette,
            "3",
            "Trusted contact",
            "Hand a recovery share to someone you trust",
            screen.trusted_contact_done,
            true,
            cx,
            |this, cx| this.open_trusted_contact_modal(cx),
        ))
        .child(
            div()
                .flex()
                .flex_col()
                .gap_2()
                .child(
                    div()
                        .flex()
                        .justify_between()
                        .text_sm()
                        .text_color(palette.on_surface_variant)
                        .child("Recovery setup progress")
                        .child(format!("{required_completed}/2 required")),
                )
                .child(
                    div()
                        .h(px(8.))
                        .w_full()
                        .rounded_full()
                        .bg(palette.surface_container_highest)
                        .child(
                            div()
                                .h_full()
                                .rounded_full()
                                .bg(palette.primary)
                                .w(gpui::relative(required_completed as f32 / 2.0)),
                        ),
                ),
        )
        .child(primary_button("continue", "Continue", can_continue, window, cx, |this, cx| {
            this.finalize_recovery(cx);
        }))
        // The publication gate can be unreachable on a machine without cloud
        // or FIDO2 support, so users may explicitly defer it. Deferring
        // discards the local all-shares cache without reporting setup ready.
        .child(skip_recovery_button(palette, cx))
        .into_any_element()
}

/// "Skip for now" under the recovery step's Continue button.
fn skip_recovery_button(palette: &Palette, cx: &mut Context<SetupScreen>) -> impl IntoElement {
    div()
        .id("skip-recovery")
        .w_full()
        .py_2()
        .flex()
        .flex_col()
        .items_center()
        .gap_1()
        .cursor_pointer()
        .child(
            div()
                .text_sm()
                .text_color(palette.on_surface_variant)
                .child("Skip for now"),
        )
        .child(
            div()
                .text_xs()
                .text_color(palette.on_surface_variant)
                .opacity(0.7)
                .child("You can set recovery up later in Settings"),
        )
        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
            tracing::info!("Recovery setup skipped during vault creation");
            this.discard_recovery(cx);
        }))
}

fn complete_step(palette: &Palette, window: &mut Window, cx: &mut Context<SetupScreen>) -> gpui::AnyElement {
    div()
        .flex()
        .flex_col()
        .items_center()
        .gap_6()
        .child(
            div()
                .w(px(96.))
                .h(px(96.))
                .rounded_full()
                .bg(gpui::Hsla { a: 0.2, ..palette.primary })
                .flex()
                .items_center()
                .justify_center()
                .child(icon("check_circle", px(48.), palette.primary)),
        )
        .child(step_title(palette, "You're all set."))
        .child(
            div()
                .flex()
                .flex_col()
                .gap_2()
                .w_full()
                .child(check_row(palette, "Vault created"))
                .child(check_row(palette, "Recovery configured")),
        )
        .child(primary_button("open-vault", "Open my vault", true, window, cx, |_this, cx| {
            cx.emit(SetupScreenEvent::Complete);
        }))
        .into_any_element()
}

fn check_row(palette: &Palette, label: &'static str) -> impl IntoElement {
    div()
        .p_3()
        .rounded_lg()
        .bg(palette.surface_container_low)
        .flex()
        .items_center()
        .gap_3()
        .child(icon("check", px(16.), palette.primary))
        .child(
            div()
                .font_family(fonts::BODY)
                .text_color(palette.on_surface)
                .child(label),
        )
}

fn recovery_row(
    palette: &Palette,
    number: &'static str,
    title: &'static str,
    subtitle: &'static str,
    done: bool,
    // `false` for methods whose native side isn't ported yet — the row still
    // lists the method (it exists in the product) but offers no button to
    // press, rather than an "Enable" that only logs.
    available: bool,
    cx: &mut Context<SetupScreen>,
    on_enable: impl Fn(&mut SetupScreen, &mut Context<SetupScreen>) + 'static,
) -> impl IntoElement {
    let border = if done { palette.primary } else { palette.outline_variant };
    let badge_bg = if done { palette.primary } else { palette.surface_container_highest };

    div()
        .p_4()
        .rounded_xl()
        .border_1()
        .border_color(border)
        .bg(palette.surface_container)
        .flex()
        .items_center()
        .justify_between()
        .child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .child(
                    div()
                        .w(px(28.))
                        .h(px(28.))
                        .rounded_full()
                        .bg(badge_bg)
                        .flex()
                        .items_center()
                        .justify_center()
                        .text_sm()
                        .when(done, |el| el.child(icon("check", px(14.), palette.on_primary)))
                        .when(!done, |el| el.child(number)),
                )
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .child(
                            div()
                                .font_family(fonts::BODY)
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .text_color(palette.on_surface)
                                .child(title),
                        )
                        .child(
                            div()
                                .text_xs()
                                .text_color(palette.on_surface_variant)
                                .child(subtitle),
                        ),
                ),
        )
        .when(!done && available, |el| {
            el.child(
                div()
                    .id(SharedString::from(format!("enable-{title}")))
                    .px_3()
                    .py_1()
                    .rounded_lg()
                    .bg(palette.surface_container_highest)
                    .text_sm()
                    .cursor_pointer()
                    .child("Enable")
                    .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                        on_enable(this, cx);
                    })),
            )
        })
        .when(!done && !available, |el| {
            el.child(
                div()
                    .px_3()
                    .py_1()
                    .text_sm()
                    .text_color(palette.on_surface_variant)
                    .opacity(0.6)
                    .child("Not available yet"),
            )
        })
}

fn primary_button(
    id: &'static str,
    label: impl Into<SharedString>,
    enabled: bool,
    window: &mut Window,
    cx: &mut Context<SetupScreen>,
    on_click: impl Fn(&mut SetupScreen, &mut Context<SetupScreen>) + 'static,
) -> impl IntoElement {
    let palette = crate::theme::current_palette(cx);
    let label = label.into();
    let hover_t = animation::hover_transition(id, window, cx);
    let t = *hover_t.evaluate(window, cx);
    let opacity = 1.0 - 0.1 * t;
    let gradient = gpui::linear_gradient(
        90.,
        gpui::linear_color_stop(palette.primary, 0.),
        gpui::linear_color_stop(palette.primary_dim, 1.),
    );
    let mut el = div()
        .id(id)
        .w_full()
        .py_4()
        .px_6()
        .rounded_xl()
        .flex()
        .items_center()
        .justify_center()
        .bg(gradient)
        .opacity(opacity)
        .text_color(palette.on_primary)
        .font_family(fonts::HEADLINE)
        .font_weight(gpui::FontWeight::BOLD)
        .child(label);
    if enabled {
        el = el
            .cursor_pointer()
            .on_hover(move |is_hovered, _, cx| {
                hover_t.update(cx, |v, cx| {
                    *v = *is_hovered as u8 as f32;
                    cx.notify();
                });
            })
            .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| on_click(this, cx)));
    } else {
        el = el.opacity(opacity * 0.5);
    }
    el
}

fn secondary_button(
    id: &'static str,
    label: impl Into<SharedString>,
    enabled: bool,
    cx: &mut Context<SetupScreen>,
    on_click: impl Fn(&mut SetupScreen, &mut Context<SetupScreen>) + 'static,
) -> impl IntoElement {
    let palette = crate::theme::current_palette(cx);
    let mut el = div()
        .id(id)
        .w_full()
        .py_4()
        .px_6()
        .rounded_xl()
        .border_1()
        .border_color(palette.outline_variant)
        .flex()
        .items_center()
        .justify_center()
        .bg(palette.surface_container)
        .text_color(palette.on_surface)
        .font_family(fonts::HEADLINE)
        .font_weight(gpui::FontWeight::BOLD)
        .child(label.into());
    if enabled {
        el = el
            .cursor_pointer()
            .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| on_click(this, cx)));
    } else {
        el = el.opacity(0.5);
    }
    el
}

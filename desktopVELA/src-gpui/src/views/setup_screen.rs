//! Port of `desktopVELA/src/views/SetupScreen.tsx` — first-run onboarding
//! wizard: welcome -> biometric or password -> recovery -> complete.
//!
//! **Deliberately stubbed, not wired to real writes**: this dev machine
//! already has a real vault, and `create_vault`/`create_vault_with_password`
//! have no "abort if a vault already exists" guard — calling them for real
//! here would create/overwrite vault state alongside the real one. Matches
//! the session's write-path safety agreement. The recovery step's three
//! methods (cloud backup via rclone, security key via WebAuthn, trusted
//! contact) each need real native work not yet ported (WebAuthn is on the
//! migration plan's explicit "do last" risk list) — their "Enable" buttons
//! log rather than act, so the 2-of-3 gate can never actually clear yet.
//! This proves the full navigable wizard shape, not a working vault-creation
//! flow — a real follow-up once write-path testing is set up safely (e.g.
//! against an isolated fixture store).

use std::sync::Arc;

use gpui::{
    div, prelude::*, px, Context, EventEmitter, IntoElement, MouseButton, Render, SharedString,
    Window,
};
use gpui_elements::editable_text::{text_input, EditableTextState, StringStorage};

use vela_desktop_core::biometric::BiometricProvider;
use vela_desktop_core::AppState;

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
}

impl SetupScreen {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        cx.spawn(async move |this, cx| {
            let status = cx
                .background_spawn(async { vela_desktop_core::biometric::check_enrollment() })
                .await;
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
        }
    }

    fn completed_recovery_steps(&self) -> u32 {
        [self.cloud_backup_done, self.security_key_done, self.trusted_contact_done]
            .iter()
            .filter(|b| **b)
            .count() as u32
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
        tracing::info!(
            "Would call create_vault_with_password here — stubbed, real vault already exists on this machine"
        );
        self.step = Step::Recovery;
        cx.notify();
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

        div()
            .size_full()
            .flex()
            .items_center()
            .justify_center()
            .bg(palette.surface)
            .font_family(fonts::LABEL)
            .p_8()
            .child(div().w(px(480.)).child(content))
    }
}

fn back_button(target: Step, cx: &mut Context<SetupScreen>) -> impl IntoElement {
    let palette = crate::theme::current_palette(cx);
    div()
        .id("back")
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
    div()
        .w(px(80.))
        .h(px(80.))
        .rounded_2xl()
        .bg(palette.surface_container)
        .flex()
        .items_center()
        .justify_center()
        .child(icon(name, px(36.), palette.primary))
}

fn step_title(palette: &Palette, title: &'static str) -> impl IntoElement {
    div()
        .font_family(fonts::HEADLINE)
        .font_weight(gpui::FontWeight::BOLD)
        .text_2xl()
        .text_color(palette.on_surface)
        .child(title)
}

fn step_body(palette: &Palette, body: &'static str) -> impl IntoElement {
    div()
        .font_family(fonts::BODY)
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
        .child(back_button(Step::Welcome, cx))
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
            |this, cx| {
                tracing::info!(
                    "Would call create_vault() (biometric-backed) here — stubbed, real vault already exists"
                );
                this.step = Step::Recovery;
                cx.notify();
            },
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
        .child(back_button(Step::Welcome, cx))
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
    let completed = screen.completed_recovery_steps();
    let progress = (completed.min(2) as f32) / 2.0;
    let can_continue = completed >= 2;

    div()
        .flex()
        .flex_col()
        .gap_4()
        .child(back_button(Step::Password, cx))
        .child(step_title(palette, "Set up recovery"))
        .child(step_body(
            palette,
            "Configure at least 2 recovery methods to restore your vault if all devices are lost.",
        ))
        .child(recovery_row(
            palette,
            "1",
            "Cloud backup",
            "Upload a recovery share via rclone",
            screen.cloud_backup_done,
            cx,
            |this, cx| {
                tracing::info!("Cloud backup recovery — rclone upload not yet ported, stubbed");
                this.cloud_backup_done = true;
                cx.notify();
            },
        ))
        .child(recovery_row(
            palette,
            "2",
            "Security Key",
            "Passkey recovery enabled",
            screen.security_key_done,
            cx,
            |_this, _cx| {
                tracing::info!(
                    "Security key recovery needs native WebAuthn/CTAP2 — deliberately deferred (plan risk #1)"
                );
            },
        ))
        .child(recovery_row(
            palette,
            "3",
            "Trusted contact",
            "Optional but recommended",
            screen.trusted_contact_done,
            cx,
            |_this, _cx| {
                tracing::info!("Trusted contact recovery — TrustedContactRecovery not yet ported");
            },
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
                        .child(format!("{}/2 required", completed.min(2))),
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
                                .w(gpui::relative(progress)),
                        ),
                ),
        )
        .child(primary_button("continue", "Continue", can_continue, window, cx, |this, cx| {
            this.step = Step::Complete;
            cx.notify();
        }))
        .into_any_element()
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
        .when(!done, |el| {
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
        .py_3()
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
        .py_3()
        .rounded_xl()
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

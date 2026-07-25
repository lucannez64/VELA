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
    SharedString, Window,
};
use gpui_elements::editable_text::{text_input, EditableTextState, StringStorage};

use vela_desktop_core::AppState;

use crate::animation;
use crate::fonts;
use crate::icon::icon;
use crate::theme::Palette;

pub enum WelcomeEvent {
    CreateVault,
    AddExistingDevice,
}

impl EventEmitter<WelcomeEvent> for WelcomeScreen {}

pub struct WelcomeScreen {
    app_state: Arc<AppState>,
    /// `None` while the initial `check_enrollment()` background call is in
    /// flight (mirrors the original's `biometricAvailable === null` state).
    biometric_available: Option<bool>,
    show_reset_modal: bool,
    reset_confirm_state: gpui::Entity<EditableTextState>,
    resetting: bool,
    reset_error: Option<SharedString>,
}

impl WelcomeScreen {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        cx.spawn(async move |this, cx| {
            let status = cx
                .background_spawn(async { vela_desktop_core::biometric::check_enrollment() })
                .await;
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

        Self {
            app_state,
            biometric_available: None,
            show_reset_modal: false,
            reset_confirm_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
            resetting: false,
            reset_error: None,
        }
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

        div()
            .relative()
            .size_full()
            .flex()
            .items_center()
            .justify_center()
            .bg(palette.surface)
            .font_family(fonts::LABEL)
            .p_8()
            .child(
                div()
                    .flex()
                    .w(px(880.))
                    .rounded_xl()
                    .overflow_hidden()
                    .bg(palette.surface_container_low)
                    .child(
                        // Left branding panel — desktop-only column in the
                        // original (`hidden md:flex`); always shown here for
                        // now since there's no responsive breakpoint system
                        // yet.
                        div()
                            .w(px(340.))
                            .p_8()
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
                                            .text_2xl()
                                            .text_color(palette.on_surface)
                                            .child("Secure your identity in the void."),
                                    ),
                            )
                            .child(
                                div()
                                    .p_3()
                                    .rounded_lg()
                                    .bg(palette.surface_container_high)
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
                    )
                    .child(
                        div()
                            .flex_1()
                            .p_10()
                            .flex()
                            .flex_col()
                            .justify_center()
                            .gap_6()
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_2()
                                    .child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .font_family(fonts::HEADLINE)
                                            .font_weight(gpui::FontWeight::BOLD)
                                            .text_3xl()
                                            .text_color(palette.on_surface)
                                            .child(fonts::tracked_text("Your vault.", px(30.), -0.025))
                                            .child(fonts::tracked_text("No passwords.", px(30.), -0.025)),
                                    )
                                    .child(
                                        div()
                                            .font_family(fonts::BODY)
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
                                    .gap_3()
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
                                        cx.listener(|_this, _event, _window, _cx| {
                                            tracing::info!(
                                                "Join existing account — import-code modal not yet ported"
                                            );
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
                                        cx.listener(|_this, _event, _window, _cx| {
                                            tracing::info!(
                                                "Recover account — recovery modal not yet ported"
                                            );
                                        }),
                                    )),
                            ),
                    ),
            )
            .when(self.show_reset_modal, |el| el.child(reset_confirm_modal(&palette, self, window, cx)))
    }
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
                .w(px(420.))
                .p_8()
                .rounded_2xl()
                .bg(palette.surface_container)
                .border_1()
                .border_color(gpui::Hsla { a: 0.3, ..palette.error })
                .flex()
                .flex_col()
                .gap_4()
                .on_mouse_down(MouseButton::Left, |_, _, _| {})
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
        .py_3()
        .px_5()
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

    let mut outer = div().id(id).w_full().rounded_xl().p(px(1.)).bg(gradient).child(
        div()
            .w_full()
            .bg(inner_bg)
            .rounded(px(11.))
            .py_3()
            .px_5()
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

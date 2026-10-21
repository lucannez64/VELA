use super::*;
use crate::instrument::shell::pill;
use crate::instrument::{
    alpha, anim_id,
    dot_matrix::{dot_text, DotStyle},
    mono, page, paint, stagger, tile, tokens,
};
use gpui::AnimationExt;

impl BiometricGate {
    pub(super) fn render_instrument(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let t = tokens(cx);
        let wide = f32::from(window.viewport_size().width) >= 1000.;
        let password = self.mode == Mode::Password || !self.biometric_available;
        let disabled = self.is_authenticating || self.is_locked() || self.checking_biometric;
        let status = if self.is_locked() {
            format!("Try again in {} seconds", self.lockout_seconds_left)
        } else if self.checking_biometric {
            "Checking unlock methods…".into()
        } else if self.is_authenticating {
            "Unlocking your vault…".into()
        } else if password {
            "Enter your master password to continue.".into()
        } else {
            "Confirm with your device to continue.".into()
        };
        let hero = div().relative().min_w_0().flex_1().h_full().rounded(px(26.)).overflow_hidden()
            .child(div().absolute().inset_0().child(paint::sunrise(t,t.bg,26.,1.)))
            .child(div().relative().h_full().p(px(32.)).flex().flex_col().justify_between().gap(px(28.))
                .child(dot_text("VELA",DotStyle::new(6.,t.hero_fg).gradient(t.grad)))
                .child(div().flex().flex_col().gap(px(16.))
                    .child(mono("01 / Your vault",alpha(t.hero_fg,0.6)))
                    .child(div().font_family(fonts::HEADLINE).text_size(px(48.)).text_color(t.hero_fg).child("Your keys.\nOnly yours."))
                    .child(div().text_size(px(14.)).line_height(px(23.)).text_color(alpha(t.hero_fg,0.65)).child("Your vault is sealed. Unlock it on this device to pick up where you left off.")))
                .child(mono("Encrypted on this device",alpha(t.hero_fg,0.7))));
        let mut form = tile(&t)
            .w_full()
            .max_w(px(440.))
            .flex()
            .flex_col()
            .gap(px(20.))
            .child(
                div()
                    .size(px(52.))
                    .rounded(px(16.))
                    .bg(t.panel2)
                    .border_1()
                    .border_color(t.line)
                    .flex()
                    .items_center()
                    .justify_center()
                    .child(icon("lock", px(24.), t.violet)),
            )
            .child(page::heading("02 / Locked", "Welcome back.", &status, &t));
        if password {
            let reveal = self.password_revealed;
            form = form.child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(8.))
                    .on_key_down(crate::keyboard::submit_on_enter(cx, |this, _, cx| {
                        if !this.is_authenticating && !this.is_locked() && !this.checking_biometric
                        {
                            this.trigger_password_auth(cx);
                        }
                    }))
                    .child(mono("Master password", t.muted))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .rounded(px(14.))
                            .bg(t.panel2)
                            .border_1()
                            .border_color(t.line2)
                            .overflow_hidden()
                            .child(
                                text_input("instrument-unlock-password")
                                    .state(self.password_state.downgrade())
                                    .mask_char((!reveal).then_some('•'))
                                    .placeholder("Master password")
                                    .placeholder_color(t.muted)
                                    .text_color(t.text)
                                    .caret_color(t.text)
                                    .font_family(fonts::MONO)
                                    .text_size(px(14.))
                                    .p(px(14.))
                                    .flex_1()
                                    .min_w_0()
                                    .whitespace_nowrap()
                                    .overflow_x_scroll(),
                            )
                            .child(
                                crate::instrument::shell::icon_btn(
                                    "instrument-unlock-reveal",
                                    if reveal {
                                        "visibility_off"
                                    } else {
                                        "visibility"
                                    },
                                    &t,
                                )
                                .on_click(cx.listener(
                                    |this, _, _, cx| {
                                        this.password_revealed = !this.password_revealed;
                                        cx.notify();
                                    },
                                )),
                            ),
                    )
                    .child(
                        pill(
                            "instrument-unlock",
                            if self.is_authenticating {
                                "Unlocking…"
                            } else {
                                "Unlock vault"
                            },
                            true,
                            &t,
                        )
                        .w_full()
                        .justify_center()
                        .opacity(if disabled { 0.5 } else { 1. })
                        .on_click(cx.listener(|this, _, _, cx| {
                            if !this.is_authenticating
                                && !this.is_locked()
                                && !this.checking_biometric
                            {
                                this.trigger_password_auth(cx);
                            }
                        })),
                    ),
            );
            if self.biometric_available {
                form = form.child(
                    pill(
                        "instrument-use-biometric",
                        "Use biometric instead",
                        false,
                        &t,
                    )
                    .child(icon("fingerprint", px(18.), t.violet))
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.mode = Mode::Biometric;
                        this.error = None;
                        cx.notify();
                    })),
                );
            }
        } else {
            form = form
                .child(
                    pill("instrument-biometric", "Unlock with biometrics", true, &t)
                        .w_full()
                        .justify_center()
                        .h(px(52.))
                        .child(icon("fingerprint", px(24.), t.primary_fg))
                        .opacity(if disabled { 0.5 } else { 1. })
                        .on_click(cx.listener(|this, _, _, cx| {
                            if !this.is_authenticating && !this.is_locked() {
                                this.trigger_biometric_auth(cx);
                            }
                        })),
                )
                .child(
                    pill("instrument-use-password", "Use master password", false, &t)
                        .w_full()
                        .justify_center()
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.mode = Mode::Password;
                            this.error = None;
                            cx.notify();
                        })),
                );
        }
        form = form
            .when_some(self.error.clone(), |el, error| {
                el.child(div().text_size(px(13.)).text_color(t.risk).child(error))
            })
            .when(self.is_locked(), |el| {
                el.child(mono(
                    format!("Retry in {}s", self.lockout_seconds_left),
                    t.warn,
                ))
            })
            .child(
                div()
                    .pt(px(12.))
                    .border_t_1()
                    .border_color(t.line)
                    .child(mono("Local unlock / End-to-end encrypted", t.faint)),
            )
            .child(reset_link(&crate::theme::current_palette(cx), cx));
        div()
            .id("instrument-lock")
            .debug_selector(|| "instrument-lock".into())
            .size_full()
            .bg(t.bg)
            .text_color(t.text)
            .p(px(20.))
            .child(
                div()
                    .size_full()
                    .flex()
                    .gap(px(20.))
                    .when(wide, |el| el.child(hero))
                    .child(
                        div()
                            .id("instrument-lock-scroll")
                            .flex_1()
                            .min_w_0()
                            .h_full()
                            .overflow_y_scroll()
                            .child(
                                div()
                                    .min_h_full()
                                    .flex()
                                    .flex_col()
                                    .items_center()
                                    .justify_center()
                                    .gap(px(20.))
                                    .py(px(16.))
                                    .when(!wide, |el| {
                                        el.child(dot_text(
                                            "VELA",
                                            DotStyle::new(5., t.text).gradient(t.grad),
                                        ))
                                    })
                                    .child(form.with_animation(
                                        anim_id("unlock-enter", 0),
                                        stagger(0, 0, 350),
                                        |el, d| el.opacity(d).top(px(12. * (1. - d))),
                                    )),
                            ),
                    ),
            )
            .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modal_test_support as ui;
    use gpui::{size, Modifiers, TestAppContext};
    #[gpui::test]
    fn instrument_unlock_reveal_preserves_the_password_and_lock_state(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let state = ui::state(&dir);
        cx.update(|cx| {
            cx.set_global(crate::instrument::ActiveInterface(
                crate::instrument::InterfaceMode::Instrument,
            ))
        });
        let (gate, cx) = cx.add_window_view(|_, cx| {
            ui::fonts(cx);
            // No biometric probe or authentication is run by this fixture.
            BiometricGate {
                app_state: state,
                mode: Mode::Password,
                biometric_available: false,
                checking_biometric: false,
                is_authenticating: false,
                error: None,
                retry_count: 0,
                lockout_seconds_left: 0,
                password_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
                password_revealed: false,
                show_reset_modal: false,
                reset_confirm_state: cx
                    .new(|cx| EditableTextState::new(StringStorage::default(), cx)),
                resetting: false,
                reset_error: None,
                _lockout_task: None,
                _pulse_task: Task::ready(()),
            }
        });
        gate.update(cx, |gate, cx| {
            gate.password_state
                .update(cx, |field, cx| field.emplace("synthetic test password", cx))
        });
        for width in [1280., 640., 390.] {
            cx.simulate_resize(size(px(width), px(720.)));
            cx.run_until_parked();
            let b = ui::bounds(cx, "instrument-unlock-reveal");
            assert!(b.left() >= px(0.) && b.right() <= px(width));
            cx.simulate_mouse_move(b.center(), None, Modifiers::default());
            cx.simulate_click(b.center(), Modifiers::default());
            cx.run_until_parked();
            gate.read_with(cx, |gate, cx| {
                assert_eq!(
                    gate.password_state.read(cx).as_str(),
                    "synthetic test password"
                );
                assert!(!gate.is_authenticating);
                assert_eq!(gate.retry_count, 0);
            });
            assert!(ui::bounds(cx, "instrument-unlock").bottom() <= px(720.));
        }
    }
}

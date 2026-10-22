use super::*;
use crate::instrument::shell::pill;
use crate::instrument::{alpha, mono, page, tag, tile, tokens, TagKind};

impl DevicesScreen {
    pub(super) fn instrument_web_access_modal(
        &self, window: &mut Window, cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let p = crate::modal::palette(cx);
        let t = tokens(cx);
        let close = crate::modal::close_button("web-access-close", &p)
            .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| this.close_web_access_modal(cx)));
        let body = div().flex().flex_col().gap(px(20.))
            .child(div().pt(px(8.))
                .child(mono("TEMPORARY SESSION", t.muted))
                .child(div().mt(px(12.)).text_size(px(30.)).font_family(fonts::HEADLINE).child("Open a window to your vault."))
                .child(div().mt(px(10.)).text_size(px(13.)).line_height(px(20.)).text_color(t.muted)
                    .child("Enter your VELA account ID on the web page, then paste its access code here. This session expires automatically. You can revoke it at any time.")))
            .child(crate::ui::labeled_field(&p, "Web access code",
                crate::ui::text_field("web-access-code-input", &self.web_access_code_state, &p)
                    .font_family(fonts::MONO).placeholder("Paste the code from the web page")))
            .child(div().flex().flex_col().gap(px(10.)).child(mono("DURATION", t.muted))
                .child(div().flex().flex_wrap().gap(px(6.)).children(WEB_ACCESS_TTL_PRESETS.iter().map(|(label, secs)| {
                    let secs = *secs;
                    pill(format!("web-access-ttl-{secs}"), *label, self.web_access_ttl_secs == secs, &t)
                        .on_click(cx.listener(move |this, _, _, cx| { this.web_access_ttl_secs = secs; cx.notify(); }))
                }))))
            .child(div().flex().flex_col().gap(px(10.)).child(mono("ACCESS", t.muted))
                .child(div().flex().flex_wrap().gap(px(6.)).children([
                    ("web-access-mode-ro", "Read-only (safer)", WebAccessMode::ReadOnly),
                    ("web-access-mode-rw", "Read & write", WebAccessMode::ReadWrite),
                ].into_iter().map(|(id, label, mode)| pill(id, label, self.web_access_mode == mode, &t)
                    .on_click(cx.listener(move |this, _, _, cx| { this.web_access_mode = mode; cx.notify(); })))))
                .when(self.web_access_mode == WebAccessMode::ReadWrite, |el| el.child(
                    div().text_size(px(12.)).line_height(px(18.)).text_color(t.warn)
                        .child("Read & write sends this device's master key to the browser for the session. Only use it on a device you trust."))))
            .when_some(self.web_access_error.clone(), |el, error| el.child(div().text_size(px(13.)).text_color(t.risk).child(error)));
        let footer = div().flex().justify_end().gap(px(8.))
            .child(pill("web-access-cancel", "Cancel", false, &t)
                .on_click(cx.listener(|this, _, _, cx| this.close_web_access_modal(cx))))
            .child(pill("web-access-approve", if self.granting_web_access { "Approving…" } else { "Approve access" }, true, &t)
                .when(self.granting_web_access, |el| el.opacity(0.45))
                .on_click(cx.listener(|this, _, _, cx| { if !this.granting_web_access { this.approve_web_access(cx); } })));
        let card = crate::modal::frame("web-access-modal-body", 560., 680.,
            crate::modal::header("Approve web access", close, &p),
            crate::modal::scroll_body("web-access-scroll", body), footer, &p)
            .map(|el| crate::keyboard::trap_tab(el, "web-access-modal-trap", window, cx))
            .on_key_down(cx.listener(|this, event: &gpui::KeyDownEvent, _, cx| {
                if event.keystroke.key == "escape" { cx.stop_propagation(); this.close_web_access_modal(cx); }
            }));
        crate::modal::present(window, crate::modal::backdrop("web-access-modal-backdrop")
            .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| this.close_web_access_modal(cx)))
            .child(crate::modal::animate(card, true, false))).into_any_element()
    }

    pub(super) fn render_instrument(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let t = tokens(cx);
        let palette = crate::theme::current_palette(cx);
        let devices = self.devices.clone().unwrap_or_default();
        let active = devices.iter().filter(|d| !d.revoked && !d.pending).count();
        let pending = devices.iter().filter(|d| !d.revoked && d.pending).count();
        let sessions = self.web_sessions.as_ref().map_or(0, Vec::len);
        let narrow = f32::from(window.viewport_size().width) < 900.;
        let header = div()
            .flex()
            .flex_wrap()
            .items_end()
            .gap(px(16.))
            .child(page::heading(
                "This device / Devices",
                "Devices",
                "Manage devices that have access to your vault.",
                &t,
            ))
            .child(div().flex_1())
            .child(
                pill("instrument-enroll", "Enroll new device", true, &t)
                    .child(icon("add", px(16.), t.primary_fg))
                    .on_click(cx.listener(|this, _, _, cx| this.open_enroll_v3(cx))),
            )
            .child(
                pill("instrument-web-access", "Approve web access", false, &t)
                    .on_click(cx.listener(|this, _, _, cx| this.open_web_access_modal(cx))),
            );
        let mut cards = div().flex().flex_col().gap(px(12.)).min_w_0();
        for device in devices.iter().filter(|d| !self.hide_revoked || !d.revoked) {
            let copy = device.clone();
            let access = if device.revoked {
                "Revoked"
            } else if device.pending {
                "Awaiting enrollment"
            } else {
                "Vault access"
            };
            let card = tile(&t)
                .id(SharedString::from(format!(
                    "instrument-device-{}",
                    device.id
                )))
                .debug_selector({
                    let id = device.id.clone();
                    move || format!("instrument-device-{id}")
                })
                .flex()
                .flex_col()
                .gap(px(16.))
                .when(device.revoked, |el| el.opacity(0.6))
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .gap(px(14.))
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
                                .child(icon(device_icon(&device.device_type), px(23.), t.violet)),
                        )
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .child(
                                    div()
                                        .font_family(fonts::HEADLINE)
                                        .text_size(px(22.))
                                        .child(device.name.clone()),
                                )
                                .child(mono(
                                    if device.this_device {
                                        "This device"
                                    } else {
                                        "Enrolled device"
                                    },
                                    t.muted,
                                )),
                        )
                        .child(tag(
                            access,
                            if device.revoked {
                                TagKind::Risk
                            } else if device.pending {
                                TagKind::Warn
                            } else {
                                TagKind::Ok
                            },
                            &t,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_end()
                        .gap(px(20.))
                        .pt(px(14.))
                        .border_t_1()
                        .border_color(t.line)
                        .child(
                            div().flex_1().child(mono("Enrolled", t.faint)).child(
                                div()
                                    .text_size(px(13.))
                                    .mt(px(5.))
                                    .child(format_date(device.enrolled_at)),
                            ),
                        )
                        .child(
                            div().flex_1().child(mono("Last active", t.faint)).child(
                                div()
                                    .text_size(px(13.))
                                    .mt(px(5.))
                                    .child(format_last_active(device.last_active)),
                            ),
                        )
                        .when(!device.revoked, |el| {
                            el.child(
                                pill(
                                    SharedString::from(format!("instrument-revoke-{}", device.id)),
                                    if device.pending {
                                        "Cancel enrollment"
                                    } else {
                                        "Revoke access"
                                    },
                                    false,
                                    &t,
                                )
                                .text_color(t.risk)
                                .on_click(cx.listener(
                                    move |this, _, _, cx| {
                                        this.revoke_confirm = Some(copy.clone());
                                        cx.notify();
                                    },
                                )),
                            )
                        }),
                );
            cards = cards.child(card);
        }
        div()
            .id("instrument-devices")
            .debug_selector(|| "instrument-devices".into())
            .size_full()
            .overflow_y_scroll()
            .p(px(20.))
            .bg(t.bg)
            .text_color(t.text)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(20.))
                    .pb(px(12.))
                    .child(header)
                    .child(
                        div()
                            .flex()
                            .gap(px(10.))
                            .child(page::metric(
                                if narrow { "Active" } else { "Active devices" },
                                active,
                                &t,
                            ))
                            .child(page::metric("Pending", pending, &t))
                            .child(page::metric(
                                if narrow { "Web" } else { "Web sessions" },
                                sessions,
                                &t,
                            )),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(mono("01 / Enrolled devices", t.muted))
                            .child(
                                pill(
                                    "instrument-hide-revoked",
                                    if self.hide_revoked {
                                        "Show revoked"
                                    } else {
                                        "Hide revoked"
                                    },
                                    false,
                                    &t,
                                )
                                .h(px(32.))
                                .on_click(cx.listener(
                                    |this, _, _, cx| {
                                        this.hide_revoked = !this.hide_revoked;
                                        cx.notify();
                                    },
                                )),
                            ),
                    )
                    .when(self.devices.is_none() && self.error.is_none(), |el| {
                        el.child(mono("Loading devices…", t.muted))
                    })
                    .when(self.devices.as_ref().is_some_and(|d| d.is_empty()), |el| {
                        el.child(tile(&t).child("No enrolled devices were returned."))
                    })
                    .child(cards)
                    .when_some(self.error.clone(), |el, error| {
                        el.child(
                            tile(&t)
                                .border_color(alpha(t.risk, 0.3))
                                .text_color(t.risk)
                                .child(error),
                        )
                    })
                    .when_some(self.web_access_success.clone(), |el, msg| {
                        el.child(tile(&t).text_color(t.signal).child(msg))
                    })
                    .child(
                        tile(&t)
                            .child(mono("02 / Temporary access", t.violet))
                            .child(web_sessions_section(
                                &palette,
                                self.web_sessions.as_deref(),
                                narrow,
                                window,
                                cx,
                            )),
                    )
                    .child(
                        pill(
                            "instrument-legacy-enroll",
                            "Enroll a device using an older VELA version",
                            false,
                            &t,
                        )
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.confirm_legacy_enroll = true;
                            cx.notify();
                        })),
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
    fn web_access_options_and_actions_fit_small_windows(cx: &mut TestAppContext) {
        let demo = crate::demo::DemoVault::new().unwrap();
        cx.update(|cx| {
            cx.set_global(crate::demo::DemoMode);
            cx.set_global(crate::instrument::ActiveInterface(crate::instrument::InterfaceMode::Instrument));
        });
        let (screen, cx) = cx.add_window_view(|_, cx| {
            ui::fonts(cx);
            DevicesScreen::new(demo.state.clone(), cx)
        });
        screen.update(cx, |s, cx| s.open_web_access_modal(cx));
        for (width, height) in [(945., 1025.), (390., 480.)] {
            cx.simulate_resize(size(px(width), px(height)));
            cx.run_until_parked();
            let footer = ui::bounds(cx, "web-access-modal-body-footer");
            assert!(footer.bottom() <= px(height));
            assert!(footer.left() >= px(0.));
        }
        cx.simulate_resize(size(px(945.), px(1025.)));
        cx.run_until_parked();
        let b = ui::bounds(cx, "web-access-mode-rw");
        cx.simulate_mouse_move(b.center(), None, Modifiers::default());
        cx.simulate_click(b.center(), Modifiers::default());
        cx.run_until_parked();
        assert!(screen.read_with(cx, |s, _| s.web_access_mode == WebAccessMode::ReadWrite));
        let b = ui::bounds(cx, "web-access-approve");
        cx.simulate_mouse_move(b.center(), None, Modifiers::default());
        cx.simulate_click(b.center(), Modifiers::default());
        cx.run_until_parked();
        assert!(screen.read_with(cx, |s, _| s.web_access_error.is_some() && !s.granting_web_access));
    }

    #[gpui::test]
    fn device_actions_remain_connected_in_the_instrument_layout(cx: &mut TestAppContext) {
        let demo = crate::demo::DemoVault::new().unwrap();
        cx.update(|cx| {
            cx.set_global(crate::demo::DemoMode);
            cx.set_global(crate::instrument::ActiveInterface(
                crate::instrument::InterfaceMode::Instrument,
            ));
        });
        let (screen, cx) = cx.add_window_view(|_, cx| {
            ui::fonts(cx);
            DevicesScreen::new(demo.state.clone(), cx)
        });
        for width in [1440., 1024., 390.] {
            cx.simulate_resize(size(px(width), px(820.)));
            cx.run_until_parked();
            for selector in [
                "instrument-enroll",
                "instrument-web-access",
                "instrument-hide-revoked",
            ] {
                let b = ui::bounds(cx, selector);
                assert!(
                    b.left() >= px(0.) && b.right() <= px(width),
                    "overflow: {selector} at {width}: {b:?}"
                );
            }
        }
        cx.simulate_resize(size(px(1024.), px(820.)));
        cx.run_until_parked();
        let b = ui::bounds(cx, "instrument-revoke-demo-laptop");
        cx.simulate_mouse_move(b.center(), None, Modifiers::default());
        cx.simulate_click(b.center(), Modifiers::default());
        cx.run_until_parked();
        assert!(screen.read_with(cx, |screen, _| screen
            .revoke_confirm
            .as_ref()
            .is_some_and(|d| d.id == "demo-laptop")));
    }
}

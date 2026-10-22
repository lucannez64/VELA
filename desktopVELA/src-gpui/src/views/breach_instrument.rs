use super::*;
use crate::instrument::dot_matrix::{dot_text, DotStyle};
use crate::instrument::icons::icon;
use crate::instrument::shell::pill;
use crate::instrument::{mono, page, tag, tile, tokens, TagKind};

impl BreachMonitorScreen {
    pub(super) fn render_instrument(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let t = tokens(cx);
        let monitored = self
            .items
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter(|i| matches!(i, VaultItem::BreachMonitor { .. }))
            .collect::<Vec<_>>();
        let exposures = monitored
            .iter()
            .map(|i| {
                if let VaultItem::BreachMonitor { breach_count, .. } = i {
                    *breach_count as usize
                } else {
                    0
                }
            })
            .sum::<usize>();
        let mut emails = tile(&t).flex_1().min_w_0().child(
            div()
                .flex()
                .items_center()
                .gap(px(12.))
                .mb(px(16.))
                .child(mono("01 / Monitored emails", t.muted))
                .child(div().flex_1())
                .child(tag(
                    format!("{} emails", monitored.len()),
                    TagKind::Plain,
                    &t,
                )),
        );
        if monitored.is_empty() {
            emails = emails.child(
                div()
                    .py(px(44.))
                    .flex()
                    .flex_col()
                    .items_center()
                    .gap(px(12.))
                    .child(icon("shield", px(28.), t.faint))
                    .child(
                        div()
                            .font_family(fonts::HEADLINE)
                            .text_size(px(20.))
                            .child("No emails monitored"),
                    )
                    .child(
                        div()
                            .text_size(px(12.5))
                            .text_color(t.muted)
                            .child("Add an email to check it for known data breaches."),
                    )
                    .child(
                        pill("breach-add-empty", "Add email", false, &t)
                            .mt(px(8.))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.show_add_email = true;
                                cx.notify();
                            })),
                    ),
            );
        }
        for item in monitored.iter() {
            if let VaultItem::BreachMonitor {
                email,
                checked_at,
                breach_count,
                breaches,
                ..
            } = item
            {
                emails = emails.child(
                    div()
                        .py(px(16.))
                        .border_t_1()
                        .border_color(t.line)
                        .child(
                            div()
                                .flex()
                                .flex_wrap()
                                .items_center()
                                .gap(px(12.))
                                .child(icon(
                                    "shield",
                                    px(18.),
                                    if *breach_count > 0 { t.risk } else { t.signal },
                                ))
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w(px(140.))
                                        .child(div().text_size(px(14.)).child(email.clone()))
                                        .child(
                                            div()
                                                .mt(px(5.))
                                                .text_size(px(12.))
                                                .text_color(t.muted)
                                                .child(format!(
                                                    "Last checked: {}",
                                                    format_checked_at(*checked_at)
                                                )),
                                        ),
                                )
                                .child(tag(
                                    if *breach_count > 0 {
                                        format!("{breach_count} exposures")
                                    } else {
                                        "No exposures".into()
                                    },
                                    if *breach_count > 0 {
                                        TagKind::Risk
                                    } else {
                                        TagKind::Ok
                                    },
                                    &t,
                                )),
                        )
                        .children(breaches.iter().map(|breach| {
                            div()
                                .text_size(px(12.))
                                .mt(px(10.))
                                .text_color(t.muted)
                                .child(format!("{}", breach.name))
                        })),
                );
            }
        }
        let wide = f32::from(window.viewport_size().width) > 1060.;
        let aside=div().flex().flex_col().gap(px(12.))
            .child(tile(&t).child(mono("Known exposures",t.muted)).child(div().mt(px(20.)).child(dot_text(format!("{exposures:02}"),DotStyle::new(8.,if exposures>0{t.risk}else{t.signal}))))
                .child(div().mt(px(16.)).text_size(px(12.5)).line_height(px(20.)).text_color(t.muted).child("Results from the last checks saved on this device. A clear result does not guarantee an account is safe.")))
            .child(tile(&t).child(mono("02 / Password check",t.muted)).child(div().font_family(fonts::HEADLINE).text_size(px(22.)).mt(px(16.)).child("Check your passwords."))
                .child(div().mt(px(12.)).text_size(px(12.5)).line_height(px(20.)).text_color(t.muted).child("Compare your vault passwords with Pwned Passwords. Only a hash prefix is sent; your passwords stay on this device."))
                .child(pill("instrument-check-passwords",if self.checking_passwords{"Checking…"}else{"Check vault passwords"},false,&t).mt(px(18.)).on_click(cx.listener(|this,_,_,cx|{if !this.checking_passwords{this.check_all_passwords(cx);}}))))
            .child(tile(&t).child(mono("How it works",t.muted)).child(div().mt(px(14.)).text_size(px(12.5)).line_height(px(21.)).text_color(t.muted).child("Email checks use Have I Been Pwned. An exposed account should have its password changed at the original website, then updated in VELA.")));
        let form = self.show_add_email.then(|| {
            tile(&t)
                .mb(px(12.))
                .child(mono("Add an email", t.muted))
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap(px(10.))
                        .mt(px(14.))
                        .on_key_down(crate::keyboard::submit_on_enter(cx, |this, _, cx| {
                            if !this.adding_email {
                                this.check_and_add_email(cx);
                            }
                        }))
                        .child(
                            text_input("instrument-monitor-email")
                                .state(self.email_state.downgrade())
                                .placeholder("you@example.com")
                                .placeholder_color(t.muted)
                                .text_color(t.text)
                                .caret_color(t.text)
                                .p(px(12.))
                                .rounded(px(14.))
                                .bg(t.panel2)
                                .flex_1()
                                .min_w(px(150.)),
                        )
                        .child(
                            pill(
                                "instrument-add-monitor",
                                if self.adding_email {
                                    "Checking…"
                                } else {
                                    "Check & add"
                                },
                                true,
                                &t,
                            )
                            .on_click(cx.listener(|this, _, _, cx| {
                                if !this.adding_email {
                                    this.check_and_add_email(cx);
                                }
                            })),
                        )
                        .child(
                            pill("cancel-monitor", "Cancel", false, &t).on_click(cx.listener(
                                |this, _, _, cx| {
                                    this.show_add_email = false;
                                    cx.notify();
                                },
                            )),
                        ),
                )
        });
        div()
            .id("instrument-breach")
            .debug_selector(|| "instrument-breach".into())
            .size_full()
            .overflow_y_scroll()
            .bg(t.bg)
            .text_color(t.text)
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_end()
                    .gap(px(16.))
                    .pb(px(24.))
                    .child(page::heading(
                        "Security / Breach watch",
                        "Breach watch",
                        "Check your accounts for known exposures.",
                        &t,
                    ))
                    .child(div().flex_1())
                    .child(
                        pill(
                            "instrument-check-emails",
                            if self.checking_emails {
                                "Checking…"
                            } else {
                                "Check vault emails"
                            },
                            false,
                            &t,
                        )
                        .on_click(cx.listener(|this, _, _, cx| {
                            if !this.checking_emails {
                                this.check_all_emails(cx);
                            }
                        })),
                    )
                    .child(
                        pill("instrument-add-email", "Add email", true, &t)
                            .child(icon("add", px(16.), t.primary_fg))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.show_add_email = true;
                                cx.notify();
                            })),
                    ),
            )
            .children(form)
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .when(!wide, |el| el.flex_col()).when(wide,|el|el.items_start())
                    .child(emails)
                    .child(
                        div()
                            .when(wide, |el| el.w(px(340.)).flex_shrink_0())
                            .child(aside),
                    ),
            )
            .when_some(self.error.clone(), |el, error| {
                el.child(tile(&t).mt(px(12.)).text_color(t.risk).child(error))
            })
            .when_some(self.status_message.clone(), |el, status| {
                el.child(tile(&t).mt(px(12.)).text_size(px(13.)).child(status))
            })
            .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modal_test_support as ui;
    use gpui::{size, Modifiers, TestAppContext};
    #[gpui::test]
    fn add_email_opens_the_instrument_form_without_running_a_check(cx: &mut TestAppContext) {
        let demo = crate::demo::DemoVault::new().unwrap();
        cx.update(|cx| {
            cx.set_global(crate::instrument::ActiveInterface(
                crate::instrument::InterfaceMode::Instrument,
            ))
        });
        let (screen, cx) = cx.add_window_view(|_, cx| {
            ui::fonts(cx);
            BreachMonitorScreen::new(demo.state.clone(), cx)
        });
        cx.simulate_resize(size(px(945.), px(1025.)));
        cx.run_until_parked();
        let b = ui::bounds(cx, "instrument-add-email");
        cx.simulate_mouse_move(b.center(), None, Modifiers::default());
        cx.simulate_click(b.center(), Modifiers::default());
        cx.run_until_parked();
        assert!(screen.read_with(cx, |s, _| s.show_add_email
            && !s.adding_email
            && !s.checking_passwords
            && !s.checking_emails));
    }
}

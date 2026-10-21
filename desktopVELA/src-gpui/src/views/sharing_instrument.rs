use super::*;
use crate::instrument::dot_matrix::{dot_text, DotStyle};
use crate::instrument::icons::icon;
use crate::instrument::shell::{icon_btn, pill};
use crate::instrument::{alpha, avatar, mono, page, paint, tag, tile, tokens, TagKind};

impl SharingScreen {
    pub(super) fn render_instrument(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let t = tokens(cx);
        let now = chrono::Utc::now();
        let links = self
            .links
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter(|l| l.expires_at > now)
            .collect::<Vec<_>>();
        let shares = self.shares.clone().unwrap_or_default();
        let mut tabs = div()
            .flex()
            .flex_wrap()
            .p(px(3.))
            .rounded_full()
            .bg(t.panel2)
            .border_1()
            .border_color(t.line);
        for (id, label, tab, count) in [
            ("sharing-links", "Links", Tab::Links, links.len()),
            (
                "sharing-sent",
                "Sent",
                Tab::Sent,
                shares
                    .iter()
                    .filter(|s| s.direction == ShareDirection::Sent)
                    .count(),
            ),
            (
                "sharing-received",
                "Received",
                Tab::Received,
                shares
                    .iter()
                    .filter(|s| s.direction == ShareDirection::Received && s.accepted.is_none())
                    .count(),
            ),
        ] {
            tabs = tabs.child(
                pill(
                    id,
                    format!(
                        "{label}{}",
                        if count > 0 {
                            format!("  {count}")
                        } else {
                            String::new()
                        }
                    ),
                    tab == self.tab,
                    &t,
                )
                .h(px(32.))
                .px(px(13.))
                .border_0()
                .when(tab != self.tab, |el| el.bg(alpha(t.panel, 0.)))
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.tab = tab;
                    this.confirm_revoke = None;
                    cx.notify();
                })),
            );
        }
        let mut list = div().flex().flex_col();
        let mut count = 0;
        if self.tab == Tab::Links {
            for link in &links {
                count += 1;
                let id = link.id.clone();
                let copy = link.url.clone();
                let confirm = self.confirm_revoke.as_deref() == Some(id.as_str());
                let fraction = (link.expires_at - now).num_seconds() as f32
                    / (link.expires_at - link.created_at).num_seconds().max(1) as f32;
                let hours = (link.expires_at - now).num_hours().max(0);
                list = list.child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .gap(px(12.))
                        .py(px(16.))
                        .border_b_1()
                        .border_color(t.line)
                        .child(avatar(&link.item_name, 36., &t))
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(130.))
                                .child(div().text_size(px(14.)).child(link.item_name.clone()))
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .text_color(t.muted)
                                        .mt(px(4.))
                                        .child(format!("Expires in {hours} hours")),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .gap(px(6.))
                                        .mt(px(6.))
                                        .when(link.view_once, |el| {
                                            el.child(tag("One view", TagKind::Plain, &t))
                                        })
                                        .when(link.has_passphrase, |el| {
                                            el.child(tag("Passphrase", TagKind::Plain, &t))
                                        }),
                                ),
                        )
                        .child(div().flex().gap(px(3.)).children((0..12).map(|i| {
                            div().w(px(4.)).h(px(10.)).rounded(px(2.)).bg(
                                if i as f32 / 12. < fraction {
                                    t.signal
                                } else {
                                    t.panel3
                                },
                            )
                        })))
                        .child(
                            icon_btn(format!("copy-link-{id}"), "content_copy", &t).on_click(
                                cx.listener(move |_, _, _, cx| {
                                    crate::clipboard::copy(cx, "Link", &copy)
                                }),
                            ),
                        )
                        .child(
                            pill(
                                format!("revoke-link-{id}"),
                                if confirm { "Confirm" } else { "Revoke" },
                                false,
                                &t,
                            )
                            .h(px(32.))
                            .when(confirm, |el| el.text_color(t.risk))
                            .on_click(cx.listener(
                                move |this, _, _, cx| {
                                    if this.confirm_revoke.as_deref() == Some(id.as_str()) {
                                        this.confirm_revoke = None;
                                        this.revoke_link(id.clone(), cx);
                                    } else {
                                        this.confirm_revoke = Some(id.clone());
                                        cx.notify();
                                    }
                                },
                            )),
                        ),
                );
            }
        } else {
            for share in shares.iter().filter(|s| {
                if self.tab == Tab::Sent {
                    s.direction == ShareDirection::Sent
                } else {
                    s.direction == ShareDirection::Received
                }
            }) {
                count += 1;
                let id = share.id.clone();
                let id2 = id.clone();
                let id3 = id.clone();
                let confirm = self.confirm_revoke.as_deref() == Some(id.as_str());
                let received = share.direction == ShareDirection::Received;
                let mut actions = div().flex().items_center().gap(px(8.));
                if received && share.accepted.is_none() {
                    actions = actions
                        .child(
                            pill(format!("decline-{id}"), "Decline", false, &t)
                                .h(px(32.))
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.decline_share(id2.clone(), cx)
                                })),
                        )
                        .child(
                            pill(format!("accept-{id}"), "Accept", true, &t)
                                .h(px(32.))
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.accept_share(id3.clone(), cx)
                                })),
                        );
                } else {
                    actions = actions.child(tag(
                        if share.accepted == Some(true) {
                            "Accepted"
                        } else if share.accepted == Some(false) {
                            "Declined"
                        } else {
                            "Pending"
                        },
                        if share.accepted == Some(true) {
                            TagKind::Ok
                        } else {
                            TagKind::Plain
                        },
                        &t,
                    ));
                    if !received {
                        actions = actions.child(
                            pill(
                                format!("revoke-share-{id}"),
                                if confirm { "Confirm" } else { "Revoke access" },
                                false,
                                &t,
                            )
                            .h(px(32.))
                            .on_click(cx.listener(
                                move |this, _, _, cx| {
                                    if this.confirm_revoke.as_deref() == Some(id.as_str()) {
                                        this.confirm_revoke = None;
                                        this.delete_share(id.clone(), cx);
                                    } else {
                                        this.confirm_revoke = Some(id.clone());
                                        cx.notify();
                                    }
                                },
                            )),
                        );
                    }
                }
                list = list.child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .gap(px(12.))
                        .py(px(16.))
                        .border_b_1()
                        .border_color(t.line)
                        .child(avatar(&share.item_name, 36., &t))
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(140.))
                                .child(div().text_size(px(14.)).child(share.item_name.clone()))
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .mt(px(4.))
                                        .text_color(t.muted)
                                        .child(if received {
                                            format!("From {}", share.from)
                                        } else {
                                            format!(
                                                "To {}",
                                                share.to.as_deref().unwrap_or("Unknown recipient")
                                            )
                                        }),
                                ),
                        )
                        .child(actions),
                );
            }
        }
        if count == 0 {
            list = list.child(
                div()
                    .py(px(46.))
                    .flex()
                    .flex_col()
                    .items_center()
                    .gap(px(10.))
                    .child(icon(
                        if self.tab == Tab::Links {
                            "link"
                        } else {
                            "share"
                        },
                        px(28.),
                        t.faint,
                    ))
                    .child(div().text_size(px(16.)).child(match self.tab {
                        Tab::Links => "No active share links",
                        Tab::Sent => "You haven't shared any items yet",
                        Tab::Received => "No items shared with you yet",
                    }))
                    .child(div().text_size(px(12.5)).text_color(t.muted).child(
                        if self.tab == Tab::Links {
                            "Create one to send an item to someone without VELA."
                        } else {
                            "Shared items will appear here."
                        },
                    )),
            );
        }
        let user_id = self.app_state.store.load_user_id().unwrap_or_default();
        let copy_id = user_id.clone();
        let aside=div().flex().flex_col().gap(px(12.))
            .child(div().relative().h(px(270.)).rounded(px(22.)).overflow_hidden().text_color(t.hero_fg)
                .child(div().absolute().inset_0().child(paint::sunrise(t,t.bg,22.,1.)))
                .child(div().relative().p(px(20.)).child(mono("Active links",alpha(t.hero_fg,0.7))).child(div().mt(px(26.)).child(dot_text(format!("{:02}",links.len()),DotStyle::new(8.,t.hero_fg))))
                    .child(div().mt(px(18.)).text_size(px(13.)).line_height(px(20.)).text_color(alpha(t.hero_fg,0.75)).child("Anyone with a link can open its item until it expires or you revoke it. Send a passphrase through a different app."))))
            .child(tile(&t).child(mono("Your VELA ID",t.muted)).child(div().text_size(px(12.5)).line_height(px(20.)).text_color(t.muted).mt(px(14.)).child("Give this to other VELA users so they can share items with you."))
                .child(div().flex().items_center().gap(px(8.)).mt(px(12.)).p(px(10.)).rounded(px(14.)).bg(t.panel2).border_1().border_color(t.line)
                    .child(div().flex_1().min_w_0().font_family(fonts::MONO).text_size(px(12.)).truncate().child(user_id))
                    .child(icon_btn("copy-sharing-id","content_copy",&t).on_click(cx.listener(move|_,_,_,cx|crate::clipboard::copy(cx,"VELA ID",&copy_id))))));
        let wide = f32::from(window.viewport_size().width) > 1060.;
        div()
            .id("instrument-sharing")
            .debug_selector(|| "instrument-sharing".into())
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
                        "Security / Sharing",
                        "Sharing",
                        "Send items to people with VELA, or make a link for anyone else.",
                        &t,
                    ))
                    .child(div().flex_1())
                    .child(
                        pill("instrument-share-item", "Share with a VELA user", false, &t)
                            .on_click(cx.listener(|this, _, _, cx| this.open_share_modal(cx))),
                    )
                    .child(
                        pill("instrument-new-link", "New share link", true, &t)
                            .child(icon("add", px(16.), t.primary_fg))
                            .on_click(cx.listener(|this, _, _, cx| this.open_link_modal(cx))),
                    ),
            )
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .when(!wide, |el| el.flex_col())
                    .when(wide, |el| el.items_start())
                    .child(
                        tile(&t)
                            .flex_1()
                            .min_w_0()
                            .child(div().flex().child(tabs))
                            .child(list)
                            .when_some(self.error.clone(), |el, error| {
                                el.child(
                                    div()
                                        .text_size(px(12.))
                                        .text_color(t.risk)
                                        .mt(px(12.))
                                        .child(error),
                                )
                            })
                            .when_some(self.action_error.clone(), |el, error| {
                                el.child(
                                    div()
                                        .text_size(px(12.))
                                        .text_color(t.risk)
                                        .mt(px(12.))
                                        .child(error),
                                )
                            }),
                    )
                    .child(
                        div()
                            .when(wide, |el| el.w(px(340.)).flex_shrink_0())
                            .child(aside),
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
    fn reference_sharing_tabs_and_create_link_still_open_the_real_picker(cx: &mut TestAppContext) {
        let demo = crate::demo::DemoVault::new().unwrap();
        cx.update(|cx| {
            cx.set_global(crate::demo::DemoMode);
            cx.set_global(crate::instrument::ActiveInterface(
                crate::instrument::InterfaceMode::Instrument,
            ));
        });
        let (screen, cx) = cx.add_window_view(|_, cx| {
            ui::fonts(cx);
            SharingScreen::new(demo.state.clone(), cx)
        });
        cx.simulate_resize(size(px(945.), px(1025.)));
        cx.run_until_parked();
        let b = ui::bounds(cx, "sharing-received");
        cx.simulate_mouse_move(b.center(), None, Modifiers::default());
        cx.simulate_click(b.center(), Modifiers::default());
        cx.run_until_parked();
        assert!(screen.read_with(cx, |s, _| s.tab == Tab::Received));
        let b = ui::bounds(cx, "instrument-new-link");
        cx.simulate_mouse_move(b.center(), None, Modifiers::default());
        cx.simulate_click(b.center(), Modifiers::default());
        cx.run_until_parked();
        assert!(screen.read_with(cx, |s, _| s.show_link_modal && s.picking_item));
        let results = ui::bounds(cx, "share-picker-results");
        cx.simulate_mouse_move(gpui::point(results.left() + px(30.), results.top() + px(80.)), None, Modifiers::default());
        cx.run_until_parked();
        assert_eq!(screen.read_with(cx, |s, _| s.picker_active), 1, "hover must follow the pointer");
        cx.simulate_mouse_move(gpui::point(results.left() + px(30.), results.top() + px(144.)), None, Modifiers::default());
        cx.run_until_parked();
        assert_eq!(screen.read_with(cx, |s, _| s.picker_active), 2);
        // Choosing an item must continue to link options, not direct sharing.
        screen.update(cx, |s, cx| {
            s.selected_item_id = Some(s.shareable_items[0].id().to_string());
            s.picking_item = false;
            cx.notify();
        });
        cx.run_until_parked();
        assert!(ui::bounds(cx, "submit-sharing-modal").size.width > px(0.));
        screen.update(cx, |s, cx| s.close_dialog(cx));
        cx.run_until_parked();
        let b = ui::bounds(cx, "instrument-share-item");
        cx.simulate_mouse_move(b.center(), None, Modifiers::default());
        cx.simulate_click(b.center(), Modifiers::default());
        cx.run_until_parked();
        assert!(screen.read_with(cx, |s, _| s.show_share_modal && !s.show_link_modal && s.picking_item));
        let search = screen.read_with(cx, |s, _| s.share_search_state.clone());
        search.update(cx, |s, cx| s.emplace("Personal email", cx));
        cx.run_until_parked();
        assert!(screen.read_with(cx, |s, _| s.picker_query == "Personal email"));
        screen.update(cx, |s, cx| {
            s.selected_item_id = Some(s.shareable_items[0].id().to_string());
            s.picking_item = false;
            cx.notify();
        });
        cx.run_until_parked();
        assert!(ui::bounds(cx, "submit-sharing-modal").size.width > px(0.));
        assert!(screen.read_with(cx, |s, cx| s.recipient_state.read(cx).as_str().is_empty()));
    }
}

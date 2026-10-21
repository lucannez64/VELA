use super::icons::icon;
use super::shell::{icon_btn, pill, InstrumentShell, ListKind, View};
use super::{alpha, mono, Tok};
use gpui::{div, prelude::*, px, Context, IntoElement};

impl InstrumentShell {
    pub(super) fn render_mobile_top(&self, t: &Tok, cx: &mut Context<Self>) -> impl IntoElement {
        use gpui_elements::editable_text::text_input;
        div()
            .h(px(48.))
            .flex_shrink_0()
            .flex()
            .items_center()
            .gap(px(8.))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .h(px(42.))
                    .px(px(12.))
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .rounded_full()
                    .bg(t.panel)
                    .border_1()
                    .border_color(t.line)
                    .child(icon("search", px(16.), t.muted))
                    .child(
                        text_input("instrument-search")
                            .state(self.search.downgrade())
                            .placeholder("Search vault…")
                            .placeholder_color(t.muted)
                            .text_color(t.text)
                            .caret_color(t.text)
                            .text_size(px(13.))
                            .flex_1()
                            .min_w_0()
                            .whitespace_nowrap()
                            .overflow_x_scroll(),
                    ),
            )
            .child(
                icon_btn("mobile-new-item", "add", t)
                    .on_click(cx.listener(|this, _, _, cx| this.new_item(cx))),
            )
            .child(icon_btn("mobile-theme", "palette", t).on_click(cx.listener(
                |this, _, _, cx| {
                    this.theme_menu = !this.theme_menu;
                    this.more_menu = false;
                    cx.notify();
                },
            )))
    }

    pub(super) fn render_dock(&self, t: &Tok, cx: &mut Context<Self>) -> impl IntoElement {
        let mut dock = div()
            .id("instrument-dock")
            .debug_selector(|| "instrument-dock".into())
            .flex()
            .gap(px(4.))
            .p(px(5.))
            .rounded_full()
            .bg(t.panel)
            .border_1()
            .border_color(t.line2)
            .occlude();
        for (id, label, glyph, active) in [
            (
                "dock-overview",
                "Overview",
                "dashboard",
                self.view == View::Overview,
            ),
            ("dock-vault", "Vault", "lock", self.view == View::Vault),
            (
                "dock-generate",
                "Generate",
                "casino",
                self.generator.is_some(),
            ),
            (
                "dock-more",
                "More",
                "more_horiz",
                self.more_menu || !matches!(self.view, View::Overview | View::Vault),
            ),
        ] {
            let fg = if active { t.text } else { t.muted };
            dock = dock.child(
                div()
                    .id(id)
                    .debug_selector(move || id.into())
                    .w(px(66.))
                    .h(px(48.))
                    .rounded_full()
                    .flex()
                    .flex_col()
                    .items_center()
                    .justify_center()
                    .gap(px(3.))
                    .bg(if active { t.panel3 } else { alpha(t.panel, 0.) })
                    .text_color(fg)
                    .text_size(px(10.))
                    .cursor_pointer()
                    .hover(|el| el.bg(t.panel2))
                    .child(icon(glyph, px(18.), fg))
                    .child(label)
                    .on_click(cx.listener(move |this, _, _, cx| match id {
                        "dock-overview" => this.set_view(View::Overview, cx),
                        "dock-vault" => this.open_list(ListKind::All, false, cx),
                        "dock-generate" => {
                            this.more_menu = false;
                            this.open_generator(cx);
                        }
                        _ => {
                            this.more_menu = !this.more_menu;
                            this.theme_menu = false;
                            cx.notify();
                        }
                    })),
            );
        }
        div()
            .w_full()
            .flex()
            .justify_center()
            .flex_shrink_0()
            .child(dock)
    }

    pub(super) fn render_more(&self, t: &Tok, cx: &mut Context<Self>) -> impl IntoElement {
        let group = |label: &'static str| {
            div()
                .pt(px(16.))
                .pb(px(8.))
                .px(px(4.))
                .child(mono(label, t.faint))
        };
        let list = || {
            div()
                .rounded(px(20.))
                .bg(t.panel2)
                .border_1()
                .border_color(t.line)
                .overflow_hidden()
        };
        let row = |id: &'static str,
                   label: &'static str,
                   glyph: &'static str,
                   count: String,
                   action: u8,
                   last: bool,
                   cx: &mut Context<Self>| {
            div()
                .id(id)
                .debug_selector(move || id.into())
                .h(px(54.))
                .px(px(16.))
                .flex()
                .items_center()
                .gap(px(14.))
                .when(!last, |el| el.border_b_1().border_color(t.line))
                .text_size(px(14.))
                .cursor_pointer()
                .hover(|el| el.bg(t.panel3))
                .child(icon(glyph, px(16.), t.text))
                .child(label)
                .child(div().flex_1())
                .child(
                    div()
                        .font_family(crate::fonts::MONO)
                        .text_size(px(12.))
                        .text_color(t.muted)
                        .child(count),
                )
                .child(icon("chevron_right", px(16.), t.faint))
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.more_menu = false;
                    match action {
                        0 => this.open_list(ListKind::Favorites, false, cx),
                        1 => this.open_list(ListKind::All, true, cx),
                        2 => this.open_generator(cx),
                        3 => this.set_view(View::Sharing, cx),
                        4 => this.set_view(View::Devices, cx),
                        5 => this.set_view(View::Activity, cx),
                        6 => this.set_view(View::Settings, cx),
                        _ => this.set_view(View::Breach, cx),
                    }
                }))
        };
        let menu =
            div()
                .id("instrument-more")
                .debug_selector(|| "instrument-more".into())
                .w(px(704.))
                .max_w_full()
                .max_h_full()
                .min_h_0()
                .overflow_y_scroll()
                .p(px(20.))
                .rounded(px(26.))
                .bg(t.panel)
                .border_1()
                .border_color(t.line2)
                .occlude()
                .child(
                    div()
                        .flex()
                        .justify_center()
                        .pb(px(14.))
                        .child(div().w(px(40.)).h(px(4.)).rounded_full().bg(t.line2)),
                )
                .child(
                    div()
                        .p(px(16.))
                        .rounded(px(20.))
                        .bg(t.panel2)
                        .border_1()
                        .border_color(t.line)
                        .flex()
                        .items_center()
                        .gap(px(16.))
                        .child(super::avatar(&self.profile_name, 62., t))
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .child(
                                    div()
                                        .font_family(crate::fonts::HEADLINE)
                                        .text_size(px(20.))
                                        .child(self.profile_name.clone()),
                                )
                                .child(
                                    div()
                                        .text_size(px(13.))
                                        .text_color(t.muted)
                                        .truncate()
                                        .child(self.profile_id.clone()),
                                )
                                .child(mono("This device", t.faint).mt(px(6.))),
                        )
                        .child(pill("more-profile", "Profile", false, t).on_click(
                            cx.listener(|this, _, _, cx| this.set_view(View::Profile, cx)),
                        )),
                )
                .child(group("01 / Vault"))
                .child(
                    list()
                        .child(row(
                            "more-favorites",
                            "Favourites",
                            "star",
                            self.analysis.favorites.len().to_string(),
                            0,
                            false,
                            cx,
                        ))
                        .child(row(
                            "more-attention",
                            "Needs attention",
                            "shield",
                            self.analysis.at_risk.to_string(),
                            1,
                            true,
                            cx,
                        )),
                )
                .child(group("02 / Security"))
                .child(
                    list()
                        .child(row(
                            "more-generator",
                            "Generator",
                            "casino",
                            String::new(),
                            2,
                            false,
                            cx,
                        ))
                        .child(row(
                            "more-sharing",
                            "Sharing",
                            "share",
                            String::new(),
                            3,
                            false,
                            cx,
                        ))
                        .child(row(
                            "more-breach",
                            "Breach watch",
                            "shield",
                            String::new(),
                            7,
                            true,
                            cx,
                        )),
                )
                .child(group("03 / This device"))
                .child(
                    list()
                        .child(row(
                            "more-devices",
                            "Devices",
                            "devices",
                            String::new(),
                            4,
                            false,
                            cx,
                        ))
                        .child(row(
                            "more-activity",
                            "Activity",
                            "history",
                            String::new(),
                            5,
                            false,
                            cx,
                        ))
                        .child(row(
                            "more-settings",
                            "Settings",
                            "settings",
                            String::new(),
                            6,
                            true,
                            cx,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .gap(px(10.))
                        .mt(px(20.))
                        .child(
                            pill(
                                "more-theme",
                                super::theme_name(
                                    cx.try_global::<crate::theme::ActiveTheme>()
                                        .map(|x| x.0)
                                        .unwrap_or(crate::theme::ThemeId::Vela),
                                ),
                                false,
                                t,
                            )
                            .flex_1()
                            .justify_center()
                            .child(icon("palette", px(16.), t.text))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.more_menu = false;
                                this.theme_menu = true;
                                cx.notify();
                            })),
                        )
                        .child(
                            pill("more-lock", "Lock vault", true, t)
                                .flex_1()
                                .justify_center()
                                .child(icon("lock", px(16.), t.primary_fg))
                                .on_click(cx.listener(|this, _, _, cx| this.lock(cx))),
                        ),
                )
                .child(
                    div().flex().justify_center().mt(px(10.)).child(
                        div()
                            .id("more-classic")
                            .text_size(px(11.))
                            .text_color(t.faint)
                            .cursor_pointer()
                            .child("Classic interface · Ctrl Alt U")
                            .on_click(cx.listener(|this, _, _, cx| {
                                super::switch_interface(
                                    &this.app_state,
                                    super::InterfaceMode::Classic,
                                    cx,
                                )
                            })),
                    ),
                );
        div()
            .absolute()
            .inset_0()
            .p(px(12.))
            .flex()
            .items_center()
            .justify_center()
            .child(
                div()
                    .id("more-scrim")
                    .absolute()
                    .inset_0()
                    .bg(alpha(t.bg, 0.5))
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.more_menu = false;
                        cx.notify();
                    })),
            )
            .child(menu)
    }

    pub(super) fn render_profile(&self, t: &Tok, cx: &mut Context<Self>) -> gpui::AnyElement {
        div()
            .id("instrument-profile")
            .size_full()
            .overflow_y_scroll()
            .child(
                super::page::heading(
                    "Account / Profile",
                    "Profile",
                    "Your identity on this device.",
                    t,
                )
                .mb(px(20.)),
            )
            .child(
                super::tile(t)
                    .flex()
                    .flex_col()
                    .gap(px(18.))
                    .child(super::avatar(&self.profile_name, 64., t))
                    .child(
                        div()
                            .font_family(crate::fonts::HEADLINE)
                            .text_size(px(28.))
                            .child(self.profile_name.clone()),
                    )
                    .child(mono("Your VELA ID", t.muted))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(12.))
                            .child(
                                div()
                                    .min_w_0()
                                    .flex_1()
                                    .font_family(crate::fonts::MONO)
                                    .text_size(px(13.))
                                    .child(self.profile_id.clone()),
                            )
                            .child(icon_btn("profile-copy", "content_copy", t).on_click(
                                cx.listener(|this, _, _, cx| {
                                    this.copy("VELA ID", &this.profile_id, cx)
                                }),
                            )),
                    )
                    .child(
                        div()
                            .flex()
                            .gap(px(10.))
                            .child(super::page::metric("Items", self.items.len(), t))
                            .child(super::page::metric(
                                "Favourites",
                                self.analysis.favorites.len(),
                                t,
                            )),
                    )
                    .child(
                        pill("profile-settings", "Manage settings", false, t).on_click(
                            cx.listener(|this, _, _, cx| this.set_view(View::Settings, cx)),
                        ),
                    ),
            )
            .into_any_element()
    }
}

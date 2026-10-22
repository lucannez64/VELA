//! Vault list and item details.

use std::sync::Arc;

use gpui::{div, prelude::*, px, uniform_list, AnimationExt, Context, FontWeight, IntoElement, SharedString, Window};
use vela_desktop_core::vault::VaultItem;

use super::analysis::Kind;
use super::dot_matrix::{dot_text, DotStyle};
use super::shell::{ago, heading, icon_btn, pill, strength_color, subtitle, InstrumentShell, ListKind, Sort};
use super::{alpha, anim_id, avatar, mono, paint, stagger, tag, TagKind, Tok};
use crate::fonts;
use super::icons::icon;

const ROW_H: f32 = 58.;
const DETAIL_W: f32 = 432.;

impl InstrumentShell {
    pub(super) fn refresh_rows_with(&mut self, query: &str) {
        let a = &self.analysis;
        let items = &self.items;
        let mut rows: Vec<usize> = a
            .facts
            .iter()
            .enumerate()
            .filter(|(_, f)| match self.list_kind {
                ListKind::All => true,
                ListKind::Favorites => f.favorite,
                ListKind::Of(k) => f.kind == k,
            })
            .filter(|(_, f)| !self.risk_only || f.at_risk())
            .filter(|(_, f)| {
                if query.is_empty() {
                    return true;
                }
                let item = &items[f.index];
                item.name().to_lowercase().contains(query)
                    || item.username().is_some_and(|u| u.to_lowercase().contains(query))
                    || item.url().is_some_and(|u| u.to_lowercase().contains(query))
            })
            .map(|(slot, _)| slot)
            .collect();
        match self.sort {
            Sort::Recent => rows.sort_by_key(|s| a.facts[*s].age_days),
            Sort::Name => rows.sort_by_key(|s| items[a.facts[*s].index].name().to_lowercase()),
            Sort::Weakest => rows.sort_by_key(|s| {
                let f = &a.facts[*s];
                let risk = f.weak as u8 + (f.reused_with > 0) as u8 + f.old as u8;
                (std::cmp::Reverse(risk), f.strength.unwrap_or(9))
            }),
        }
        self.rows = Arc::new(rows);
    }

    pub(super) fn render_vault(&mut self, window: &mut Window, t: &Tok, cx: &mut Context<Self>) -> gpui::AnyElement {
        let width = f32::from(window.viewport_size().width);
        let side_by_side = width >= 1240.;
        let list = self.render_list(width < 760., t, cx);
        let detail = self.render_detail(t, cx);
        if side_by_side {
            div()
                .size_full()
                .flex()
                .gap(px(12.))
                .child(list)
                .child(div().w(px(DETAIL_W)).flex_shrink_0().h_full().child(detail))
                .into_any_element()
        } else {
            let open = self.selected.is_some();
            div()
                .relative()
                .size_full()
                .child(list)
                .when(open, |d| {
                    d.child(
                        div()
                            .id("detail-scrim")
                            .absolute()
                            .inset_0()
                            .bg(gpui::black().opacity(0.35))
                            .on_click(cx.listener(|this, _, _, cx| this.select(None, cx))),
                    )
                    .child(
                        div()
                            .id("detail-sheet")
                            .debug_selector(|| "detail-sheet".into())
                            .absolute()
                            .top_0()
                            .bottom_0()
                            .right_0()
                            .w(px(DETAIL_W))
                            .max_w_full()
                            // The backdrop is a sibling behind this sheet.
                            // Occlusion keeps controls from hitting it too.
                            .occlude()
                            .on_click(|_, _, cx| cx.stop_propagation())
                            .child(detail),
                    )
                })
                .into_any_element()
        }
    }

    fn filter_chip(&self, id: &'static str, label: &str, active: bool, t: &Tok) -> gpui::Stateful<gpui::Div> {
        let (bg, fg) = if active { (t.primary_bg, t.primary_fg) } else { (alpha(t.panel, 0.), t.muted) };
        let hover = t.text;
        div()
            .id(id)
            .debug_selector(move || id.to_string())
            .h(px(30.))
            .px(px(13.))
            .rounded_full()
            .flex()
            .items_center()
            .bg(bg)
            .text_color(fg)
            .text_size(px(12.5))
            .font_weight(FontWeight::MEDIUM)
            .cursor_pointer()
            .when(!active, move |d| d.hover(move |s| s.text_color(hover)))
            .child(SharedString::from(label.to_string()))
    }

    fn render_list(&mut self, compact: bool, t: &Tok, cx: &mut Context<Self>) -> impl IntoElement {
        let count = self.rows.len();
        let crumb = match (self.list_kind, self.risk_only) {
            (_, true) => "Vault / Needs attention",
            (ListKind::Favorites, _) => "Vault / Favourites",
            (ListKind::Of(Kind::Login), _) => "Vault / Logins",
            (ListKind::Of(Kind::Card), _) => "Vault / Cards",
            (ListKind::Of(Kind::Note), _) => "Vault / Notes",
            (ListKind::Of(Kind::Identity), _) => "Vault / Identities",
            (ListKind::Of(Kind::Passkey), _) => "Vault / Passkeys",
            _ => "Vault / All items",
        };
        let kinds: [(&'static str, &'static str, ListKind); 6] = [
            ("f-all", "All", ListKind::All),
            ("f-login", "Logins", ListKind::Of(Kind::Login)),
            ("f-card", "Cards", ListKind::Of(Kind::Card)),
            ("f-note", "Notes", ListKind::Of(Kind::Note)),
            ("f-identity", "Identities", ListKind::Of(Kind::Identity)),
            ("f-passkey", "Passkeys", ListKind::Of(Kind::Passkey)),
        ];
        let mut seg = div()
            .flex()
            .flex_wrap()
            .gap(px(2.))
            .p(px(3.))
            .rounded_full()
            .bg(t.panel2)
            .border_1()
            .border_color(t.line);
        for (id, label, kind) in kinds {
            let active = self.list_kind == kind || (kind == ListKind::All && self.list_kind == ListKind::Favorites);
            seg = seg.child(self.filter_chip(id, label, active, t).on_click(cx.listener(move |this, _, _, cx| {
                this.list_kind = kind;
                this.refresh_rows();
                this.anim_gen += 1;
                cx.notify();
            })));
        }
        let risk_on = self.risk_only;
        let at_risk = self.analysis.at_risk;
        let risk_chip = div()
            .id("f-risk")
            .debug_selector(|| "f-risk".into())
            .h(px(36.))
            .px(px(13.))
            .rounded_full()
            .flex()
            .items_center()
            .gap(px(7.))
            .border_1()
            .border_color(if risk_on { alpha(t.risk, 0.45) } else { t.line })
            .bg(if risk_on { alpha(t.risk, 0.10) } else { t.panel2 })
            .text_color(if risk_on { t.risk } else { t.muted })
            .text_size(px(12.5))
            .font_weight(FontWeight::MEDIUM)
            .cursor_pointer()
            .child(div().size(px(6.)).rounded_full().bg(t.risk))
            .child(format!("At risk · {at_risk}"))
            .on_click(cx.listener(|this, _, _, cx| {
                this.risk_only = !this.risk_only;
                this.refresh_rows();
                this.anim_gen += 1;
                cx.notify();
            }));
        let sort = pill("f-sort", self.sort.label(), false, t)
            .h(px(36.))
            .text_size(px(12.5))
            .text_color(t.muted)
            .child(icon("swap_vert", px(15.), t.muted))
            .on_click(cx.listener(|this, _, _, cx| {
                this.sort = this.sort.next();
                this.refresh_rows();
                cx.notify();
            }));

        let header = div()
            .flex()
            .flex_col()
            .gap(px(16.))
            .px(px(20.))
            .pt(px(20.))
            .pb(px(12.))
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap(px(14.))
                    .child(div().flex().flex_col().gap(px(8.)).child(mono(crumb, t.muted)).child(heading("Vault", 34., t)))
                    .child(div().pb(px(3.)).child(dot_text(format!("{count:02}"), DotStyle::new(5., t.text).gradient(t.grad))))
                    .child(div().flex_1())
                    .child(sort),
            )
            .child(div().flex().flex_wrap().items_center().gap(px(6.)).child(seg).child(risk_chip));

        let cols = div()
            .flex()
            .items_center()
            .gap(px(14.))
            .px(px(20.))
            .py(px(8.))
            .border_t_1()
            .border_b_1()
            .border_color(t.line)
            .child(div().flex_1().child(mono("Name", t.faint)))
            .when(!compact, |d| d.child(div().debug_selector(|| "vault-heading-type".into()).w(px(84.)).flex_shrink_0().child(mono("Type", t.faint))))
            .child(div().w(px(70.)).flex_shrink_0().child(mono("Strength", t.faint)))
            .when(!compact, |d| d.child(div().w(px(56.)).flex_shrink_0().flex().justify_end().child(mono("Changed", t.faint))))
            .child(div().w(px(30.)).flex_shrink_0());

        let body: gpui::AnyElement = if !self.loaded {
            div().p(px(40.)).text_color(t.muted).child("Loading…").into_any_element()
        } else if count == 0 {
            div()
                .flex()
                .flex_col()
                .items_center()
                .gap(px(6.))
                .p(px(60.))
                .child(heading("Nothing here.", 18., t))
                .child(div().text_color(t.muted).child(if self.risk_only { "Every login is healthy." } else { "Try another search or type." }))
                .into_any_element()
        } else {
            let rows = self.rows.clone();
            let entity = cx.entity().downgrade();
            let tk = *t;
            let gen = self.anim_gen;
            // Snapshot what each row shows; secrets are looked up on click.
            let data: Arc<Vec<RowData>> = Arc::new(
                rows.iter()
                    .map(|slot| {
                        let f = &self.analysis.facts[*slot];
                        let item = &self.items[f.index];
                        RowData {
                            id: item.id().to_string(),
                            name: item.name().to_string(),
                            sub: subtitle(item),
                            kind: f.kind.label(),
                            strength: f.strength,
                            age: ago(f.age_days),
                            old: f.old,
                            risk: f.at_risk(),
                            copy: match item {
                                VaultItem::Login { pass, .. } if !pass.is_empty() => Some("Password"),
                                VaultItem::CreditCard { .. } => Some("Card number"),
                                _ => None,
                            },
                        }
                    })
                    .collect(),
            );
            let selected = self.selected.clone();
            uniform_list("vault-rows", count, move |range, _window, _cx| {
                range
                    .map(|ix| {
                        let r = &data[ix];
                        let is_sel = selected.as_deref() == Some(r.id.as_str());
                        let row = vault_row(r, ix, is_sel, compact, &tk, entity.clone());
                        if ix < 14 {
                            row.with_animation(anim_id("vault-row", gen * 1000 + ix as u64), stagger(ix, 28, 320), |el, d| {
                                el.opacity(d).left(px(10. * (1. - d)))
                            })
                            .into_any_element()
                        } else {
                            row.into_any_element()
                        }
                    })
                    .collect()
            })
            .track_scroll(&self.list_scroll)
            .flex_1()
            .px(px(8.))
            .py(px(6.))
            .into_any_element()
        };

        div()
            .flex_1()
            .min_w_0()
            .h_full()
            .flex()
            .flex_col()
            .rounded(px(22.))
            .bg(t.panel)
            .border_1()
            .border_color(t.line)
            .overflow_hidden()
            .child(header)
            .child(cols)
            .child(body)
    }

    fn render_detail(&mut self, t: &Tok, cx: &mut Context<Self>) -> impl IntoElement {
        let shell = div()
            .id("vault-detail")
            .size_full()
            .rounded(px(22.))
            .bg(t.panel)
            .border_1()
            .border_color(t.line)
            .overflow_y_scroll()
            .p(px(20.));
        let Some((slot, item)) = self.selected_item() else {
            return shell
                .flex()
                .flex_col()
                .items_center()
                .justify_center()
                .gap(px(10.))
                .child(dot_text("VELA", DotStyle::new(5., t.text).gradient(t.grad)))
                .child(heading("Pick an item", 18., t).mt(px(10.)))
                .child(div().text_color(t.muted).text_size(px(13.)).child("Details, codes and fixes appear here."))
                .into_any_element();
        };
        let item = item.clone();
        let is_passkey = matches!(item, VaultItem::Passkey { .. });
        let is_received_share = item.is_received_share();
        let fact = self.analysis.facts[slot].clone();
        let gen = self.detail_gen;

        let mut reasons = Vec::new();
        if fact.reused_with > 0 {
            reasons.push((format!("Same password as {} other login{}.", fact.reused_with, if fact.reused_with == 1 { "" } else { "s" }), "Reused", TagKind::Warn));
        }
        if fact.weak {
            reasons.push(("Easy to guess.".into(), "Weak", TagKind::Risk));
        }
        if fact.old {
            reasons.push((format!("Unchanged for {}.", ago(fact.age_days)), "Over 1 year", TagKind::Plain));
        }

        let top = div()
            .flex()
            .items_center()
            .gap(px(6.))
            .mb(px(20.))
            .child(mono(fact.kind.label(), t.muted))
            .child(div().flex_1())
            .child(
                icon_btn("d-fav", if item.favorite() { "star" } else { "star_outline" }, t)
                    .when(item.favorite(), |d| d.text_color(t.signal))
                    .on_click(cx.listener(|this, _, _, cx| this.toggle_favorite(cx))),
            )
            // Same rules as the classic detail: a passkey's private key never
            // reaches an editor or a share, and received shares are read-only.
            .when(!is_passkey && !is_received_share, |el| {
                el.child(icon_btn("d-share", "share", t).on_click(cx.listener(|this, _, _, cx| this.share_selected(cx))))
                    .child(icon_btn("d-edit", "edit", t).on_click(cx.listener(|this, _, _, cx| this.edit_selected(cx))))
            })
            .child(icon_btn("d-close", "close", t).on_click(cx.listener(|this, _, _, cx| this.select(None, cx))));

        let url = item.url().filter(|u| !u.is_empty()).map(str::to_string);
        let ident = div()
            .flex()
            .items_center()
            .gap(px(16.))
            .mb(px(18.))
            .child(avatar(item.name(), 58., t))
            .child(
                div()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .gap(px(4.))
                    .child(heading(item.name().to_string(), 28., t))
                    .when_some(url.clone(), |d, u| {
                        let open = u.clone();
                        d.child(
                            div()
                                .id("d-url")
                                .text_size(px(12.5))
                                .text_color(t.muted)
                                .cursor_pointer()
                                .truncate()
                                .child(format!("{u} ↗"))
                                .on_click(move |_, _, _| {
                                    let target = if open.contains("://") { open.clone() } else { format!("https://{open}") };
                                    let _ = open::that(target);
                                }),
                        )
                    }),
            );

        let alert = (!reasons.is_empty()).then(|| {
            div()
                .flex()
                .flex_col()
                .gap(px(10.))
                .p(px(14.))
                .mb(px(12.))
                .rounded(px(16.))
                .bg(t.violet_bg)
                .border_1()
                .border_color(t.violet_line)
                .child(div().flex().items_center().gap(px(7.)).child(icon("auto_awesome", px(13.), t.violet)).child(mono("VELA noticed", t.violet)))
                .child(div().font_weight(FontWeight::MEDIUM).child(reasons.iter().map(|r| r.0.as_str()).collect::<Vec<_>>().join(" ")))
                .child(div().flex().flex_wrap().gap(px(6.)).children(reasons.iter().map(|r| tag(r.1, r.2, t))))
                .child(
                    div().child(
                        pill("d-fix", "Change password", true, t)
                            .h(px(34.))
                            .child(icon("casino", px(15.), t.primary_fg))
                            .on_click(cx.listener(|this, _, _, cx| this.edit_selected(cx))),
                    ),
                )
        });

        let reveal = self.reveal;
        let mut fields = FieldGroup::new(t);
        match &item {
            VaultItem::Login { username, pass, .. } => {
                if !username.is_empty() {
                    fields = fields.row("Username", username.clone(), false, Some(("Username", username.clone())), cx);
                }
                if !pass.is_empty() {
                    let shown = if reveal { pass.clone() } else { "•".repeat(pass.chars().count().min(16)) };
                    fields = fields.secret_row("Password", shown, reveal, ("Password", pass.clone()), cx);
                    if let Some(level) = fact.strength {
                        fields = fields.meter(level);
                    }
                }
            }
            VaultItem::CreditCard { number, exp, cvv, cardholder_name, .. } => {
                let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
                let last: String = digits.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
                let grouped = digits.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).to_string()).collect::<Vec<_>>().join(" ");
                let shown = if reveal { grouped } else { format!("•••• •••• •••• {last}") };
                fields = fields.secret_row("Number", shown, reveal, ("Card number", digits.clone()), cx);
                fields = fields.row("Expires", exp.clone(), true, None, cx);
                if !cvv.is_empty() {
                    fields = fields.row("Security code", if reveal { cvv.clone() } else { "•••".into() }, true, Some(("Security code", cvv.clone())), cx);
                }
                if let Some(holder) = cardholder_name.as_ref().filter(|h| !h.is_empty()) {
                    fields = fields.row("Cardholder", holder.clone(), false, None, cx);
                }
            }
            VaultItem::Passkey { user_name, rp_id, rp_name, .. } => {
                if !user_name.is_empty() {
                    fields = fields.row("Account", user_name.clone(), false, Some(("Account", user_name.clone())), cx);
                }
                let site = if rp_name.is_empty() { rp_id.clone() } else { format!("{rp_name} · {rp_id}") };
                fields = fields.row("Site", site, false, None, cx);
                fields = fields.row("Signs in", "With this passkey, no password".into(), false, None, cx);
            }
            VaultItem::SecureNote { content, .. } => {
                fields = fields.note(content.clone());
            }
            VaultItem::Identity { first_name, last_name, ssn, .. } => {
                fields = fields.row("Full name", format!("{first_name} {last_name}").trim().to_string(), false, None, cx);
                if !ssn.is_empty() {
                    fields = fields.secret_row("ID number", if reveal { ssn.clone() } else { "••••••••".into() }, reveal, ("ID number", ssn.clone()), cx);
                }
            }
            _ => {}
        }
        if let Some(u) = &url {
            fields = fields.row("Website", u.clone(), false, Some(("Website", u.clone())), cx);
        }

        let totp = self.totp.as_ref().map(|code| {
            let mid = code.code.len().div_ceil(2);
            let pretty = format!("{} {}", &code.code[..mid], &code.code[mid..]);
            let raw = code.code.clone();
            let frac = code.remaining as f32 / code.period as f32;
            div()
                .flex()
                .items_center()
                .gap(px(16.))
                .p(px(16.))
                .mb(px(12.))
                .rounded(px(16.))
                .bg(t.panel2)
                .border_1()
                .border_color(t.line)
                .child(
                    div()
                        .relative()
                        .size(px(44.))
                        .child(paint::ring(*t, frac, 44.))
                        .child(div().absolute().inset_0().flex().items_center().justify_center().font_family(fonts::MONO).text_size(px(11.)).child(code.remaining.to_string())),
                )
                .child(div().flex_1().flex().flex_col().gap(px(8.)).child(mono("One-time code", t.muted)).child(dot_text(pretty, DotStyle::new(5., t.text).off(alpha(t.text, 0.07)))))
                .child(icon_btn("d-copy-totp", "content_copy", t).on_click(cx.listener(move |this, _, _, cx| this.copy("One-time code", &raw, cx))))
        });

        let notes = item.notes().filter(|n| !n.trim().is_empty() && !matches!(item, VaultItem::SecureNote { .. })).map(|n| {
            div().p(px(14.)).mb(px(12.)).rounded(px(16.)).bg(t.panel2).border_1().border_color(t.line).text_size(px(13.)).line_height(px(21.)).child(n.to_string())
        });

        let confirm = self.confirm_delete;
        let meta = div()
            .flex()
            .flex_col()
            .gap(px(9.))
            .p(px(14.))
            .rounded(px(16.))
            .border_1()
            .border_color(t.line2)
            .child(kv("Changed", if fact.age_days < 1 { "Today".into() } else { format!("{} ago", ago(fact.age_days)) }, t))
            .child(kv("Created", item.created_at().format("%d %b %Y").to_string(), t))
            .child(
                div()
                    .flex()
                    .items_center()
                    .pt(px(6.))
                    .child(mono("Delete", t.faint))
                    .child(div().flex_1())
                    .child(
                        pill("d-delete", if confirm { "Confirm delete" } else { "Delete item" }, false, t)
                            .h(px(32.))
                            .when(confirm, |d| d.bg(alpha(t.risk, 0.14)).border_color(alpha(t.risk, 0.45)).text_color(t.risk))
                            .on_click(cx.listener(|this, _, _, cx| this.delete_selected(cx))),
                    ),
            );

        shell
            .child(
                div()
                    .child(top)
                    .child(ident)
                    .children(alert)
                    .child(fields.finish())
                    .children(totp)
                    .children(notes)
                    .child(meta)
                    .with_animation(anim_id("detail", gen), stagger(0, 0, 300), |el, d| el.opacity(d).left(px(14. * (1. - d)))),
            )
            .into_any_element()
    }
}

struct RowData {
    id: String,
    name: String,
    sub: String,
    kind: &'static str,
    strength: Option<u8>,
    age: String,
    old: bool,
    risk: bool,
    copy: Option<&'static str>,
}

fn vault_row(r: &RowData, ix: usize, selected: bool, compact: bool, t: &Tok, entity: gpui::WeakEntity<InstrumentShell>) -> gpui::Stateful<gpui::Div> {
    let id = r.id.clone();
    let hover = t.panel2;
    let strength: gpui::AnyElement = match r.strength {
        Some(level) => div()
            .flex()
            .gap(px(3.))
            .children((0..5).map(|k| {
                let on = k <= level as usize;
                div()
                    .size(px(7.))
                    .rounded_full()
                    .when(on, |d| d.bg(strength_color(level, t)))
                    .when(!on, |d| d.bg(t.panel3).border_1().border_color(t.line2))
            }))
            .into_any_element(),
        None => mono("—", t.faint).into_any_element(),
    };
    let copy_entity = entity.clone();
    let copy_id = r.id.clone();
    div()
        .id(gpui::ElementId::NamedInteger("vault-row".into(), ix as u64))
        .debug_selector(move || format!("vault-row-{ix}"))
        .w_full()
        .h(px(ROW_H - 4.))
        .my(px(2.))
        .px(px(12.))
        .rounded(px(14.))
        .flex()
        .items_center()
        .gap(px(14.))
        .cursor_pointer()
        .when(selected, |d| d.bg(t.panel3).border_1().border_color(t.line2))
        .when(!selected, move |d| d.hover(move |s| s.bg(hover)))
        .on_click(move |_, _, cx| {
            let id = id.clone();
            entity.update(cx, |this, cx| this.select(Some(id), cx)).ok();
        })
        .child(
            div()
                .flex_1()
                .min_w_0()
                .flex()
                .items_center()
                .gap(px(12.))
                .child(avatar(&r.name, 36., t))
                .when(r.risk, |d| d.child(div().size(px(6.)).ml(px(-6.)).rounded_full().bg(t.risk)))
                .child(
                    div()
                        .flex_1().min_w_0().overflow_hidden()
                        .child(div().font_weight(FontWeight::MEDIUM).text_size(px(13.5)).truncate().child(r.name.clone()))
                        .child(div().text_size(px(12.)).text_color(t.muted).truncate().child(r.sub.clone())),
                ),
        )
        .when(!compact, |d| d.child(div().debug_selector(move || format!("vault-type-{ix}")).w(px(84.)).flex_shrink_0().child(mono(r.kind, t.muted))))
        .child(div().w(px(70.)).flex_shrink_0().child(strength))
        .when(!compact, |d| d.child(div().w(px(56.)).flex_shrink_0().flex().justify_end().child(mono(r.age.clone(), if r.old { t.warn } else { t.muted }))))
        .child(div().w(px(30.)).flex_shrink_0().when_some(r.copy, |d, label| {
            d.child(
                div()
                    .id(gpui::ElementId::NamedInteger("row-copy".into(), ix as u64))
                    .size(px(30.))
                    .rounded(px(9.))
                    .flex()
                    .items_center()
                    .justify_center()
                    .hover({
                        let c = t.panel;
                        move |s| s.bg(c)
                    })
                    .child(icon("content_copy", px(15.), t.muted))
                    .on_click(move |_, _, cx| {
                        cx.stop_propagation();
                        let id = copy_id.clone();
                        copy_entity
                            .update(cx, |this, cx| {
                                let value = this.items.iter().find(|i| i.id() == id).and_then(|i| match i {
                                    VaultItem::Login { pass, .. } => Some(pass.clone()),
                                    VaultItem::CreditCard { number, .. } => Some(number.clone()),
                                    _ => None,
                                });
                                if let Some(v) = value {
                                    this.copy(label, &v, cx);
                                }
                            })
                            .ok();
                    }),
            )
        }))
}

fn kv(label: &'static str, value: String, t: &Tok) -> gpui::Div {
    div().flex().items_center().gap(px(18.)).child(div().w(px(70.)).flex_shrink_0().child(mono(label, t.faint))).child(div().text_size(px(12.5)).child(value))
}

struct FieldGroup {
    el: gpui::Div,
    t: Tok,
    n: usize,
}

impl FieldGroup {
    fn new(t: &Tok) -> Self {
        Self {
            el: div().flex().flex_col().mb(px(12.)).rounded(px(16.)).bg(t.panel2).border_1().border_color(t.line),
            t: *t,
            n: 0,
        }
    }

    fn base(&mut self, label: &'static str, value: String, mono_value: bool) -> gpui::Div {
        let t = self.t;
        let first = self.n == 0;
        self.n += 1;
        div()
            .flex()
            .items_center()
            .gap(px(8.))
            .px(px(14.))
            .py(px(12.))
            .when(!first, |d| d.border_t_1().border_color(t.line))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .gap(px(4.))
                    .child(mono(label, t.muted))
                    .child(
                        div()
                            .text_size(px(14.))
                            .when(mono_value, |d| d.font_family(fonts::MONO))
                            .truncate()
                            .child(value),
                    ),
            )
    }

    fn row(
        mut self,
        label: &'static str,
        value: String,
        mono_value: bool,
        copy: Option<(&'static str, String)>,
        cx: &mut Context<InstrumentShell>,
    ) -> Self {
        let t = self.t;
        let n = self.n;
        let row = self.base(label, value, mono_value).when_some(copy, |d, (what, v)| {
            d.child(
                icon_btn(format!("d-copy-{n}"), "content_copy", &t)
                    .on_click(cx.listener(move |this, _, _, cx| this.copy(what, &v, cx))),
            )
        });
        self.el = self.el.child(row);
        self
    }

    fn secret_row(
        mut self,
        label: &'static str,
        shown: String,
        revealed: bool,
        (what, value): (&'static str, String),
        cx: &mut Context<InstrumentShell>,
    ) -> Self {
        let t = self.t;
        let n = self.n;
        let row = self
            .base(label, shown, true)
            .child(
                icon_btn(format!("d-reveal-{n}"), if revealed { "visibility_off" } else { "visibility" }, &t).on_click(cx.listener(|this, _, _, cx| {
                    this.reveal = !this.reveal;
                    cx.notify();
                })),
            )
            .child(icon_btn(format!("d-copy-{n}"), "content_copy", &t).on_click(cx.listener(move |this, _, _, cx| this.copy(what, &value, cx))));
        self.el = self.el.child(row);
        self
    }

    fn meter(mut self, level: u8) -> Self {
        let t = self.t;
        let color = strength_color(level, &t);
        let label = ["Very weak", "Weak", "Fair", "Good", "Strong"][level as usize];
        let lit = (level as usize + 1) * 4;
        self.el = self.el.child(
            div()
                .flex()
                .items_center()
                .gap(px(10.))
                .px(px(14.))
                .pb(px(12.))
                .mt(px(-4.))
                .child(div().flex_1().flex().gap(px(3.)).children((0..20).map(move |k| {
                    div().size(px(8.)).rounded_full().bg(if k < lit { color } else { t.panel3 })
                })))
                .child(mono(label, t.muted)),
        );
        self
    }

    fn note(mut self, text: String) -> Self {
        self.n += 1;
        self.el = self.el.child(div().p(px(14.)).text_size(px(13.5)).line_height(px(22.)).child(text));
        self
    }

    fn finish(self) -> gpui::Div {
        if self.n == 0 {
            div()
        } else {
            self.el
        }
    }
}

#[cfg(test)]
mod interaction_tests {
    use super::*;
    use gpui::{size, Modifiers, TestAppContext};
    use crate::modal_test_support as fixture;

    #[gpui::test]
    fn detail_reveal_and_copy_do_not_dismiss_the_sheet(cx: &mut TestAppContext) {
        let demo = crate::demo::DemoVault::new().unwrap();
        let id = demo.state.vault.read().items.iter().find(|i|i.name()=="Personal email").unwrap().id().to_string();
        cx.update(|cx| {
            cx.set_global(crate::demo::DemoMode);
            crate::clipboard::set_clear_seconds(cx, 0);
            cx.set_global(crate::instrument::ActiveInterface(crate::instrument::InterfaceMode::Instrument));
        });
        let (shell, cx) = cx.add_window_view(|_, cx| {
            fixture::fonts(cx);
            InstrumentShell::new(demo.state.clone(), cx)
        });
        cx.run_until_parked();
        for width in [1024., 390., 1440.] {
            cx.simulate_resize(size(px(width),px(820.)));
            shell.update(cx,|shell,cx|shell.open_item(id.clone(),cx));
            cx.run_until_parked();
            assert!(!shell.read_with(cx,|shell,_|shell.reveal));
            for (button, revealed) in [("d-reveal-1",true),("d-copy-1",true),("d-reveal-1",false)] {
                let bounds=fixture::bounds(cx,button);
                assert!(bounds.left()>=px(0.) && bounds.right()<=px(width));
                cx.simulate_mouse_move(bounds.center(),None,Modifiers::default());
                cx.simulate_click(bounds.center(),Modifiers::default());
                cx.run_until_parked();
                assert_eq!(shell.read_with(cx,|shell,_|shell.selected.clone()),Some(id.clone()));
                assert_eq!(shell.read_with(cx,|shell,_|shell.reveal),revealed);
            }
            let dock=fixture::bounds(cx,"instrument-dock");
            assert!(dock.bottom()<=px(820.) && dock.right()<=px(width));
            let close=fixture::bounds(cx,"d-close");
            cx.simulate_mouse_move(close.center(),None,Modifiers::default());
            cx.simulate_click(close.center(),Modifiers::default());
            cx.run_until_parked();
            assert!(shell.read_with(cx,|shell,_|shell.selected.is_none()));
        }
    }
}

#[cfg(test)]
mod column_tests {
    use super::*;
    use gpui::{size,TestAppContext};
    use crate::modal_test_support as ui;
    #[gpui::test]
    fn rows_with_different_lengths_share_the_header_columns(cx:&mut TestAppContext){
        let demo=crate::demo::DemoVault::new().unwrap();
        cx.update(|cx|cx.set_global(crate::demo::DemoMode));
        let (shell,cx)=cx.add_window_view(|_,cx|{ui::fonts(cx);InstrumentShell::new(demo.state.clone(),cx)});
        cx.run_until_parked();
        shell.update(cx,|shell,cx|shell.open_list(ListKind::All,false,cx));
        for width in [945.,1440.] {
            cx.simulate_resize(size(px(width),px(1025.)));
            cx.run_until_parked();
            let header=ui::bounds(cx,"vault-heading-type");
            for index in 0..8 {
                let selector: &'static str=Box::leak(format!("vault-type-{index}").into_boxed_str());
                let column=ui::bounds(cx,selector);
                assert!((f32::from(column.left())-f32::from(header.left())).abs()<=1.,"type column drifts at width {width}, row {index}: {column:?} vs {header:?}");
                assert_eq!(column.size.width,header.size.width);
            }
        }
    }
}

//! The overview bento. Every figure comes from `Analysis` or the audit log.

use chrono::{Datelike, Local, TimeZone, Utc};
use gpui::{div, prelude::*, px, relative, AnimationExt, Context, FontWeight, Hsla, IntoElement, Window};
use vela_desktop_core::audit::{AuditAction, AuditEntry};
use vela_desktop_core::vault::VaultItem;

use super::analysis::{Kind, AGE_LABELS};
use super::dot_matrix::{dot_text, DotStyle};
use super::shell::{heading, icon_btn, pill, subtitle, InstrumentShell, ListKind, View};
use super::{alpha, anim_id, avatar, mono, paint, stagger, tag, tile, TagKind, Tok};
use crate::fonts;
use super::icons::icon;

struct Issue {
    tag: (&'static str, TagKind),
    title: String,
    names: String,
    first: Option<String>,
}

fn names(shell: &InstrumentShell, slots: &[usize]) -> (String, Option<String>) {
    let mut list: Vec<&str> = slots.iter().map(|s| shell.item_at(*s).name()).collect();
    list.sort_unstable();
    list.dedup();
    let first = slots.first().map(|s| shell.item_at(*s).id().to_string());
    let shown = list.iter().take(3).copied().collect::<Vec<_>>().join(", ");
    let more = list.len().saturating_sub(3);
    (if more > 0 { format!("{shown} +{more}") } else { shown }, first)
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Coarse category colour for an audit action.
fn action_tone(action: &AuditAction, t: &Tok) -> Hsla {
    match action {
        AuditAction::VaultUnlocked | AuditAction::DeviceEnrolled { .. } | AuditAction::WebSessionGranted { .. } => t.signal,
        AuditAction::ShareSent { .. }
        | AuditAction::ShareReceived { .. }
        | AuditAction::ShareLinkCreated { .. }
        | AuditAction::CredentialReleased { .. }
        | AuditAction::VaultRekeyed { .. } => t.violet,
        AuditAction::DeviceRevoked { .. } | AuditAction::ShareLinkRevoked { .. } | AuditAction::ItemDeleted { .. } => t.risk,
        _ => t.faint,
    }
}

fn when(entry: &AuditEntry) -> String {
    let local = entry.timestamp.with_timezone(&Local);
    let today = Local::now().date_naive();
    match (today - local.date_naive()).num_days() {
        0 => local.format("%H:%M").to_string(),
        1 => "Yest.".into(),
        _ => local.format("%d %b").to_string(),
    }
}

impl InstrumentShell {
    fn issues(&self) -> Vec<Issue> {
        let a = &self.analysis;
        let mut out = Vec::new();
        if !a.reused.is_empty() {
            let (names, first) = names(self, &a.reused);
            out.push(Issue {
                tag: ("Reused", TagKind::Warn),
                title: format!("{} share a password", plural(a.reused.len(), "login", "logins")),
                names,
                first,
            });
        }
        let weak: Vec<usize> = a.weak.iter().copied().filter(|s| !a.reused.contains(s)).collect();
        if !weak.is_empty() {
            let (names, first) = names(self, &weak);
            out.push(Issue {
                tag: ("Weak", TagKind::Risk),
                title: plural(weak.len(), "weak password", "weak passwords"),
                names,
                first,
            });
        }
        let old: Vec<usize> = a
            .old
            .iter()
            .copied()
            .filter(|s| !a.reused.contains(s) && !a.weak.contains(s))
            .collect();
        if !old.is_empty() {
            let (names, first) = names(self, &old);
            out.push(Issue {
                tag: ("Over 1 year", TagKind::Plain),
                title: format!("{} not changed in over a year", plural(old.len(), "password", "passwords")),
                names,
                first,
            });
        }
        out
    }

    pub(super) fn render_overview(&mut self, window: &mut Window, t: &Tok, cx: &mut Context<Self>) -> gpui::AnyElement {
        let viewport = f32::from(window.viewport_size().width);
        let rail = if viewport < 760. { 0. } else if super::shell::wide_rail(window) { 224. } else { 72. };
        let cw = viewport - rail - 36.;
        // The gauge and its four metrics need roughly 440px beside the hero.
        let two_col = cw >= 1080.;
        let gen = self.anim_gen;
        let a = &self.analysis;
        let issues = self.issues();

        let hour = Local::now().hour();
        let greet = if hour < 12 { "Good morning." } else if hour < 18 { "Good afternoon." } else { "Good evening." };
        let summary = match issues.len() {
            0 => "Nothing needs you. Everything else is sealed.".to_string(),
            n => format!("{} need{} you. Everything else is sealed.", plural(n, "thing", "things"), if n == 1 { "s" } else { "" }),
        };
        let date = Local::now().format("%a %d %b").to_string();

        let head = div()
            .flex()
            .items_end()
            .gap(px(20.))
            .px(px(6.))
            .pt(px(10.))
            .pb(px(8.))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(10.))
                    .child(mono(format!("Overview / {date}"), t.muted))
                    .child(heading(greet, 42., t))
                    .child(div().text_size(px(14.)).text_color(t.muted).child(summary)),
            )
            .child(div().flex_1())
            .when(two_col, |d| {
                d.child(
                    pill("ov-open-vault", "Open vault", false, t)
                        .child(icon("north_east", px(15.), t.text))
                        .on_click(cx.listener(|this, _, _, cx| this.open_list(ListKind::All, false, cx))),
                )
            });

        let hero = self.hero_tile(two_col, t, cx);
        let health = self.health_tile(cw < 500., t, cx);
        let noticed = self.noticed_tile(issues, t, cx);
        let age = self.age_tile(t);
        let heat = self.heat_tile(t, cx);
        let recent = self.recent_tile(t, cx);
        let pinned = self.pinned_tile(two_col, t, cx);

        let enter = move |el: gpui::Div, i: usize| {
            el.with_animation(anim_id("ov-tile", gen * 100 + i as u64), stagger(i, 70, 460), |el, d| {
                el.opacity(d).top(px(16. * (1. - d)))
            })
        };

        let row1 = if two_col {
            div()
                .flex()
                .gap(px(12.))
                .child(div().w(relative(0.585)).flex_shrink_0().child(enter(hero, 0)))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .flex()
                        .flex_col()
                        .gap(px(12.))
                        .child(enter(health, 1))
                        .child(enter(noticed.flex_1(), 2)),
                )
        } else {
            div()
                .flex()
                .flex_col()
                .gap(px(12.))
                .child(enter(hero, 0))
                .child(enter(health, 1))
                .child(enter(noticed, 2))
        };
        let row2 = div()
            .flex()
            .gap(px(12.))
            .when(!two_col, |d| d.flex_col())
            .child(div().flex_1().min_w_0().flex().child(enter(age.flex_1(), 3)))
            .child(div().flex_1().min_w_0().flex().child(enter(heat.flex_1(), 4)))
            .child(div().flex_1().min_w_0().flex().child(enter(recent.flex_1(), 5)));

        let _ = a;
        div()
            .id("overview")
            .size_full()
            .overflow_y_scroll()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(12.))
                    .pb(px(12.))
                    .child(head)
                    .child(row1)
                    .child(row2)
                    .child(enter(pinned, 6)),
            )
            .into_any_element()
    }

    fn hero_tile(&self, two_col: bool, t: &Tok, cx: &mut Context<Self>) -> gpui::Div {
        let a = &self.analysis;
        let gen = self.anim_gen;
        let tk = *t;
        let fg = t.hero_fg;
        let soft = alpha(fg, 0.62);
        let stat = |id: &'static str, n: usize, label: &'static str, i: usize| {
            let off = alpha(fg, 0.07);
            div()
                .flex()
                .flex_col()
                .gap(px(9.))
                .child(div().with_animation(anim_id(id, gen), stagger(i, 120, 900), move |el, d| {
                    let shown = ((n as f32) * d).round() as usize;
                    el.child(dot_text(shown.to_string(), DotStyle::new(7., fg).off(off)))
                }))
                .child(mono(label, soft))
        };
        let pixels = {
            let pattern = ["000011", "000110", "001110", "011100", "111000", "010001", "100000"];
            let colors = [t.grad[0], t.grad[0], t.grad[1], t.grad[2], t.grad[2], t.grad[3]];
            div()
                .absolute()
                .right(px(26.))
                .top(px(62.))
                .flex()
                .flex_col()
                .gap(px(3.))
                .children(pattern.iter().enumerate().map(move |(y, row)| {
                    div().flex().gap(px(3.)).children(row.chars().enumerate().map(move |(x, c)| {
                        div()
                            .size(px(11.))
                            .rounded(px(2.))
                            .when(c == '1', |d| d.bg(colors[(x + y) % 6]))
                    }))
                }))
        };
        let _ = cx;
        div()
            .relative()
            .h(px(if two_col { 392. } else { 340. }))
            .rounded(px(22.))
            .overflow_hidden()
            .text_color(fg)
            .child(div().absolute().inset_0().with_animation(
                anim_id("ov-sunrise", gen),
                gpui::Animation::new(super::ms(1400)).with_easing(super::ease_out),
                move |el, d| el.child(paint::sunrise(tk, tk.bg, 22., d)),
            ))
            .when(two_col, |d| d.child(pixels))
            .child(
                div()
                    .relative()
                    .size_full()
                    .p(px(24.))
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .child(mono("01 / Vault", soft))
                            .child(div().flex_1())
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(8.))
                                    .px(px(12.))
                                    .py(px(6.))
                                    .rounded_full()
                                    .bg(alpha(t.hero_base, 0.55))
                                    .border_1()
                                    .border_color(alpha(fg, 0.14))
                                    .text_size(px(12.))
                                    .child(div().size(px(7.)).rounded_full().bg(t.signal))
                                    .child("Encrypted on this device"),
                            ),
                    )
                    .child(
                        div()
                            .mt(px(if two_col { 54. } else { 28. }))
                            .font_family(fonts::HEADLINE)
                            .font_weight(FontWeight::MEDIUM)
                            .text_size(px(if two_col { 50. } else { 40. }))
                            .line_height(relative(1.0))
                            .child("Your keys.")
                            .child(div().text_color(alpha(fg, 0.55)).child("Only yours.")),
                    )
                    .child(div().flex_1())
                    .child(
                        div()
                            .flex()
                            .items_end()
                            .gap(px(32.))
                            .child(stat("ov-stat-items", a.facts.len(), "Items", 0))
                            .child(stat("ov-stat-2fa", a.totp, "2FA codes", 1))
                            .child(stat("ov-stat-pk", a.passkeys, "Passkeys", 2)),
                    ),
            )
    }

    fn health_tile(&self, compact: bool, t: &Tok, cx: &mut Context<Self>) -> gpui::Div {
        let a = &self.analysis;
        let gen = self.anim_gen;
        let tk = *t;
        let score = a.score;
        let healthy = a.logins - a.at_risk;
        let dots = 8usize;
        let risk_dots = if a.logins == 0 { 0 } else { ((dots * a.at_risk) as f32 / a.logins as f32).round() as usize };
        let bar = |lit: usize, color: Hsla, idle: Hsla| {
            div().flex().gap(px(3.)).mt(px(8.)).children((0..dots).map(move |k| {
                div().size(px(5.)).rounded_full().bg(if k < lit { color } else { idle })
            }))
        };
        let metric = |label: &'static str, value: usize, risk: bool| {
            div()
                .flex()
                .flex_col()
                .gap(px(4.))
                .min_w_0()
                .overflow_hidden()
                .child(mono(label, tk.muted))
                .child(
                    div()
                        .font_family(fonts::HEADLINE)
                        .font_weight(FontWeight::MEDIUM)
                                .text_size(px(24.))
                        .text_color(if risk && value > 0 { tk.risk } else { tk.text })
                        .child(value.to_string()),
                )
        };
        tile(t)
            .child(
                div()
                    .flex()
                    .items_center()
                    .mb(px(10.))
                    .child(mono("02 / Health", t.muted))
                    .child(div().flex_1())
                    .child(icon_btn("ov-health-open", "north_east", t).on_click(cx.listener(|this, _, _, cx| this.open_list(ListKind::All, true, cx)))),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(18.))
                    .when(compact, |d| d.flex_col())
                    .child(
                        div()
                            .relative()
                            .w(px(212.))
                            .h(px(118.))
                            .flex_shrink_0()
                            .child(div().absolute().inset_0().with_animation(
                                anim_id("ov-gauge", gen),
                                stagger(1, 120, 1200),
                                move |el, d| el.child(paint::gauge(tk, score as f32 / 100. * d)),
                            ))
                            .child(
                                div()
                                    .absolute()
                                    .left_0()
                                    .right_0()
                                    .bottom(px(14.))
                                    .flex()
                                    .flex_col()
                                    .items_center()
                                    .gap(px(7.))
                                    .child(div().with_animation(anim_id("ov-score", gen), stagger(1, 120, 1200), move |el, d| {
                                        let shown = ((score as f32) * d).round() as u32;
                                        el.child(dot_text(shown.to_string(), DotStyle::new(5.5, tk.text)))
                                    }))
                                    .child(mono("Health / 100", t.faint)),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .when(compact, |d| d.w_full())
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .gap(px(14.))
                            .child(
                                div()
                                    .flex()
                                    .gap(px(18.))
                                    .child(div().flex_1().child(metric("Healthy", healthy, false)).child(bar(dots - risk_dots, t.text, t.faint)))
                                    .child(div().flex_1().child(metric("At risk", a.at_risk, true)).child(bar(risk_dots, t.risk, t.faint))),
                            )
                            .child(
                                div()
                                    .flex()
                                    .gap(px(18.))
                                    .child(div().flex_1().child(metric("2FA codes", a.totp, false)))
                                    .child(div().flex_1().child(metric("Logins", a.logins, false))),
                            ),
                    ),
            )
    }

    fn noticed_tile(&self, issues: Vec<Issue>, t: &Tok, cx: &mut Context<Self>) -> gpui::Div {
        let count = issues.len();
        let mut body = div().flex().flex_col();
        if issues.is_empty() {
            body = body.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(12.))
                    .child(tag("Clear", TagKind::Ok, t))
                    .child(
                        div()
                            .child(div().font_weight(FontWeight::MEDIUM).child("No open issues"))
                            .child(div().text_size(px(12.)).text_color(t.muted).child("Every login is strong, unique and recent.")),
                    ),
            );
        }
        for (i, issue) in issues.into_iter().enumerate() {
            let first = issue.first.clone();
            body = body.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(12.))
                    .py(px(11.))
                    .when(i > 0, |d| d.border_t_1().border_color(t.line))
                    .child(tag(issue.tag.0, issue.tag.1, t))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(div().font_weight(FontWeight::MEDIUM).child(issue.title))
                            .child(div().text_size(px(12.)).text_color(t.muted).truncate().child(issue.names)),
                    )
                    .child(
                        pill(format!("ov-review-{i}"), "Review", false, t)
                            .h(px(32.))
                            .px(px(13.))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.open_list(ListKind::All, true, cx);
                                this.select(first.clone(), cx);
                            })),
                    ),
            );
        }
        tile(t)
            .bg(t.violet_bg)
            .border_color(t.violet_line)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .mb(px(8.))
                    .child(icon("auto_awesome", px(14.), t.violet))
                    .child(mono("VELA noticed", t.violet))
                    .child(div().flex_1())
                    .child(mono(format!("{count} open"), t.violet)),
            )
            .child(body)
    }

    fn age_tile(&self, t: &Tok) -> gpui::Div {
        let a = &self.analysis;
        let gen = self.anim_gen;
        let max = a.age_buckets.iter().copied().max().unwrap_or(0).max(1);
        let rows = 8usize;
        let older: usize = a.age_buckets[4] + a.age_buckets[5];
        let cols = a.age_buckets.iter().enumerate().map(|(b, &count)| {
            let lit = if max <= rows { count } else { ((count * rows) as f32 / max as f32).ceil() as usize };
            let color = if b >= 4 { t.warn } else { t.text };
            let (faint, line) = (t.faint, t.muted);
            div()
                .flex_1()
                .flex()
                .flex_col()
                .items_center()
                .gap(px(8.))
                .child(div().with_animation(anim_id("ov-age", gen * 10 + b as u64), stagger(b + 3, 60, 700), move |el, d| {
                    let shown = ((lit as f32) * d).round() as usize;
                    el.flex().flex_col().gap(px(4.)).children((0..rows).rev().map(move |r| {
                        let on = r < shown;
                        div().flex().gap(px(4.)).children((0..3).map(move |_| {
                            div().size(px(6.)).rounded_full().bg(if on { color } else { alpha(faint, 0.35) })
                        }))
                    }))
                }))
                .child(mono(AGE_LABELS[b], line))
        });
        tile(t)
            .flex()
            .flex_col()
            .child(div().mb(px(16.)).child(mono("03 / Password age", t.muted)))
            .child(div().flex().children(cols))
            .child(div().flex_1())
            .child(
                div()
                    .mt(px(14.))
                    .flex()
                    .items_center()
                    .text_size(px(12.5))
                    .text_color(t.muted)
                    .child(div().text_color(t.text).font_weight(FontWeight::MEDIUM).child(older.to_string()))
                    .child("\u{a0}older than a year")
                    .child(div().flex_1())
                    .child(mono(format!("{} logins", a.logins), t.faint)),
            )
    }

    fn heat_tile(&self, t: &Tok, cx: &mut Context<Self>) -> gpui::Div {
        const WEEKS: usize = 17;
        let days = WEEKS * 7;
        let today = Local::now().date_naive();
        let mut counts = vec![0usize; days];
        for e in &self.audit {
            let d = (today - e.timestamp.with_timezone(&Local).date_naive()).num_days();
            if (0..days as i64).contains(&d) {
                counts[days - 1 - d as usize] += 1;
            }
        }
        let total: usize = counts.iter().sum();
        let gen = self.anim_gen;
        let tk = *t;
        tile(t)
            .flex()
            .flex_col()
            .child(
                div()
                    .flex()
                    .items_center()
                    .mb(px(16.))
                    .child(mono("04 / Activity heat", t.muted))
                    .child(div().flex_1())
                    .child(super::tag(format!("{WEEKS} weeks"), TagKind::Plain, t)),
            )
            .child(div().with_animation(anim_id("ov-heat", gen), stagger(4, 70, 900), move |el, d| {
                let reach = (d * WEEKS as f32).ceil() as usize;
                let counts = counts.clone();
                el.flex().gap(px(3.)).children((0..WEEKS).map(move |w| {
                    let counts = counts.clone();
                    div().flex().flex_col().gap(px(3.)).children((0..7).map(move |r| {
                        let n = counts[w * 7 + r];
                        let color = if w >= reach {
                            tk.panel3
                        } else {
                            match n {
                                0 => tk.panel3,
                                1..=2 => alpha(tk.signal, 0.35),
                                3..=5 => alpha(tk.signal, 0.65),
                                _ => tk.signal,
                            }
                        };
                        div().size(px(11.)).rounded(px(2.)).bg(color)
                    }))
                }))
            }))
            .child(div().flex_1())
            .child(
                div()
                    .mt(px(14.))
                    .flex()
                    .items_center()
                    .text_size(px(12.5))
                    .text_color(t.muted)
                    .child(div().text_color(t.text).font_weight(FontWeight::MEDIUM).child(total.to_string()))
                    .child("\u{a0}events on this account")
                    .child(div().flex_1())
                    .child(
                        pill("ov-open-log", "Open log", false, t)
                            .h(px(32.))
                            .px(px(13.))
                            .on_click(cx.listener(|this, _, _, cx| this.set_view(View::Activity, cx))),
                    ),
            )
    }

    fn recent_tile(&self, t: &Tok, cx: &mut Context<Self>) -> gpui::Div {
        let rows: Vec<_> = self.audit.iter().take(5).collect();
        let n = rows.len();
        let mut list = div().flex().flex_col();
        if rows.is_empty() {
            list = list.child(div().text_color(t.muted).text_size(px(12.5)).child("No activity yet."));
        }
        for (i, e) in rows.into_iter().enumerate() {
            let (label, _) = crate::views::audit_log_screen::action_label_icon(&e.action);
            let detail = crate::views::audit_log_screen::action_details(&e.action).unwrap_or_default();
            list = list.child(
                div()
                    .flex()
                    .gap(px(10.))
                    .py(px(7.))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .items_center()
                            .w(px(9.))
                            .pt(px(4.))
                            .child(div().size(px(9.)).rounded(px(2.)).bg(action_tone(&e.action, t)))
                            .when(i + 1 < n, |d| d.child(div().mt(px(4.)).w(px(1.)).h(px(22.)).bg(t.line2))),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(div().font_weight(FontWeight::MEDIUM).child(label))
                            .when(!detail.is_empty(), |d| d.child(div().text_size(px(12.)).text_color(t.muted).truncate().child(detail))),
                    )
                    .child(mono(when(e), t.muted)),
            );
        }
        tile(t)
            .child(
                div()
                    .flex()
                    .items_center()
                    .mb(px(10.))
                    .child(mono("05 / Recent activity", t.muted))
                    .child(div().flex_1())
                    .child(icon_btn("ov-activity-open", "north_east", t).on_click(cx.listener(|this, _, _, cx| this.set_view(View::Activity, cx)))),
            )
            .child(list)
    }

    fn pinned_tile(&self, two_col: bool, t: &Tok, cx: &mut Context<Self>) -> gpui::Div {
        let favs: Vec<usize> = self.analysis.favorites.iter().copied().take(4).collect();
        let mut row = div().flex().gap(px(10.)).when(!two_col, |d| d.flex_col());
        if favs.is_empty() {
            row = row.child(div().text_color(t.muted).text_size(px(12.5)).child("Star an item to pin it here."));
        }
        for slot in favs {
            let item: &VaultItem = self.item_at(slot);
            let fact = &self.analysis.facts[slot];
            let id = item.id().to_string();
            let open_id = id.clone();
            let (copy_label, copy_value) = match item {
                VaultItem::Login { pass, .. } if !pass.is_empty() => ("Password", Some(pass.clone())),
                VaultItem::CreditCard { number, .. } => ("Card number", Some(number.clone())),
                _ => ("", None),
            };
            let hint: gpui::AnyElement = if fact.has_totp {
                tag("2FA", TagKind::Ok, t).into_any_element()
            } else {
                match item {
                    VaultItem::CreditCard { exp, .. } => mono(format!("Exp {exp}"), t.muted).into_any_element(),
                    _ => mono(fact.kind.label(), t.muted).into_any_element(),
                }
            };
            let hover = t.line2;
            row = row.child(
                div()
                    .id(gpui::ElementId::Name(format!("pin-{id}").into()))
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .gap(px(14.))
                    .p(px(14.))
                    .rounded(px(16.))
                    .bg(t.panel2)
                    .border_1()
                    .border_color(t.line)
                    .cursor_pointer()
                    .hover(move |s| s.border_color(hover))
                    .on_click(cx.listener(move |this, _, _, cx| this.open_item(open_id.clone(), cx)))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(10.))
                            .child(avatar(item.name(), 36., t))
                            .child(
                                div()
                                    .min_w_0()
                                    .child(div().font_weight(FontWeight::MEDIUM).truncate().child(item.name().to_string()))
                                    .child(div().text_size(px(12.)).text_color(t.muted).truncate().child(subtitle(item))),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .child(hint)
                            .child(div().flex_1())
                            .when_some(copy_value, |d, value| {
                                d.child(
                                    icon_btn(format!("pin-copy-{id}"), "content_copy", t).on_click(cx.listener(
                                        move |this, _, _, cx| {
                                            cx.stop_propagation();
                                            this.copy(copy_label, &value, cx);
                                        },
                                    )),
                                )
                            }),
                    ),
            );
        }
        let _ = Kind::Login;
        let _ = (Utc::now(), Local.timestamp_opt(0, 0), Local::now().year());
        tile(t)
            .child(
                div()
                    .flex()
                    .items_center()
                    .mb(px(14.))
                    .child(mono("06 / Pinned", t.muted))
                    .child(div().flex_1())
                    .child(
                        pill("ov-all-favs", "All favourites", false, t)
                            .h(px(32.))
                            .px(px(13.))
                            .on_click(cx.listener(|this, _, _, cx| this.open_list(ListKind::Favorites, false, cx))),
                    ),
            )
            .child(row)
    }
}

use chrono::Timelike;

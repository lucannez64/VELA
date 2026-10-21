//! Password generator overlay. Uses the core's `generate_password`, so the
//! output and the entropy figure are exactly what the classic generator
//! produces; only the presentation is new.

use gpui::{div, prelude::*, px, AnimationExt, Context, FontWeight, IntoElement, MouseButton, Window};
use vela_desktop_core::commands::vault::{generate_password, log_password_generated};
use vela_desktop_core::vault::PasswordGeneratorOptions;

use super::dot_matrix::{dot_text, DotStyle};
use super::shell::{icon_btn, pill, InstrumentShell};
use super::{alpha, anim_id, ease_out, mono, ms, Tok};
use crate::fonts;
use super::icons::icon;

pub struct GenState {
    pub options: PasswordGeneratorOptions,
    pub password: String,
    pub bits: u32,
    /// Bumped on every regeneration so the readout re-animates.
    pub gen: u64,
}

const PRESETS: [usize; 5] = [12, 16, 20, 24, 32];

impl InstrumentShell {
    pub(super) fn open_generator(&mut self, cx: &mut Context<Self>) {
        let mut state = GenState {
            options: PasswordGeneratorOptions::default(),
            password: String::new(),
            bits: 0,
            gen: 0,
        };
        regenerate(&mut state);
        self.theme_menu = false;
        self.generator = Some(state);
        cx.notify();
    }

    fn update_generator(&mut self, cx: &mut Context<Self>, f: impl FnOnce(&mut GenState)) {
        if let Some(g) = &mut self.generator {
            f(g);
            regenerate(g);
            cx.notify();
        }
    }

    pub(super) fn render_generator(&mut self, window: &mut Window, t: &Tok, cx: &mut Context<Self>) -> impl IntoElement {
        let g = self.generator.as_ref().expect("generator open");
        let bits = g.bits;
        let gen = g.gen;
        let len = g.options.length;
        let opts = (g.options.uppercase, g.options.lowercase, g.options.numbers, g.options.symbols, g.options.easy_to_type);
        let tk = *t;
        let (label, color) = match bits {
            b if b < 50 => ("Weak", t.risk),
            b if b < 75 => ("Fair", t.warn),
            b if b < 100 => ("Strong", t.signal),
            _ => ("Very strong", t.signal),
        };
        let lit = ((bits as f32 / 128.) * 24.).round().min(24.) as usize;

        let chars = g.password.chars().map(|c| {
            let col = if c.is_ascii_digit() {
                tk.signal
            } else if c.is_ascii_alphanumeric() {
                tk.text
            } else {
                tk.violet
            };
            div().text_color(col).child(c.to_string())
        });

        let toggle = |id: &'static str, text: &'static str, on: bool, t: &Tok| {
            let (bg, fg, border) = if on { (t.signal, t.on_signal, alpha(t.signal, 0.)) } else { (alpha(t.panel, 0.), t.muted, t.line2) };
            div()
                .id(id)
                .debug_selector(move || id.to_string())
                .h(px(34.))
                .px(px(14.))
                .rounded_full()
                .flex()
                .items_center()
                .bg(bg)
                .text_color(fg)
                .border_1()
                .border_color(border)
                .text_size(px(12.5))
                .font_weight(FontWeight::MEDIUM)
                .cursor_pointer()
                .child(text)
        };

        let panel = div()
            .id("generator")
            .debug_selector(|| "generator".into())
            .occlude()
            .w(px(560.))
            .max_w(px(f32::from(window.viewport_size().width) - 24.))
            .p(px(22.))
            .rounded(px(26.))
            .bg(t.panel)
            .border_1()
            .border_color(t.line2)
            .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
            .child(
                div()
                    .flex()
                    .items_center()
                    .child(mono("Generator", t.muted))
                    .child(div().flex_1())
                    .child(icon_btn("gen-close", "close", t).on_click(cx.listener(|this, _, _, cx| {
                        this.generator = None;
                        cx.notify();
                    }))),
            )
            .child(
                div()
                    .my(px(16.))
                    .p(px(20.))
                    .min_h(px(96.))
                    .rounded(px(18.))
                    .bg(t.panel2)
                    .border_1()
                    .border_color(t.line)
                    .flex()
                    .flex_wrap()
                    .font_family(fonts::MONO)
                    .text_size(px(22.))
                    .line_height(px(31.))
                    .children(chars)
                    .with_animation(anim_id("gen-out", gen), gpui::Animation::new(ms(260)).with_easing(ease_out), |el, d| el.opacity(0.25 + 0.75 * d)),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(16.))
                    .mb(px(18.))
                    .child(
                        div()
                            .flex()
                            .items_end()
                            .gap(px(8.))
                            .child(div().with_animation(anim_id("gen-bits", gen), gpui::Animation::new(ms(500)).with_easing(ease_out), move |el, d| {
                                el.child(dot_text(((bits as f32) * d).round().to_string(), DotStyle::new(5., tk.text).gradient(tk.grad)))
                            }))
                            .child(mono("bits", t.muted)),
                    )
                    .child(div().flex_1().with_animation(anim_id("gen-dots", gen), gpui::Animation::new(ms(600)).with_easing(ease_out), move |el, d| {
                        let shown = ((lit as f32) * d).round() as usize;
                        el.flex().flex_wrap().gap(px(4.)).children((0..24).map(move |k| div().size(px(8.)).rounded_full().bg(if k < shown { color } else { tk.panel3 })))
                    }))
                    .child(mono(label, t.muted)),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .mb(px(12.))
                    .child(mono("Length", t.muted))
                    .child(icon_btn("gen-shorter", "remove", t).on_click(cx.listener(|this, _, _, cx| this.update_generator(cx, |g| g.options.length = g.options.length.saturating_sub(1).max(8)))))
                    .child(div().w(px(34.)).flex().justify_center().font_family(fonts::MONO).child(len.to_string()))
                    .child(icon_btn("gen-longer", "add", t).on_click(cx.listener(|this, _, _, cx| this.update_generator(cx, |g| g.options.length = (g.options.length + 1).min(64)))))
                    .child(div().flex_1())
                    .children(PRESETS.iter().map(|&n| {
                        let active = n == len;
                        div()
                            .id(gpui::ElementId::NamedInteger("gen-preset".into(), n as u64))
                            .px(px(9.))
                            .py(px(4.))
                            .rounded(px(8.))
                            .cursor_pointer()
                            .font_family(fonts::MONO)
                            .text_size(px(12.))
                            .text_color(if active { t.text } else { t.muted })
                            .when(active, |d| d.bg(t.panel3))
                            .child(n.to_string())
                            .on_click(cx.listener(move |this, _, _, cx| this.update_generator(cx, |g| g.options.length = n)))
                    })),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap(px(6.))
                    .mb(px(20.))
                    .child(toggle("gen-upper", "A–Z", opts.0, t).on_click(cx.listener(|this, _, _, cx| this.update_generator(cx, |g| g.options.uppercase = !g.options.uppercase || !(g.options.lowercase || g.options.numbers || g.options.symbols)))))
                    .child(toggle("gen-lower", "a–z", opts.1, t).on_click(cx.listener(|this, _, _, cx| this.update_generator(cx, |g| g.options.lowercase = !g.options.lowercase || !(g.options.uppercase || g.options.numbers || g.options.symbols)))))
                    .child(toggle("gen-digits", "0–9", opts.2, t).on_click(cx.listener(|this, _, _, cx| this.update_generator(cx, |g| g.options.numbers = !g.options.numbers || !(g.options.uppercase || g.options.lowercase || g.options.symbols)))))
                    .child(toggle("gen-symbols", "!@#", opts.3, t).on_click(cx.listener(|this, _, _, cx| this.update_generator(cx, |g| g.options.symbols = !g.options.symbols || !(g.options.uppercase || g.options.lowercase || g.options.numbers)))))
                    .child(toggle("gen-easy", "Easy to type", opts.4, t).on_click(cx.listener(|this, _, _, cx| this.update_generator(cx, |g| g.options.easy_to_type = !g.options.easy_to_type)))),
            )
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap(px(8.))
                    .child(
                        pill("gen-again", "Regenerate", false, t)
                            .child(icon("refresh", px(16.), t.text))
                            .on_click(cx.listener(|this, _, _, cx| this.update_generator(cx, |_| {}))),
                    )
                    .child(
                        pill("gen-copy", "Copy password", true, t)
                            .child(icon("content_copy", px(15.), t.primary_fg))
                            .on_click(cx.listener(|this, _, _, cx| {
                                if let Some(g) = &this.generator {
                                    let pw = g.password.clone();
                                    log_password_generated(&this.app_state, pw.chars().count());
                                    this.copy("Password", &pw, cx);
                                }
                            })),
                    ),
            )
            .with_animation(anim_id("gen-panel", 1), gpui::Animation::new(ms(220)).with_easing(ease_out), |el, d| {
                el.opacity(d).mt(px(18. * (1. - d)))
            });

        div()
            .id("generator-backdrop")
            .absolute()
            .inset_0()
            .occlude()
            .bg(gpui::black().opacity(0.5))
            .flex()
            .items_center()
            .justify_center()
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, _, cx| {
                    this.generator = None;
                    cx.notify();
                }),
            )
            .child(panel)
    }
}

fn regenerate(g: &mut GenState) {
    match generate_password(PasswordGeneratorOptions { ..g.options.clone() }) {
        Ok(p) => {
            g.bits = p.strength.entropy.round() as u32;
            g.password = p.password;
        }
        Err(e) => {
            tracing::warn!("Password generation failed: {e}");
            g.password.clear();
            g.bits = 0;
        }
    }
    g.gen += 1;
}

//! The editor generator uses the same controls and readout as the preview generator.
use super::*;
use crate::instrument::{alpha, anim_id, dot_matrix::{dot_text, DotStyle}, ease_out, mono, ms, tokens};
use crate::instrument::shell::{icon_btn, pill};
use gpui::AnimationExt;

impl PasswordGenerator {
    pub(super) fn render_instrument(&self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let t = tokens(cx);
        let bits = self.bits;
        let lit = ((bits as f32 / 128.) * 24.).round().min(24.) as usize;
        let (label, color) = match bits {
            0..50 => ("Weak", t.risk), 50..75 => ("Fair", t.warn),
            75..100 => ("Strong", t.signal), _ => ("Very strong", t.signal),
        };
        div().id("editor-generator").debug_selector(|| "editor-generator".into())
            .w_full().min_w_0().p(px(16.)).rounded(px(22.)).bg(t.panel)
            .border_1().border_color(t.line2).font_family(fonts::BODY).text_color(t.text)
            .child(div().flex().items_center().child(mono("Generator", t.muted)).child(div().flex_1())
                .child(icon_btn("editor-gen-close", "close", &t)
                    .on_click(cx.listener(|_, _, _, cx| cx.emit(PasswordGeneratorEvent::Close)))))
            .child(div().my(px(16.)).p(px(16.)).min_h(px(76.)).rounded(px(18.))
                .bg(t.panel2).border_1().border_color(t.line).flex().flex_wrap()
                .font_family(fonts::MONO).text_size(px(20.)).line_height(px(28.))
                .children(self.password.chars().map(|c| div().text_color(if c.is_ascii_digit() {
                    t.signal
                } else if c.is_ascii_alphanumeric() { t.text } else { t.violet }).child(c.to_string())))
                .with_animation(anim_id("editor-gen-out", self.generation), gpui::Animation::new(ms(260)).with_easing(ease_out), |el, d| el.opacity(0.25 + 0.75 * d)))
            .child(div().flex().flex_wrap().items_center().gap(px(12.)).mb(px(18.))
                .child(div().flex().items_end().gap(px(6.))
                    .child(dot_text(bits.to_string(), DotStyle::new(4., t.text).gradient(t.grad)))
                    .child(mono("bits", t.muted)))
                .child(div().flex_1().min_w(px(80.)).flex().flex_wrap().gap(px(3.))
                    .children((0..24).map(|k| div().size(px(6.)).rounded_full().bg(if k < lit {color} else {t.panel3}))))
                .child(mono(label, t.muted)))
            .child(div().flex().flex_wrap().items_center().gap(px(8.)).mb(px(12.))
                .child(mono("Length", t.muted))
                .child(icon_btn("editor-gen-shorter", "remove", &t).on_click(cx.listener(|this, _, _, cx| {
                    this.options.length = this.options.length.saturating_sub(1).max(8); this.regenerate(cx);
                })))
                .child(div().font_family(fonts::MONO).w(px(24.)).text_center().child(self.options.length.to_string()))
                .child(icon_btn("editor-gen-longer", "add", &t).on_click(cx.listener(|this, _, _, cx| {
                    this.options.length = (this.options.length + 1).min(64); this.regenerate(cx);
                })))
                .children([12,16,20,24,32].into_iter().map(|n| {
                    let active = n == self.options.length;
                    div().id(gpui::ElementId::NamedInteger("editor-gen-preset".into(), n as u64))
                        .debug_selector(move || format!("editor-gen-preset-{n}"))
                        .px(px(7.)).py(px(4.)).rounded(px(8.)).cursor_pointer().font_family(fonts::MONO).text_size(px(12.))
                        .text_color(if active {t.text} else {t.muted}).when(active, |el| el.bg(t.panel3))
                        .hover(|el| el.bg(t.panel3).text_color(t.text)).child(n.to_string())
                        .on_click(cx.listener(move |this, _, _, cx| { this.options.length = n; this.regenerate(cx); }))
                })))
            .child(div().flex().flex_wrap().gap(px(6.)).mb(px(18.)).children([
                ("editor-gen-upper", "A–Z", self.options.uppercase, 0),
                ("editor-gen-lower", "a–z", self.options.lowercase, 1),
                ("editor-gen-digits", "0–9", self.options.numbers, 2),
                ("editor-gen-symbols", "!@#", self.options.symbols, 3),
                ("editor-gen-easy", "Easy to type", self.options.easy_to_type, 4),
            ].into_iter().map(|(id, label, on, index)| {
                div().id(id).debug_selector(move || id.into()).h(px(34.)).px(px(12.)).rounded_full()
                    .flex().items_center().border_1().border_color(if on {alpha(t.signal,0.)} else {t.line2})
                    .bg(if on {t.signal} else {alpha(t.panel,0.)}).text_color(if on {t.on_signal} else {t.muted})
                    .text_size(px(12.5)).cursor_pointer().hover(|el| el.border_color(t.signal)).child(label)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        let o = &mut this.options;
                        match index {
                            0 => o.uppercase = !o.uppercase || !(o.lowercase || o.numbers || o.symbols),
                            1 => o.lowercase = !o.lowercase || !(o.uppercase || o.numbers || o.symbols),
                            2 => o.numbers = !o.numbers || !(o.uppercase || o.lowercase || o.symbols),
                            3 => o.symbols = !o.symbols || !(o.uppercase || o.lowercase || o.numbers),
                            _ => o.easy_to_type = !o.easy_to_type,
                        }
                        this.regenerate(cx);
                    }))
            })))
            .child(div().flex().flex_wrap().justify_end().gap(px(8.))
                .child(pill("editor-gen-again", "Regenerate", false, &t)
                    .on_click(cx.listener(|this, _, _, cx| this.regenerate(cx))))
                .child(pill("editor-gen-use", "Use this password", true, &t)
                    .on_click(cx.listener(|this, _, _, cx| cx.emit(PasswordGeneratorEvent::Use(this.password.to_string()))))))
            .into_any_element()
    }
}

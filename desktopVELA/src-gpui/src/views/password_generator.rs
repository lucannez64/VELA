//! Port of `desktopVELA/src/components/PasswordGenerator.tsx` — a popover
//! that calls the real (pure, no-`AppState`) `vela_desktop_core::commands::
//! vault::generate_password` on mount and on every option change.
//!
//! Simplification: the original's drag-slider for length (8-64) becomes
//! +/- stepper buttons — gpui/gpui_elements has no slider widget, and a
//! stepper is a reasonable substitute (no functional loss, matches the
//! plan's "don't chase pixel parity" guidance). Checkboxes are likewise
//! clickable toggle rows — gpui has no native checkbox element either.

use gpui::{div, prelude::*, px, Context, EventEmitter, IntoElement, MouseButton, Render, SharedString, Window};

use vela_desktop_core::commands::vault::generate_password;
use vela_desktop_core::vault::PasswordGeneratorOptions;

use crate::animation;
use crate::fonts;
use crate::icon::icon;
use crate::theme::Palette;

pub enum PasswordGeneratorEvent {
    Use(String),
    Close,
}
impl EventEmitter<PasswordGeneratorEvent> for PasswordGenerator {}

pub struct PasswordGenerator {
    options: PasswordGeneratorOptions,
    password: SharedString,
}

impl PasswordGenerator {
    pub fn new(cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        let mut this = Self {
            options: PasswordGeneratorOptions::default(),
            password: "".into(),
        };
        this.regenerate(cx);
        this
    }

    fn regenerate(&mut self, cx: &mut Context<Self>) {
        match generate_password(self.options.clone()) {
            Ok(result) => self.password = result.password.into(),
            Err(e) => tracing::warn!("Failed to generate password: {e}"),
        }
        cx.notify();
    }
}

impl Render for PasswordGenerator {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = crate::theme::current_palette(cx);
        let length = self.options.length;

        div()
            .w(px(360.))
            .p_4()
            .rounded_xl()
            .bg(palette.surface_container)
            .font_family(fonts::LABEL)
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .text_xs()
                            .text_color(palette.on_surface_variant)
                            .child("GENERATED"),
                    )
                    .child({
                        let hover_t = animation::hover_transition("close-generator", window, cx);
                        let t = *hover_t.evaluate(window, cx);
                        let bg = animation::lerp_hsla(gpui::transparent_black(), palette.surface_container_high, t);
                        div()
                            .id("close-generator")
                            .p_1()
                            .rounded(px(4.))
                            .bg(bg)
                            .cursor_pointer()
                            .child(icon("close", px(16.), palette.on_surface_variant))
                            .on_hover(move |is_hovered, _, cx| {
                                hover_t.update(cx, |v, cx| {
                                    *v = *is_hovered as u8 as f32;
                                    cx.notify();
                                });
                            })
                            .on_mouse_down(MouseButton::Left, cx.listener(|_this, _, _, cx| {
                                cx.emit(PasswordGeneratorEvent::Close);
                            }))
                    }),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .flex_1()
                            .p_3()
                            .rounded_lg()
                            .bg(palette.surface_container_highest)
                            .text_color(palette.primary)
                            .font_family(fonts::MONO)
                            .child(self.password.clone()),
                    )
                    .child({
                        let hover_t = animation::hover_transition("regenerate", window, cx);
                        let t = *hover_t.evaluate(window, cx);
                        let bg = animation::lerp_hsla(palette.surface_container_highest, palette.surface_container_high, t);
                        let icon_color = animation::lerp_hsla(palette.on_surface_variant, palette.primary, t);
                        div()
                            .id("regenerate")
                            .px_3()
                            .py_2()
                            .rounded_lg()
                            .bg(bg)
                            .cursor_pointer()
                            .child(icon("refresh", px(18.), icon_color))
                            .on_hover(move |is_hovered, _, cx| {
                                hover_t.update(cx, |v, cx| {
                                    *v = *is_hovered as u8 as f32;
                                    cx.notify();
                                });
                            })
                            .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                this.regenerate(cx);
                            }))
                    }),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(palette.on_surface_variant)
                                    .child("LENGTH"),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(stepper_button(&palette, "len-minus", "−", cx, |this, cx| {
                                        this.options.length = this.options.length.saturating_sub(1).max(8);
                                        this.regenerate(cx);
                                    }))
                                    .child(
                                        div()
                                            .font_family(fonts::MONO)
                                            .text_color(palette.primary)
                                            .child(length.to_string()),
                                    )
                                    .child(stepper_button(&palette, "len-plus", "+", cx, |this, cx| {
                                        this.options.length = (this.options.length + 1).min(64);
                                        this.regenerate(cx);
                                    })),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(toggle_row(&palette, "Uppercase (A-Z)", self.options.uppercase, cx, |this, cx| {
                        this.options.uppercase = !this.options.uppercase;
                        this.regenerate(cx);
                    }))
                    .child(toggle_row(&palette, "Lowercase (a-z)", self.options.lowercase, cx, |this, cx| {
                        this.options.lowercase = !this.options.lowercase;
                        this.regenerate(cx);
                    }))
                    .child(toggle_row(&palette, "Numbers (0-9)", self.options.numbers, cx, |this, cx| {
                        this.options.numbers = !this.options.numbers;
                        this.regenerate(cx);
                    }))
                    .child(toggle_row(&palette, "Symbols (!@#$...)", self.options.symbols, cx, |this, cx| {
                        this.options.symbols = !this.options.symbols;
                        this.regenerate(cx);
                    })),
            )
            .child({
                let password = self.password.to_string();
                let hover_t = animation::hover_transition("use-password", window, cx);
                let t = *hover_t.evaluate(window, cx);
                let bg = animation::lerp_hsla(palette.primary, gpui::Hsla { a: 0.9, ..palette.primary }, t);
                div()
                    .id("use-password")
                    .py_3()
                    .rounded_xl()
                    .bg(bg)
                    .text_color(palette.on_primary)
                    .font_family(fonts::HEADLINE)
                    .font_weight(gpui::FontWeight::BOLD)
                    .flex()
                    .items_center()
                    .justify_center()
                    .cursor_pointer()
                    .child("Use this password")
                    .on_hover(move |is_hovered, _, cx| {
                        hover_t.update(cx, |v, cx| {
                            *v = *is_hovered as u8 as f32;
                            cx.notify();
                        });
                    })
                    .on_mouse_down(MouseButton::Left, cx.listener(move |_this, _, _, cx| {
                        cx.emit(PasswordGeneratorEvent::Use(password.clone()));
                    }))
            })
    }
}

fn stepper_button(
    palette: &Palette,
    id: &'static str,
    glyph: &'static str,
    cx: &mut Context<PasswordGenerator>,
    on_click: impl Fn(&mut PasswordGenerator, &mut Context<PasswordGenerator>) + 'static,
) -> impl IntoElement {
    div()
        .id(id)
        .w(px(24.))
        .h(px(24.))
        .rounded_md()
        .bg(palette.surface_container_highest)
        .flex()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .child(glyph)
        .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| on_click(this, cx)))
}

fn toggle_row(
    palette: &Palette,
    label: &'static str,
    checked: bool,
    cx: &mut Context<PasswordGenerator>,
    on_click: impl Fn(&mut PasswordGenerator, &mut Context<PasswordGenerator>) + 'static,
) -> impl IntoElement {
    let box_bg = if checked { palette.primary } else { palette.surface_container_highest };
    div()
        .id(SharedString::from(format!("toggle-{label}")))
        .flex()
        .items_center()
        .gap_3()
        .cursor_pointer()
        .child(
            div()
                .w(px(16.))
                .h(px(16.))
                .rounded_md()
                .bg(box_bg)
                .flex()
                .items_center()
                .justify_center()
                .when(checked, |el| el.child(icon("check", px(12.), palette.on_primary))),
        )
        .child(
            div()
                .font_family(fonts::BODY)
                .text_sm()
                .text_color(palette.on_surface)
                .child(label),
        )
        .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| on_click(this, cx)))
}

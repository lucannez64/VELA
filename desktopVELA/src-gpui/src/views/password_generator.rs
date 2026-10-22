//! Port of `desktopVELA/src/components/PasswordGenerator.tsx` — a popover
//! that calls the real (pure, no-`AppState`) `vela_desktop_core::commands::
//! vault::generate_password` on mount and on every option change.
//!
//! Simplification: the original's drag-slider for length (8-64) becomes
//! +/- stepper buttons — gpui/gpui_elements has no slider widget, and a
//! stepper is a reasonable substitute (no functional loss, matches the
//! plan's "don't chase pixel parity" guidance). Checkboxes are likewise
//! clickable toggle rows — gpui has no native checkbox element either.

#[path = "password_generator_instrument.rs"]
mod instrument_view;

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
    bits: u32,
    generation: u64,
}

impl PasswordGenerator {
    pub fn new(cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        let mut this = Self {
            options: PasswordGeneratorOptions::default(),
            password: "".into(),
            bits: 0,
            generation: 0,
        };
        this.regenerate(cx);
        this
    }

    fn regenerate(&mut self, cx: &mut Context<Self>) {
        match generate_password(self.options.clone()) {
            Ok(result) => {
                self.password = result.password.into();
                self.bits = result.strength.entropy.round() as u32;
                self.generation += 1;
            },
            Err(e) => tracing::warn!("Failed to generate password: {e}"),
        }
        cx.notify();
    }
}

impl Render for PasswordGenerator {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if crate::instrument::is_instrument(cx) { return self.render_instrument(cx); }
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
            }).into_any_element()
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

#[cfg(test)]
mod instrument_tests {
    use super::*;
    use crate::modal_test_support as ui;
    use gpui::{Entity, size, Modifiers, TestAppContext};
    use std::{cell::RefCell, rc::Rc};
    struct Host { generator: Entity<PasswordGenerator>, _subscription: gpui::Subscription }
    impl Render for Host {
        fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
            div().max_w(px(580.)).child(self.generator.clone())
        }
    }
    #[gpui::test]
    fn editor_generator_presets_options_and_use_work_at_narrow_width(cx: &mut TestAppContext) {
        let used = Rc::new(RefCell::new(None));
        let (host, cx) = cx.add_window_view(|_, cx| {
            ui::fonts(cx);
            cx.set_global(crate::instrument::ActiveInterface(crate::instrument::InterfaceMode::Instrument));
            cx.set_global(crate::theme::ActiveTheme(crate::theme::ThemeId::Macchiato));
            let generator = cx.new(PasswordGenerator::new);
            let used = used.clone();
            let subscription = cx.subscribe(&generator, move |_: &mut Host, _, event, _| {
                if let PasswordGeneratorEvent::Use(password) = event { *used.borrow_mut() = Some(password.clone()); }
            });
            Host { generator, _subscription: subscription }
        });
        for width in [580., 320.] {
            cx.simulate_resize(size(px(width), px(760.)));
            cx.run_until_parked();
            for id in ["editor-gen-close", "editor-gen-use", "editor-gen-again", "editor-gen-easy"] {
                let b = ui::bounds(cx, id);
                assert!(b.left() >= px(0.) && b.right() <= px(width) && b.bottom() <= px(760.), "{id} overflows: {b:?}");
            }
        }
        for id in ["editor-gen-preset-32", "editor-gen-upper", "editor-gen-lower", "editor-gen-digits", "editor-gen-symbols", "editor-gen-easy"] {
            let b = ui::bounds(cx, id);
            cx.simulate_mouse_move(b.center(), None, Modifiers::default());
            cx.simulate_click(b.center(), Modifiers::default());
            cx.run_until_parked();
        }
        let generator = host.read_with(cx, |h, _| h.generator.clone());
        let expected = generator.read_with(cx, |g, _| {
            assert_eq!(g.options.length, 32);
            assert!(g.options.uppercase || g.options.lowercase || g.options.numbers || g.options.symbols);
            assert_eq!(g.password.len(), 32);
            g.password.to_string()
        });
        let b = ui::bounds(cx, "editor-gen-use");
        cx.simulate_mouse_move(b.center(), None, Modifiers::default());
        cx.simulate_click(b.center(), Modifiers::default());
        cx.run_until_parked();
        assert_eq!(used.borrow().as_deref(), Some(expected.as_str()));
    }
}

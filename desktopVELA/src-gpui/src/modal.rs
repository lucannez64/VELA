//! Shared modal chrome. Only the middle region scrolls; controls keep their
//! hitboxes and position even when the hosting view is shorter than the window.
use crate::{fonts, icon::icon, theme::Palette};
use gpui::{div, prelude::*, px, Div, IntoElement, MouseButton, SharedString, Stateful};

pub fn backdrop(id: &'static str) -> Stateful<Div> {
    div()
        .id(id)
        .debug_selector(move || id.to_owned())
        .absolute()
        .inset_0()
        .occlude()
        .bg(gpui::black().opacity(0.6))
        .flex()
        .items_center()
        .justify_center()
        .p_3()
}

/// Present above the whole app body, including navigation and reminder banners.
/// A dialog must not inherit the clipping rectangle of the screen that opened it.
pub fn present(window: &gpui::Window, backdrop: impl IntoElement) -> gpui::Deferred {
    let viewport = window.viewport_size();
    gpui::deferred(
        gpui::anchored()
            .position(gpui::point(px(0.), px(56.)))
            .snap_to_window()
            .child(
                div()
                    .relative()
                    .w(viewport.width)
                    .h((viewport.height - px(56.)).max(px(0.)))
                    .child(backdrop),
            ),
    )
    .with_priority(100)
}

pub fn close_button(id: &'static str, palette: &Palette) -> Stateful<Div> {
    div()
        .id(id)
        .debug_selector(move || id.to_owned())
        .size(px(40.))
        .flex_shrink_0()
        .flex()
        .items_center()
        .justify_center()
        .rounded_lg()
        .text_color(palette.on_surface_variant)
        .cursor_pointer()
        .occlude()
        .child(icon("close", px(20.), palette.on_surface_variant))
}

pub fn header(title: impl Into<SharedString>, close: impl IntoElement, palette: &Palette) -> Div {
    div()
        .flex()
        .items_center()
        .gap_3()
        .px_4()
        .py_2()
        .child(
            div()
                .flex_1()
                .min_w_0()
                .font_family(fonts::HEADLINE)
                .font_weight(gpui::FontWeight::BOLD)
                .text_xl()
                .text_color(palette.on_surface)
                .child(title.into()),
        )
        .child(close)
}

pub fn scroll_body(id: &'static str, content: impl IntoElement) -> Stateful<Div> {
    div()
        .id(id)
        .debug_selector(move || id.to_owned())
        .size_full()
        .min_h_0()
        .min_w_0()
        .overflow_hidden()
        .overflow_y_scroll()
        .occlude()
        .px_4()
        .py_3()
        .child(div().w_full().min_w_0().child(content))
}

pub fn frame(
    id: &'static str,
    width: f32,
    height: f32,
    header: impl IntoElement,
    body: impl IntoElement,
    footer: impl IntoElement,
    palette: &Palette,
) -> Stateful<Div> {
    div()
        .id(id)
        .debug_selector(move || id.to_owned())
        .w_full()
        .max_w(px(width))
        .h_full()
        .max_h(px(height))
        .min_h_0()
        .min_w_0()
        .flex()
        .flex_col()
        .overflow_hidden()
        .rounded_2xl()
        .bg(palette.surface_container)
        .border_1()
        .border_color(gpui::Hsla {
            a: 0.2,
            ..palette.outline_variant
        })
        .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
        .child(
            div()
                .flex_shrink_0()
                .border_b_1()
                .border_color(gpui::Hsla {
                    a: 0.12,
                    ..palette.outline_variant
                })
                .child(header),
        )
        .child(
            div()
                .flex_1()
                .min_h_0()
                .min_w_0()
                .overflow_hidden()
                .child(body),
        )
        .child(
            div()
                .debug_selector(move || format!("{id}-footer"))
                .flex_shrink_0()
                .px_4()
                .py_3()
                .border_t_1()
                .border_color(gpui::Hsla {
                    a: 0.12,
                    ..palette.outline_variant
                })
                .child(footer),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui::{
        point, size, Bounds, Context, Modifiers, Pixels, Render, ScrollDelta, ScrollWheelEvent,
        TestAppContext, Window,
    };
    use std::{cell::Cell, rc::Rc};

    struct Harness {
        close_bounds: Rc<Cell<Bounds<Pixels>>>,
        footer_bounds: Rc<Cell<Bounds<Pixels>>>,
        first_row: Rc<Cell<Bounds<Pixels>>>,
        closes: Rc<Cell<usize>>,
    }
    impl Render for Harness {
        fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
            let palette = crate::theme::ThemeId::Vela.palette();
            let close_bounds = self.close_bounds.clone();
            let footer_bounds = self.footer_bounds.clone();
            let first_row = self.first_row.clone();
            let header = header(
                "Modal",
                close_button("test-close", &palette).on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _, _, _| this.closes.set(this.closes.get() + 1)),
                ),
                &palette,
            )
            .on_children_prepainted(move |bounds, _, _| close_bounds.set(*bounds.last().unwrap()));
            let content = div()
                .flex()
                .flex_col()
                .gap_3()
                .children((0..30).map(|_| div().h(px(64.)).flex_shrink_0().w_full()))
                .on_children_prepainted(move |bounds, _, _| first_row.set(bounds[0]));
            let footer = div()
                .child(div().h(px(44.)))
                .on_children_prepainted(move |bounds, _, _| footer_bounds.set(bounds[0]));
            div()
                .relative()
                .size_full()
                .child(backdrop("test-backdrop").child(frame(
                    "test-frame",
                    560.,
                    640.,
                    header,
                    scroll_body("test-body", content),
                    footer,
                    &palette,
                )))
        }
    }

    #[gpui::test]
    fn controls_stay_visible_and_clickable_after_scrolling(cx: &mut TestAppContext) {
        let cx = cx.add_empty_window();
        for (width, height) in [(945., 382.), (360., 260.), (945., 899.)] {
            let close = Rc::new(Cell::new(Bounds::default()));
            let footer = Rc::new(Cell::new(Bounds::default()));
            let first = Rc::new(Cell::new(Bounds::default()));
            let closes = Rc::new(Cell::new(0));
            let view = cx.update(|_, cx| {
                for (_, bytes) in crate::fonts::FONT_FILES {
                    cx.text_system()
                        .add_fonts(vec![std::borrow::Cow::Borrowed(*bytes)])
                        .unwrap();
                }
                cx.new(|_| Harness {
                    close_bounds: close.clone(),
                    footer_bounds: footer.clone(),
                    first_row: first.clone(),
                    closes: closes.clone(),
                })
            });
            let viewport = size(px(width), px(height));
            cx.draw(point(px(0.), px(0.)), viewport, |_, _| {
                view.clone().into_any_element()
            });
            let close_before = close.get();
            let footer_before = footer.get();
            assert!(close_before.top() >= px(0.) && close_before.bottom() <= px(height));
            assert!(
                footer_before.bottom() <= px(height),
                "footer outside {width}×{height}: {footer_before:?}"
            );
            let first_top = first.get().top();
            cx.simulate_event(ScrollWheelEvent {
                position: point(px(width / 2.), px(height / 2.)),
                delta: ScrollDelta::Pixels(point(px(0.), px(-1200.))),
                ..Default::default()
            });
            cx.draw(point(px(0.), px(0.)), viewport, |_, _| {
                view.clone().into_any_element()
            });
            assert!(first.get().top() < first_top, "body did not scroll");
            assert_eq!(
                close.get(),
                close_before,
                "close button moved during scroll"
            );
            assert_eq!(footer.get(), footer_before, "footer moved during scroll");
            cx.simulate_click(close.get().center(), Modifiers::default());
            assert_eq!(closes.get(), 1, "close button is covered after scrolling");
        }
    }
}

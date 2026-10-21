//! Shared page hierarchy for the Instrument screens.
use super::{
    dot_matrix::{dot_text, DotStyle},
    mono, Tok,
};
use crate::fonts;
use gpui::{div, prelude::*, px, Div};

pub fn heading(section: &str, title: &str, description: &str, t: &Tok) -> Div {
    div()
        .flex()
        .flex_col()
        .gap(px(9.))
        .min_w_0()
        .flex_shrink_0()
        .child(mono(section.to_string(), t.muted))
        .child(
            div()
                .font_family(fonts::HEADLINE)
                .text_size(px(42.))
                .text_color(t.text)
                .child(title.to_string()),
        )
        .child(
            div()
                .text_size(px(13.))
                .line_height(px(20.))
                .text_color(t.muted)
                .child(description.to_string()),
        )
}

pub fn metric(label: &str, value: usize, t: &Tok) -> Div {
    super::tile(t)
        .flex_1()
        .min_w_0()
        .flex()
        .flex_col()
        .gap(px(12.))
        .child(mono(label.to_string(), t.muted))
        .child(dot_text(
            value.to_string(),
            DotStyle::new(4., t.text).off(super::alpha(t.text, 0.06)),
        ))
}

/// Subtle structural grid used behind the reference's page cards.
pub fn grid(t: Tok) -> impl gpui::IntoElement {
    gpui::canvas(
        |_, _, _| (),
        move |bounds, (), window, _| {
            let step = 52.;
            let color = super::alpha(t.text, 0.018);
            let width = f32::from(bounds.size.width);
            let height = f32::from(bounds.size.height);
            let x = f32::from(bounds.origin.x);
            let y = f32::from(bounds.origin.y);
            for i in 0..=(width / step) as usize {
                window.paint_quad(gpui::fill(
                    gpui::Bounds::new(
                        gpui::point(px(x + i as f32 * step), px(y)),
                        gpui::size(px(1.), px(height)),
                    ),
                    color,
                ));
            }
            for i in 0..=(height / step) as usize {
                window.paint_quad(gpui::fill(
                    gpui::Bounds::new(
                        gpui::point(px(x), px(y + i as f32 * step)),
                        gpui::size(px(width), px(1.)),
                    ),
                    color,
                ));
            }
        },
    )
    .absolute()
    .inset_0()
    .size_full()
}

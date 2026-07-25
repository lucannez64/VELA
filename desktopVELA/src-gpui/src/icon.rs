//! Material Symbols Outlined icons. gpui's text shaper (harfrust) performs
//! real OpenType ligature substitution, so typing the icon's name (exactly
//! as the original TSX did — `<span class="material-symbols-outlined">key
//! </span>`) with `font_family(fonts::ICONS)` renders the actual glyph, not
//! literal text. Confirmed by direct visual test before adopting this
//! approach app-wide (see plan doc).

use gpui::{div, prelude::*, Div, Hsla, IntoElement, Pixels};

use crate::fonts;

/// A single Material Symbol, sized and colored like a text run so it can be
/// dropped inline (`.child(icon("key", size, color))`) same as the
/// original's `<span class="material-symbols-outlined">`.
pub fn icon(name: &'static str, size: Pixels, color: Hsla) -> Div {
    div()
        .font_family(fonts::ICONS)
        .text_size(size)
        .text_color(color)
        .line_height(size)
        .child(name)
}

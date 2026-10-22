//! A 5×7 dot-matrix display font, painted as round quads on a canvas.
//!
//! Used for the numbers that matter (item counts, health score, one-time
//! codes, generator entropy). Each lit dot is one quad, so "VELA" is ~60
//! quads — cheap enough to repaint every animation frame.

use gpui::{canvas, point, prelude::*, px, size, Bounds, Hsla, IntoElement};

use super::grad_at;

const ROWS: usize = 7;
const COLS: usize = 5;

fn glyph(c: char) -> Option<[&'static str; ROWS]> {
    Some(match c.to_ascii_uppercase() {
        '0' => [" ### ", "#   #", "#  ##", "# # #", "##  #", "#   #", " ### "],
        '1' => ["  #  ", " ##  ", "  #  ", "  #  ", "  #  ", "  #  ", " ### "],
        '2' => [" ### ", "#   #", "    #", "   # ", "  #  ", " #   ", "#####"],
        '3' => ["#####", "   # ", "  #  ", "   # ", "    #", "#   #", " ### "],
        '4' => ["   # ", "  ## ", " # # ", "#  # ", "#####", "   # ", "   # "],
        '5' => ["#####", "#    ", "#### ", "    #", "    #", "#   #", " ### "],
        '6' => ["  ## ", " #   ", "#    ", "#### ", "#   #", "#   #", " ### "],
        '7' => ["#####", "    #", "   # ", "  #  ", " #   ", " #   ", " #   "],
        '8' => [" ### ", "#   #", "#   #", " ### ", "#   #", "#   #", " ### "],
        '9' => [" ### ", "#   #", "#   #", " ####", "    #", "   # ", " ##  "],
        'A' => [" ### ", "#   #", "#   #", "#####", "#   #", "#   #", "#   #"],
        'B' => ["#### ", "#   #", "#   #", "#### ", "#   #", "#   #", "#### "],
        'C' => [" ### ", "#   #", "#    ", "#    ", "#    ", "#   #", " ### "],
        'D' => ["#### ", "#   #", "#   #", "#   #", "#   #", "#   #", "#### "],
        'E' => ["#####", "#    ", "#    ", "#### ", "#    ", "#    ", "#####"],
        'H' => ["#   #", "#   #", "#   #", "#####", "#   #", "#   #", "#   #"],
        'I' => [" ### ", "  #  ", "  #  ", "  #  ", "  #  ", "  #  ", " ### "],
        'K' => ["#   #", "#  # ", "# #  ", "##   ", "# #  ", "#  # ", "#   #"],
        'L' => ["#    ", "#    ", "#    ", "#    ", "#    ", "#    ", "#####"],
        'M' => ["#   #", "## ##", "# # #", "# # #", "#   #", "#   #", "#   #"],
        'N' => ["#   #", "##  #", "# # #", "#  ##", "#   #", "#   #", "#   #"],
        'O' => [" ### ", "#   #", "#   #", "#   #", "#   #", "#   #", " ### "],
        'R' => ["#### ", "#   #", "#   #", "#### ", "# #  ", "#  # ", "#   #"],
        'S' => [" ####", "#    ", "#    ", " ### ", "    #", "    #", "#### "],
        'T' => ["#####", "  #  ", "  #  ", "  #  ", "  #  ", "  #  ", "  #  "],
        'V' => ["#   #", "#   #", "#   #", "#   #", "#   #", " # # ", "  #  "],
        'Y' => ["#   #", "#   #", " # # ", "  #  ", "  #  ", "  #  ", "  #  "],
        '%' => ["##   ", "##  #", "   # ", "  #  ", " #   ", "#  ##", "   ##"],
        '/' => ["    #", "    #", "   # ", "  #  ", " #   ", "#    ", "#    "],
        '-' => ["     ", "     ", "     ", "#####", "     ", "     ", "     "],
        ':' => ["     ", "  #  ", "     ", "     ", "     ", "  #  ", "     "],
        ' ' => ["     "; ROWS],
        _ => return None,
    })
}

#[derive(Clone, Copy)]
pub struct DotStyle {
    /// Distance between dot centres.
    pub pitch: f32,
    pub on: Hsla,
    /// Faint "unlit LED" dots behind the text, or none.
    pub off: Option<Hsla>,
    /// Colour lit dots along the brand gradient instead of `on`.
    pub gradient: Option<[Hsla; 4]>,
    /// 0..1 — how much of the text is lit, left to right. Animating this
    /// reads as the display "scanning" the value in.
    pub reveal: f32,
}

impl DotStyle {
    pub fn new(pitch: f32, on: Hsla) -> Self {
        Self {
            pitch,
            on,
            off: None,
            gradient: None,
            reveal: 1.,
        }
    }
    pub fn off(mut self, off: Hsla) -> Self {
        self.off = Some(off);
        self
    }
    pub fn gradient(mut self, grad: [Hsla; 4]) -> Self {
        self.gradient = Some(grad);
        self
    }
}

/// Width/height the text will occupy, for layout.
pub fn measure(text: &str, pitch: f32) -> (f32, f32) {
    let n = text.chars().count().max(1);
    ((n * (COLS + 1) - 1) as f32 * pitch, ROWS as f32 * pitch)
}

pub fn dot_text(text: impl Into<String>, style: DotStyle) -> impl IntoElement {
    let text: String = text.into();
    let (w, h) = measure(&text, style.pitch);
    let chars: Vec<char> = text.chars().collect();
    canvas(
        |_, _, _| (),
        move |bounds: Bounds<gpui::Pixels>, (), window, _cx| {
            let p = style.pitch;
            let d = p * 0.72;
            let total_cols = (chars.len() * (COLS + 1)).max(1) as f32;
            let lit_cols = style.reveal.clamp(0., 1.) * total_cols;
            for (ci, ch) in chars.iter().enumerate() {
                let Some(rows) = glyph(*ch) else { continue };
                let blank = *ch == ' ';
                for (y, row) in rows.iter().enumerate() {
                    for (x, cell) in row.chars().enumerate() {
                        let col = ci * (COLS + 1) + x;
                        let on = cell == '#' && (col as f32) < lit_cols;
                        let color = if on {
                            match style.gradient {
                                Some(g) => grad_at(&g, col as f32 / total_cols),
                                None => style.on,
                            }
                        } else {
                            match style.off {
                                Some(off) if !blank => off,
                                _ => continue,
                            }
                        };
                        let origin = point(
                            bounds.origin.x + px(col as f32 * p + (p - d) / 2.),
                            bounds.origin.y + px(y as f32 * p + (p - d) / 2.),
                        );
                        window.paint_quad(
                            gpui::fill(Bounds::new(origin, size(px(d), px(d))), color)
                                .corner_radii(px(d / 2.)),
                        );
                    }
                }
            }
        },
    )
    .w(px(w))
    .h(px(h))
    .flex_shrink_0()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_digit_and_used_letter_has_a_glyph() {
        for c in "0123456789 VELAREADY%/-:".chars() {
            let g = glyph(c).unwrap_or_else(|| panic!("missing glyph {c:?}"));
            for row in g {
                assert_eq!(row.chars().count(), COLS, "{c:?}");
            }
        }
    }

    #[test]
    fn measure_matches_cell_grid() {
        assert_eq!(measure("71", 6.), (11. * 6., 42.));
        assert_eq!(measure("", 6.), (5. * 6., 42.));
    }
}

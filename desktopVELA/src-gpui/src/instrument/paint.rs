//! Canvas painters: the sunrise glow, the health gauge and the countdown ring.
//!
//! gpui-ce has linear gradients but no radial ones, so the sunrise is built
//! from translucent concentric discs. Content masks are rectangular, so a
//! rounded tile gets its corners re-cut with the colour behind it.

use std::f32::consts::PI;

use gpui::{
    canvas, point, prelude::*, px, size, Bounds, ContentMask, Hsla, IntoElement, PathBuilder,
    Pixels, Point, Window,
};

use super::{alpha, Tok};
use crate::animation::lerp_hsla;

fn p(x: f32, y: f32) -> Point<Pixels> {
    point(px(x), px(y))
}

fn disc(window: &mut Window, cx: f32, cy: f32, r: f32, color: Hsla) {
    window.paint_quad(
        gpui::fill(
            Bounds::new(p(cx - r, cy - r), size(px(r * 2.), px(r * 2.))),
            color,
        )
        .corner_radii(px(r)),
    );
}

fn ring_outline(window: &mut Window, cx: f32, cy: f32, r: f32, color: Hsla, width: f32) {
    window.paint_quad(
        gpui::outline(
            Bounds::new(p(cx - r, cy - r), size(px(r * 2.), px(r * 2.))),
            color,
            gpui::BorderStyle::Solid,
        )
        .corner_radii(px(r))
        .border_widths(px(width)),
    );
}

/// Paint `color` into the four corners outside a `radius` rounded rect, so
/// whatever was drawn under it looks clipped to the rounded shape.
pub fn cut_corners(window: &mut Window, b: Bounds<Pixels>, radius: f32, color: Hsla) {
    let (l, t) = (f32::from(b.left()), f32::from(b.top()));
    let (r, btm) = (f32::from(b.right()), f32::from(b.bottom()));
    let k = radius;
    // (corner, start-on-vertical-edge, end-on-horizontal-edge)
    let corners = [
        (p(l, t), p(l, t + k), p(l + k, t)),
        (p(r, t), p(r - k, t), p(r, t + k)),
        (p(r, btm), p(r, btm - k), p(r - k, btm)),
        (p(l, btm), p(l + k, btm), p(l, btm - k)),
    ];
    for (corner, a, z) in corners {
        let mut path = PathBuilder::fill();
        path.move_to(a);
        path.line_to(corner);
        path.line_to(z);
        path.arc_to(p(k, k), px(0.), false, false, a);
        path.close();
        if let Ok(path) = path.build() {
            window.paint_path(path, color);
        }
    }
}

/// The violet → ember sunrise. `rise` (0..1) lifts and brightens it, used
/// for the entrance animation.
pub fn sunrise(t: Tok, outer_bg: Hsla, radius: f32, rise: f32) -> impl IntoElement {
    canvas(
        |_, _, _| (),
        move |bounds, (), window, _| {
            let w = f32::from(bounds.size.width);
            let h = f32::from(bounds.size.height);
            let (ox, oy) = (f32::from(bounds.left()), f32::from(bounds.top()));
            window.with_content_mask(Some(ContentMask { bounds }), |window| {
                window.paint_quad(gpui::fill(bounds, t.hero_base));
                let cx = ox + w * 0.68;
                let cy = oy + h * (1.34 - 0.14 * rise);
                // Sized off the height so the upper part of the panel stays
                // dark ink, like the CSS original's off-canvas ellipse.
                let max_r = h * 1.18;
                let stops = [t.glow[4], t.glow[3], t.glow[2], t.glow[1], t.glow[0]];
                let layers = 36;
                for i in 0..layers {
                    let f = i as f32 / (layers - 1) as f32; // 0 outer .. 1 core
                    let r = max_r * (1. - f * 0.9);
                    let seg = (f * 4.).min(3.999);
                    let si = seg.floor() as usize;
                    let c = lerp_hsla(stops[si], stops[si + 1], seg - si as f32);
                    let a = (0.012 + 0.15 * f.powf(1.6)) * (0.3 + 0.7 * rise);
                    disc(window, cx, cy, r, alpha(c, a));
                }
                // Radiating lines and two orbit rings.
                let line = alpha(t.hero_fg, 0.13 * rise.max(0.3));
                let reach = max_r * 1.6;
                for k in 0..=18 {
                    let ang = PI + k as f32 * PI / 18.;
                    let mut path = PathBuilder::stroke(px(0.7));
                    path.move_to(p(cx, cy));
                    path.line_to(p(cx + ang.cos() * reach, cy + ang.sin() * reach));
                    if let Ok(path) = path.build() {
                        window.paint_path(path, line);
                    }
                }
                ring_outline(window, cx, cy, h * 0.72, line, 0.7);
                ring_outline(window, cx, cy, h * 1.02, alpha(t.hero_fg, 0.07), 0.7);
            });
            cut_corners(window, bounds, radius, outer_bg);
        },
    )
    .absolute()
    .inset_0()
}

fn arc_point(cx: f32, cy: f32, r: f32, frac: f32) -> Point<Pixels> {
    // frac 0 = left, 1 = right, over the top.
    let ang = PI * (1. - frac);
    p(cx + r * ang.cos(), cy - r * ang.sin())
}

/// Semicircle health gauge with ticks. `frac` is the animated score / 100.
pub fn gauge(t: Tok, frac: f32) -> impl IntoElement {
    canvas(
        |_, _, _| (),
        move |bounds, (), window, _| {
            let w = f32::from(bounds.size.width);
            let h = f32::from(bounds.size.height);
            let cx = f32::from(bounds.left()) + w / 2.;
            let cy = f32::from(bounds.top()) + h - 8.;
            let r = (w / 2. - 22.).min(h - 22.);
            let frac = frac.clamp(0., 1.);
            for i in 0..=40 {
                let f = i as f32 / 40.;
                let ang = PI * (1. - f);
                let (r1, r2) = (r + 10., r + if i % 10 == 0 { 18. } else { 13. });
                let mut path = PathBuilder::stroke(px(1.));
                path.move_to(p(cx + r1 * ang.cos(), cy - r1 * ang.sin()));
                path.line_to(p(cx + r2 * ang.cos(), cy - r2 * ang.sin()));
                if let Ok(path) = path.build() {
                    let a = if f <= frac { 0.55 } else { 0.18 };
                    window.paint_path(path, alpha(t.text, a));
                }
            }
            let mut track = PathBuilder::stroke(px(1.4)).dash_array(&[px(3.), px(5.)]);
            track.move_to(arc_point(cx, cy, r, 0.));
            track.arc_to(p(r, r), px(0.), false, true, arc_point(cx, cy, r, 1.));
            if let Ok(path) = track.build() {
                window.paint_path(path, t.line2);
            }
            if frac > 0.002 {
                let mut prog = PathBuilder::stroke(px(2.4));
                prog.move_to(arc_point(cx, cy, r, 0.));
                prog.arc_to(p(r, r), px(0.), false, true, arc_point(cx, cy, r, frac));
                if let Ok(path) = prog.build() {
                    window.paint_path(path, t.text);
                }
            }
            disc(window, cx - r, cy, 3.5, t.text);
            let end = arc_point(cx, cy, r, frac);
            let (ex, ey) = (f32::from(end.x), f32::from(end.y));
            disc(window, ex, ey, 8., t.panel);
            disc(window, ex, ey, 5.5, t.signal);
        },
    )
    .size_full()
}

/// Countdown ring for one-time codes. `frac` is the time left (1 → 0).
pub fn ring(t: Tok, frac: f32, diameter: f32) -> impl IntoElement {
    canvas(
        |_, _, _| (),
        move |bounds, (), window, _| {
            let r = diameter / 2. - 2.;
            let cx = f32::from(bounds.left()) + diameter / 2.;
            let cy = f32::from(bounds.top()) + diameter / 2.;
            ring_outline(window, cx, cy, r + 1.25, t.line2, 2.5);
            let frac = frac.clamp(0., 1.);
            if frac <= 0.001 {
                return;
            }
            let color = if frac < 0.2 { t.warn } else { t.signal };
            let mut path = PathBuilder::stroke(px(2.5));
            let at = |f: f32| {
                let ang = -PI / 2. + f * 2. * PI;
                p(cx + r * ang.cos(), cy + r * ang.sin())
            };
            path.move_to(at(0.));
            if frac >= 0.999 {
                path.arc_to(p(r, r), px(0.), false, true, at(0.5));
                path.arc_to(p(r, r), px(0.), false, true, at(0.9999));
            } else {
                path.arc_to(p(r, r), px(0.), frac > 0.5, true, at(frac));
            }
            if let Ok(path) = path.build() {
                window.paint_path(path, color);
            }
        },
    )
    .size(px(diameter))
    .flex_shrink_0()
}

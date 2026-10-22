//! "Instrument" interface — the design explored in
//! `docs/desktop-redesign-direction-04.html`, ported to gpui.
//!
//! It is the default shell, with a reversible classic interface option:
//!
//! - `--ui=instrument` / `--ui=classic` on the command line, or
//! - `VELA_UI=instrument` in the environment, or
//! - Ctrl+Alt+U at any time (also the "Classic interface" button in the rail).
//!
//! The runtime toggle is remembered in a one-line `ui-preview` file next to
//! the vault store, so a restart keeps either choice. Nothing in the vault,
//! the settings file, or `vela-desktop-core` changes. Launch with `--ui=classic` to force the original interface.
//!
//! Dedicated Instrument layouts cover the shell, overview, vault list/detail,
//! generator, lock gate, Sharing, Breach, Devices, Activity, Profile and
//! Settings, with dedicated dialog chrome and an item-editor drawer. All layouts
//! continue to call the same commands and authentication handlers.

pub mod analysis;
pub mod dot_matrix;
pub mod paint;
mod generator;
pub mod page;
pub mod icons;
mod navigation;
mod overview;
pub mod shell;
mod vault;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use gpui::{div, prelude::*, px, rgb, Animation, App, Div, ElementId, Global, Hsla, SharedString};

use crate::fonts;
use crate::theme::{ActiveTheme, ThemeId};

pub const THEMES: [ThemeId;4] = [ThemeId::Vela,ThemeId::Paper,ThemeId::Macchiato,ThemeId::Latte];
pub fn theme_name(id: ThemeId) -> &'static str { match id {ThemeId::Vela=>"Night",ThemeId::Paper=>"Paper",ThemeId::Macchiato=>"Catppuccin Macchiato",ThemeId::Latte=>"Catppuccin Latte",ThemeId::Gruvbox=>"Gruvbox"} }

// ── mode switch ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum InterfaceMode {
    Classic,
    #[default]
    Instrument,
}

impl InterfaceMode {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "instrument" | "new" | "preview" => Some(Self::Instrument),
            "classic" | "old" => Some(Self::Classic),
            _ => None,
        }
    }

    pub fn toggled(self) -> Self {
        match self {
            Self::Classic => Self::Instrument,
            Self::Instrument => Self::Classic,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ActiveInterface(pub InterfaceMode);
impl Global for ActiveInterface {}

pub fn is_instrument(cx: &App) -> bool {
    cx.try_global::<ActiveInterface>()
        .is_some_and(|m| m.0 == InterfaceMode::Instrument)
}

const PREF_FILE: &str = "ui-preview";

fn pref_path(store_path: &Path) -> PathBuf {
    store_path.join(PREF_FILE)
}

/// Command line beats environment beats the remembered choice.
pub fn initial_mode(store_path: Option<&Path>) -> InterfaceMode {
    let from_args = std::env::args()
        .find_map(|a| a.strip_prefix("--ui=").and_then(InterfaceMode::parse));
    let from_env = || std::env::var("VELA_UI").ok().and_then(|v| InterfaceMode::parse(&v));
    let from_file = || {
        store_path
            .and_then(|p| std::fs::read_to_string(pref_path(p)).ok())
            .and_then(|v| InterfaceMode::parse(&v))
    };
    from_args
        .or_else(from_env)
        .or_else(from_file)
        .unwrap_or_default()
}

/// Remember either choice explicitly; a missing preference uses Instrument.
pub fn remember(store_path: &Path, mode: InterfaceMode) {
    let path = pref_path(store_path);
    let value = match mode {
        InterfaceMode::Instrument => "instrument\n",
        InterfaceMode::Classic => "classic\n",
    };
    let result = std::fs::write(&path, value);
    if let Err(e) = result {
        tracing::warn!("Could not remember interface choice: {e}");
    }
}

/// Switch at runtime. `RootView` observes the global and rebuilds the shell;
/// the classic palette override in `theme.rs` follows the same global.
pub fn switch_interface(app_state: &vela_desktop_core::AppState, mode: InterfaceMode, cx: &mut App) {
    cx.set_global(ActiveInterface(mode));
    if !cx.has_global::<crate::demo::DemoMode>() {
        remember(app_state.store.store_path(), mode);
    }
}

// ── motion ──────────────────────────────────────────────────────────────

/// `VELA_REDUCED_MOTION=1` turns every entrance animation into a jump cut.
pub fn reduced_motion() -> bool {
    static REDUCED: OnceLock<bool> = OnceLock::new();
    *REDUCED.get_or_init(|| {
        std::env::var("VELA_REDUCED_MOTION").is_ok_and(|v| v != "0" && !v.is_empty())
    })
}

pub fn ms(n: u64) -> Duration {
    Duration::from_millis(if reduced_motion() { 1 } else { n })
}

pub fn ease_out(t: f32) -> f32 {
    1. - (1. - t.clamp(0., 1.)).powi(3)
}

/// gpui animations have no delay, so a staggered entrance is one longer
/// animation whose easing holds at 0 for the first `index * step` ms.
pub fn stagger(index: usize, step_ms: u64, duration_ms: u64) -> Animation {
    let delay = if reduced_motion() { 0 } else { index as u64 * step_ms };
    let total = delay + duration_ms;
    let start = delay as f32 / total.max(1) as f32;
    Animation::new(ms(total)).with_easing(move |t| {
        if t <= start {
            0.
        } else {
            ease_out((t - start) / (1. - start))
        }
    })
}

pub fn anim_id(name: &'static str, n: u64) -> ElementId {
    ElementId::NamedInteger(name.into(), n)
}

// ── tokens ──────────────────────────────────────────────────────────────

fn hex(v: u32) -> Hsla {
    rgb(v).into()
}

pub fn alpha(c: Hsla, a: f32) -> Hsla {
    Hsla { a, ..c }
}

/// Colours for the instrument frame, derived from the active theme so the
/// existing theme setting keeps working: VELA Dark becomes "Night".
#[derive(Debug, Clone, Copy)]
pub struct Tok {
    pub bg: Hsla,
    pub panel: Hsla,
    pub panel2: Hsla,
    pub panel3: Hsla,
    pub line: Hsla,
    pub line2: Hsla,
    pub text: Hsla,
    pub muted: Hsla,
    pub faint: Hsla,
    /// "OK / active" signal colour (lime on Night, green on Catppuccin).
    pub signal: Hsla,
    pub on_signal: Hsla,
    pub risk: Hsla,
    pub warn: Hsla,
    pub violet: Hsla,
    pub violet_bg: Hsla,
    pub violet_line: Hsla,
    pub primary_bg: Hsla,
    pub primary_fg: Hsla,
    /// The sunrise panels stay dark in every theme.
    pub hero_base: Hsla,
    pub hero_fg: Hsla,
    /// Sunrise glow, core first.
    pub glow: [Hsla; 5],
    /// Brand gradient for dot-matrix accents.
    pub grad: [Hsla; 4],
    pub dark: bool,
}

pub fn tokens(cx: &App) -> Tok {
    let theme = cx
        .try_global::<ActiveTheme>()
        .map(|t| t.0)
        .unwrap_or(ThemeId::Vela);
    tokens_for(theme)
}

pub fn tokens_for(theme: ThemeId) -> Tok {
    let macchiato_glow = [
        hex(0xf4dbd6),
        hex(0xf5a97f),
        hex(0xf5bde6),
        hex(0xc6a0f6),
        hex(0x8aadf4),
    ];
    match theme {
        ThemeId::Vela => Tok {
            bg: hex(0x060609),
            panel: hex(0x0e0e14),
            panel2: hex(0x15151d),
            panel3: hex(0x1c1c26),
            line: alpha(hex(0xffffff), 0.07),
            line2: alpha(hex(0xffffff), 0.13),
            text: hex(0xf3f2ef),
            muted: hex(0x8e8d98),
            faint: hex(0x4e4d58),
            signal: hex(0xd9f36a),
            on_signal: hex(0x14160a),
            risk: hex(0xff5d4a),
            warn: hex(0xffb547),
            violet: hex(0x9c8bff),
            violet_bg: alpha(hex(0x7c68ff), 0.10),
            violet_line: alpha(hex(0x9c8bff), 0.28),
            primary_bg: hex(0xf3f2ef),
            primary_fg: hex(0x0b0b0f),
            hero_base: hex(0x09090f),
            hero_fg: hex(0xf5f3ff),
            glow: [
                hex(0xffe7c2),
                hex(0xff8a4c),
                hex(0xff6b3d),
                hex(0xc35bea),
                hex(0x5a3bf0),
            ],
            grad: [hex(0x5b4bff), hex(0xa274ff), hex(0xff7a45), hex(0xffc28a)],
            dark: true,
        },
        ThemeId::Paper => Tok {
            bg: hex(0xe8e6df), panel: hex(0xf7f6f2), panel2: hex(0xefeee9), panel3: hex(0xe1e0d9),
            line: alpha(hex(0x24232b),0.10), line2: alpha(hex(0x24232b),0.18),
            text: hex(0x24232b),muted:hex(0x706f78),faint:hex(0x99979e),
            signal:hex(0x657a16),on_signal:hex(0xffffff),risk:hex(0xcb493b),warn:hex(0xa76a12),
            violet:hex(0x6950c6),violet_bg:alpha(hex(0x6950c6),0.08),violet_line:alpha(hex(0x6950c6),0.25),
            primary_bg:hex(0x24232b),primary_fg:hex(0xf7f6f2),hero_base:hex(0x09090f),hero_fg:hex(0xf5f3ff),
            glow:[hex(0xffe7c2),hex(0xff8a4c),hex(0xff6b3d),hex(0xc35bea),hex(0x5a3bf0)],
            grad:[hex(0x5b4bff),hex(0xa274ff),hex(0xff7a45),hex(0xffc28a)],dark:false,
        },
        ThemeId::Macchiato => Tok {
            bg: hex(0x181926),
            panel: hex(0x1e2030),
            panel2: hex(0x24273a),
            panel3: hex(0x363a4f),
            line: alpha(hex(0xcad3f5), 0.08),
            line2: alpha(hex(0xcad3f5), 0.15),
            text: hex(0xcad3f5),
            muted: hex(0xa5adcb),
            faint: hex(0x5b6078),
            signal: hex(0xa6da95),
            on_signal: hex(0x181926),
            risk: hex(0xed8796),
            warn: hex(0xf5a97f),
            violet: hex(0xc6a0f6),
            violet_bg: alpha(hex(0xc6a0f6), 0.09),
            violet_line: alpha(hex(0xc6a0f6), 0.30),
            primary_bg: hex(0xc6a0f6),
            primary_fg: hex(0x181926),
            hero_base: hex(0x181926),
            hero_fg: hex(0xcad3f5),
            glow: macchiato_glow,
            grad: [hex(0x8aadf4), hex(0xc6a0f6), hex(0xf5bde6), hex(0xf5a97f)],
            dark: true,
        },
        ThemeId::Latte => Tok {
            bg: hex(0xdce0e8),
            panel: hex(0xeff1f5),
            panel2: hex(0xe6e9ef),
            panel3: hex(0xccd0da),
            line: alpha(hex(0x4c4f69), 0.10),
            line2: alpha(hex(0x4c4f69), 0.20),
            text: hex(0x4c4f69),
            muted: hex(0x6c6f85),
            faint: hex(0x9ca0b0),
            signal: hex(0x40a02b),
            on_signal: hex(0xeff1f5),
            risk: hex(0xd20f39),
            warn: hex(0xfe640b),
            violet: hex(0x8839ef),
            violet_bg: alpha(hex(0x8839ef), 0.07),
            violet_line: alpha(hex(0x8839ef), 0.25),
            primary_bg: hex(0x8839ef),
            primary_fg: hex(0xeff1f5),
            hero_base: hex(0x1e2030),
            hero_fg: hex(0xcad3f5),
            glow: macchiato_glow,
            grad: [hex(0x1e66f5), hex(0x8839ef), hex(0xea76cb), hex(0xfe640b)],
            dark: false,
        },
        ThemeId::Gruvbox => Tok {
            bg: hex(0x1d2021),
            panel: hex(0x282828),
            panel2: hex(0x32302f),
            panel3: hex(0x3c3836),
            line: alpha(hex(0xebdbb2), 0.07),
            line2: alpha(hex(0xebdbb2), 0.14),
            text: hex(0xebdbb2),
            muted: hex(0xa89984),
            faint: hex(0x665c54),
            signal: hex(0xb8bb26),
            on_signal: hex(0x1d2021),
            risk: hex(0xfb4934),
            warn: hex(0xfe8019),
            violet: hex(0xd3869b),
            violet_bg: alpha(hex(0xd3869b), 0.09),
            violet_line: alpha(hex(0xd3869b), 0.30),
            primary_bg: hex(0xebdbb2),
            primary_fg: hex(0x1d2021),
            hero_base: hex(0x1d2021),
            hero_fg: hex(0xfbf1c7),
            glow: [
                hex(0xfbf1c7),
                hex(0xfabd2f),
                hex(0xfe8019),
                hex(0xd3869b),
                hex(0x458588),
            ],
            grad: [hex(0x83a598), hex(0xd3869b), hex(0xfe8019), hex(0xfabd2f)],
            dark: true,
        },
    }
}

/// Linear blend across the brand gradient, `t` in 0..1.
pub fn grad_at(grad: &[Hsla; 4], t: f32) -> Hsla {
    let t = t.clamp(0., 1.) * 3.;
    let i = (t.floor() as usize).min(2);
    crate::animation::lerp_hsla(grad[i], grad[i + 1], t - i as f32)
}

// ── small shared pieces ─────────────────────────────────────────────────

/// Uppercase mono metadata label (`01 / VAULT`). gpui has no letter-spacing,
/// so the tracking is simulated per character like `fonts::tracked_text`.
pub fn mono(text: impl Into<SharedString>, color: Hsla) -> Div {
    let text: SharedString = text.into();
    let upper = text.to_uppercase();
    fonts::tracked_text(&upper, px(10.), 0.08)
        .font_family(fonts::MONO)
        .text_size(px(10.))
        .line_height(px(14.))
        .text_color(color)
        .flex_shrink_0()
}

#[derive(Clone, Copy)]
pub enum TagKind {
    Risk,
    Warn,
    Ok,
    Plain,
}

pub fn tag(text: impl Into<SharedString>, kind: TagKind, t: &Tok) -> Div {
    let color = match kind {
        TagKind::Risk => t.risk,
        TagKind::Warn => t.warn,
        TagKind::Ok => t.signal,
        TagKind::Plain => t.muted,
    };
    let (bg, border) = match kind {
        TagKind::Plain => (alpha(t.panel, 0.), t.line2),
        _ => (alpha(color, 0.12), alpha(color, 0.32)),
    };
    div()
        .px(px(7.))
        .py(px(2.))
        .rounded(px(6.))
        .bg(bg)
        .border_1()
        .border_color(border)
        .child(mono(text, color))
}

/// The tile surface used throughout the bento.
pub fn tile(t: &Tok) -> Div {
    div()
        .relative()
        .rounded(px(22.))
        .bg(t.panel)
        .border_1()
        .border_color(t.line)
        .p(px(20.))
        .overflow_hidden()
        .min_w_0()
}

pub fn initials(name: &str) -> String {
    let words: Vec<&str> = name
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    let mut out = String::new();
    match words.as_slice() {
        [] => out.push('?'),
        [one] => out.extend(one.chars().take(2)),
        [first, second, ..] => {
            out.extend(first.chars().take(1));
            out.extend(second.chars().take(1));
        }
    }
    out.to_uppercase()
}

pub fn avatar(name: &str, size: f32, t: &Tok) -> Div {
    div()
        .size(px(size))
        .flex_shrink_0()
        .rounded(px(size * 0.3))
        .bg(t.panel3)
        .border_1()
        .border_color(t.line2)
        .flex()
        .items_center()
        .justify_center()
        .font_family(fonts::MONO)
        .text_size(px(size * 0.32))
        .text_color(t.text)
        .child(initials(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_documented_values() {
        assert_eq!(InterfaceMode::parse("instrument"), Some(InterfaceMode::Instrument));
        assert_eq!(InterfaceMode::parse(" Classic\n"), Some(InterfaceMode::Classic));
        assert_eq!(InterfaceMode::parse("bogus"), None);
    }

    #[test]
    fn instrument_is_default_and_either_choice_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(initial_mode(Some(dir.path())), InterfaceMode::Instrument);
        remember(dir.path(), InterfaceMode::Classic);
        assert_eq!(initial_mode(Some(dir.path())), InterfaceMode::Classic);
        remember(dir.path(), InterfaceMode::Instrument);
        assert_eq!(initial_mode(Some(dir.path())), InterfaceMode::Instrument);
        std::fs::write(pref_path(dir.path()), "invalid choice").unwrap();
        assert_eq!(initial_mode(Some(dir.path())), InterfaceMode::Instrument);
    }

    #[test]
    fn stagger_holds_then_finishes() {
        let anim = stagger(3, 100, 300);
        let ease = anim.easing.clone();
        if !reduced_motion() {
            assert_eq!(ease(0.25), 0.);
        }
        assert!((ease(1.) - 1.).abs() < 1e-4);
    }

    #[test]
    fn initials_cover_edge_cases() {
        assert_eq!(initials("GitHub"), "GI");
        assert_eq!(initials("Personal email"), "PE");
        assert_eq!(initials("  "), "?");
    }

    #[test]
    fn every_theme_has_instrument_tokens() {
        for id in ThemeId::ALL.into_iter().chain(THEMES) {
            let t = tokens_for(id);
            assert_eq!(t.dark, id.is_dark(), "{id:?}");
        }
    }
}

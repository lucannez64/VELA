//! Font family names, matching `tailwind.config.js`'s `fontFamily` mapping
//! 1:1 (`font-headline`/`font-body`/`font-label`/`font-mono` classes in the
//! original React app) plus the icon font. All weights of each family are
//! loaded once at startup (`main.rs::load_all_fonts`); which weight
//! actually renders is picked by gpui's font matcher from `.font_weight(...)`.

/// `font-headline` — titles, big numbers.
pub const HEADLINE: &str = "Space Grotesk";
/// `font-body` — paragraph copy.
pub const BODY: &str = "Manrope";
/// `font-label` — small-caps labels, buttons, UI chrome. Also the base/
/// default font applied to the whole app root, matching Inter being the
/// most-used family across the original's components.
pub const LABEL: &str = "Inter";
/// `font-mono` — passwords, card numbers, TOTP codes, secrets.
pub const MONO: &str = "JetBrains Mono";
/// Material Symbols Outlined — see `icon.rs`.
pub const ICONS: &str = "Material Symbols Outlined";

macro_rules! embedded_fonts {
    ($($file:literal),* $(,)?) => {
        /// All font files under `desktopVELA/src/assets/fonts/`, embedded into
        /// the binary and registered once at startup so every weight is
        /// available to gpui's font matcher.
        ///
        /// Embedded rather than read from disk at runtime: the fonts live in
        /// the source tree, not in any install prefix, so a `std::fs::read`
        /// relative to `CARGO_MANIFEST_DIR` resolves to the *build* machine's
        /// checkout and panics on every machine that isn't it (the released
        /// binary looked for `/home/runner/work/VELA/...`). Same reason
        /// `tray.rs` embeds the tray icon. ~3.7 MiB of the binary.
        pub const FONT_FILES: &[(&str, &[u8])] = &[
            $((
                $file,
                include_bytes!(concat!("../../src/assets/fonts/", $file)),
            )),*
        ];
    };
}

embedded_fonts![
    "inter-300.ttf",
    "inter-400.ttf",
    "inter-500.ttf",
    "inter-600.ttf",
    "inter-700.ttf",
    "manrope-200.ttf",
    "manrope-300.ttf",
    "manrope-400.ttf",
    "manrope-500.ttf",
    "manrope-600.ttf",
    "manrope-700.ttf",
    "manrope-800.ttf",
    "space-grotesk-300.ttf",
    "space-grotesk-400.ttf",
    "space-grotesk-500.ttf",
    "space-grotesk-600.ttf",
    "space-grotesk-700.ttf",
    "jetbrains-mono-400.ttf",
    "jetbrains-mono-500.ttf",
    "material-symbols-outlined-400.ttf",
];

/// Simulates CSS letter-spacing (Tailwind `tracking-[Nem]`), which gpui has
/// no direct equivalent for — confirmed by checking `Styled`'s macro-
/// generated method list (`gpui_macros::styles::style_helpers`) and
/// `text_system.rs` directly: no `letter_spacing`/`kerning`/`tracking`
/// method exists anywhere in gpui-ce. Renders each character as its own
/// flex child with a gap of `tracking_em * font_size`, which reproduces the
/// visual effect exactly (uniform inter-character spacing) since gpui's
/// flex `gap` is a real layout primitive, not an approximation. Text
/// styling (`.font_family()`/`.text_color()`/`.font_weight()`/etc.) should
/// be chained onto the returned `Div` as usual — those inherit to the
/// per-character children the same way any parent text style does in gpui.
pub fn tracked_text(text: &str, font_size: gpui::Pixels, tracking_em: f32) -> gpui::Div {
    use gpui::{div, prelude::*};
    div()
        .flex()
        .gap(font_size * tracking_em)
        .children(text.chars().map(|c| div().child(c.to_string())))
}

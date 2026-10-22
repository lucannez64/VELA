//! Port of `desktopVELA/src/themes.ts` + the `--color-*` custom properties in
//! `desktopVELA/src/index.css`. Four runtime-switchable palettes; `System`
//! resolves to `Vela` or `Latte` based on the OS light/dark preference.

use gpui::{rgb, App, Global, Hsla};

/// App-wide current theme, stored as a gpui `Global` so every screen reads
/// the same live value instead of each hardcoding its own palette (that was
/// the actual bug behind "theme doesn't work" — every view independently
/// called `Palette::vela()`, so changing the setting had nothing to affect).
/// Set once at startup in `main.rs` and updated whenever `SettingsScreen`
/// saves a new theme; every view's `render()` should call
/// [`current_palette`] instead of constructing a `Palette` directly, and
/// every view's constructor should call
/// `cx.observe_global::<ActiveTheme>(|_, cx| cx.notify()).detach()` so
/// already-mounted views (the persistent `Sidebar`, whatever's in
/// `AppShell`) actually repaint when the global changes.
#[derive(Debug, Clone, Copy)]
pub struct ActiveTheme(pub ThemeId);
impl Global for ActiveTheme {}

/// Reads the live app-wide theme, falling back to `Vela` if the global
/// hasn't been set yet (shouldn't happen post-startup, but render() must
/// never panic).
pub fn current_palette(cx: &App) -> Palette {
    let id = cx.try_global::<ActiveTheme>().map(|t| t.0).unwrap_or(ThemeId::Vela);
    let instrument = crate::instrument::is_instrument(cx);
    // The instrument interface recolours VELA Dark as "Night" and maps Paper
    // onto its own light tokens so hosted classic screens match its frame.
    let mut p = if instrument && id == ThemeId::Vela {
        Palette::night()
    } else if instrument && id == ThemeId::Paper {
        let t=crate::instrument::tokens_for(ThemeId::Paper);
        let mut p=Palette::latte();
        p.primary=t.primary_bg;p.primary_dim=t.muted;p.on_primary=t.primary_fg;
        p.secondary=t.signal;p.on_secondary=t.on_signal;p.error=t.risk;p.accent_violet=t.violet;
        p.surface=t.bg;p.surface_dim=t.bg;p.surface_container_lowest=t.bg;p.surface_container_low=t.panel;
        p.surface_container=t.panel;p.surface_container_high=t.panel2;p.surface_container_highest=t.panel3;
        p.surface_bright=t.panel3;p.surface_variant=t.panel2;p.on_surface=t.text;p.on_surface_variant=t.muted;
        p.outline=t.faint;p.outline_variant=t.line2;
        p
    } else {
        id.palette()
    };
    // Shared controls (buttons, form labels, dialogs) switch shape and type
    // from this flag, so it must reflect the active interface, not the theme.
    p.instrument = instrument;
    p
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeId {
    Vela,
    Paper,
    Macchiato,
    Latte,
    Gruvbox,
}

impl ThemeId {
    pub const ALL: [ThemeId; 4] = [
        ThemeId::Vela,
        ThemeId::Macchiato,
        ThemeId::Latte,
        ThemeId::Gruvbox,
    ];

    pub fn label(self) -> &'static str {
        match self {
            ThemeId::Vela => "VELA Dark",
            ThemeId::Paper => "Paper",
            ThemeId::Macchiato => "Macchiato",
            ThemeId::Latte => "Latte",
            ThemeId::Gruvbox => "Gruvbox",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            ThemeId::Vela => "Default obsidian look",
            ThemeId::Paper => "Warm paper — light",
            ThemeId::Macchiato => "Catppuccin Macchiato",
            ThemeId::Latte => "Catppuccin Latte — light",
            ThemeId::Gruvbox => "Retro groove, warm dark",
        }
    }

    pub fn is_dark(self) -> bool {
        !matches!(self, ThemeId::Latte | ThemeId::Paper)
    }

    pub fn palette(self) -> Palette {
        match self {
            ThemeId::Vela => Palette::vela(),
            ThemeId::Paper => Palette::latte(),
            ThemeId::Macchiato => Palette::macchiato(),
            ThemeId::Latte => Palette::latte(),
            ThemeId::Gruvbox => Palette::gruvbox(),
        }
    }

    /// Maps a stored `Settings::Theme` (including the legacy `Dark`/`Light`
    /// values and `System`) to a concrete palette id. The legacy Light value
    /// stores Paper in the opt-in preview; its classic palette remains Latte. `System` doesn't query
    /// the OS light/dark preference yet (unlike `themes.ts`'s
    /// `systemPreferredTheme`) — resolves to `Vela`, documented simplification.
    pub fn from_setting(theme: &vela_desktop_core::settings::Theme) -> ThemeId {
        use vela_desktop_core::settings::Theme;
        match theme {
            Theme::Vela | Theme::Dark | Theme::System => ThemeId::Vela,
            Theme::Macchiato => ThemeId::Macchiato,
            Theme::Latte => ThemeId::Latte,
            Theme::Light => ThemeId::Paper,
            Theme::Gruvbox => ThemeId::Gruvbox,
        }
    }

    pub fn to_setting(self) -> vela_desktop_core::settings::Theme {
        use vela_desktop_core::settings::Theme;
        match self {
            ThemeId::Vela => Theme::Vela,
            ThemeId::Paper => Theme::Light,
            ThemeId::Macchiato => Theme::Macchiato,
            ThemeId::Latte => Theme::Latte,
            ThemeId::Gruvbox => Theme::Gruvbox,
        }
    }
}

/// Maps 1:1 to the `--color-*` custom properties in `index.css`.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    /// Presentation hint used only by shared dialog controls.
    pub instrument: bool,
    pub primary: Hsla,
    pub primary_dim: Hsla,
    pub secondary: Hsla,
    pub error: Hsla,
    pub accent_violet: Hsla,
    pub surface: Hsla,
    pub surface_dim: Hsla,
    pub surface_bright: Hsla,
    pub surface_container_lowest: Hsla,
    pub surface_container_low: Hsla,
    pub surface_container: Hsla,
    pub surface_container_high: Hsla,
    pub surface_container_highest: Hsla,
    pub surface_variant: Hsla,
    pub on_surface: Hsla,
    pub on_surface_variant: Hsla,
    pub on_primary: Hsla,
    pub on_secondary: Hsla,
    pub outline: Hsla,
    pub outline_variant: Hsla,
}

impl Palette {
    pub fn vela() -> Palette {
        Palette {
            instrument: false,
            primary: rgb(0x73db9a).into(),
            primary_dim: rgb(0x1c8f56).into(),
            secondary: rgb(0x44e2cd).into(),
            error: rgb(0xffb4ab).into(),
            accent_violet: rgb(0x8b5cf6).into(),
            surface: rgb(0x121416).into(),
            surface_dim: rgb(0x121416).into(),
            surface_bright: rgb(0x37393b).into(),
            surface_container_lowest: rgb(0x0c0e10).into(),
            surface_container_low: rgb(0x1a1c1e).into(),
            surface_container: rgb(0x1e2022).into(),
            surface_container_high: rgb(0x282a2c).into(),
            surface_container_highest: rgb(0x333537).into(),
            surface_variant: rgb(0x333537).into(),
            on_surface: rgb(0xe2e2e5).into(),
            on_surface_variant: rgb(0xc4c7c7).into(),
            on_primary: rgb(0x00391d).into(),
            on_secondary: rgb(0x003731).into(),
            outline: rgb(0x8e9192).into(),
            outline_variant: rgb(0x444748).into(),
        }
    }

    /// VELA Dark as seen through the instrument preview: ink surfaces, lime
    /// signal, violet accent. Only used while that preview is active.
    pub fn night() -> Palette {
        Palette {
            instrument: false,
            primary: rgb(0xd9f36a).into(),
            primary_dim: rgb(0x9db040).into(),
            secondary: rgb(0xb6a9ff).into(),
            error: rgb(0xff5d4a).into(),
            accent_violet: rgb(0x9c8bff).into(),
            surface: rgb(0x0e0e14).into(),
            surface_dim: rgb(0x060609).into(),
            surface_bright: rgb(0x2a2a36).into(),
            surface_container_lowest: rgb(0x060609).into(),
            surface_container_low: rgb(0x0e0e14).into(),
            surface_container: rgb(0x15151d).into(),
            surface_container_high: rgb(0x1c1c26).into(),
            surface_container_highest: rgb(0x252532).into(),
            surface_variant: rgb(0x252532).into(),
            on_surface: rgb(0xf3f2ef).into(),
            on_surface_variant: rgb(0xa9a8b2).into(),
            on_primary: rgb(0x14160a).into(),
            on_secondary: rgb(0x0b0b0f).into(),
            outline: rgb(0x6e6d78).into(),
            outline_variant: rgb(0x2c2c38).into(),
        }
    }

    pub fn macchiato() -> Palette {
        Palette {
            instrument: false,
            primary: rgb(0xa6da95).into(),
            primary_dim: rgb(0x6c8e61).into(),
            secondary: rgb(0x8bd5ca).into(),
            error: rgb(0xed8796).into(),
            accent_violet: rgb(0xc6a0f6).into(),
            surface: rgb(0x24273a).into(),
            surface_dim: rgb(0x1e2030).into(),
            surface_bright: rgb(0x494d64).into(),
            surface_container_lowest: rgb(0x181926).into(),
            surface_container_low: rgb(0x1e2030).into(),
            surface_container: rgb(0x24273a).into(),
            surface_container_high: rgb(0x363a4f).into(),
            surface_container_highest: rgb(0x494d64).into(),
            surface_variant: rgb(0x5b6078).into(),
            on_surface: rgb(0xcad3f5).into(),
            on_surface_variant: rgb(0xa5adcb).into(),
            on_primary: rgb(0x181926).into(),
            on_secondary: rgb(0x181926).into(),
            outline: rgb(0x8087a2).into(),
            outline_variant: rgb(0x5b6078).into(),
        }
    }

    pub fn latte() -> Palette {
        Palette {
            instrument: false,
            primary: rgb(0x40a02b).into(),
            primary_dim: rgb(0x2d701e).into(),
            secondary: rgb(0x179299).into(),
            error: rgb(0xd20f39).into(),
            accent_violet: rgb(0x8839ef).into(),
            surface: rgb(0xeff1f5).into(),
            surface_dim: rgb(0xe6e9ef).into(),
            surface_bright: rgb(0xffffff).into(),
            surface_container_lowest: rgb(0xffffff).into(),
            surface_container_low: rgb(0xeff1f5).into(),
            surface_container: rgb(0xe6e9ef).into(),
            surface_container_high: rgb(0xdce0e8).into(),
            surface_container_highest: rgb(0xccd0da).into(),
            surface_variant: rgb(0xbcc0cc).into(),
            on_surface: rgb(0x4c4f69).into(),
            on_surface_variant: rgb(0x6c6f85).into(),
            on_primary: rgb(0xffffff).into(),
            on_secondary: rgb(0xffffff).into(),
            outline: rgb(0x8c8fa1).into(),
            outline_variant: rgb(0xacb0be).into(),
        }
    }

    pub fn gruvbox() -> Palette {
        Palette {
            instrument: false,
            primary: rgb(0xb8bb26).into(),
            primary_dim: rgb(0x98971a).into(),
            secondary: rgb(0x8ec07c).into(),
            error: rgb(0xfb4934).into(),
            accent_violet: rgb(0xd3869b).into(),
            surface: rgb(0x282828).into(),
            surface_dim: rgb(0x1d2021).into(),
            surface_bright: rgb(0x504945).into(),
            surface_container_lowest: rgb(0x1d2021).into(),
            surface_container_low: rgb(0x282828).into(),
            surface_container: rgb(0x32302f).into(),
            surface_container_high: rgb(0x3c3836).into(),
            surface_container_highest: rgb(0x504945).into(),
            surface_variant: rgb(0x504945).into(),
            on_surface: rgb(0xebdbb2).into(),
            on_surface_variant: rgb(0xd5c4a1).into(),
            on_primary: rgb(0x282828).into(),
            on_secondary: rgb(0x282828).into(),
            outline: rgb(0x928374).into(),
            outline_variant: rgb(0x665c54).into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vela_desktop_core::settings::Theme;

    fn assert_hsla_eq(a: Hsla, b: Hsla, what: &str) {
        assert!(
            a.h == b.h && a.s == b.s && a.l == b.l && a.a == b.a,
            "{what}: ({},{},{},{}) != ({},{},{},{})",
            a.h, a.s, a.l, a.a, b.h, b.s, b.l, b.a
        );
    }

    #[test]
    fn from_setting_maps_every_variant_including_legacy() {
        assert_eq!(ThemeId::from_setting(&Theme::Vela), ThemeId::Vela);
        assert_eq!(ThemeId::from_setting(&Theme::Macchiato), ThemeId::Macchiato);
        assert_eq!(ThemeId::from_setting(&Theme::Latte), ThemeId::Latte);
        assert_eq!(ThemeId::from_setting(&Theme::Gruvbox), ThemeId::Gruvbox);
        // Legacy stored values keep their documented meaning.
        assert_eq!(ThemeId::from_setting(&Theme::Dark), ThemeId::Vela);
        assert_eq!(ThemeId::from_setting(&Theme::Light), ThemeId::Paper);
        // System resolves to Vela in the gpui build (documented simplification).
        assert_eq!(ThemeId::from_setting(&Theme::System), ThemeId::Vela);
    }

    #[test]
    fn to_setting_roundtrips_all_concrete_themes() {
        for id in ThemeId::ALL {
            assert_eq!(ThemeId::from_setting(&id.to_setting()), id, "{id:?}");
        }
    }

    #[test]
    fn metadata_is_complete_and_latte_is_the_only_light_theme() {
        for id in ThemeId::ALL {
            assert!(!id.label().is_empty());
            assert!(!id.description().is_empty());
        }
        let light: Vec<_> = ThemeId::ALL.into_iter().filter(|t| !t.is_dark()).collect();
        assert_eq!(light, vec![ThemeId::Latte]);
    }

    #[test]
    fn vela_palette_matches_design_tokens() {
        // README design tokens: primary VELA Green, accent Electric Violet.
        let p = Palette::vela();
        assert_hsla_eq(p.primary, rgb(0x73db9a).into(), "vela primary");
        assert_hsla_eq(p.accent_violet, rgb(0x8b5cf6).into(), "vela accent");
    }

    #[test]
    fn latte_surfaces_are_lighter_than_dark_themes() {
        let latte = Palette::latte();
        for dark in [Palette::vela(), Palette::macchiato(), Palette::gruvbox()] {
            assert!(
                latte.surface.l > dark.surface.l,
                "latte surface lightness {} should exceed dark surface {}",
                latte.surface.l,
                dark.surface.l
            );
        }
    }

    #[test]
    fn palettes_are_distinct() {
        let vela = Palette::vela();
        let macchiato = Palette::macchiato();
        assert!(vela.surface.l != macchiato.surface.l || vela.surface.h != macchiato.surface.h);
    }
}

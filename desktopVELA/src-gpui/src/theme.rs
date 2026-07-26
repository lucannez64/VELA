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
    cx.try_global::<ActiveTheme>()
        .map(|t| t.0.palette())
        .unwrap_or_else(|| ThemeId::Vela.palette())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeId {
    Vela,
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
            ThemeId::Macchiato => "Macchiato",
            ThemeId::Latte => "Latte",
            ThemeId::Gruvbox => "Gruvbox",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            ThemeId::Vela => "Default obsidian look",
            ThemeId::Macchiato => "Catppuccin Macchiato",
            ThemeId::Latte => "Catppuccin Latte — light",
            ThemeId::Gruvbox => "Retro groove, warm dark",
        }
    }

    pub fn is_dark(self) -> bool {
        !matches!(self, ThemeId::Latte)
    }

    pub fn palette(self) -> Palette {
        match self {
            ThemeId::Vela => Palette::vela(),
            ThemeId::Macchiato => Palette::macchiato(),
            ThemeId::Latte => Palette::latte(),
            ThemeId::Gruvbox => Palette::gruvbox(),
        }
    }

    /// Maps a stored `Settings::Theme` (including the legacy `Dark`/`Light`
    /// values and `System`) to a concrete palette id. `System` doesn't query
    /// the OS light/dark preference yet (unlike `themes.ts`'s
    /// `systemPreferredTheme`) — resolves to `Vela`, documented simplification.
    pub fn from_setting(theme: &vela_desktop_core::settings::Theme) -> ThemeId {
        use vela_desktop_core::settings::Theme;
        match theme {
            Theme::Vela | Theme::Dark | Theme::System => ThemeId::Vela,
            Theme::Macchiato => ThemeId::Macchiato,
            Theme::Latte | Theme::Light => ThemeId::Latte,
            Theme::Gruvbox => ThemeId::Gruvbox,
        }
    }

    pub fn to_setting(self) -> vela_desktop_core::settings::Theme {
        use vela_desktop_core::settings::Theme;
        match self {
            ThemeId::Vela => Theme::Vela,
            ThemeId::Macchiato => Theme::Macchiato,
            ThemeId::Latte => Theme::Latte,
            ThemeId::Gruvbox => Theme::Gruvbox,
        }
    }
}

/// Maps 1:1 to the `--color-*` custom properties in `index.css`.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
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

    pub fn macchiato() -> Palette {
        Palette {
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

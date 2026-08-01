use serde::{Deserialize, Serialize};

pub const DEFAULT_QUICK_SEARCH_SHORTCUT: &str = "Ctrl+Alt+V";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub auto_lock_minutes: u32,
    pub clipboard_clear_seconds: u32,
    pub require_biometric_on_reveal: bool,
    pub sync_on_startup: bool,
    pub background_sync_minutes: u32,
    pub theme: Theme,
    pub compact_list: bool,
    pub user_id: String,
    pub server_url: String,
    #[serde(default = "default_quick_search_shortcut")]
    pub quick_search_shortcut: String,
    pub extension_connected: bool,
    pub extension_version: Option<String>,
}

fn default_quick_search_shortcut() -> String {
    DEFAULT_QUICK_SEARCH_SHORTCUT.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    System,
    /// Default VELA dark theme.
    Vela,
    /// Catppuccin Macchiato.
    Macchiato,
    /// Catppuccin Latte (light).
    Latte,
    /// Gruvbox Dark.
    Gruvbox,
    /// Legacy value kept for backwards compatibility with stored settings.
    /// Treated as `Vela` by the frontend.
    Dark,
    /// Legacy value kept for backwards compatibility with stored settings.
    /// Treated as `Latte` by the frontend.
    Light,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 5,
            clipboard_clear_seconds: 30,
            require_biometric_on_reveal: false,
            sync_on_startup: true,
            background_sync_minutes: 5,
            theme: Theme::System,
            compact_list: false,
            user_id: String::new(),
            server_url: String::new(),
            quick_search_shortcut: default_quick_search_shortcut(),
            extension_connected: false,
            extension_version: None,
        }
    }
}

pub fn normalize_quick_search_shortcut(shortcut: &str) -> String {
    let shortcut = shortcut.trim();
    if shortcut.is_empty() {
        DEFAULT_QUICK_SEARCH_SHORTCUT.to_string()
    } else {
        shortcut.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_shortcut_falls_back_to_default_on_empty() {
        assert_eq!(normalize_quick_search_shortcut(""), DEFAULT_QUICK_SEARCH_SHORTCUT);
        assert_eq!(normalize_quick_search_shortcut("   "), DEFAULT_QUICK_SEARCH_SHORTCUT);
        assert_eq!(normalize_quick_search_shortcut("\t\n "), DEFAULT_QUICK_SEARCH_SHORTCUT);
    }

    #[test]
    fn normalize_shortcut_trims_and_keeps_valid() {
        assert_eq!(normalize_quick_search_shortcut(" Ctrl+Alt+Q "), "Ctrl+Alt+Q");
        assert_eq!(normalize_quick_search_shortcut("Ctrl+Shift+F"), "Ctrl+Shift+F");
    }

    #[test]
    fn theme_deserializes_all_variants_including_legacy() {
        for (json, expected) in [
            ("\"system\"", Theme::System),
            ("\"vela\"", Theme::Vela),
            ("\"macchiato\"", Theme::Macchiato),
            ("\"latte\"", Theme::Latte),
            ("\"gruvbox\"", Theme::Gruvbox),
            ("\"dark\"", Theme::Dark),
            ("\"light\"", Theme::Light),
        ] {
            let parsed: Theme = serde_json::from_str(json).unwrap();
            assert_eq!(parsed, expected, "parsing {json}");
        }
        assert!(serde_json::from_str::<Theme>("\"Dracula\"").is_err());
    }

    #[test]
    fn theme_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Theme::Macchiato).unwrap(), "\"macchiato\"");
        assert_eq!(serde_json::to_string(&Theme::Dark).unwrap(), "\"dark\"");
    }

    #[test]
    fn default_settings_values() {
        let s = Settings::default();
        assert_eq!(s.auto_lock_minutes, 5);
        assert_eq!(s.clipboard_clear_seconds, 30);
        assert_eq!(s.theme, Theme::System);
        assert_eq!(s.quick_search_shortcut, DEFAULT_QUICK_SEARCH_SHORTCUT);
        assert!(s.sync_on_startup);
        assert!(!s.extension_connected);
    }

    #[test]
    fn settings_json_missing_shortcut_uses_default() {
        // Stored settings from before the shortcut option existed must
        // deserialize with the default rather than failing.
        let json = serde_json::json!({
            "auto_lock_minutes": 5,
            "clipboard_clear_seconds": 30,
            "require_biometric_on_reveal": false,
            "sync_on_startup": true,
            "background_sync_minutes": 5,
            "theme": "system",
            "compact_list": false,
            "user_id": "",
            "server_url": "",
            "extension_connected": false,
            "extension_version": null
        });
        let s: Settings = serde_json::from_value(json).unwrap();
        assert_eq!(s.quick_search_shortcut, DEFAULT_QUICK_SEARCH_SHORTCUT);
    }

    #[test]
    fn settings_roundtrip() {
        let s = Settings::default();
        let json = serde_json::to_string(&s).unwrap();
        let back: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(back.auto_lock_minutes, s.auto_lock_minutes);
        assert_eq!(back.theme, s.theme);
        assert_eq!(back.quick_search_shortcut, s.quick_search_shortcut);
    }
}

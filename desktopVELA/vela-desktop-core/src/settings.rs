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

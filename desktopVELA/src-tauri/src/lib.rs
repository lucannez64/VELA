//! Thin Tauri-specific layer over `vela-desktop-core`: the toolkit-agnostic
//! crypto/vault/sync/device/biometric/IPC/portal-shortcut modules live there;
//! this crate keeps the `#[tauri::command]` wrappers (`commands/`), window
//! and tray bootstrap (`main.rs`), and the `Host` trait implementation
//! bridging to `tauri::AppHandle`.
pub use vela_desktop_core::*;

pub mod commands;
pub mod tauri_host;

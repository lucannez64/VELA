//! Toolkit-agnostic core logic extracted from `src-tauri/src/commands/*`.
//! Plain `&Arc<AppState>` functions — no `tauri::State`/`AppHandle` — so both
//! `src-tauri`'s thin `#[tauri::command]` wrappers and `src-gpui`'s view
//! actions can call the same code. See
//! /home/hirew/.claude/plans/mighty-wibbling-wave.md Step 1.2.
pub mod devices;
pub mod session;
pub mod settings;
pub mod vault;
pub mod web_session;

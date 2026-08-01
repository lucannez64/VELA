//! Headless end-to-end sync tests: one desktop client (`vela-desktop-core`,
//! the real production code) and one android client (a faithful Rust stand-in
//! for `VaultSyncManager.kt`, using the same libVELA crypto the real app runs
//! via JNI) synchronising against a shared in-process mock server.
//!
//! No Android device, no emulator, no Android SDK — a plain `cargo test`.

pub mod android_client;
pub mod desktop_client;
pub mod mock_server;

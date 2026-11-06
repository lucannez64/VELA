//! Rust reference policy exposed to Kush. `ffi.rs` and
//! `../src/oracle.kush` are generated from `../Bridge.toml` by
//! `kush bindgen`; `bridge.rs` is hand-written safe Rust.
mod bridge;
mod ffi;

pub use bridge::*;

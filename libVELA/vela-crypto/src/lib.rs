//! VELA core cryptographic library.
//!
//! Provides all cryptographic primitives used by the VELA protocol.
//!
//! # Modules
//!
//! - [`kdf`]    — BLAKE3 key derivation (context-separated, from RMS)
//! - [`aead`]   — XChaCha20-Poly1305 authenticated encryption
//! - [`kem`]    — Hybrid ML-KEM-1024 + X25519 key encapsulation
//! - [`shamir`] — Shamir's Secret Sharing over GF(2^8)
//! - [`oram`]   — Path ORAM client state machine
//! - [`verification`] — Out-of-band short verification codes (device enrollment)

pub mod aead;
pub mod error;
pub mod kdf;
pub mod kem;
pub mod oram;
pub mod password_kdf;
pub mod shamir;
pub mod signing;
pub mod verification;

pub use error::{Result, VelaError};

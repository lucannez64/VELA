//! Shared client core for VELA applications.
//!
//! This crate intentionally contains platform-neutral behavior only. Android,
//! desktop, and future clients should put OS storage, biometric prompts, and UI
//! concerns outside this crate.

pub mod password;
/// Organization and richer-item schema. Writers are enabled only after the
/// compatibility rollout; these types do not migrate a legacy vault on load.
pub mod rich_items;
pub mod rich_api;
pub mod vault;

pub use password::{
    calculate_password_strength, generate_password, password_entropy, strength_verdict,
    PasswordGeneratorOptions, PasswordStrength,
};
pub use vault::{BreachEntry, ItemType, Tombstone, VaultItem, VaultStore};

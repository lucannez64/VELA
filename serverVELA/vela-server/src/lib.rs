//! VELA Protocol v2.0 — API Server library.
//!
//! Re-exports all modules so integration tests (and future library consumers)
//! can import them.

pub mod account;
pub mod auth;
pub mod config;
pub mod data_lock;
pub mod db;
pub mod device;
pub mod error;
pub mod middleware;
pub mod migration;
pub mod rate_limit;
pub mod recovery;
pub mod routes;
pub mod share;
pub mod state;
pub mod store;
pub mod transport;
pub mod vault;

//! Bounds on the identifiers clients put in URL paths.
//!
//! `chunk_id` and `tree_id` arrive as free-form path segments and are used as
//! primary keys and sled key fragments. Nothing checked their length or charset:
//! the 414 hyper returns on a very long URI is an accident of the HTTP stack,
//! not a decision this service made, and it stops applying the moment a request
//! arrives over HTTP/2 or HTTP/3 where there is no request line to overflow
//! (audit, server hardening).
//!
//! A client has no reason to name a chunk anything other than what our own
//! clients generate — `vault-data-000007`, `audit-log`, `vault-main` — so the
//! rule is deliberately narrow. Rejecting early keeps unbounded strings out of
//! the database, out of sled keys and out of log lines.

use crate::error::{AppError, Result};

/// Longest identifier we will accept. Our own are under 20 characters; this
/// leaves room for a client with a different scheme without letting anyone
/// stream a megabyte into a key.
pub const MAX_ID_LEN: usize = 128;

/// Characters an identifier may contain: ASCII alphanumerics plus `-`, `_`, `.`.
///
/// Excludes `/` and `:` so an id can never reshape a sled key, and excludes
/// everything non-ASCII so two ids that look identical cannot be distinct.
fn is_allowed(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')
}

/// Validate a client-supplied path identifier, returning it unchanged.
///
/// `what` names the field in the error, which is safe to echo: the caller
/// supplied it, so it tells them nothing they did not already know.
pub fn validate_id<'a>(what: &str, id: &'a str) -> Result<&'a str> {
    if id.is_empty() {
        return Err(AppError::BadRequest(format!("{what} must not be empty")));
    }
    if id.len() > MAX_ID_LEN {
        return Err(AppError::BadRequest(format!(
            "{what} must be at most {MAX_ID_LEN} characters"
        )));
    }
    if !id.chars().all(is_allowed) {
        return Err(AppError::BadRequest(format!(
            "{what} may only contain letters, digits, '-', '_' and '.'"
        )));
    }
    // A leading dot, or any run of dots, is never something we generate and is
    // the shape path-traversal attempts take if an id ever reaches a filesystem.
    if id.starts_with('.') || id.contains("..") {
        return Err(AppError::BadRequest(format!("{what} is not a valid id")));
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_ids_our_own_clients_generate() {
        for id in [
            "vault-data-000000",
            "vault-data-999999",
            "vault-main",
            "vault",
            "audit-log",
            "oram.tree_1",
        ] {
            assert!(validate_id("chunk_id", id).is_ok(), "rejected {id}");
        }
    }

    #[test]
    fn rejects_an_unbounded_id() {
        let long = "a".repeat(MAX_ID_LEN + 1);
        assert!(validate_id("chunk_id", &long).is_err());
        assert!(validate_id("chunk_id", &"a".repeat(MAX_ID_LEN)).is_ok(), "the bound itself is fine");
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_id("chunk_id", "").is_err());
    }

    #[test]
    fn rejects_separators_that_could_reshape_a_key() {
        for id in ["a/b", "a:b", "a b", "a\tb", "a\nb", "a%2Fb"] {
            assert!(validate_id("chunk_id", id).is_err(), "accepted {id:?}");
        }
    }

    #[test]
    fn rejects_traversal_shapes() {
        for id in ["..", "../etc", ".hidden", "a..b"] {
            assert!(validate_id("chunk_id", id).is_err(), "accepted {id:?}");
        }
    }

    #[test]
    fn rejects_non_ascii_lookalikes() {
        // Cyrillic 'а' is not Latin 'a'; two ids that render identically must
        // not both be storable.
        assert!(validate_id("chunk_id", "vаult-main").is_err());
        assert!(validate_id("chunk_id", "vault\u{200b}-main").is_err());
    }

    #[test]
    fn the_error_names_the_field() {
        let err = validate_id("tree_id", "").unwrap_err();
        assert!(format!("{err:?}").contains("tree_id"));
    }
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VelaError {
    #[error("KEM encapsulation/decapsulation failed")]
    KemError,

    #[error("AEAD encryption/decryption failed")]
    AeadError,

    /// Every failure to open attacker-supplied ciphertext (C15).
    ///
    /// A bad tag, a truncated blob, a wrong key, a malformed capsule and an
    /// unsupported header all map to this one variant, so an error value can
    /// never act as a decryption oracle. Callers that need to show a local user
    /// why their own data did not open must log the detailed cause at the point
    /// where it is produced; the open wrappers deliberately do not keep it.
    #[error("decryption failed")]
    DecryptionFailed,

    #[error("KDF error: {0}")]
    KdfError(String),

    #[error("Shamir SSS error: {0}")]
    ShamirError(String),

    #[error("ORAM error: {0}")]
    OramError(String),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Insufficient shares: need {need}, got {got}")]
    InsufficientShares { need: u8, got: usize },

    #[error("Signing error: {0}")]
    SigningError(String),
}

pub type Result<T> = std::result::Result<T, VelaError>;

/// Collapse every failure of an attacker-facing open into one error (C15).
///
/// `open`, `decrypt` and the KEM/envelope wrappers that consume ciphertext an
/// attacker chose route their failures through this function, so a caller
/// cannot tell a bad tag from a bad length, header, key or capsule by the error
/// value. Some refusals that inspect a *public* header (for example the
/// legacy-unsealed chunk shape) stay outside this helper: that header is input
/// the attacker already knows, so naming it reveals nothing they did not send.
pub(crate) fn uniform_open<T>(result: Result<T>) -> Result<T> {
    result.map_err(|_| VelaError::DecryptionFailed)
}

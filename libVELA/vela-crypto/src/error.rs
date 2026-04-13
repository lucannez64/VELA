use thiserror::Error;

#[derive(Debug, Error)]
pub enum VelaError {
    #[error("KEM encapsulation/decapsulation failed")]
    KemError,

    #[error("AEAD encryption/decryption failed")]
    AeadError,

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

    #[error("Cyclo ZKP error: {0}")]
    CycloError(String),

    #[error("Signing error: {0}")]
    SigningError(String),
}

pub type Result<T> = std::result::Result<T, VelaError>;

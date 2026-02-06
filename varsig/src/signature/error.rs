//! Error types for signing and verification operations.

/// Error type for signing operations.
#[derive(Debug, thiserror::Error)]
pub enum SignError<E: std::error::Error> {
    /// Codec error.
    #[error(transparent)]
    EncodingError(E),

    /// Signing error.
    #[error("Signing error: {0}")]
    SigningError(signature::Error),
}

/// Error type for verification operations.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError<E: std::error::Error> {
    /// Codec error.
    #[error(transparent)]
    EncodingError(E),

    /// Verification error.
    #[error("Verification error: {0}")]
    VerificationError(signature::Error),
}

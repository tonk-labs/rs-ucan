//! Shared builder utilities for UCAN tokens.

use std::error::Error;
use thiserror::Error;

/// Errors that can occur when building UCAN tokens.
///
/// This error type is used by both [`DelegationBuilder::try_build`] and
/// [`InvocationBuilder::try_build`].
///
/// [`DelegationBuilder::try_build`]: crate::delegation::builder::DelegationBuilder::try_build
/// [`InvocationBuilder::try_build`]: crate::invocation::builder::InvocationBuilder::try_build
#[derive(Debug, Error)]
pub enum AsyncBuildError<E: Error> {
    /// Encoding error when serializing the payload.
    #[error("encoding error: {0}")]
    EncodingError(String),

    /// Signing error from the signer.
    #[error("signing error: {0}")]
    SigningError(E),
}

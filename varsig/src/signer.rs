//! Signature verification.

use signature::Signer;
use std::{error::Error, fmt::Debug};
use thiserror::Error;

use crate::{codec::Codec, verify::Verify};

/// Synchronous signing trait.
pub trait Sign: Verify {
    /// The signing key.
    type Signer: Signer<Self::Signature>;

    /// Signing errors.
    type SignError: Error;

    /// Synchronously sign a payload.
    ///
    /// # Errors
    ///
    /// If encoding or signing fails, a `SignerError` is returned.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(skip_all)]
    fn try_sign<T, C: Codec<T>>(
        &self,
        codec: &C,
        signer: &Self::Signer,
        payload: &T,
    ) -> Result<(Self::Signature, Vec<u8>), SignerError<C::EncodingError, Self::SignError>> {
        let mut buffer = Vec::new();
        codec
            .encode_payload(payload, &mut buffer)
            .map_err(SignerError::EncodingError)?;
        let sig = signer
            .try_sign(&buffer)
            .map_err(SignerError::SigningError)?;
        Ok((sig, buffer))
    }
}

/// Signing errors.
#[derive(Debug, Error)]
pub enum SignerError<Ee: Error, Ve: Error> {
    /// Encoding error.
    #[error(transparent)]
    EncodingError(Ee),

    /// Signing error.
    #[error("Signing error: {0}")]
    SigningError(signature::Error),

    /// Varsig error.
    #[error(transparent)]
    VarsigError(Ve),
}

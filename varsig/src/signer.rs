//! Signature verification.

use async_signature::AsyncSigner;
use signature::Signer;
use std::{error::Error, future::Future};
use thiserror::Error;

use crate::{codec::Codec, verify::Verify};

/// Synchronous signing trait.
pub trait Sign: Verify {
    /// The signing key.
    type Signer: Signer<Self::Signature>;

    /// Signing errors.
    type SignError: Error;

    /// Synchronously sign a payload.
    #[tracing::instrument(skip_all)]
    fn try_sign<T, C: Codec<T>>(
        &self,
        codec: &C,
        signer: &Self::Signer,
        payload: &T,
    ) -> Result<Self::Signature, SignerError<C::EncodingError, Self::SignError>> {
        let mut buffer = Vec::new();
        codec
            .encode_payload(payload, &mut buffer)
            .map_err(SignerError::EncodingError)?;
        signer.try_sign(&buffer).map_err(SignerError::SigningError)
    }
}

/// Asynchronous signing trait.
pub trait AsyncSign: Verify {
    /// The asynchronous signing key.
    type AsyncSigner: AsyncSigner<Self::Signature>;

    /// Asynchronous signing errors.
    type AsyncSignError: Error;

    /// Asynchronously sign a payload.
    #[tracing::instrument(skip_all)]
    fn try_sign_async<T, C: Codec<T>>(
        &self,
        codec: &C,
        signer: &Self::AsyncSigner,
        payload: &T,
    ) -> impl Future<Output = Result<Self::Signature, SignerError<C::EncodingError, Self::AsyncSignError>>>
    {
        async {
            let mut buffer = Vec::new();
            codec
                .encode_payload(payload, &mut buffer)
                .map_err(SignerError::EncodingError)?;
            signer
                .sign_async(&buffer)
                .await
                .map_err(SignerError::SigningError)
        }
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

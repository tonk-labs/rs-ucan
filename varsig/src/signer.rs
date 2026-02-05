//! Signature signing traits.

use async_signature::AsyncSigner;
use std::{error::Error, future::Future};
use thiserror::Error;

use crate::{codec::Codec, verify::Verify};

/// Signing trait for UCAN tokens.
///
/// This trait provides async signing capabilities for signers that may not
/// have synchronous access to their signing keys, such as `WebCrypto` signers
/// with non-extractable keys, HSMs, or remote signing services.
pub trait Sign: Verify {
    /// The signing key type.
    type Signer: AsyncSigner<Self::Signature>;

    /// Signing errors.
    type SignError: Error + Send + Sync + 'static;

    /// Sign a payload asynchronously.
    ///
    /// # Errors
    ///
    /// If encoding or signing fails, a `SignerError` is returned.
    #[allow(clippy::type_complexity)]
    fn try_sign<T, C: Codec<T>>(
        &self,
        codec: &C,
        signer: &Self::Signer,
        payload: &T,
    ) -> impl Future<
        Output = Result<(Self::Signature, Vec<u8>), SignerError<C::EncodingError, Self::SignError>>,
    > {
        async move {
            let mut buffer = Vec::new();
            codec
                .encode_payload(payload, &mut buffer)
                .map_err(SignerError::EncodingError)?;
            let sig = signer
                .sign_async(&buffer)
                .await
                .map_err(SignerError::SigningError)?;
            Ok((sig, buffer))
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

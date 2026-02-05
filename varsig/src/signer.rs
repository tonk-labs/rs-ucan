//! Signature signing traits.

use async_signature::AsyncSigner;
use std::{error::Error, future::Future};
use thiserror::Error;

use crate::{codec::Codec, verify::Verify};

/// Ed25519 key material for import/export.
///
/// On native platforms, only the `Extractable` variant is available.
/// On WASM (`wasm32-unknown-unknown`), a `NonExtractable` variant is also
/// available for opaque `WebCrypto` key pairs whose key material cannot be read.
#[derive(Debug, Clone)]
pub enum KeyExport {
    /// Raw seed bytes — the key material is accessible.
    Extractable(Vec<u8>),

    /// Opaque WebCrypto key pair — key material is NOT accessible.
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    NonExtractable {
        /// The WebCrypto private key.
        private_key: web_sys::CryptoKey,
        /// The WebCrypto public key.
        public_key: web_sys::CryptoKey,
    },
}

impl From<&[u8; 32]> for KeyExport {
    fn from(seed: &[u8; 32]) -> Self {
        KeyExport::Extractable(seed.to_vec())
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
impl From<web_sys::CryptoKeyPair> for KeyExport {
    fn from(pair: web_sys::CryptoKeyPair) -> Self {
        KeyExport::NonExtractable {
            private_key: pair.get_private_key(),
            public_key: pair.get_public_key(),
        }
    }
}

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

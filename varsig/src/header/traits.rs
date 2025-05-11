use crate::codec::Codec;
use signature::{SignatureEncoding, Verifier};
use std::{error::Error, fmt::Debug};
use thiserror::Error;

// FIXME rename? Varsig?
pub trait Header<T>: Codec<T> {
    /// The signature type for the header.
    type Signature: SignatureEncoding;

    /// The associated signer (referenced or owned signing key for the header).
    type Verifier: Verifier<Self::Signature>;

    fn try_verify(
        &self,
        verifier: &Self::Verifier,
        signature: &Self::Signature,
        payload: &T,
    ) -> Result<(), VerificationError<Self::EncodingError>> {
        let mut buffer = vec![];
        self.encode_payload(payload, &mut buffer)
            .map_err(VerificationError::EncodingError)?;
        verifier
            .verify(&buffer, signature)
            .map_err(VerificationError::SignatureError)
    }
}

/// Error type for verification errors.
#[derive(Debug, Error)]
pub enum VerificationError<E: Error + Debug> {
    /// Codec error.
    #[error("Codec error: {0}")]
    EncodingError(E),

    /// Signature error.
    #[error("Signature error: {0}")]
    SignatureError(signature::Error),
}

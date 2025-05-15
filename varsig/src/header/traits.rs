use crate::codec::Codec;
use signature::{SignatureEncoding, Verifier};
use std::{error::Error, fmt::Debug};
use thiserror::Error;

// FIXME rename? Varsig?
pub trait Verify<T>: Codec<T> {
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
        let mut buffer = Vec::new();
        self.encode_payload(payload, &mut buffer)
            .map_err(VerificationError::EncodingError)?;
        verifier
            .verify(&buffer, signature)
            .map_err(VerificationError::VerificationError)
    }
}

/// Error type for verification errors.
#[derive(Error)]
pub enum VerificationError<E: Error> {
    /// Codec error.
    #[error(transparent)]
    EncodingError(E),

    /// Verification error.
    #[error(transparent)]
    VerificationError(signature::Error),
}

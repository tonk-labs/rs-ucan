use crate::codec::Codec;
use signature::{SignatureEncoding, Verifier};
use std::error::Error;
use thiserror::Error;

pub trait Verify {
    /// The signature type for the header.
    type Signature: SignatureEncoding;

    /// The associated signer (referenced or owned signing key for the header).
    type Verifier: Verifier<Self::Signature>;

    fn prefix(&self) -> u32;
    fn config(&self) -> Vec<u8>; // FIXME

    fn try_verify<T, C: Codec<T>>(
        &self,
        codec: &C,
        verifier: &Self::Verifier, // e.g. PK
        signature: &Self::Signature,
        payload: &T,
    ) -> Result<(), VerificationError<C::EncodingError>> {
        let mut buffer = Vec::new();
        codec
            .encode_payload(payload, &mut buffer)
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

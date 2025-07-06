use crate::codec::Codec;
use signature::{SignatureEncoding, Verifier};
use std::error::Error;
use thiserror::Error;

pub trait Verify {
    /// The signature type for the header.
    type Signature: SignatureEncoding;

    /// The associated signer (referenced or owned signing key for the header).
    type Verifier: Verifier<Self::Signature>;

    /// The prefix for the signature type.
    ///
    /// For example, EdDSA would be `0xED`.
    fn prefix(&self) -> u64;

    /// The configuration as [`u64`] tags.
    ///
    /// These will be automatically converted to LEB128 by the serializer.
    fn config_tags(&self) -> Vec<u64>;

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
    #[error("Verification error: {0}")]
    VerificationError(signature::Error),
}

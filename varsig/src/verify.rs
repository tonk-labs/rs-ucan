//! Signature verification and configuration.

use signature::SignatureEncoding;
use std::{error::Error, fmt::Debug, future::Future};
use thiserror::Error;

/// Describes a signature algorithm as multicodec tags.
///
/// This trait captures the metadata needed to encode/decode a signature
/// algorithm in a Varsig header (prefix tag, config tags, reconstruction
/// from tags). It does NOT know about signers or verifiers.
pub trait VarsigHeader: Sized + Debug {
    /// The signature type produced by this algorithm.
    type Signature: SignatureEncoding + Debug;

    /// The prefix for the signature type.
    ///
    /// For example, `EdDSA` would be `0xED`.
    fn prefix(&self) -> u64;

    /// The configuration as a series of [`u64`] tags.
    ///
    /// NOTE: these will be automatically converted to LEB128 by the serializer.
    fn config_tags(&self) -> Vec<u64>;

    /// Try to create a codec from a series of bytes.
    fn try_from_tags(bytes: &[u64]) -> Option<(Self, &[u64])>;
}

/// Can produce signatures of a given type.
///
/// Each signer type maps to exactly one signature type (associated type,
/// not type parameter). The connection to a [`VarsigHeader`] is via the
/// shared `Signature` type: `VarsigSigner::Signature == VarsigHeader::Signature`.
pub trait VarsigSigner {
    /// The signature type this signer produces.
    type Signature;

    /// Sign a message asynchronously.
    ///
    /// # Errors
    ///
    /// Returns `signature::Error` if signing fails.
    fn sign(&self, msg: &[u8]) -> impl Future<Output = Result<Self::Signature, signature::Error>>;
}

/// Can verify signatures of a given type.
///
/// Each verifier type maps to exactly one signature type (associated type,
/// not type parameter).
pub trait VarsigVerifier {
    /// The signature type this verifier checks.
    type Signature;

    /// Verify a signature for the given message asynchronously.
    ///
    /// # Errors
    ///
    /// Returns `signature::Error` if verification fails.
    fn verify(
        &self,
        msg: &[u8],
        signature: &Self::Signature,
    ) -> impl Future<Output = Result<(), signature::Error>>;
}

/// Error type for verification errors.
#[derive(Debug, Error)]
pub enum VerificationError<E: Error> {
    /// Codec error.
    #[error(transparent)]
    EncodingError(E),

    /// Verification error.
    #[error("Verification error: {0}")]
    VerificationError(signature::Error),
}

//! Signature verification and configuration.

use crate::codec::Codec;
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

/// Async signature verification trait.
///
/// This is the async counterpart to `signature::Verifier`. All verifiers
/// that implement `signature::Verifier` automatically get an `AsyncVerifier`
/// impl via the blanket implementation.
///
/// For algorithms backed by `WebCrypto` (or other async verification backends),
/// implement this trait directly.
pub trait AsyncVerifier<S> {
    /// Verify a signature for the given message asynchronously.
    ///
    /// # Errors
    ///
    /// Returns `signature::Error` if verification fails.
    fn verify_async(
        &self,
        msg: &[u8],
        signature: &S,
    ) -> impl Future<Output = Result<(), signature::Error>>;
}

/// Blanket implementation: any sync `Verifier` is automatically an `AsyncVerifier`.
impl<S, T: signature::Verifier<S>> AsyncVerifier<S> for T {
    async fn verify_async(&self, msg: &[u8], signature: &S) -> Result<(), signature::Error> {
        self.verify(msg, signature)
    }
}

/// A trait for signature verification (e.g. public keys).
///
/// This extends [`VarsigHeader`] with an associated verifier type.
/// During the transition, this trait is kept for backward compatibility.
pub trait Verify: VarsigHeader {
    /// The associated verifier (e.g. public key for the header).
    type Verifier: AsyncVerifier<Self::Signature> + Debug;

    /// Try to verify a signature for some payload.
    ///
    /// This method encodes the payload using the provided codec,
    /// then verifies the signature. The payload does not need to be
    /// serialized ahead of time (the `codec` field configures that).
    ///
    /// ## Parameters
    ///
    /// - `codec`: The codec to use for encoding the payload.
    /// - `verifier`: The verifier (e.g. public key) to use for verification.
    /// - `signature`: The signature to verify.
    /// - `payload`: The payload to verify the signature against.
    ///
    /// ## Returns
    ///
    /// Returns `Ok(())` on success, or an error of type `VerificationError` on failure.
    ///
    /// ## Errors
    ///
    /// If the encoding fails, it returns an error of type `VerificationError::EncodingError`.
    /// If the verification fails, it returns an error of type `VerificationError::VerificationError`.
    fn try_verify<T, C: Codec<T>>(
        &self,
        codec: &C,
        verifier: &Self::Verifier, // e.g. verifying ("public") key
        signature: &Self::Signature,
        payload: &T,
    ) -> impl Future<Output = Result<(), VerificationError<C::EncodingError>>> {
        async {
            let mut buffer = Vec::new();
            codec
                .encode_payload(payload, &mut buffer)
                .map_err(VerificationError::EncodingError)?;
            verifier
                .verify_async(&buffer, signature)
                .await
                .map_err(VerificationError::VerificationError)
        }
    }
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

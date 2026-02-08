//! Async verification trait.

use std::future::Future;

use crate::algorithm::SignatureAlgorithm;

/// Can verify signatures of a given type.
///
/// Each verifier type maps to exactly one signature algorithm
/// (via the associated `Algorithm` type).
pub trait Verifier {
    /// Cryptographic algorithm of the signature this verifier verifies.
    type Algorithm: SignatureAlgorithm;

    /// Verify that provided signature is for the given payload and was signed
    /// by the corresponding signer.
    ///
    /// # Errors
    ///
    /// Returns `signature::Error` if verification fails.
    fn verify(
        &self,
        payload: &[u8],
        signature: &<Self::Algorithm as SignatureAlgorithm>::Signature,
    ) -> impl Future<Output = Result<(), signature::Error>>;
}

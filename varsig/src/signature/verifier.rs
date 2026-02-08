//! Async verification trait.

use std::future::Future;

/// Can verify signatures of a given type.
///
/// Each verifier type maps to exactly one signature type (associated type,
/// not type parameter).
pub trait Verifier {
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

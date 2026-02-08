//! Async signing trait.

use std::future::Future;

/// Can produce signatures of a given type.
///
/// Each signer type maps to exactly one signature type (associated type,
/// not type parameter). The connection to a [`SignatureAlgorithm`](crate::algorithm::SignatureAlgorithm)
/// is via the shared `Signature` type: `Signer::Signature == SignatureAlgorithm::Signature`.
pub trait Signer {
    /// The signature type this signer produces.
    type Signature;

    /// Sign a message asynchronously.
    ///
    /// # Errors
    ///
    /// Returns `signature::Error` if signing fails.
    fn sign(&self, msg: &[u8]) -> impl Future<Output = Result<Self::Signature, signature::Error>>;
}

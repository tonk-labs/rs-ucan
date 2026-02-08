//! Async signing trait.

use std::future::Future;

use crate::algorithm::SignatureAlgorithm;

use super::verifier::Verifier;

/// Can produce signatures of a given type.
///
/// Each signer type maps to exactly one signature algorithm
/// (via the associated `Algorithm` type) and one principal (public identity).
pub trait Signer {
    /// The signature algorithm this signer uses.
    type Algorithm: SignatureAlgorithm;

    /// The principal (public identity) this signer signs as.
    type Principal: Verifier<Algorithm = Self::Algorithm>;

    /// Sign a given payload.
    ///
    /// # Errors
    ///
    /// Returns `signature::Error` if signing fails.
    fn sign(
        &self,
        payload: &[u8],
    ) -> impl Future<Output = Result<<Self::Algorithm as SignatureAlgorithm>::Signature, signature::Error>>;

    /// Get the principal (public identity) for this signer.
    fn principal(&self) -> &Self::Principal;
}

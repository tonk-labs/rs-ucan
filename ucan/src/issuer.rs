//! UCAN issuer trait.

use crate::principal::Principal;
use varsig::signature::signer::Signer;

/// A UCAN issuer — a signer whose principal is a UCAN [`Principal`].
///
/// Extends [`Signer`] with the constraint that its [`Principal`](Signer::Principal)
/// associated type satisfies the [`Principal`] trait. Automatically
/// implemented for any `Signer` that meets this requirement.
pub trait Issuer: Signer<Principal: Principal> {}

// Blanket implementation
impl<T> Issuer for T where T: Signer<Principal: Principal> {}

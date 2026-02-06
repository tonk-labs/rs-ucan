//! UCAN issuer trait.

use super::Principal;
use varsig::{algorithm::SignatureAlgorithm, signature::signer::Signer};

/// A UCAN issuer — a principal that can sign tokens.
///
/// An issuer **is** the signer: it implements [`Signer`] directly,
/// so there is no separate `.signer()` method.
pub trait Issuer:
    Signer<Signature = <<Self::Principal as Principal>::Algorithm as SignatureAlgorithm>::Signature>
{
    /// The associated principal type.
    type Principal: Principal + Clone;

    /// Get the principal (public identity) for this issuer.
    fn principal(&self) -> &Self::Principal;
}

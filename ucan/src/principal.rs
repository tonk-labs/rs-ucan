//! UCAN principal and issuer traits.

mod issuer;

use serde::{Deserialize, Serialize};
use std::{fmt::Debug, str::FromStr};
use varsig::{algorithm::SignatureAlgorithm, signature::verifier::Verifier};

pub use issuer::Issuer;

const KEY: &str = "key";

/// A UCAN principal identified by a [DID].
///
/// A principal **is** the verifier: it implements [`Verifier`] directly,
/// so there is no separate `.verifier()` method.
///
/// [DID]: https://en.wikipedia.org/wiki/Decentralized_identifier
pub trait Principal:
    PartialEq
    + ToString
    + FromStr
    + Serialize
    + for<'de> Deserialize<'de>
    + Debug
    + Verifier<Signature = <Self::Algorithm as SignatureAlgorithm>::Signature>
{
    /// The signature algorithm for this principal.
    type Algorithm: SignatureAlgorithm + Clone;

    /// Get the DID method header (e.g. `key` for `did:key`).
    ///
    /// Defaults to `"key"` since `did:key` is the most common method.
    fn did_method(&self) -> &str {
        KEY
    }
}

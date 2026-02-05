//! Decentralized Identifier (DID) helpers.

pub mod ed25519;

use serde::{Deserialize, Serialize};
use std::{fmt::Debug, str::FromStr};
use varsig::{signer::Sign, verify::Verify};

pub use ed25519::{Ed25519Did, Ed25519DidFromStrError, Ed25519Signer};
pub use varsig::signer::KeyExport;

/// A trait for [DID]s.
///
/// [DID]: https://en.wikipedia.org/wiki/Decentralized_identifier
pub trait Did:
    PartialEq + ToString + FromStr + Serialize + for<'de> Deserialize<'de> + Debug
{
    /// The associated `Varsig` configuration.
    type VarsigConfig: Sign + Clone;

    /// Get the DID method header (e.g. `key` for `did-keys`)
    fn did_method(&self) -> &str;

    /// Get the associated `Varsig` configuration.
    fn varsig_config(&self) -> &Self::VarsigConfig;

    /// Get the verifier (e.g. public key) for signature verification.
    fn verifier(&self) -> <Self::VarsigConfig as Verify>::Verifier;
}

/// A trait for DID signers.
///
/// This trait provides access to the signer instance associated with a DID.
/// The signer must implement `AsyncSigner` from the varsig `Sign` trait.
pub trait DidSigner {
    /// The associated DID type.
    type Did: Did + Clone;

    /// Get the associated DID.
    fn did(&self) -> &Self::Did;

    /// Get the associated signer instance.
    fn signer(&self) -> &<<Self::Did as Did>::VarsigConfig as Sign>::Signer;
}

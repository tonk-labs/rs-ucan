//! Decentralized Identifier (DID) helpers.

#[cfg(feature = "ed25519")]
pub mod ed25519;

use serde::{Deserialize, Serialize};
use std::{fmt::Debug, str::FromStr};
use varsig::verify::{VarsigHeader, VarsigSigner, VarsigVerifier};

#[cfg(feature = "ed25519")]
pub use ed25519::{Ed25519Did, Ed25519DidFromStrError, Ed25519Signer, KeyExport};

/// A trait for [DID]s.
///
/// A DID **is** the verifier: it implements [`VarsigVerifier`] directly,
/// so there is no separate `.verifier()` method.
///
/// [DID]: https://en.wikipedia.org/wiki/Decentralized_identifier
pub trait Did:
    PartialEq
    + ToString
    + FromStr
    + Serialize
    + for<'de> Deserialize<'de>
    + Debug
    + VarsigVerifier<Signature = <Self::VarsigConfig as VarsigHeader>::Signature>
{
    /// The associated `Varsig` configuration.
    type VarsigConfig: VarsigHeader + Clone;

    /// Get the DID method header (e.g. `key` for `did-keys`)
    fn did_method(&self) -> &str;

    /// Get the associated `Varsig` configuration.
    fn varsig_config(&self) -> &Self::VarsigConfig;
}

/// A trait for DID signers.
///
/// A DID signer **is** the signer: it implements [`VarsigSigner`] directly,
/// so there is no separate `.signer()` method.
pub trait DidSigner:
    VarsigSigner<
        Signature = <<Self::Did as Did>::VarsigConfig as VarsigHeader>::Signature,
    >
{
    /// The associated DID type.
    type Did: Did + Clone;

    /// Get the associated DID.
    fn did(&self) -> &Self::Did;
}

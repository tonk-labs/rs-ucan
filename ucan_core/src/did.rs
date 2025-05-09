//! Decentralized Identifier (DID) helpers.

use signature::{SignatureEncoding, Signer, Verifier};
use std::{fmt::Debug, str::FromStr};

/// A trait for [DID]s.
///
/// [DID]: https://en.wikipedia.org/wiki/Decentralized_identifier
pub trait Did: PartialEq + ToString + FromStr + Verifier<Self::Signature> {
    /// The signature type for the DID
    type Signature: SignatureEncoding + PartialEq + Debug;

    /// The associated signer (referenced or owned signing key for the DID)
    type Signer: Signer<Self::Signature> + Debug;
}

//! Decentralized Identifier (DID) helpers.

use std::{fmt::Debug, str::FromStr};
use varsig::{signer::Sign, verify::Verify};

/// A trait for [DID]s.
///
/// [DID]: https://en.wikipedia.org/wiki/Decentralized_identifier
pub trait Did: PartialEq + ToString + FromStr + Verify {
    fn did_method(&self) -> &str;
}

// FIXME rename issuer?
pub trait DidSigner: Sign + Debug {
    type Did: Did;

    fn did(&self) -> &Self::Did;
    fn signer(&self) -> &Self::Signer;
}

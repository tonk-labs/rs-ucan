//! UCAN principal trait.

use serde::{Deserialize, Serialize};
use std::{fmt::Debug, str::FromStr};
use varsig::signature::verifier::Verifier;

const KEY: &str = "key";

/// A UCAN principal — a DID-identified verifier.
///
/// Automatically implemented for any `Verifier` that also satisfies
/// DID-string and serialization requirements.
pub trait Principal:
    Verifier + Clone + PartialEq + ToString + FromStr + Serialize + for<'de> Deserialize<'de> + Debug
{
    /// Get the DID method header (e.g. `key` for `did:key`).
    ///
    /// Defaults to `"key"` since `did:key` is the most common method.
    fn did_method(&self) -> &str {
        KEY
    }
}

// Blanket implementation
impl<T> Principal for T where
    T: Verifier
        + Clone
        + PartialEq
        + ToString
        + FromStr
        + Serialize
        + for<'de> Deserialize<'de>
        + Debug
{
}

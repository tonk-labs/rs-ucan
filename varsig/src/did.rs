//! DID (Decentralized Identifier) types.

use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// A [Decentralized Identifier][spec] string.
///
/// Wraps a raw DID string like `did:key:z6Mk...` or `did:web:example.com`.
/// Use [`method()`][Did::method] to inspect the DID method at runtime.
///
/// [spec]: https://www.w3.org/TR/did-core/
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Did(String);

impl Did {
    /// Create a `Did` from a raw DID string.
    ///
    /// Does not validate the string — use [`FromStr`] for validation.
    #[must_use]
    pub const fn new(raw: String) -> Self {
        Self(raw)
    }

    /// Get the raw DID string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the DID method name (e.g. `"key"` for `did:key:...`,
    /// `"web"` for `did:web:...`).
    ///
    /// # Panics
    ///
    /// Panics if the DID string is malformed (no second `:`). This
    /// cannot happen for values created via [`FromStr`].
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn method(&self) -> &str {
        let after_did = &self.0["did:".len()..];
        after_did
            .split(':')
            .next()
            .expect("DID has no method segment")
    }
}

impl fmt::Debug for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Error when parsing a DID string.
#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid DID: {0}")]
pub struct DidParseError(pub String);

impl FromStr for Did {
    type Err = DidParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("did:") {
            return Err(DidParseError(format!("expected did: prefix, got: {s}")));
        }
        // Must have at least did:method:identifier
        let rest = &s["did:".len()..];
        if !rest.contains(':') {
            return Err(DidParseError(format!(
                "expected did:method:identifier, got: {s}"
            )));
        }
        Ok(Did(s.to_string()))
    }
}

impl Serialize for Did {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Did {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

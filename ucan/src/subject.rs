//! UCAN Subject type.

use serde::{de::Deserialize, ser::Serializer, Serialize};
use std::fmt::Display;
use varsig::did::Did;

/// The Subject of a delegation.
///
/// This represents what is being delegated to be later invoked.
/// To allow for powerline delegation (a node in the auth graph
/// that is a mere proxy for ANY capability), the wildcard `Any`
/// may be used.
///
/// Since it is so powerful, only use `Any` directly if you know
/// what you're doing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Hash)]
pub enum Subject {
    /// A specific subject (recommended)
    Specific(Did),

    /// A wildcard subject (specialized use case)
    Any,
}

impl Subject {
    /// Check that the [`Subject`] either matches the given DID, or is `Any`.
    #[must_use]
    pub fn allows(&self, subject: &Did) -> bool {
        match self {
            Subject::Specific(did) => did == subject,
            Subject::Any => true,
        }
    }

    /// Both sides match, or one is `Any`.
    #[must_use]
    pub fn coherent(&self, other: &Self) -> bool {
        match (self, other) {
            (Subject::Any, _) | (_, Subject::Any) => true,
            (Subject::Specific(did), Subject::Specific(other_did)) => did == other_did,
        }
    }
}

impl From<Did> for Subject {
    fn from(subject: Did) -> Self {
        Subject::Specific(subject)
    }
}

impl Display for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Subject::Specific(did) => Display::fmt(did, f),
            Subject::Any => "Null".fmt(f),
        }
    }
}

impl Serialize for Subject {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Subject::Specific(did) => did.serialize(serializer),
            Subject::Any => serializer.serialize_none(),
        }
    }
}

impl<'de> Deserialize<'de> for Subject {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_value::Value::deserialize(deserializer)?;

        if value == serde_value::Value::Option(None) {
            return Ok(Subject::Any);
        }

        if let Ok(did) = Did::deserialize(value.clone()) {
            return Ok(Subject::Specific(did));
        }

        Err(serde::de::Error::custom("invalid subject format"))
    }
}

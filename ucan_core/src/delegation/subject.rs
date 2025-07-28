//! Subject of a delegation

use crate::did::Did;
use serde::{ser::Serializer, Deserialize, Serialize};
use std::fmt::Display;

/// The Subject of a delegation
///
/// This represents what is being delegated to be later invoked.
/// To allow for powerline delegation (a node in the auth graph
/// that is a mere proxy for ANY capability), the wildcard `Any`
/// may be used.
///
/// Since it is so powerful, only use `Any` directly if you know
/// what you're doing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Hash)]
pub enum DelegatedSubject<D: Did> {
    /// A specific subject (recommended)
    Specific(D),

    /// A wildcard subject (secialized use case)
    Any,
}

impl<D: Did> From<D> for DelegatedSubject<D> {
    fn from(subject: D) -> Self {
        DelegatedSubject::Specific(subject)
    }
}

impl<D: Did + Display> Display for DelegatedSubject<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DelegatedSubject::Specific(did) => did.fmt(f),
            DelegatedSubject::Any => "*".fmt(f),
        }
    }
}

impl<D: Did + Serialize> Serialize for DelegatedSubject<D> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            DelegatedSubject::Specific(did) => did.serialize(serializer),
            DelegatedSubject::Any => serializer.serialize_str("*"),
        }
    }
}

impl<'de, I: Did + Deserialize<'de>> serde::Deserialize<'de> for DelegatedSubject<I> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_value::Value::deserialize(deserializer)?;

        if let Ok(did) = I::deserialize(value.clone()) {
            return Ok(DelegatedSubject::Specific(did));
        }

        if let Ok(s) = String::deserialize(value) {
            if s == "*" {
                return Ok(DelegatedSubject::Any);
            }
        }

        Err(serde::de::Error::custom("invalid subject format"))
    }
}

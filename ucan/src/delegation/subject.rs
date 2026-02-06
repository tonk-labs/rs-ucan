//! Subject of a delegation

use crate::principal::Principal;
use serde::{de::Deserialize, ser::Serializer, Serialize};
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
pub enum DelegatedSubject<D: Principal> {
    /// A specific subject (recommended)
    Specific(D),

    /// A wildcard subject (specialized use case)
    Any,
}

impl<D: Principal> DelegatedSubject<D> {
    /// Check that the [`DelegatedSubject`] either matches the subject, or is `Any`.
    pub fn allows(&self, subject: &D) -> bool {
        match self {
            DelegatedSubject::Specific(did) => did == subject,
            DelegatedSubject::Any => true,
        }
    }

    /// Both sides match, or one is `Any`.
    pub fn coherent(&self, other: &Self) -> bool {
        match (self, other) {
            (DelegatedSubject::Any, _) | (_, DelegatedSubject::Any) => true,
            (DelegatedSubject::Specific(did), DelegatedSubject::Specific(other_did)) => {
                did == other_did
            }
        }
    }
}

impl<D: Principal> From<D> for DelegatedSubject<D> {
    fn from(subject: D) -> Self {
        DelegatedSubject::Specific(subject)
    }
}

impl<D: Principal + Display> Display for DelegatedSubject<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DelegatedSubject::Specific(did) => Display::fmt(did, f),
            DelegatedSubject::Any => "Null".fmt(f),
        }
    }
}

impl<D: Principal + Serialize> Serialize for DelegatedSubject<D> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            DelegatedSubject::Specific(did) => did.serialize(serializer),
            DelegatedSubject::Any => serializer.serialize_none(),
        }
    }
}

impl<'de, I: Principal> Deserialize<'de> for DelegatedSubject<I> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_value::Value::deserialize(deserializer)?;

        if value == serde_value::Value::Option(None) {
            return Ok(DelegatedSubject::Any);
        }

        if let Ok(did) = I::deserialize(value.clone()) {
            return Ok(DelegatedSubject::Specific(did));
        }

        Err(serde::de::Error::custom("invalid subject format"))
    }
}


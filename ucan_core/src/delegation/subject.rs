//! Subject of a delegation

use crate::did::Did;
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

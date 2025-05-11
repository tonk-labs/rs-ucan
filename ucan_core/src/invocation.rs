//! UCAN Invocation

pub mod builder;

use self::builder::InvocationBuilder;
use crate::{crypto::nonce::Nonce, did::Did, promise::Promised, time::timestamp::Timestamp};
use ipld_core::{cid::Cid, ipld::Ipld};
use std::collections::BTreeMap;

/// UCAN Invocation
///
/// Invoke a UCAN capability. This type implements the
/// [UCAN Invocation spec](https://github.com/ucan-wg/invocation/README.md).
#[derive(Debug, Clone, PartialEq)]
pub struct Invocation<D: Did> {
    pub(crate) issuer: D,
    pub(crate) audience: D,

    pub(crate) subject: D,
    pub(crate) command: Vec<String>,
    pub(crate) arguments: BTreeMap<String, Promised>,

    pub(crate) proofs: Vec<Cid>,
    pub(crate) cause: Option<Cid>,

    pub(crate) issued_at: Option<Timestamp>,
    pub(crate) expiration: Option<Timestamp>,

    pub(crate) meta: BTreeMap<String, Ipld>,
    pub(crate) nonce: Nonce,
}

impl<D: Did> Invocation<D> {
    /// Creates a blank [`DelegationBuilder`] instance.
    #[must_use]
    pub const fn builder() -> InvocationBuilder<D> {
        InvocationBuilder::new()
    }

    /// Getter for the `issuer` field.
    pub const fn issuer(&self) -> &D {
        &self.issuer
    }

    /// Getter for the `audience` field.
    pub const fn audience(&self) -> &D {
        &self.audience
    }

    /// Getter for the `subject` field.
    pub const fn subject(&self) -> &D {
        &self.subject
    }

    /// Getter for the `command` field.
    pub const fn command(&self) -> &Vec<String> {
        &self.command
    }

    /// Getter for the `arguments` field.
    pub const fn arguments(&self) -> &BTreeMap<String, Promised> {
        &self.arguments
    }

    /// Getter for the `proofs` field.
    pub const fn proofs(&self) -> &Vec<Cid> {
        &self.proofs
    }

    /// Getter for the `cause` field.
    pub const fn cause(&self) -> Option<Cid> {
        self.cause
    }

    /// Getter for the `expiration` field.
    pub const fn expiration(&self) -> Option<Timestamp> {
        self.expiration
    }

    /// Getter for the `meta` field.
    pub const fn meta(&self) -> &BTreeMap<String, Ipld> {
        &self.meta
    }

    /// Getter for the `nonce` field.
    pub const fn nonce(&self) -> &Nonce {
        &self.nonce
    }
}

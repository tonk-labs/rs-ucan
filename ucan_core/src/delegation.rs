//! UCAN Delegation

pub mod builder;
pub mod policy;
pub mod subject;

use self::subject::DelegatedSubject;
use crate::{crypto::nonce::Nonce, did::Did, time::timestamp::Timestamp, unset::Unset};
use builder::DelegationBuilder;
use ipld_core::ipld::Ipld;
use policy::predicate::Predicate;
use std::collections::BTreeMap;

// FIXME tag the spec and link to taht instead
/// UCAN Delegation
///
/// Grant or delegate a UCAN capability to another. This type implements the
/// [UCAN Delegation spec](https://github.com/ucan-wg/delegation/README.md).
#[derive(Debug, Clone, PartialEq)]
pub struct Delegation<D: Did> {
    pub(crate) issuer: D,
    pub(crate) audience: D,

    pub(crate) subject: DelegatedSubject<D>,
    pub(crate) command: Vec<String>,
    pub(crate) policy: Vec<Predicate>,

    pub(crate) expiration: Option<Timestamp>,
    pub(crate) not_before: Option<Timestamp>,

    pub(crate) meta: BTreeMap<String, Ipld>,
    pub(crate) nonce: Nonce,
}

impl<D: Did> Delegation<D> {
    /// Creates a blank [`DelegationBuilder`] instance.
    #[must_use]
    pub const fn builder() -> DelegationBuilder<D, Unset, Unset, Unset, Unset> {
        DelegationBuilder::new()
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
    pub const fn subject(&self) -> &DelegatedSubject<D> {
        &self.subject
    }

    /// Getter for the `command` field.
    pub const fn command(&self) -> &Vec<String> {
        &self.command
    }

    /// Getter for the `policy` field.
    pub const fn policy(&self) -> &Vec<Predicate> {
        &self.policy
    }

    /// Getter for the `expiration` field.
    pub const fn expiration(&self) -> Option<Timestamp> {
        self.expiration
    }

    /// Getter for the `not_before` field.
    pub const fn not_before(&self) -> Option<Timestamp> {
        self.not_before
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

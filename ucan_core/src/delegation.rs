//! UCAN Delegation

pub mod builder;
pub mod policy;
pub mod subject;

use self::subject::DelegatedSubject;
use crate::{crypto::nonce::Nonce, did::Did, time::timestamp::Timestamp};
use builder::{DelegationBuilder, Unset};
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
    pub fn builder() -> DelegationBuilder<D, Unset, Unset, Unset, Unset> {
        DelegationBuilder::new()
    }

    /// Getter for the issuer field.
    pub fn issuer(&self) -> &D {
        &self.issuer
    }

    /// Getter for the audience field.
    pub fn audience(&self) -> &D {
        &self.audience
    }

    /// Getter for the subject field.
    pub fn subject(&self) -> &DelegatedSubject<D> {
        &self.subject
    }

    /// Getter for the command field.
    pub fn command(&self) -> &[String] {
        &self.command
    }

    /// Getter for the policy field.
    pub fn policy(&self) -> &[Predicate] {
        &self.policy
    }

    /// Getter for the expiration field.
    pub fn expiration(&self) -> Option<&Timestamp> {
        self.expiration.as_ref()
    }

    /// Getter for the not_before field.
    pub fn not_before(&self) -> Option<&Timestamp> {
        self.not_before.as_ref()
    }

    /// Getter for the meta field.
    pub fn meta(&self) -> &BTreeMap<String, Ipld> {
        &self.meta
    }

    /// Getter for the nonce.
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }
}

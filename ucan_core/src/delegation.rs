//! UCAN Delegation
//!
//! The spec for UCAN Delegations can be found at
//! [the GitHub repo](https://github.com/ucan-wg/invocation/).

pub mod builder;
pub mod policy;
pub mod subject;

use self::subject::DelegatedSubject;
use crate::{
    crypto::nonce::Nonce,
    did::{Did, DidSigner},
    envelope::Envelope,
    time::timestamp::Timestamp,
    unset::Unset,
};
use builder::DelegationBuilder;
use ipld_core::ipld::Ipld;
use policy::predicate::Predicate;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt::Debug};
use varsig::verify::Verify;

/// Top-level UCAN Delegation.
#[derive(Clone)]
pub struct Delegation<D: Did>(
    Envelope<D::VarsigConfig, DelegationPayload<D>, <D::VarsigConfig as Verify>::Signature>,
);

impl<D: Did> Delegation<D> {
    /// Creates a blank [`DelegationBuilder`] instance.
    #[must_use]
    pub const fn builder<S: DidSigner<Did = D>>() -> DelegationBuilder<S, Unset, Unset, Unset, Unset>
    {
        DelegationBuilder::new()
    }

    /// Getter for the `issuer` field.
    pub const fn issuer(&self) -> &D {
        &self.0 .1.payload.issuer
    }

    /// Getter for the `audience` field.
    pub const fn audience(&self) -> &D {
        &self.0 .1.payload.audience
    }

    /// Getter for the `subject` field.
    pub const fn subject(&self) -> &DelegatedSubject<D> {
        &self.0 .1.payload.subject
    }

    /// Getter for the `command` field.
    pub const fn command(&self) -> &Vec<String> {
        &self.0 .1.payload.command
    }

    /// Getter for the `policy` field.
    pub const fn policy(&self) -> &Vec<Predicate> {
        &self.0 .1.payload.policy
    }

    /// Getter for the `expiration` field.
    pub const fn expiration(&self) -> Option<Timestamp> {
        self.0 .1.payload.expiration
    }

    /// Getter for the `not_before` field.
    pub const fn not_before(&self) -> Option<Timestamp> {
        self.0 .1.payload.not_before
    }

    /// Getter for the `meta` field.
    pub const fn meta(&self) -> &BTreeMap<String, Ipld> {
        &self.0 .1.payload.meta
    }

    /// Getter for the `nonce` field.
    pub const fn nonce(&self) -> &Nonce {
        &self.0 .1.payload.nonce
    }
}

impl<D: Did> Debug for Delegation<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Delegation").field(&self.0).finish()
    }
}

impl<D: Did> Serialize for Delegation<D> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, I: Did> Deserialize<'de> for Delegation<I>
where
    <I::VarsigConfig as Verify>::Signature: for<'ze> Deserialize<'ze>,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let envelope = Envelope::<_, _, _>::deserialize(deserializer)?;
        Ok(Delegation(envelope))
    }
}

/// UCAN Delegation
///
/// Grant or delegate a UCAN capability to another. This type implements the
/// [UCAN Delegation spec](https://github.com/ucan-wg/delegation/README.md).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound(deserialize = "D: Did"))]
pub struct DelegationPayload<D: Did> {
    #[serde(rename = "iss")]
    pub(crate) issuer: D,

    #[serde(rename = "aud")]
    pub(crate) audience: D,

    #[serde(rename = "sub")]
    pub(crate) subject: DelegatedSubject<D>,

    #[serde(rename = "cmd")]
    pub(crate) command: Vec<String>,

    #[serde(rename = "pol")]
    pub(crate) policy: Vec<Predicate>,

    #[serde(rename = "exp")]
    pub(crate) expiration: Option<Timestamp>,

    #[serde(rename = "nbf")]
    pub(crate) not_before: Option<Timestamp>,

    pub(crate) meta: BTreeMap<String, Ipld>,
    pub(crate) nonce: Nonce,
}

impl<D: Did> DelegationPayload<D> {
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

#[cfg(test)]
mod tests {
    use crate::did::Ed25519Signer;

    use super::*;
    use testresult::TestResult;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct EdKey(ed25519_dalek::VerifyingKey);

    #[test]
    fn issuer_round_trip() -> TestResult {
        let iss: Ed25519Signer = ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]).into();
        let aud = ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32]).unwrap();
        let sub = ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32]).unwrap();

        let delegation = DelegationBuilder::new()
            .issuer(iss)
            .audience(aud)
            .subject(DelegatedSubject::Specific(sub))
            .command(vec!["read".to_string(), "write".to_string()])
            .try_build()?;

        dbg!(&delegation.issuer().to_string());

        assert_eq!(delegation.issuer().to_string(), "did:example:alice");
        Ok(())
    }
}

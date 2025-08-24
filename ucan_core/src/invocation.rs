//! UCAN Invocation

pub mod builder;

use self::builder::InvocationBuilder;
use crate::{
    crypto::nonce::Nonce, did::Did, envelope::Envelope, promise::Promised,
    time::timestamp::Timestamp,
};
use ipld_core::{cid::Cid, ipld::Ipld};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt::Debug};
use varsig::verify::Verify;

#[derive(Clone)]
pub struct Invocation<V: Verify, D: Did + Serialize + for<'de> Deserialize<'de>>(
    Envelope<V, InvocationPayload<D>, <V as Verify>::Signature>,
);

impl<V: Verify + Debug, D: Did + Serialize + for<'de> Deserialize<'de> + Debug> Debug
    for Invocation<V, D>
where
    <V as Verify>::Signature: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Invocation").field(&self.0).finish()
    }
}

impl<V: Verify + Serialize, D: Did + Serialize + for<'de> Deserialize<'de>> Serialize
    for Invocation<V, D>
where
    <V as Verify>::Signature: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, V: Verify + Deserialize<'de>, I: Did + Serialize + for<'ze> Deserialize<'ze>>
    Deserialize<'de> for Invocation<V, I>
where
    <V as Verify>::Signature: for<'xe> Deserialize<'xe>,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let envelope = Envelope::<_, _, _>::deserialize(deserializer)?;
        Ok(Invocation(envelope))
    }
}

/// UCAN Invocation
///
/// Invoke a UCAN capability. This type implements the
/// [UCAN Invocation spec](https://github.com/ucan-wg/invocation/README.md).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvocationPayload<D: Did> {
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

impl<D: Did> InvocationPayload<D> {
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

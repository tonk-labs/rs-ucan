//! UCAN Delegation
//!
//! The spec for UCAN Delegations can be found at
//! [the GitHub repo](https://github.com/ucan-wg/invocation/).

pub mod builder;
pub mod policy;
pub mod store;
pub mod subject;

use self::subject::DelegatedSubject;
use crate::{
    cid::to_dagcbor_cid,
    command::Command,
    crypto::nonce::Nonce,
    envelope::{payload_tag::PayloadTag, Envelope},
    principal::{Issuer, Principal},
    time::timestamp::Timestamp,
    unset::Unset,
};
use builder::DelegationBuilder;
use ipld_core::{cid::Cid, ipld::Ipld};
use policy::predicate::Predicate;
use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use std::{borrow::Cow, collections::BTreeMap, fmt::Debug};
use varsig::algorithm::SignatureAlgorithm;

/// Top-level UCAN Delegation.
#[derive(Clone)]
pub struct Delegation<D: Principal>(
    Envelope<D::Algorithm, DelegationPayload<D>, <D::Algorithm as SignatureAlgorithm>::Signature>,
);

impl<D: Principal> Delegation<D> {
    /// Creates a blank [`DelegationBuilder`] instance.
    #[must_use]
    pub const fn builder<S: Issuer<Principal = D>>(
    ) -> DelegationBuilder<S, Unset, Unset, Unset, Unset> {
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
    pub const fn command(&self) -> &Command {
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

    /// Compute the CID for this delegation.
    pub fn to_cid(&self) -> Cid {
        to_dagcbor_cid(&self)
    }

    /// Verify only the signature of this delegation.
    ///
    /// # Errors
    ///
    /// Returns an error if signature verification fails.
    pub async fn verify_signature(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let signature = &self.0 .0;
        let header = &self.0 .1.header;
        let payload = &self.0 .1.payload;
        header
            .verify(payload.issuer(), payload, signature)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }
}

impl<D: Principal> Debug for Delegation<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Delegation").field(&self.0).finish()
    }
}

impl<D: Principal> Serialize for Delegation<D> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, I: Principal> Deserialize<'de> for Delegation<I>
where
    <I::Algorithm as SignatureAlgorithm>::Signature: for<'ze> Deserialize<'ze>,
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
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DelegationPayload<D: Principal> {
    #[serde(rename = "iss")]
    pub(crate) issuer: D,

    #[serde(rename = "aud")]
    pub(crate) audience: D,

    #[serde(rename = "sub")]
    pub(crate) subject: DelegatedSubject<D>,

    #[serde(rename = "cmd")]
    pub(crate) command: Command,

    #[serde(rename = "pol")]
    pub(crate) policy: Vec<Predicate>,

    #[serde(rename = "exp")]
    pub(crate) expiration: Option<Timestamp>,

    #[serde(rename = "nbf")]
    pub(crate) not_before: Option<Timestamp>,

    pub(crate) meta: BTreeMap<String, Ipld>,
    pub(crate) nonce: Nonce,
}

impl<D: Principal> DelegationPayload<D> {
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
    pub const fn command(&self) -> &Command {
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

impl<'de, D> Deserialize<'de> for DelegationPayload<D>
where
    D: Principal,
    DelegatedSubject<D>: Deserialize<'de>,
    Predicate: Deserialize<'de>,
    Timestamp: Deserialize<'de>,
    Nonce: Deserialize<'de>,
    Ipld: Deserialize<'de>,
{
    #[allow(clippy::too_many_lines)]
    fn deserialize<T>(deserializer: T) -> Result<Self, T::Error>
    where
        T: Deserializer<'de>,
    {
        struct PayloadVisitor<D: Principal>(std::marker::PhantomData<D>);

        impl<'de, D> Visitor<'de> for PayloadVisitor<D>
        where
            D: Principal,
            DelegatedSubject<D>: Deserialize<'de>,
            Predicate: Deserialize<'de>,
            Timestamp: Deserialize<'de>,
            Nonce: Deserialize<'de>,
            Ipld: Deserialize<'de>,
        {
            type Value = DelegationPayload<D>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a map with keys iss,aud,sub,cmd,pol,exp,nbf,meta,nonce")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut issuer: Option<D> = None;
                let mut audience: Option<D> = None;
                let mut subject: Option<DelegatedSubject<D>> = None;
                let mut command: Option<Command> = None;
                let mut policy: Option<Vec<Predicate>> = None;
                let mut expiration: Option<Option<Timestamp>> = None;
                let mut not_before: Option<Option<Timestamp>> = None;
                let mut meta: Option<BTreeMap<String, Ipld>> = None;
                let mut nonce: Option<Nonce> = None;

                while let Some(key) = map.next_key::<Cow<'de, str>>()? {
                    match key.as_ref() {
                        "iss" => {
                            if issuer.is_some() {
                                return Err(de::Error::duplicate_field("iss"));
                            }
                            issuer = Some(map.next_value()?);
                        }
                        "aud" => {
                            if audience.is_some() {
                                return Err(de::Error::duplicate_field("aud"));
                            }
                            audience = Some(map.next_value()?);
                        }
                        "sub" => {
                            if subject.is_some() {
                                return Err(de::Error::duplicate_field("sub"));
                            }
                            subject = Some(map.next_value()?);
                        }
                        "cmd" => {
                            if command.is_some() {
                                return Err(de::Error::duplicate_field("cmd"));
                            }
                            let cmd: Command = map.next_value()?;
                            command = Some(cmd);
                        }
                        "pol" => {
                            if policy.is_some() {
                                return Err(de::Error::duplicate_field("pol"));
                            }
                            policy = Some(map.next_value()?);
                        }
                        "exp" => {
                            if expiration.is_some() {
                                return Err(de::Error::duplicate_field("exp"));
                            }
                            expiration = Some(map.next_value()?);
                        }
                        "nbf" => {
                            if not_before.is_some() {
                                return Err(de::Error::duplicate_field("nbf"));
                            }
                            not_before = Some(map.next_value()?);
                        }
                        "meta" => {
                            if meta.is_some() {
                                return Err(de::Error::duplicate_field("meta"));
                            }
                            meta = Some(map.next_value()?);
                        }
                        "nonce" => {
                            if nonce.is_some() {
                                return Err(de::Error::duplicate_field("nonce"));
                            }
                            let ipld: Ipld = map.next_value()?;
                            let v = match ipld {
                                Ipld::Bytes(b) => b,
                                Ipld::String(s) => {
                                    return Err(de::Error::invalid_type(
                                        de::Unexpected::Str(&s),
                                        &"bytes",
                                    ));
                                }
                                Ipld::Integer(i) => {
                                    return Err(de::Error::invalid_type(
                                        de::Unexpected::Other(&i.to_string()),
                                        &"bytes",
                                    ));
                                }
                                Ipld::Float(f) => {
                                    return Err(de::Error::invalid_type(
                                        de::Unexpected::Float(f),
                                        &"bytes",
                                    ));
                                }
                                Ipld::Bool(b) => {
                                    return Err(de::Error::invalid_type(
                                        de::Unexpected::Bool(b),
                                        &"bytes",
                                    ));
                                }
                                Ipld::Null => {
                                    return Err(de::Error::invalid_type(
                                        de::Unexpected::Unit,
                                        &"bytes",
                                    ));
                                }
                                Ipld::List(_) => {
                                    return Err(de::Error::invalid_type(
                                        de::Unexpected::Other("list"),
                                        &"bytes",
                                    ));
                                }
                                Ipld::Map(_) => {
                                    return Err(de::Error::invalid_type(
                                        de::Unexpected::Map,
                                        &"bytes",
                                    ));
                                }
                                Ipld::Link(_) => {
                                    return Err(de::Error::invalid_type(
                                        de::Unexpected::Other("link"),
                                        &"bytes",
                                    ));
                                }
                            };

                            if let Ok(arr) = <[u8; 16]>::try_from(v.clone()) {
                                nonce = Some(Nonce::Nonce16(arr));
                            } else {
                                nonce = Some(Nonce::Custom(v));
                            }
                        }
                        other => {
                            return Err(de::Error::unknown_field(
                                other,
                                &[
                                    "iss", "aud", "sub", "cmd", "pol", "exp", "nbf", "meta",
                                    "nonce",
                                ],
                            ));
                        }
                    }
                }

                let issuer = issuer.ok_or_else(|| de::Error::missing_field("iss"))?;
                let audience = audience.ok_or_else(|| de::Error::missing_field("aud"))?;
                let subject = subject.ok_or_else(|| de::Error::missing_field("sub"))?;
                let command = command.ok_or_else(|| de::Error::missing_field("cmd"))?;
                let policy = policy.ok_or_else(|| de::Error::missing_field("pol"))?;
                let nonce = nonce.ok_or_else(|| de::Error::missing_field("nonce"))?;

                Ok(DelegationPayload {
                    issuer,
                    audience,
                    subject,
                    command,
                    policy,
                    nonce,
                    expiration: expiration.unwrap_or(None),
                    not_before: not_before.unwrap_or(None),
                    meta: meta.unwrap_or_default(),
                })
            }
        }

        deserializer.deserialize_map(PayloadVisitor::<D>(std::marker::PhantomData))
    }
}

impl<D: Principal> PayloadTag for DelegationPayload<D> {
    fn spec_id() -> &'static str {
        "dlg"
    }

    fn version() -> &'static str {
        "1.0.0-rc.1"
    }
}

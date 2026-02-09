//! UCAN Delegation
//!
//! The spec for UCAN Delegations can be found at
//! [the GitHub repo](https://github.com/ucan-wg/invocation/).

pub mod builder;
pub mod policy;
pub mod store;

use crate::{
    cid::to_dagcbor_cid,
    command::Command,
    crypto::nonce::Nonce,
    envelope::{payload_tag::PayloadTag, Envelope},
    subject::Subject,
    time::timestamp::Timestamp,
};
use ipld_core::{cid::Cid, ipld::Ipld};
use policy::predicate::Predicate;
use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_ipld_dagcbor::error::CodecError;
use std::{borrow::Cow, collections::BTreeMap, fmt::Debug};
use varsig::{did::Did, signature::Signature};

/// Top-level UCAN Delegation.
///
/// Parameterized by `S: Signature` — the signature type (e.g. `Ed25519Signature`).
#[derive(Clone)]
pub struct Delegation<S: Signature>(Envelope<S, DelegationPayload>);

impl<S: Signature> Delegation<S> {
    /// Creates a blank [`DelegationBuilder`][builder::DelegationBuilder] instance.
    #[must_use]
    pub const fn builder() -> builder::DelegationBuilder<S> {
        builder::DelegationBuilder::new()
    }

    /// Getter for the `issuer` field.
    #[must_use]
    pub const fn issuer(&self) -> &Did {
        &self.0 .1.payload.issuer
    }

    /// Getter for the `audience` field.
    #[must_use]
    pub const fn audience(&self) -> &Did {
        &self.0 .1.payload.audience
    }

    /// Getter for the `subject` field.
    #[must_use]
    pub const fn subject(&self) -> &Subject {
        &self.0 .1.payload.subject
    }

    /// Getter for the `command` field.
    #[must_use]
    pub const fn command(&self) -> &Command {
        &self.0 .1.payload.command
    }

    /// Getter for the `policy` field.
    #[must_use]
    pub const fn policy(&self) -> &Vec<Predicate> {
        &self.0 .1.payload.policy
    }

    /// Getter for the `expiration` field.
    #[must_use]
    pub const fn expiration(&self) -> Option<Timestamp> {
        self.0 .1.payload.expiration
    }

    /// Getter for the `not_before` field.
    #[must_use]
    pub const fn not_before(&self) -> Option<Timestamp> {
        self.0 .1.payload.not_before
    }

    /// Getter for the `meta` field.
    #[must_use]
    pub const fn meta(&self) -> &BTreeMap<String, Ipld> {
        &self.0 .1.payload.meta
    }

    /// Getter for the `nonce` field.
    #[must_use]
    pub const fn nonce(&self) -> &Nonce {
        &self.0 .1.payload.nonce
    }

    /// Compute the CID for this delegation.
    #[must_use]
    pub fn to_cid(&self) -> Cid {
        to_dagcbor_cid(&self)
    }

    /// Verify only the signature of this delegation using a resolver.
    ///
    /// The resolver resolves the issuer DID to a verifier, then verifies
    /// the signature.
    ///
    /// # Errors
    ///
    /// Returns a [`SignatureVerificationError`] if signature verification fails.
    pub async fn verify_signature<R>(
        &self,
        resolver: &R,
    ) -> Result<(), SignatureVerificationError<R::Error>>
    where
        R: varsig::resolver::Resolver<S>,
    {
        let signature = &self.0 .0;
        let header = &self.0 .1.header;
        let payload = &self.0 .1.payload;
        let encoded = header
            .encode(payload)
            .map_err(SignatureVerificationError::EncodingError)?;
        let verifier = resolver
            .resolve(payload.issuer())
            .await
            .map_err(SignatureVerificationError::ResolutionError)?;
        varsig::signature::Verifier::verify(&verifier, &encoded, signature)
            .await
            .map_err(SignatureVerificationError::VerificationError)
    }
}

impl<S: Signature> Debug for Delegation<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Delegation").field(&self.0).finish()
    }
}

impl<S: Signature> Serialize for Delegation<S> {
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, S: Signature + for<'ze> Deserialize<'ze>> Deserialize<'de> for Delegation<S> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let envelope = Envelope::<S, DelegationPayload>::deserialize(deserializer)?;
        Ok(Delegation(envelope))
    }
}

/// UCAN Delegation payload.
///
/// Zero generics — all identity fields are concrete `Did`.
/// Generics (`S: Signature`) live on `Delegation<S>` — the envelope level only.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DelegationPayload {
    #[serde(rename = "iss")]
    pub(crate) issuer: Did,

    #[serde(rename = "aud")]
    pub(crate) audience: Did,

    #[serde(rename = "sub")]
    pub(crate) subject: Subject,

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

impl DelegationPayload {
    /// Getter for the `issuer` field.
    #[must_use]
    pub const fn issuer(&self) -> &Did {
        &self.issuer
    }

    /// Getter for the `audience` field.
    #[must_use]
    pub const fn audience(&self) -> &Did {
        &self.audience
    }

    /// Getter for the `subject` field.
    #[must_use]
    pub const fn subject(&self) -> &Subject {
        &self.subject
    }

    /// Getter for the `command` field.
    #[must_use]
    pub const fn command(&self) -> &Command {
        &self.command
    }

    /// Getter for the `policy` field.
    #[must_use]
    pub const fn policy(&self) -> &Vec<Predicate> {
        &self.policy
    }

    /// Getter for the `expiration` field.
    #[must_use]
    pub const fn expiration(&self) -> Option<Timestamp> {
        self.expiration
    }

    /// Getter for the `not_before` field.
    #[must_use]
    pub const fn not_before(&self) -> Option<Timestamp> {
        self.not_before
    }

    /// Getter for the `meta` field.
    #[must_use]
    pub const fn meta(&self) -> &BTreeMap<String, Ipld> {
        &self.meta
    }

    /// Getter for the `nonce` field.
    #[must_use]
    pub const fn nonce(&self) -> &Nonce {
        &self.nonce
    }
}

impl<'de> Deserialize<'de> for DelegationPayload {
    #[allow(clippy::too_many_lines)]
    fn deserialize<T>(deserializer: T) -> Result<Self, T::Error>
    where
        T: Deserializer<'de>,
    {
        struct PayloadVisitor;

        impl<'de> Visitor<'de> for PayloadVisitor {
            type Value = DelegationPayload;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a map with keys iss,aud,sub,cmd,pol,exp,nbf,meta,nonce")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut issuer: Option<Did> = None;
                let mut audience: Option<Did> = None;
                let mut subject: Option<Subject> = None;
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

        deserializer.deserialize_map(PayloadVisitor)
    }
}

/// Error type for delegation signature verification.
#[derive(Debug, thiserror::Error)]
pub enum SignatureVerificationError<E: std::error::Error = signature::Error> {
    /// Payload encoding failed.
    #[error("encoding error: {0}")]
    EncodingError(CodecError),

    /// DID resolution failed.
    #[error("resolution error: {0}")]
    ResolutionError(E),

    /// Cryptographic verification failed.
    #[error("verification error: {0}")]
    VerificationError(signature::Error),
}

impl PayloadTag for DelegationPayload {
    fn spec_id() -> &'static str {
        "dlg"
    }

    fn version() -> &'static str {
        "1.0.0-rc.1"
    }
}

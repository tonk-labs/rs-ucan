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
use serde::{
    de::{self, Deserializer, MapAccess, Visitor},
    Deserialize, Serialize,
};
use std::{
    collections::BTreeMap,
    fmt::{self, Debug},
    marker::PhantomData,
};
use varsig::verify::Verify;

/// Top-level UCAN Delegation.
#[derive(Clone)]
pub struct Delegation<D: DidSigner + Serialize + for<'de> Deserialize<'de>>(
    Envelope<D, DelegationPayload<D::Did>, <D as Verify>::Signature>,
);

impl<D: DidSigner + Serialize + for<'de> Deserialize<'de>> Delegation<D> {
    /// Creates a blank [`DelegationBuilder`] instance.
    #[must_use]
    pub const fn builder() -> DelegationBuilder<D, Unset, Unset, Unset, Unset> {
        DelegationBuilder::new()
    }

    /// Getter for the `issuer` field.
    pub const fn issuer(&self) -> &D::Did {
        &self.0 .1.payload.issuer
    }

    /// Getter for the `audience` field.
    pub const fn audience(&self) -> &D::Did {
        &self.0 .1.payload.audience
    }

    /// Getter for the `subject` field.
    pub const fn subject(&self) -> &DelegatedSubject<D::Did> {
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

impl<D: DidSigner + Serialize + for<'de> Deserialize<'de> + Debug> Debug for Delegation<D>
where
    <<D::Did as Did>::VarsigConfig as Verify>::Signature: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Delegation").field(&self.0).finish()
    }
}

impl<D: DidSigner + Serialize + for<'de> Deserialize<'de>> Serialize for Delegation<D> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, I: DidSigner + Serialize + for<'ze> Deserialize<'ze>> Deserialize<'de> for Delegation<I>
where
    <I as Verify>::Signature: for<'xe> Deserialize<'xe>,
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
pub struct DelegationPayload<D: Did> {
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

#[allow(clippy::too_many_lines)]
impl<'de, T> Deserialize<'de> for DelegationPayload<T>
where
    T: Did + Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Map field names to an enum for efficient matching
        #[derive(Debug, Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Issuer,
            Audience,
            Subject,
            Command,
            Policy,
            Expiration,
            NotBefore,
            Meta,
            Nonce,
            #[serde(other)]
            Unknown,
        }

        struct DelegationPayloadVisitor<T>(PhantomData<T>);

        impl<'de, T> Visitor<'de> for DelegationPayloadVisitor<T>
        where
            T: Did + Deserialize<'de>,
        {
            type Value = DelegationPayload<T>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(r#"a map containing "issuer", "audience", "subject", …"#)
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                // Option<> while parsing; we’ll validate at the end.
                let mut issuer: Option<T> = None;
                let mut audience: Option<T> = None;
                let mut subject: Option<DelegatedSubject<T>> = None;
                let mut command: Option<Vec<String>> = None;
                let mut policy: Option<Vec<Predicate>> = None;
                let mut expiration: Option<Option<Timestamp>> = None;
                let mut not_before: Option<Option<Timestamp>> = None;
                let mut meta: Option<BTreeMap<String, Ipld>> = None;
                let mut nonce: Option<Nonce> = None;

                while let Some(key) = map.next_key::<&str>()? {
                    match key {
                        "iss" => {
                            if issuer.is_some() {
                                return Err(de::Error::duplicate_field("issuer"));
                            }
                            issuer = Some(map.next_value()?);
                        }
                        "aud" => {
                            if audience.is_some() {
                                return Err(de::Error::duplicate_field("audience"));
                            }
                            audience = Some(map.next_value()?);
                        }
                        "sub" => {
                            if subject.is_some() {
                                return Err(de::Error::duplicate_field("subject"));
                            }
                            subject = Some(map.next_value()?);
                        }
                        "cmd" => {
                            if command.is_some() {
                                return Err(de::Error::duplicate_field("command"));
                            }
                            let txt: &str = map.next_value()?;
                            let cmd: Vec<String> =
                                txt.split('/').map(ToString::to_string).collect();
                            command = Some(cmd);
                        }
                        "pol" => {
                            if policy.is_some() {
                                return Err(de::Error::duplicate_field("policy"));
                            }
                            policy = Some(map.next_value()?);
                        }
                        "exp" => {
                            if expiration.is_some() {
                                return Err(de::Error::duplicate_field("expiration"));
                            }
                            expiration = Some(map.next_value()?);
                        }
                        "nbf" => {
                            if not_before.is_some() {
                                return Err(de::Error::duplicate_field("not_before"));
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
                            if let Ipld::Bytes(nnc) = ipld {
                                nonce = Some(Nonce::from(nnc));
                            } else {
                                return Err(de::Error::custom("nonce field is not a byte array"));
                            }
                        }
                        _ => {
                            // Skip unknowns for forward-compat
                            let _: de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                // Required fields
                let issuer = issuer.ok_or_else(|| de::Error::missing_field("issuer"))?;
                let audience = audience.ok_or_else(|| de::Error::missing_field("audience"))?;
                let subject = subject.ok_or_else(|| de::Error::missing_field("subject"))?;
                let nonce = nonce.ok_or_else(|| de::Error::missing_field("nonce"))?;

                Ok(DelegationPayload {
                    issuer,
                    audience,
                    subject,
                    command: command.unwrap_or_default(),
                    policy: policy.unwrap_or_default(),
                    expiration: expiration.unwrap_or(None),
                    not_before: not_before.unwrap_or(None),
                    meta: meta.unwrap_or_default(),
                    nonce,
                })
            }
        }

        deserializer.deserialize_map(DelegationPayloadVisitor::<T>(PhantomData))
    }
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
    use super::*;
    use testresult::TestResult;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct EdKey(ed25519_dalek::VerifyingKey);

    #[test]
    fn issuer_round_trip() -> TestResult {
        let iss = ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]);
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

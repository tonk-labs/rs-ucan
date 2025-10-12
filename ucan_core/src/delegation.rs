//! UCAN Delegation

pub mod builder;
pub mod policy;
pub mod subject;

use self::subject::DelegatedSubject;
use crate::{
    crypto::nonce::Nonce, did::Did, envelope::Envelope, time::timestamp::Timestamp, unset::Unset,
};
use builder::DelegationBuilder;
use ipld_core::ipld::Ipld;
use policy::predicate::Predicate;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt::Debug};
use varsig::verify::Verify;

#[derive(Clone)]
pub struct Delegation<V: Verify, D: Did + Serialize + for<'de> Deserialize<'de>>(
    Envelope<V, DelegationPayload<D>, <V as Verify>::Signature>,
);

impl<V: Verify, D: Did + Serialize + for<'de> Deserialize<'de>> Delegation<V, D> {
    /// Creates a blank [`DelegationBuilder`] instance.
    #[must_use]
    pub const fn builder() -> DelegationBuilder<D, Unset, Unset, Unset, Unset> {
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

impl<V: Verify + Debug, D: Did + Serialize + for<'de> Deserialize<'de> + Debug> Debug
    for Delegation<V, D>
where
    <V as Verify>::Signature: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Delegation").field(&self.0).finish()
    }
}

impl<V: Verify + Serialize, D: Did + Serialize + for<'de> Deserialize<'de>> Serialize
    for Delegation<V, D>
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
    Deserialize<'de> for Delegation<V, I>
where
    <V as Verify>::Signature: for<'xe> Deserialize<'xe>,
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

impl<D: Did> DelegationPayload<D> {
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use testresult::TestResult;
    use varsig::signer::Sign;

    use crate::did::DidSigner;

    use super::*;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct EdKey(ed25519_dalek::VerifyingKey);

    impl std::fmt::Display for EdKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "did:key:FIXME")
        }
    }

    impl FromStr for EdKey {
        type Err = ();

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() != 3 || parts[0] != "did" || parts[1] != "key" {
                return Err(());
            }
            todo!("FIXME");
            // let key_bytes = base64::decode(parts[2]).map_err(|_| ())?;
            // let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).map_err(|_| ())?;
            // Ok(EdKey(key))
        }
    }

    impl Verify for EdKey {
        type Signature = ed25519_dalek::Signature;
        type Verifier = ed25519_dalek::VerifyingKey;

        fn prefix(&self) -> u64 {
            0xED
        }

        fn config_tags(&self) -> Vec<u64> {
            vec![]
        }

        fn try_from_tags(_bytes: &[u64]) -> Option<(Self, &[u64])> {
            // FIXME implement
            None
        }
    }

    impl Did for EdKey {
        fn did_method(&self) -> &str {
            "key"
        }
    }

    impl Sign for EdKey {
        type Signer = ed25519_dalek::SigningKey;
        type SignError = signature::Error;

        fn try_sign<T, C: varsig::codec::Codec<T>>(
            &self,
            _codec: &C,
            _signer: &Self::Signer,
            _payload: &T,
        ) -> Result<
            (Self::Signature, Vec<u8>),
            varsig::signer::SignerError<C::EncodingError, Self::SignError>,
        > {
            todo!("FIXME implement signing")
        }
    }

    impl DidSigner for EdKey {
        type Did = Self;

        fn did(&self) -> &Self {
            self
        }

        fn signer(&self) -> &Self::Signer {
            todo!()
        }
    }

    #[test]
    fn it_works() -> TestResult {
        let aud = EdKey(ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32]).unwrap());
        let sub = EdKey(ed25519_dalek::VerifyingKey::from_bytes(&[1u8; 32]).unwrap());
        let iss = EdKey(ed25519_dalek::VerifyingKey::from_bytes(&[2u8; 32]).unwrap());

        let delegation = DelegationBuilder::new()
            .issuer(iss)
            .audience(aud)
            .subject(DelegatedSubject::Specific(sub))
            .command(vec!["read".to_string(), "write".to_string()])
            .try_build()?;

        assert_eq!(delegation.issuer().to_string(), "did:example:alice");
        Ok(())
    }
}

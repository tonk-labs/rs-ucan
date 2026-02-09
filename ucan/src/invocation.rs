//! UCAN Invocation
//!
//! The spec for UCAN Invocations can be found at
//! [the GitHub repo](https://github.com/ucan-wg/invocation/).

pub mod builder;

use crate::{
    cid::to_dagcbor_cid,
    command::Command,
    crypto::nonce::Nonce,
    delegation::{
        policy::predicate::{Predicate, RunError},
        store::DelegationStore,
    },
    envelope::{payload_tag::PayloadTag, Envelope},
    future::FutureKind,
    promise::{Promised, WaitingOn},
    subject::Subject,
    time::{range::TimeRange, timestamp::Timestamp},
    Delegation,
};
use builder::InvocationBuilder;
use ipld_core::{cid::Cid, ipld::Ipld};
use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use std::{
    borrow::{Borrow, Cow},
    collections::BTreeMap,
    fmt::Debug,
};
use thiserror::Error;
use varsig::{Did, Resolver, Signature, Verifier};

/// Request to perform a UCAN-authorized action.
///
/// This type implements the [UCAN Invocation spec](https://github.com/ucan-wg/invocation/blob/main/README.md).
/// An invocation references one or more [`Delegation`] proofs that authorize it.
#[derive(Clone)]
pub struct Invocation<S: Signature>(Envelope<S, InvocationPayload>);

impl<S: Signature> Invocation<S> {
    /// Creates a blank [`InvocationBuilder`] instance.
    #[must_use]
    pub const fn builder() -> InvocationBuilder<S> {
        InvocationBuilder::new()
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
    pub const fn subject(&self) -> &Did {
        &self.0 .1.payload.subject
    }

    /// Getter for the `command` field.
    #[must_use]
    pub const fn command(&self) -> &Command {
        &self.0 .1.payload.command
    }

    /// Getter for the `arguments` field.
    #[must_use]
    pub const fn arguments(&self) -> &BTreeMap<String, Promised> {
        &self.0 .1.payload.arguments
    }

    /// Getter for the `proofs` field.
    #[must_use]
    pub const fn proofs(&self) -> &Vec<Cid> {
        &self.0 .1.payload.proofs
    }

    /// Getter for the `cause` field.
    #[must_use]
    pub const fn cause(&self) -> Option<Cid> {
        self.0 .1.payload.cause
    }

    /// Getter for the `expiration` field.
    #[must_use]
    pub const fn expiration(&self) -> Option<Timestamp> {
        self.0 .1.payload.expiration
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

    /// Compute the CID for this invocation.
    #[must_use]
    pub fn to_cid(&self) -> Cid {
        to_dagcbor_cid(&self)
    }

    /// Check if this invocation is valid.
    ///
    /// This method performs two checks:
    /// 1. Verifies that the invocation's signature is valid
    /// 2. Validates the proof chain using the provided delegation store
    ///
    /// # Errors
    ///
    /// Returns an [`InvocationCheckError`] if signature verification fails
    /// or if the proof chain validation fails.
    pub async fn check<
        K: FutureKind,
        T: Borrow<Delegation<S>>,
        St: DelegationStore<K, S, T>,
        R: Resolver<S>,
    >(
        &self,
        proof_store: &St,
        resolver: &R,
    ) -> Result<TimeRange, InvocationCheckError<K, S, T, St, R>> {
        // 1. Verify signature
        self.verify_signature(resolver)
            .await
            .map_err(InvocationCheckError::SignatureVerification)?;

        // 2. Check proof chain and compute valid time range
        let time_range = self
            .0
             .1
            .payload
            .check(proof_store)
            .await
            .map_err(InvocationCheckError::StoredCheck)?;

        Ok(time_range)
    }

    /// Verify only the signature of this invocation using a resolver.
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
        R: Resolver<S>,
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
        Verifier::verify(&verifier, &encoded, signature)
            .await
            .map_err(SignatureVerificationError::VerificationError)
    }
}

impl<S: Signature> Debug for Invocation<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Invocation").field(&self.0).finish()
    }
}

impl<S: Signature> Serialize for Invocation<S> {
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, S: Signature + for<'ze> Deserialize<'ze>> Deserialize<'de> for Invocation<S> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let envelope = Envelope::<S, InvocationPayload>::deserialize(deserializer)?;
        Ok(Invocation(envelope))
    }
}

/// The unsigned content of an [`Invocation`].
///
/// See the [UCAN Invocation payload spec](https://github.com/ucan-wg/invocation/blob/main/README.md#invocation-payload).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InvocationPayload {
    #[serde(rename = "iss")]
    pub(crate) issuer: Did,

    #[serde(rename = "aud")]
    pub(crate) audience: Did,

    #[serde(rename = "sub")]
    pub(crate) subject: Did,

    #[serde(rename = "cmd")]
    pub(crate) command: Command,

    #[serde(rename = "arg")]
    pub(crate) arguments: BTreeMap<String, Promised>,

    #[serde(rename = "prf")]
    pub(crate) proofs: Vec<Cid>,

    pub(crate) cause: Option<Cid>,

    #[serde(rename = "iat")]
    pub(crate) issued_at: Option<Timestamp>,

    #[serde(rename = "exp")]
    pub(crate) expiration: Option<Timestamp>,

    pub(crate) meta: BTreeMap<String, Ipld>,
    pub(crate) nonce: Nonce,
}

impl InvocationPayload {
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
    pub const fn subject(&self) -> &Did {
        &self.subject
    }

    /// Getter for the `command` field.
    #[must_use]
    pub const fn command(&self) -> &Command {
        &self.command
    }

    /// Getter for the `arguments` field.
    #[must_use]
    pub const fn arguments(&self) -> &BTreeMap<String, Promised> {
        &self.arguments
    }

    /// Getter for the `proofs` field.
    #[must_use]
    pub const fn proofs(&self) -> &Vec<Cid> {
        &self.proofs
    }

    /// Getter for the `cause` field.
    #[must_use]
    pub const fn cause(&self) -> Option<Cid> {
        self.cause
    }

    /// Getter for the `expiration` field.
    #[must_use]
    pub const fn expiration(&self) -> Option<Timestamp> {
        self.expiration
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

    /// Compute the CID for this invocation.
    #[must_use]
    pub fn to_cid(&self) -> Cid {
        to_dagcbor_cid(&self)
    }

    /// Check if an [`InvocationPayload`] with proofs stored in a delegation store is valid.
    ///
    /// # Errors
    ///
    /// Returns a [`StoredCheckError`] if the check fails.
    pub async fn check<
        K: FutureKind,
        S: Signature,
        T: Borrow<Delegation<S>>,
        St: DelegationStore<K, S, T>,
    >(
        &self,
        proof_store: &St,
    ) -> Result<TimeRange, StoredCheckError<K, S, T, St>> {
        let realized_proofs: Vec<T> = proof_store
            .get_all(&self.proofs)
            .await
            .map_err(StoredCheckError::GetError)?;
        let dlgs: Vec<&Delegation<S>> = realized_proofs.iter().map(Borrow::borrow).collect();
        Ok(self.syntactic_checks(dlgs)?)
    }

    /// Check if an [`InvocationPayload`] is valid.
    ///
    /// Returns the effective [`TimeRange`] — the intersection of all delegation
    /// and invocation time windows. If the intersection is empty (the chain can
    /// never be valid at any point in time), returns [`CheckFailed::InvalidTimeWindow`].
    ///
    /// # Errors
    ///
    /// Returns a [`CheckFailed`] if the check fails.
    pub fn syntactic_checks<'a, S: Signature + 'a, I: IntoIterator<Item = &'a Delegation<S>>>(
        &'a self,
        proofs: I,
    ) -> Result<TimeRange, CheckFailed> {
        let args: Ipld = self
            .arguments()
            .iter()
            .map(|(k, v)| v.try_into().map(|ipld| (k.clone(), ipld)))
            .collect::<Result<BTreeMap<String, Ipld>, _>>()?
            .into();

        // Start with the invocation's own time bounds.
        let mut time_range = TimeRange::from(self);

        // Hold a last proof that was verified in the chain.
        let mut authorization: Option<&'a Delegation<S>> = None;

        for proof in proofs {
            // Resolve the delegation's subject: Specific(did) uses that did,
            // Any falls back to the previously implied subject.
            let subject = match proof.subject() {
                Subject::Specific(subject) => subject,
                Subject::Any => {
                    if authorization.is_none() {
                        proof.issuer()
                    } else {
                        self.subject()
                    }
                }
            };

            if subject != self.subject() {
                if authorization.is_none() && matches!(proof.subject(), Subject::Any) {
                    return Err(CheckFailed::UnprovenSubject {
                        subject: self.subject().clone(),
                        issuer: proof.issuer().clone(),
                    });
                }
                return Err(CheckFailed::UnauthorizedSubject {
                    claimed: self.subject().clone(),
                    authorized: subject.clone(),
                });
            }

            // Verify principal alignment: root proof's issuer must be the
            // subject, subsequent proofs' issuers must match previous audience.
            if let Some(evidence) = authorization {
                if proof.issuer() != evidence.audience() {
                    return Err(CheckFailed::DelegationAudienceMismatch {
                        claimed: proof.issuer().clone(),
                        authorized: evidence.audience().clone(),
                    });
                }
            } else if proof.issuer() != self.subject() {
                return Err(CheckFailed::UnprovenSubject {
                    subject: self.subject().clone(),
                    issuer: proof.issuer().clone(),
                });
            }

            if !self.command.starts_with(proof.command()) {
                return Err(CheckFailed::CommandEscalation {
                    claimed: self.command.clone(),
                    authorized: proof.command().clone(),
                });
            }

            for predicate in proof.policy() {
                if !predicate.clone().run(&args)? {
                    return Err(CheckFailed::PolicyViolation(Box::new(predicate.clone())));
                }
            }

            // Intersect with this delegation's time bounds.
            time_range = time_range.intersect(proof.into());

            authorization = Some(proof);
        }

        // If proof chain was not empty we ensure that invocation
        // issuer aligns with outmost delegation audience.
        if let Some(proof) = authorization {
            if proof.audience() != self.issuer() {
                return Err(CheckFailed::DelegationAudienceMismatch {
                    claimed: self.issuer().clone(),
                    authorized: proof.audience().clone(),
                });
            }
        }
        // If proof chain was empty it's self issued invocation in
        // which case we ensure that claimed subject matches issuer
        else if self.issuer() != self.subject() {
            return Err(CheckFailed::UnauthorizedSubject {
                claimed: self.subject().clone(),
                authorized: self.issuer().clone(),
            });
        }

        // Verify the accumulated time window is non-empty.
        if !time_range.is_valid() {
            return Err(CheckFailed::InvalidTimeWindow { range: time_range });
        }

        Ok(time_range)
    }
}

impl From<&InvocationPayload> for TimeRange {
    fn from(payload: &InvocationPayload) -> Self {
        Self::new(None, payload.expiration)
    }
}

impl<'de> Deserialize<'de> for InvocationPayload {
    #[allow(clippy::too_many_lines)]
    fn deserialize<T>(deserializer: T) -> Result<Self, T::Error>
    where
        T: Deserializer<'de>,
    {
        struct PayloadVisitor;

        impl<'de> Visitor<'de> for PayloadVisitor {
            type Value = InvocationPayload;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a map with keys iss,aud,sub,cmd,arg,prf,cause,iat,exp,meta,nonce")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut issuer: Option<Did> = None;
                let mut audience: Option<Did> = None;
                let mut subject: Option<Did> = None;
                let mut command: Option<Command> = None;
                let mut arguments: Option<BTreeMap<String, Promised>> = None;
                let mut proofs: Option<Vec<Cid>> = None;
                let mut cause: Option<Option<Cid>> = None;
                let mut issued_at: Option<Option<Timestamp>> = None;
                let mut expiration: Option<Option<Timestamp>> = None;
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
                            command = Some(map.next_value()?);
                        }
                        "arg" => {
                            if arguments.is_some() {
                                return Err(de::Error::duplicate_field("arg"));
                            }
                            arguments = Some(map.next_value()?);
                        }
                        "prf" => {
                            if proofs.is_some() {
                                return Err(de::Error::duplicate_field("prf"));
                            }
                            proofs = Some(map.next_value()?);
                        }
                        "cause" => {
                            if cause.is_some() {
                                return Err(de::Error::duplicate_field("cause"));
                            }
                            cause = Some(map.next_value()?);
                        }
                        "iat" => {
                            if issued_at.is_some() {
                                return Err(de::Error::duplicate_field("iat"));
                            }
                            issued_at = Some(map.next_value()?);
                        }
                        "exp" => {
                            if expiration.is_some() {
                                return Err(de::Error::duplicate_field("exp"));
                            }
                            expiration = Some(map.next_value()?);
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
                                other @ (Ipld::Null
                                | Ipld::Bool(_)
                                | Ipld::Integer(_)
                                | Ipld::Float(_)
                                | Ipld::String(_)
                                | Ipld::List(_)
                                | Ipld::Map(_)
                                | Ipld::Link(_)) => {
                                    return Err(de::Error::custom(format!(
                                        "expected nonce to be bytes, got {other:?}"
                                    )));
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
                                    "iss", "aud", "sub", "cmd", "arg", "prf", "cause", "iat",
                                    "exp", "meta", "nonce",
                                ],
                            ));
                        }
                    }
                }

                let issuer = issuer.ok_or_else(|| de::Error::missing_field("iss"))?;
                let audience = audience.ok_or_else(|| de::Error::missing_field("aud"))?;
                let subject = subject.ok_or_else(|| de::Error::missing_field("sub"))?;
                let command = command.ok_or_else(|| de::Error::missing_field("cmd"))?;
                let arguments = arguments.ok_or_else(|| de::Error::missing_field("arg"))?;
                let proofs = proofs.ok_or_else(|| de::Error::missing_field("prf"))?;
                let nonce = nonce.ok_or_else(|| de::Error::missing_field("nonce"))?;

                Ok(InvocationPayload {
                    issuer,
                    audience,
                    subject,
                    command,
                    arguments,
                    proofs,
                    nonce,
                    cause: cause.unwrap_or(None),
                    issued_at: issued_at.unwrap_or(None),
                    expiration: expiration.unwrap_or(None),
                    meta: meta.unwrap_or_default(),
                })
            }
        }

        deserializer.deserialize_map(PayloadVisitor)
    }
}

impl PayloadTag for InvocationPayload {
    fn spec_id() -> &'static str {
        "inv"
    }

    fn version() -> &'static str {
        "1.0.0-rc.1"
    }
}

/// Errors that can occur when checking an invocation
#[derive(Debug, Clone, Error)]
pub enum CheckFailed {
    /// Error indicating that the invocation is waiting on a promise to be resolved
    #[error(transparent)]
    WaitingOnPromise(#[from] WaitingOn),

    /// The invocation's command is not covered by the delegation's command scope.
    #[error("Claimed command '{claimed}' is not authorized by command '{authorized}'")]
    CommandEscalation {
        /// The command the invocation is trying to execute.
        claimed: Command,

        /// The command that is authorized.
        authorized: Command,
    },
    /// The invocation's arguments are incompatible with a delegation's
    /// policy — e.g. a selector references a field that doesn't exist,
    /// or a comparison involves incompatible types (NaN float vs integer).
    #[error(transparent)]
    PolicyIncompatibility(#[from] RunError),

    /// A delegation's policy predicate evaluated to `false` against the
    /// invocation's arguments. The invocation does not satisfy the
    /// constraints set by this delegation.
    #[error("Invocation arguments violate delegation policy: {0:?}")]
    PolicyViolation(Box<Predicate>),

    /// A proof's issuer does not match the previous delegation's audience.
    /// In a valid chain, each proof must be issued by whoever the previous
    /// link delegated to. For the first proof, that's the subject.
    #[error("Claimed issuer '{claimed}' does not match authorized audience '{authorized}'")]
    DelegationAudienceMismatch {
        /// The DID that was expected as the proof's issuer.
        claimed: Did,
        /// The DID that was actually authorized as the audience.
        authorized: Did,
    },

    /// The subject does not match the invocation subject.
    #[error("Claimed subject '{claimed}' is not authorized by subject '{authorized}'")]
    UnauthorizedSubject {
        /// The invocation's claimed subject.
        claimed: Did,
        /// The subject that is authorized.
        authorized: Did,
    },

    /// The delegation has no subject (`Any`) and no prior proof established
    /// one, so the issuer is taken as the implied subject — but it does not
    /// match the invocation subject.
    #[error("Delegation issuer '{issuer}' does not match claimed subject '{subject}'")]
    UnprovenSubject {
        /// The invocation's claimed subject.
        subject: Did,
        /// The delegation's issuer (used as implied subject).
        issuer: Did,
    },

    /// The intersection of all time bounds in the delegation chain is empty.
    /// There is no point in time at which this invocation could be valid.
    #[error("Delegation chain has no valid time window: {range}")]
    InvalidTimeWindow {
        /// The empty time range that was computed.
        range: TimeRange,
    },
}

/// Errors that can occur when checking an invocation with proofs stored in a delegation store
#[derive(Debug, Clone, Error)]
pub enum StoredCheckError<
    K: FutureKind,
    S: Signature,
    T: Borrow<Delegation<S>>,
    St: DelegationStore<K, S, T>,
> {
    /// Error getting proofs from the store
    #[error(transparent)]
    GetError(St::GetError),

    /// Proof check failed
    #[error(transparent)]
    CheckFailed(#[from] CheckFailed),
}

/// Error type for invocation signature verification.
#[derive(Debug, thiserror::Error)]
pub enum SignatureVerificationError<E: std::error::Error = signature::Error> {
    /// Payload encoding failed.
    #[error("encoding error: {0}")]
    EncodingError(serde_ipld_dagcbor::error::CodecError),

    /// DID resolution failed.
    #[error("resolution error: {0}")]
    ResolutionError(E),

    /// Cryptographic verification failed.
    #[error("verification error: {0}")]
    VerificationError(signature::Error),
}

/// Errors that can occur when checking an invocation (signature + proofs)
#[derive(Debug, Error)]
pub enum InvocationCheckError<
    K: FutureKind,
    S: Signature,
    T: Borrow<Delegation<S>>,
    St: DelegationStore<K, S, T>,
    R: Resolver<S>,
> {
    /// Signature verification failed
    #[error(transparent)]
    SignatureVerification(SignatureVerificationError<R::Error>),

    /// Proof chain check failed
    #[error(transparent)]
    StoredCheck(StoredCheckError<K, S, T, St>),
}

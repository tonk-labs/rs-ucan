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
    did::{Did, DidSigner},
    envelope::{payload_tag::PayloadTag, Envelope},
    future::FutureKind,
    promise::{Promised, WaitingOn},
    time::timestamp::Timestamp,
    unset::Unset,
    Delegation,
};
use builder::InvocationBuilder;
use ipld_core::{cid::Cid, ipld::Ipld};
use serde::{Deserialize, Serialize};
use serde_ipld_dagcbor::codec::DagCborCodec;
use std::{borrow::Borrow, collections::BTreeMap, fmt::Debug};
use thiserror::Error;
use varsig::{codec::Codec, verify::Verify};

/// Top-level UCAN Invocation.
///
/// This is the token that commands the receiver to perform some action.
/// It is backed by UCAN Delegation(s).
#[derive(Clone)]
pub struct Invocation<D: Did>(
    Envelope<D::VarsigConfig, InvocationPayload<D>, <D::VarsigConfig as Verify>::Signature>,
);

impl<D: Did> Invocation<D> {
    /// Creates a blank [`InvocationBuilder`] instance.
    #[must_use]
    pub const fn builder<S: DidSigner<Did = D>>() -> InvocationBuilder<S, Unset, Unset, Unset, Unset>
    {
        InvocationBuilder::new()
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
    pub const fn subject(&self) -> &D {
        &self.0 .1.payload.subject
    }

    /// Getter for the `command` field.
    pub const fn command(&self) -> &Command {
        &self.0 .1.payload.command
    }

    /// Getter for the `arguments` field.
    pub const fn arguments(&self) -> &BTreeMap<String, Promised> {
        &self.0 .1.payload.arguments
    }

    /// Getter for the `proofs` field.
    pub const fn proofs(&self) -> &Vec<Cid> {
        &self.0 .1.payload.proofs
    }

    /// Getter for the `cause` field.
    pub const fn cause(&self) -> Option<Cid> {
        self.0 .1.payload.cause
    }

    /// Getter for the `expiration` field.
    pub const fn expiration(&self) -> Option<Timestamp> {
        self.0 .1.payload.expiration
    }

    /// Getter for the `meta` field.
    pub const fn meta(&self) -> &BTreeMap<String, Ipld> {
        &self.0 .1.payload.meta
    }

    /// Getter for the `nonce` field.
    pub const fn nonce(&self) -> &Nonce {
        &self.0 .1.payload.nonce
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
    pub async fn check<K: FutureKind, T: Borrow<Delegation<D>>, S: DelegationStore<K, D, T>>(
        &self,
        proof_store: &S,
    ) -> Result<(), InvocationCheckError<K, D, T, S>> {
        // 1. Verify signature
        let signature = &self.0 .0;
        let header = &self.0 .1.header;
        let payload = &self.0 .1.payload;
        let verifier = payload.issuer().verifier();

        header
            .try_verify(&verifier, payload, signature)
            .map_err(InvocationCheckError::SignatureVerification)?;

        // 2. Check proof chain
        payload
            .check(proof_store)
            .await
            .map_err(InvocationCheckError::StoredCheck)?;

        Ok(())
    }

    /// Verify only the signature of this invocation, without checking proofs.
    ///
    /// This is useful when you want to verify the signature without
    /// needing access to a delegation store.
    ///
    /// # Errors
    ///
    /// Returns a [`SignatureVerificationError`] if signature verification fails.
    pub fn verify_signature(&self) -> Result<(), SignatureVerificationError> {
        let signature = &self.0 .0;
        let header = &self.0 .1.header;
        let payload = &self.0 .1.payload;
        let verifier = payload.issuer().verifier();

        header
            .try_verify(&verifier, payload, signature)
            .map_err(SignatureVerificationError)
    }
}

impl<D: Did> Debug for Invocation<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Invocation").field(&self.0).finish()
    }
}

impl<D: Did> Serialize for Invocation<D> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, I: Did> Deserialize<'de> for Invocation<I>
where
    <I::VarsigConfig as Verify>::Signature: for<'xe> Deserialize<'xe>,
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
#[serde(bound(deserialize = "D: Did"))]
pub struct InvocationPayload<D: Did> {
    #[serde(rename = "iss")]
    pub(crate) issuer: D,

    #[serde(rename = "aud")]
    pub(crate) audience: D,

    #[serde(rename = "sub")]
    pub(crate) subject: D,

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

impl<D: Did> InvocationPayload<D> {
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
    pub const fn command(&self) -> &Command {
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

    /// Compute the CID for this invocation.
    pub fn to_cid(&self) -> Cid {
        to_dagcbor_cid(&self)
    }

    /// Check if an [`InvocationPayload`] with proofs stored in a delegation store is valid.
    ///
    /// # Errors
    ///
    /// Returns a [`StoredCheckError`] if the check fails.
    pub async fn check<K: FutureKind, T: Borrow<Delegation<D>>, S: DelegationStore<K, D, T>>(
        &self,
        proof_store: &S,
    ) -> Result<(), StoredCheckError<K, D, T, S>> {
        let realized_proofs: Vec<T> = proof_store
            .get_all(&self.proofs)
            .await
            .map_err(StoredCheckError::GetError)?;
        let dlgs: Vec<&Delegation<D>> = realized_proofs.iter().map(Borrow::borrow).collect();
        self.syntactic_checks(dlgs)?;
        Ok(())
    }

    /// Check if an [`InvocationPayload`] is valid.
    ///
    /// # Errors
    ///
    /// Returns a [`CheckFailed`] if the check fails.
    pub fn syntactic_checks<'a, I: IntoIterator<Item = &'a Delegation<D>>>(
        &'a self,
        proofs: I,
    ) -> Result<(), CheckFailed> {
        let args: Ipld = self
            .arguments()
            .iter()
            .map(|(k, v)| v.try_into().map(|ipld| (k.clone(), ipld)))
            .collect::<Result<BTreeMap<String, Ipld>, _>>()?
            .into();

        let mut expected_issuer = self.subject();

        for proof in proofs {
            if !proof.subject().allows(self.subject()) {
                return Err(CheckFailed::SubjectNotAllowedByProof);
            }

            if proof.issuer() != expected_issuer {
                return Err(CheckFailed::InvalidProofIssuerChain);
            }

            if !self.command.starts_with(proof.command()) {
                return Err(CheckFailed::CommandMismatch {
                    found: proof.command().clone(),
                    expected: self.command.clone(),
                });
            }

            for predicate in proof.policy() {
                if !predicate.clone().run(&args)? {
                    return Err(CheckFailed::PredicateFailed(Box::new(predicate.clone())));
                }
            }

            expected_issuer = proof.audience();
        }

        if expected_issuer != self.issuer() {
            return Err(CheckFailed::InvalidProofIssuerChain);
        }

        Ok(())
    }
}

impl<D: Did> PayloadTag for InvocationPayload<D> {
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

    /// Error indicating that the command in the invocation does not match the command in the proof
    #[error("command mismatch: expected {expected:?}, found {expected:?}")]
    CommandMismatch {
        /// The expected command
        expected: Command,

        /// The found command
        found: Command,
    },
    /// Error indicating that a predicate failed to run
    #[error(transparent)]
    PredicateRunError(#[from] RunError),

    /// Error indicating that a predicate has failed
    #[error("predicate failed: {0:?}")]
    PredicateFailed(Box<Predicate>),

    /// Error indicating that the proof issuer chain is invalid
    #[error("invalid proof issuer chain")]
    InvalidProofIssuerChain,

    /// Error indicating that the invocation's subject is not allowed by the proof's subject
    #[error("subject not allowed by proof")]
    SubjectNotAllowedByProof,

    /// Error indicating that the root proof's issuer is not the same as the invocation's subject
    #[error("root proof issuer is not the subject")]
    RootProofIssuerIsNotSubject,
}

/// Errors that can occur when checking an invocation with proofs stored in a delegation store
#[derive(Debug, Clone, Error)]
pub enum StoredCheckError<
    K: FutureKind,
    D: Did,
    T: Borrow<Delegation<D>>,
    S: DelegationStore<K, D, T>,
> {
    /// Error getting proofs from the store
    #[error(transparent)]
    GetError(S::GetError),

    /// Proof check failed
    #[error(transparent)]
    CheckFailed(#[from] CheckFailed),
}

/// Error type for signature verification failures.
#[derive(Debug, Error)]
#[error("signature verification failed: {0}")]
pub struct SignatureVerificationError(
    pub varsig::verify::VerificationError<<DagCborCodec as Codec<()>>::EncodingError>,
);

/// Errors that can occur when checking an invocation (signature + proofs)
#[derive(Debug, Error)]
pub enum InvocationCheckError<
    K: FutureKind,
    D: Did,
    T: Borrow<Delegation<D>>,
    S: DelegationStore<K, D, T>,
> {
    /// Signature verification failed
    #[error("signature verification failed: {0}")]
    SignatureVerification(
        varsig::verify::VerificationError<<DagCborCodec as Codec<()>>::EncodingError>,
    ),

    /// Proof chain check failed
    #[error(transparent)]
    StoredCheck(StoredCheckError<K, D, T, S>),
}

#[cfg(test)]
mod tests {
    use crate::{
        did::{Ed25519Did, Ed25519Signer},
        invocation::builder::InvocationBuilder,
    };

    use super::*;
    use testresult::TestResult;

    /// Create a deterministic test signer from a seed.
    fn test_signer(seed: u8) -> Ed25519Signer {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).into()
    }

    /// Create a deterministic test DID from a seed.
    fn test_did(seed: u8) -> Ed25519Did {
        test_signer(seed).did().clone()
    }

    #[tokio::test]
    async fn issuer_round_trip() -> TestResult {
        let iss: Ed25519Signer = ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]).into();
        let aud: Ed25519Did = ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32])
            .unwrap()
            .into();

        let sub: Ed25519Did = ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32])
            .unwrap()
            .into();

        let builder: InvocationBuilder<
            Ed25519Signer,
            Ed25519Signer,
            Ed25519Did,
            Ed25519Did,
            Command,
            Vec<Cid>,
        > = InvocationBuilder::new()
            .issuer(iss.clone())
            .audience(aud)
            .subject(sub)
            .command(vec!["read".to_string(), "write".to_string()])
            .proofs(vec![]);

        let invocation = builder.try_build().await?;

        assert_eq!(invocation.issuer().to_string(), iss.to_string());
        Ok(())
    }

    #[tokio::test]
    async fn invocation_has_correct_fields() -> TestResult {
        let iss = test_signer(10);
        let aud = test_did(20);
        let sub = test_did(30);
        let cmd = vec!["storage".to_string(), "write".to_string()];

        let invocation = InvocationBuilder::new()
            .issuer(iss.clone())
            .audience(aud.clone())
            .subject(sub.clone())
            .command(cmd.clone())
            .proofs(vec![])
            .try_build()
            .await?;

        assert_eq!(invocation.issuer(), &iss.did().clone());
        assert_eq!(invocation.audience(), &aud);
        assert_eq!(invocation.subject(), &sub);
        assert_eq!(invocation.command(), &Command::new(cmd));

        Ok(())
    }

    #[tokio::test]
    async fn invocation_signature_verifies() -> TestResult {
        let iss = test_signer(42);
        let aud = test_did(43);
        let sub = test_did(44);

        let invocation = InvocationBuilder::new()
            .issuer(iss.clone())
            .audience(aud)
            .subject(sub)
            .command(vec!["test".to_string()])
            .proofs(vec![])
            .try_build()
            .await?;

        // Access the envelope internals to verify the signature
        let signature = &invocation.0 .0;
        let header = &invocation.0 .1.header;
        let payload = &invocation.0 .1.payload;
        let verifier = iss.did().verifier();

        // Verify the signature using the varsig header
        header.try_verify(&verifier, payload, signature)?;

        Ok(())
    }

    #[tokio::test]
    async fn invocation_serialization_roundtrip() -> TestResult {
        let iss = test_signer(50);
        let aud = test_did(51);
        let sub = test_did(52);

        let invocation = InvocationBuilder::new()
            .issuer(iss.clone())
            .audience(aud.clone())
            .subject(sub.clone())
            .command(vec!["roundtrip".to_string()])
            .proofs(vec![])
            .try_build()
            .await?;

        // Serialize to CBOR
        let bytes = serde_ipld_dagcbor::to_vec(&invocation)?;

        // Deserialize back
        let roundtripped: Invocation<Ed25519Did> = serde_ipld_dagcbor::from_slice(&bytes)?;

        // Verify all fields match
        assert_eq!(roundtripped.issuer(), invocation.issuer());
        assert_eq!(roundtripped.audience(), invocation.audience());
        assert_eq!(roundtripped.subject(), invocation.subject());
        assert_eq!(roundtripped.command(), invocation.command());
        assert_eq!(roundtripped.nonce(), invocation.nonce());

        Ok(())
    }

    #[tokio::test]
    async fn invocation_with_explicit_nonce_is_deterministic() -> TestResult {
        use crate::crypto::nonce::Nonce;

        let iss = test_signer(70);
        let aud = test_did(71);
        let sub = test_did(72);
        let nonce = Nonce::generate_16()?;

        // Build two invocations with the same nonce
        let invocation1 = InvocationBuilder::new()
            .issuer(iss.clone())
            .audience(aud.clone())
            .subject(sub.clone())
            .command(vec!["compare".to_string()])
            .proofs(vec![])
            .nonce(nonce.clone())
            .try_build()
            .await?;

        let invocation2 = InvocationBuilder::new()
            .issuer(iss.clone())
            .audience(aud.clone())
            .subject(sub.clone())
            .command(vec!["compare".to_string()])
            .proofs(vec![])
            .nonce(nonce)
            .try_build()
            .await?;

        // Both should have the same payload content
        assert_eq!(invocation1.issuer(), invocation2.issuer());
        assert_eq!(invocation1.audience(), invocation2.audience());
        assert_eq!(invocation1.subject(), invocation2.subject());
        assert_eq!(invocation1.command(), invocation2.command());
        assert_eq!(invocation1.nonce(), invocation2.nonce());

        // Both signatures should verify
        let verifier = iss.did().verifier();

        let sig1 = &invocation1.0 .0;
        let header1 = &invocation1.0 .1.header;
        let payload1 = &invocation1.0 .1.payload;
        header1.try_verify(&verifier, payload1, sig1)?;

        let sig2 = &invocation2.0 .0;
        let header2 = &invocation2.0 .1.header;
        let payload2 = &invocation2.0 .1.payload;
        header2.try_verify(&verifier, payload2, sig2)?;

        // With the same nonce, the signatures should be identical
        // because Ed25519 is deterministic
        assert_eq!(sig1, sig2, "Signatures should be identical with same nonce");

        Ok(())
    }

    #[tokio::test]
    async fn invocation_different_signers_different_signatures() -> TestResult {
        use crate::crypto::nonce::Nonce;

        let iss1 = test_signer(80);
        let iss2 = test_signer(81);
        let aud = test_did(82);
        let sub = test_did(83);
        let nonce = Nonce::generate_16()?;

        let invocation1 = InvocationBuilder::new()
            .issuer(iss1.clone())
            .audience(aud.clone())
            .subject(sub.clone())
            .command(vec!["test".to_string()])
            .proofs(vec![])
            .nonce(nonce.clone())
            .try_build()
            .await?;

        let invocation2 = InvocationBuilder::new()
            .issuer(iss2.clone())
            .audience(aud.clone())
            .subject(sub.clone())
            .command(vec!["test".to_string()])
            .proofs(vec![])
            .nonce(nonce)
            .try_build()
            .await?;

        // Different issuers should produce different signatures
        assert_ne!(
            invocation1.0 .0, invocation2.0 .0,
            "Different signers should produce different signatures"
        );

        // But both should verify with their respective keys
        let verifier1 = iss1.did().verifier();
        invocation1.0 .1.header.try_verify(
            &verifier1,
            &invocation1.0 .1.payload,
            &invocation1.0 .0,
        )?;

        let verifier2 = iss2.did().verifier();
        invocation2.0 .1.header.try_verify(
            &verifier2,
            &invocation2.0 .1.payload,
            &invocation2.0 .0,
        )?;

        Ok(())
    }

    #[tokio::test]
    async fn invocation_with_arguments() -> TestResult {
        use crate::promise::Promised;
        use std::collections::BTreeMap;

        let iss = test_signer(90);
        let aud = test_did(91);
        let sub = test_did(92);

        let mut args = BTreeMap::new();
        args.insert("path".to_string(), Promised::String("/foo/bar".to_string()));
        args.insert("count".to_string(), Promised::Integer(42));

        let invocation = InvocationBuilder::new()
            .issuer(iss.clone())
            .audience(aud)
            .subject(sub)
            .command(vec!["storage".to_string(), "read".to_string()])
            .arguments(args.clone())
            .proofs(vec![])
            .try_build()
            .await?;

        assert_eq!(invocation.arguments(), &args);

        // Signature should still verify
        let verifier = iss.did().verifier();
        invocation
            .0
             .1
            .header
            .try_verify(&verifier, &invocation.0 .1.payload, &invocation.0 .0)?;

        Ok(())
    }
}

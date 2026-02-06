//! Delegation integration tests using Ed25519 concrete types.
//!
//! These tests were moved from `ucan/src/delegation.rs` since they
//! depend on concrete Ed25519 key types from `ucan-authority`.

use base64::prelude::*;
use testresult::TestResult;
use ucan::{
    command::Command,
    crypto::nonce::Nonce,
    delegation::{builder::DelegationBuilder, subject::DelegatedSubject, Delegation},
};
use ucan_authority::ed25519::{Ed25519Did, Ed25519Signer};

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

    let builder: DelegationBuilder<
        Ed25519Signer,
        Ed25519Signer,
        Ed25519Did,
        DelegatedSubject<Ed25519Did>,
        Command,
    > = DelegationBuilder::new()
        .issuer(iss.clone())
        .audience(aud)
        .subject(DelegatedSubject::Specific(sub))
        .command(vec!["read".to_string(), "write".to_string()]);

    let delegation = builder.try_build().await?;

    assert_eq!(delegation.issuer().to_string(), iss.to_string());
    Ok(())
}

#[test]
fn delegation_b64_fixture_roundtrip() -> TestResult {
    // Sample delegation with sub: null, cmd: "/", exp: null, meta: {}
    let b64 = "glhA0rict5hwniXnh54Y7b0v/ZEDNSlPdBx0rsoWDYC2Ylv+UzDr00s7ojPsfvNwrofqKItK911ZGJggZSkeQIB3DqJhaEg0Ae0B7QETcXN1Y2FuL2RsZ0AxLjAuMC1yYy4xqWNhdWR4OGRpZDprZXk6ejZNa2ZGSkJ4U0JGZ29BcVRRTFM3YlRmUDhNZ3lEeXB2YTVpNkNMNVBKTjhSSlpyY2NtZGEvY2V4cPZjaXNzeDhkaWQ6a2V5Ono2TWtyQXNxMU03dEVmUHZXNWRSMlVGQ3daU3pSTU5YWWVUVzh0R1pTS3ZVbTlFWmNuYmYaaSTxp2Nwb2yAY3N1YvZkbWV0YaBlbm9uY2VMVkDFeab+58p8SMpW";
    let bytes = BASE64_STANDARD.decode(b64)?;

    // Parse as Delegation
    let delegation: Delegation<Ed25519Did> = serde_ipld_dagcbor::from_slice(&bytes)?;

    // Verify fields parsed correctly
    assert_eq!(delegation.subject(), &DelegatedSubject::Any); // sub: null
    assert_eq!(delegation.command(), &vec![].into()); // cmd: "/"
    assert_eq!(delegation.expiration(), None); // exp: null
    assert!(delegation.not_before().is_some()); // nbf: 1764028839

    // Serialize back
    let reserialized = serde_ipld_dagcbor::to_vec(&delegation)?;

    // Verify byte-exact roundtrip
    assert_eq!(
        bytes, reserialized,
        "Reserialized bytes should match original"
    );

    // Deserialize again to verify roundtrip preserves all fields
    let roundtripped: Delegation<Ed25519Did> = serde_ipld_dagcbor::from_slice(&reserialized)?;
    assert_eq!(roundtripped.subject(), delegation.subject());
    assert_eq!(roundtripped.command(), delegation.command());
    assert_eq!(roundtripped.expiration(), delegation.expiration());
    assert_eq!(roundtripped.not_before(), delegation.not_before());
    assert_eq!(roundtripped.issuer(), delegation.issuer());
    assert_eq!(roundtripped.audience(), delegation.audience());

    Ok(())
}

#[tokio::test]
async fn delegation_any_subject_roundtrips() -> TestResult {
    let iss = test_signer(1);
    let aud = test_did(2);

    let delegation = DelegationBuilder::new()
        .issuer(iss)
        .audience(aud)
        .subject(DelegatedSubject::Any)
        .command(vec!["test".to_string()])
        .try_build()
        .await?;

    assert_eq!(delegation.subject(), &DelegatedSubject::Any);

    // Serialize to CBOR and deserialize back
    let bytes = serde_ipld_dagcbor::to_vec(&delegation)?;
    let roundtripped: Delegation<Ed25519Did> = serde_ipld_dagcbor::from_slice(&bytes)?;

    // Subject should still be Any after roundtrip
    assert_eq!(roundtripped.subject(), &DelegatedSubject::Any);

    Ok(())
}

#[tokio::test]
async fn delegation_has_correct_fields() -> TestResult {
    let iss = test_signer(10);
    let aud = test_did(20);
    let sub = test_did(30);
    let cmd = vec!["storage".to_string(), "read".to_string()];

    let delegation = DelegationBuilder::new()
        .issuer(iss.clone())
        .audience(aud.clone())
        .subject(DelegatedSubject::Specific(sub.clone()))
        .command(cmd.clone())
        .try_build()
        .await?;

    assert_eq!(delegation.issuer(), &iss.did().clone());
    assert_eq!(delegation.audience(), &aud);
    assert_eq!(delegation.subject(), &DelegatedSubject::Specific(sub));
    assert_eq!(delegation.command(), &Command::new(cmd));

    Ok(())
}

#[tokio::test]
async fn delegation_signature_verifies() -> TestResult {
    let iss = test_signer(42);
    let aud = test_did(43);
    let sub = test_did(44);

    let delegation = DelegationBuilder::new()
        .issuer(iss.clone())
        .audience(aud)
        .subject(DelegatedSubject::Specific(sub))
        .command(vec!["test".to_string()])
        .try_build()
        .await?;

    delegation.verify_signature().await?;

    Ok(())
}

#[tokio::test]
async fn delegation_serialization_roundtrip() -> TestResult {
    let iss = test_signer(50);
    let aud = test_did(51);
    let sub = test_did(52);

    let delegation = DelegationBuilder::new()
        .issuer(iss.clone())
        .audience(aud.clone())
        .subject(DelegatedSubject::Specific(sub.clone()))
        .command(vec!["roundtrip".to_string()])
        .try_build()
        .await?;

    // Serialize to CBOR
    let bytes = serde_ipld_dagcbor::to_vec(&delegation)?;

    // Deserialize back
    let roundtripped: Delegation<Ed25519Did> = serde_ipld_dagcbor::from_slice(&bytes)?;

    // Verify all fields match
    assert_eq!(roundtripped.issuer(), delegation.issuer());
    assert_eq!(roundtripped.audience(), delegation.audience());
    assert_eq!(roundtripped.subject(), delegation.subject());
    assert_eq!(roundtripped.command(), delegation.command());
    assert_eq!(roundtripped.nonce(), delegation.nonce());

    Ok(())
}

#[tokio::test]
async fn delegation_with_any_subject() -> TestResult {
    let iss = test_signer(60);
    let aud = test_did(61);

    let delegation = DelegationBuilder::new()
        .issuer(iss.clone())
        .audience(aud)
        .subject(DelegatedSubject::Any)
        .command(vec!["any".to_string()])
        .try_build()
        .await?;

    assert_eq!(delegation.subject(), &DelegatedSubject::Any);

    delegation.verify_signature().await?;

    Ok(())
}

#[tokio::test]
async fn delegation_with_explicit_nonce_is_deterministic() -> TestResult {
    let iss = test_signer(70);
    let aud = test_did(71);
    let sub = test_did(72);
    let nonce = Nonce::generate_16()?;

    // Build two delegations with the same nonce
    let delegation1 = DelegationBuilder::new()
        .issuer(iss.clone())
        .audience(aud.clone())
        .subject(DelegatedSubject::Specific(sub.clone()))
        .command(vec!["compare".to_string()])
        .nonce(nonce.clone())
        .try_build()
        .await?;

    let delegation2 = DelegationBuilder::new()
        .issuer(iss.clone())
        .audience(aud.clone())
        .subject(DelegatedSubject::Specific(sub.clone()))
        .command(vec!["compare".to_string()])
        .nonce(nonce)
        .try_build()
        .await?;

    // Both should have the same payload content
    assert_eq!(delegation1.issuer(), delegation2.issuer());
    assert_eq!(delegation1.audience(), delegation2.audience());
    assert_eq!(delegation1.subject(), delegation2.subject());
    assert_eq!(delegation1.command(), delegation2.command());
    assert_eq!(delegation1.nonce(), delegation2.nonce());

    // Both signatures should verify
    delegation1.verify_signature().await?;
    delegation2.verify_signature().await?;

    // With the same nonce and same signer, the serialized form should be identical
    // because Ed25519 is deterministic
    let bytes1 = serde_ipld_dagcbor::to_vec(&delegation1)?;
    let bytes2 = serde_ipld_dagcbor::to_vec(&delegation2)?;
    assert_eq!(bytes1, bytes2, "Serialized bytes should be identical with same nonce");

    Ok(())
}

#[tokio::test]
async fn delegation_different_signers_different_signatures() -> TestResult {
    let iss1 = test_signer(80);
    let iss2 = test_signer(81);
    let aud = test_did(82);
    let nonce = Nonce::generate_16()?;

    let delegation1 = DelegationBuilder::new()
        .issuer(iss1.clone())
        .audience(aud.clone())
        .subject(DelegatedSubject::Any)
        .command(vec!["test".to_string()])
        .nonce(nonce.clone())
        .try_build()
        .await?;

    let delegation2 = DelegationBuilder::new()
        .issuer(iss2.clone())
        .audience(aud.clone())
        .subject(DelegatedSubject::Any)
        .command(vec!["test".to_string()])
        .nonce(nonce)
        .try_build()
        .await?;

    // Different issuers should produce different serialized forms
    let bytes1 = serde_ipld_dagcbor::to_vec(&delegation1)?;
    let bytes2 = serde_ipld_dagcbor::to_vec(&delegation2)?;
    assert_ne!(
        bytes1, bytes2,
        "Different signers should produce different serialized delegations"
    );

    // But both should verify with their respective keys
    delegation1.verify_signature().await?;
    delegation2.verify_signature().await?;

    Ok(())
}

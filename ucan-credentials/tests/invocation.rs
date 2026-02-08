//! Invocation integration tests using Ed25519 concrete types.
//!
//! These tests were moved from `ucan/src/invocation.rs` since they
//! depend on concrete Ed25519 key types from `ucan-credentials`.

use testresult::TestResult;
use ucan::{
    command::Command,
    crypto::nonce::Nonce,
    invocation::{builder::InvocationBuilder, Invocation},
    promise::Promised,
};
use ucan_credentials::ed25519::{Ed25519Did, Ed25519Signer};

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
    use ipld_core::cid::Cid;

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

    invocation.verify_signature().await?;

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
    invocation1.verify_signature().await?;
    invocation2.verify_signature().await?;

    // With the same nonce and same signer, the serialized form should be identical
    // because Ed25519 is deterministic
    let bytes1 = serde_ipld_dagcbor::to_vec(&invocation1)?;
    let bytes2 = serde_ipld_dagcbor::to_vec(&invocation2)?;
    assert_eq!(
        bytes1, bytes2,
        "Serialized bytes should be identical with same nonce"
    );

    Ok(())
}

#[tokio::test]
async fn invocation_different_signers_different_signatures() -> TestResult {
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

    // Different issuers should produce different serialized forms
    let bytes1 = serde_ipld_dagcbor::to_vec(&invocation1)?;
    let bytes2 = serde_ipld_dagcbor::to_vec(&invocation2)?;
    assert_ne!(
        bytes1, bytes2,
        "Different signers should produce different serialized invocations"
    );

    // But both should verify with their respective keys
    invocation1.verify_signature().await?;
    invocation2.verify_signature().await?;

    Ok(())
}

#[tokio::test]
async fn invocation_with_arguments() -> TestResult {
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
    invocation.verify_signature().await?;

    Ok(())
}

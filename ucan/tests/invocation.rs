//! Invocation integration tests using Ed25519 concrete types.

use testresult::TestResult;
use ucan::{
    command::Command,
    crypto::nonce::Nonce,
    invocation::{builder::InvocationBuilder, Invocation},
    promise::Promised,
};
use ucan_credentials::ed25519::{Ed25519KeyResolver, Ed25519Signer};
use varsig::{did::Did, eddsa::Ed25519Signature, principal::Principal};

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test;

/// Create a deterministic test signer from a seed.
async fn test_signer(seed: u8) -> Ed25519Signer {
    Ed25519Signer::import(&[seed; 32]).await.unwrap()
}

/// Create a deterministic test DID from a seed.
async fn test_did(seed: u8) -> Did {
    test_signer(seed).await.did()
}

#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
async fn issuer_round_trip() -> TestResult {
    let iss = test_signer(0).await;
    let aud = test_did(0).await;
    let sub = test_did(0).await;

    let builder = InvocationBuilder::<Ed25519Signature>::new()
        .issuer(iss.clone())
        .audience(&aud)
        .subject(&sub)
        .command(vec!["read".to_string(), "write".to_string()])
        .proofs(vec![]);

    let invocation = builder.try_build().await?;

    assert_eq!(invocation.issuer().to_string(), iss.to_string());
    Ok(())
}

#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
async fn signature_type_inferred_from_issuer() -> TestResult {
    let invocation = InvocationBuilder::new()
        .issuer(test_signer(1).await)
        .audience(&test_did(2).await)
        .subject(&test_did(3).await)
        .command(vec!["test".into()])
        .proofs(vec![])
        .try_build()
        .await?;

    assert_eq!(invocation.issuer(), &test_did(1).await);
    Ok(())
}

#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
async fn invocation_has_correct_fields() -> TestResult {
    let iss = test_signer(10).await;
    let aud = test_did(20).await;
    let sub = test_did(30).await;
    let cmd = vec!["storage".to_string(), "write".to_string()];

    let invocation = InvocationBuilder::<Ed25519Signature>::new()
        .issuer(iss.clone())
        .audience(&aud)
        .subject(&sub)
        .command(cmd.clone())
        .proofs(vec![])
        .try_build()
        .await?;

    let iss_did: Did = iss.did();
    assert_eq!(invocation.issuer(), &iss_did);
    assert_eq!(invocation.audience(), &aud);
    assert_eq!(invocation.subject(), &sub);
    assert_eq!(invocation.command(), &Command::new(cmd));

    Ok(())
}

#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
async fn invocation_signature_verifies() -> TestResult {
    let iss = test_signer(42).await;
    let aud = test_did(43).await;
    let sub = test_did(44).await;

    let invocation = InvocationBuilder::<Ed25519Signature>::new()
        .issuer(iss.clone())
        .audience(&aud)
        .subject(&sub)
        .command(vec!["test".to_string()])
        .proofs(vec![])
        .try_build()
        .await?;

    let resolver = Ed25519KeyResolver;
    invocation.verify_signature(&resolver).await?;

    Ok(())
}

#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
async fn invocation_serialization_roundtrip() -> TestResult {
    let iss = test_signer(50).await;
    let aud = test_did(51).await;
    let sub = test_did(52).await;

    let invocation = InvocationBuilder::<Ed25519Signature>::new()
        .issuer(iss.clone())
        .audience(&aud)
        .subject(&sub)
        .command(vec!["roundtrip".to_string()])
        .proofs(vec![])
        .try_build()
        .await?;

    // Serialize to CBOR
    let bytes = serde_ipld_dagcbor::to_vec(&invocation)?;

    // Deserialize back
    let roundtripped: Invocation<Ed25519Signature> = serde_ipld_dagcbor::from_slice(&bytes)?;

    // Verify all fields match
    assert_eq!(roundtripped.issuer(), invocation.issuer());
    assert_eq!(roundtripped.audience(), invocation.audience());
    assert_eq!(roundtripped.subject(), invocation.subject());
    assert_eq!(roundtripped.command(), invocation.command());
    assert_eq!(roundtripped.nonce(), invocation.nonce());

    Ok(())
}

#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
async fn invocation_with_explicit_nonce_is_deterministic() -> TestResult {
    let iss = test_signer(70).await;
    let aud = test_did(71).await;
    let sub = test_did(72).await;
    let nonce = Nonce::generate_16()?;

    // Build two invocations with the same nonce
    let invocation1 = InvocationBuilder::<Ed25519Signature>::new()
        .issuer(iss.clone())
        .audience(&aud)
        .subject(&sub)
        .command(vec!["compare".to_string()])
        .proofs(vec![])
        .nonce(nonce.clone())
        .try_build()
        .await?;

    let invocation2 = InvocationBuilder::<Ed25519Signature>::new()
        .issuer(iss.clone())
        .audience(&aud)
        .subject(&sub)
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
    let resolver = Ed25519KeyResolver;
    invocation1.verify_signature(&resolver).await?;
    invocation2.verify_signature(&resolver).await?;

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

#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
async fn invocation_different_signers_different_signatures() -> TestResult {
    let iss1 = test_signer(80).await;
    let iss2 = test_signer(81).await;
    let aud = test_did(82).await;
    let sub = test_did(83).await;
    let nonce = Nonce::generate_16()?;

    let invocation1 = InvocationBuilder::<Ed25519Signature>::new()
        .issuer(iss1.clone())
        .audience(&aud)
        .subject(&sub)
        .command(vec!["test".to_string()])
        .proofs(vec![])
        .nonce(nonce.clone())
        .try_build()
        .await?;

    let invocation2 = InvocationBuilder::<Ed25519Signature>::new()
        .issuer(iss2.clone())
        .audience(&aud)
        .subject(&sub)
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
    let resolver = Ed25519KeyResolver;
    invocation1.verify_signature(&resolver).await?;
    invocation2.verify_signature(&resolver).await?;

    Ok(())
}

#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
async fn invocation_with_arguments() -> TestResult {
    use std::collections::BTreeMap;

    let iss = test_signer(90).await;
    let aud = test_did(91).await;
    let sub = test_did(92).await;

    let mut args = BTreeMap::new();
    args.insert("path".to_string(), Promised::String("/foo/bar".to_string()));
    args.insert("count".to_string(), Promised::Integer(42));

    let invocation = InvocationBuilder::<Ed25519Signature>::new()
        .issuer(iss.clone())
        .audience(&aud)
        .subject(&sub)
        .command(vec!["storage".to_string(), "read".to_string()])
        .arguments(args.clone())
        .proofs(vec![])
        .try_build()
        .await?;

    assert_eq!(invocation.arguments(), &args);

    // Signature should still verify
    let resolver = Ed25519KeyResolver;
    invocation.verify_signature(&resolver).await?;

    Ok(())
}

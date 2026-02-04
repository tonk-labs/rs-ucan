//! WebCrypto-based signers for WASM environments.
//!
//! This module provides signers that use the Web Crypto API, enabling
//! the use of non-extractable keys for enhanced security in browser
//! and service worker environments.
//!
//! # Example
//!
//! ```ignore
//! use ucan::crypto::web_crypto::WebCryptoEd25519Signer;
//! use ucan::delegation::DelegationBuilder;
//!
//! // Generate a new keypair with non-extractable private key
//! let signer = WebCryptoEd25519Signer::generate().await?;
//!
//! // Build and sign a delegation
//! let delegation = DelegationBuilder::new()
//!     .issuer_did(signer.did().clone())
//!     .audience(audience_did)
//!     .subject(DelegatedSubject::Any)
//!     .command(vec!["storage".into(), "read".into()])
//!     .try_build(&signer)
//!     .await?;
//! ```

use crate::did::{AsyncDidSigner, Ed25519Did};
use js_sys::{Object, Reflect, Uint8Array};
use std::future::Future;
use thiserror::Error;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{CryptoKey, SubtleCrypto};

/// An Ed25519 signer backed by WebCrypto.
///
/// This signer holds a reference to a WebCrypto `CryptoKey` which may be
/// non-extractable, meaning the private key material cannot be accessed
/// directly from JavaScript/WASM code.
///
/// # Security
///
/// Using non-extractable keys provides defense-in-depth: even if an attacker
/// gains code execution in your service worker, they cannot exfiltrate the
/// private key material.
#[derive(Debug, Clone)]
pub struct WebCryptoEd25519Signer {
    did: Ed25519Did,
    private_key: CryptoKey,
}

impl WebCryptoEd25519Signer {
    /// Create a signer from an existing WebCrypto key pair.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The WebCrypto private key (may be non-extractable)
    /// * `public_key_bytes` - The raw 32-byte Ed25519 public key
    ///
    /// # Errors
    ///
    /// Returns an error if the public key bytes are invalid.
    pub fn from_key(
        private_key: CryptoKey,
        public_key_bytes: [u8; 32],
    ) -> Result<Self, WebCryptoError> {
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|e| WebCryptoError::InvalidPublicKey(e.to_string()))?;
        let did = Ed25519Did::from(verifying_key);
        Ok(Self { did, private_key })
    }

    /// Generate a new Ed25519 keypair using WebCrypto.
    ///
    /// The private key is created as non-extractable by default for security.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails or the browser doesn't support Ed25519.
    pub async fn generate() -> Result<Self, WebCryptoError> {
        Self::generate_with_extractable(false).await
    }

    /// Generate a new Ed25519 keypair with configurable extractability.
    ///
    /// # Arguments
    ///
    /// * `extractable` - If `true`, the private key can be exported. Set to `false`
    ///   for maximum security.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails or the browser doesn't support Ed25519.
    pub async fn generate_with_extractable(extractable: bool) -> Result<Self, WebCryptoError> {
        let subtle = get_subtle_crypto()?;

        // Create algorithm parameters for Ed25519
        let algorithm = Object::new();
        Reflect::set(&algorithm, &"name".into(), &"Ed25519".into())
            .map_err(|e| WebCryptoError::JsError(format!("{e:?}")))?;

        // Generate the key pair
        let key_usages = js_sys::Array::new();
        key_usages.push(&"sign".into());
        key_usages.push(&"verify".into());

        let promise = subtle
            .generate_key_with_object(&algorithm, extractable, &key_usages)
            .map_err(|e| WebCryptoError::JsError(format!("{e:?}")))?;

        let key_pair = JsFuture::from(promise)
            .await
            .map_err(|e| WebCryptoError::KeyGeneration(format!("{e:?}")))?;

        // Extract private and public keys from the key pair object
        let private_key: CryptoKey = Reflect::get(&key_pair, &"privateKey".into())
            .map_err(|e| WebCryptoError::KeyGeneration(format!("failed to get privateKey: {e:?}")))?
            .unchecked_into();

        let public_key: CryptoKey = Reflect::get(&key_pair, &"publicKey".into())
            .map_err(|e| WebCryptoError::KeyGeneration(format!("failed to get publicKey: {e:?}")))?
            .unchecked_into();

        // Export public key to get the raw bytes
        let public_key_bytes = export_public_key_raw(&subtle, &public_key).await?;

        Self::from_key(private_key, public_key_bytes)
    }

    /// Import a keypair from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `private_key_bytes` - The 32-byte Ed25519 private key seed
    /// * `extractable` - If `true`, the imported key can be exported again
    ///
    /// # Errors
    ///
    /// Returns an error if the key bytes are invalid or import fails.
    pub async fn from_bytes(
        private_key_bytes: &[u8; 32],
        extractable: bool,
    ) -> Result<Self, WebCryptoError> {
        let subtle = get_subtle_crypto()?;

        // Import as PKCS#8 - Ed25519 private keys need proper formatting
        // For Ed25519, we need to construct a PKCS#8 wrapper around the raw seed
        let pkcs8 = create_ed25519_pkcs8(private_key_bytes);

        let algorithm = Object::new();
        Reflect::set(&algorithm, &"name".into(), &"Ed25519".into())
            .map_err(|e| WebCryptoError::JsError(format!("{e:?}")))?;

        let key_usages = js_sys::Array::new();
        key_usages.push(&"sign".into());

        let pkcs8_array = Uint8Array::from(pkcs8.as_slice());

        let promise = subtle
            .import_key_with_object(
                "pkcs8",
                &pkcs8_array.buffer(),
                &algorithm,
                extractable,
                &key_usages,
            )
            .map_err(|e| WebCryptoError::KeyImport(format!("{e:?}")))?;

        let private_key: CryptoKey = JsFuture::from(promise)
            .await
            .map_err(|e| WebCryptoError::KeyImport(format!("{e:?}")))?
            .unchecked_into();

        // Derive public key from private key bytes
        let signing_key = ed25519_dalek::SigningKey::from_bytes(private_key_bytes);
        let verifying_key = signing_key.verifying_key();
        let did = Ed25519Did::from(verifying_key);

        Ok(Self { did, private_key })
    }

    /// Get the DID associated with this signer.
    #[must_use]
    pub const fn did(&self) -> &Ed25519Did {
        &self.did
    }

    /// Get a reference to the underlying WebCrypto key.
    ///
    /// This can be useful for storing the key in IndexedDB or other
    /// WebCrypto-compatible storage.
    #[must_use]
    pub const fn crypto_key(&self) -> &CryptoKey {
        &self.private_key
    }
}

/// Implementation of `DidSigner` for `WebCryptoEd25519Signer`.
///
/// # Why This Exists
///
/// The [`DelegationBuilder`] and [`InvocationBuilder`] require `D: DidSigner` as a
/// generic bound. This implementation allows `WebCryptoEd25519Signer` to be used
/// with those builders.
///
/// # Safe Usage
///
/// This is safe to use when you call [`DelegationBuilder::try_build`] or
/// [`InvocationBuilder::try_build`], which use [`AsyncDidSigner::sign`]
/// instead of accessing the signing key directly.
///
/// # Panics
///
/// The [`signer()`](DidSigner::signer) method will panic if called.
///
/// [`DelegationBuilder`]: crate::delegation::builder::DelegationBuilder
/// [`InvocationBuilder`]: crate::invocation::builder::InvocationBuilder
/// [`DelegationBuilder::try_build`]: crate::delegation::builder::DelegationBuilder::try_build
/// [`InvocationBuilder::try_build`]: crate::invocation::builder::InvocationBuilder::try_build
/// [`AsyncDidSigner::sign`]: crate::did::AsyncDidSigner::sign
impl crate::did::DidSigner for WebCryptoEd25519Signer {
    type Did = Ed25519Did;

    fn did(&self) -> &Self::Did {
        &self.did
    }

    /// # Panics
    ///
    /// This method always panics because WebCrypto keys cannot be accessed
    /// synchronously.
    fn signer(&self) -> &ed25519_dalek::SigningKey {
        panic!("WebCryptoEd25519Signer does not support returning a reference to the signing key.")
    }
}

impl AsyncDidSigner for WebCryptoEd25519Signer {
    type Did = Ed25519Did;
    type Signature = ed25519_dalek::Signature;
    type SignError = WebCryptoError;

    fn did(&self) -> &Self::Did {
        &self.did
    }

    fn sign(&self, msg: &[u8]) -> impl Future<Output = Result<Self::Signature, Self::SignError>> {
        // Clone what we need for the async block
        let private_key = self.private_key.clone();
        let msg = msg.to_vec();

        async move {
            let subtle = get_subtle_crypto()?;

            let algorithm = Object::new();
            Reflect::set(&algorithm, &"name".into(), &"Ed25519".into())
                .map_err(|e| WebCryptoError::JsError(format!("{e:?}")))?;

            let msg_array = Uint8Array::from(msg.as_slice());

            let promise = subtle
                .sign_with_object_and_buffer_source(&algorithm, &private_key, &msg_array)
                .map_err(|e| WebCryptoError::Signing(format!("{e:?}")))?;

            let signature_buffer = JsFuture::from(promise)
                .await
                .map_err(|e| WebCryptoError::Signing(format!("{e:?}")))?;

            let signature_array = Uint8Array::new(&signature_buffer);
            let mut signature_bytes = [0u8; 64];

            if signature_array.length() != 64 {
                return Err(WebCryptoError::InvalidSignature(format!(
                    "expected 64 bytes, got {}",
                    signature_array.length()
                )));
            }

            signature_array.copy_to(&mut signature_bytes);

            Ok(ed25519_dalek::Signature::from_bytes(&signature_bytes))
        }
    }
}

/// Errors that can occur when using WebCrypto signers.
#[derive(Debug, Clone, Error)]
pub enum WebCryptoError {
    /// WebCrypto API is not available.
    #[error("WebCrypto not available: {0}")]
    NotAvailable(String),

    /// Key generation failed.
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    /// Key import failed.
    #[error("key import failed: {0}")]
    KeyImport(String),

    /// Key export failed.
    #[error("key export failed: {0}")]
    KeyExport(String),

    /// Signing operation failed.
    #[error("signing failed: {0}")]
    Signing(String),

    /// Invalid public key.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid signature format.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// JavaScript error.
    #[error("JS error: {0}")]
    JsError(String),
}

/// Get the SubtleCrypto interface.
fn get_subtle_crypto() -> Result<SubtleCrypto, WebCryptoError> {
    // Try globalThis first (works in service workers)
    let global = js_sys::global();

    // Try to get crypto from the global object
    let crypto = Reflect::get(&global, &"crypto".into())
        .map_err(|_| WebCryptoError::NotAvailable("crypto not found on global".into()))?;

    if crypto.is_undefined() {
        return Err(WebCryptoError::NotAvailable("crypto is undefined".into()));
    }

    let subtle = Reflect::get(&crypto, &"subtle".into())
        .map_err(|_| WebCryptoError::NotAvailable("subtle not found on crypto".into()))?;

    if subtle.is_undefined() {
        return Err(WebCryptoError::NotAvailable(
            "crypto.subtle is undefined".into(),
        ));
    }

    Ok(subtle.unchecked_into())
}

/// Export a public key as raw bytes.
async fn export_public_key_raw(
    subtle: &SubtleCrypto,
    public_key: &CryptoKey,
) -> Result<[u8; 32], WebCryptoError> {
    let promise = subtle
        .export_key("raw", public_key)
        .map_err(|e| WebCryptoError::KeyExport(format!("{e:?}")))?;

    let exported = JsFuture::from(promise)
        .await
        .map_err(|e| WebCryptoError::KeyExport(format!("{e:?}")))?;

    let array = Uint8Array::new(&exported);
    let mut bytes = [0u8; 32];

    if array.length() != 32 {
        return Err(WebCryptoError::KeyExport(format!(
            "expected 32 bytes, got {}",
            array.length()
        )));
    }

    array.copy_to(&mut bytes);
    Ok(bytes)
}

/// Create a PKCS#8 wrapper for an Ed25519 private key seed.
///
/// WebCrypto requires PKCS#8 format for importing Ed25519 private keys.
fn create_ed25519_pkcs8(seed: &[u8; 32]) -> Vec<u8> {
    // PKCS#8 header for Ed25519:
    // SEQUENCE {
    //   INTEGER 0 (version)
    //   SEQUENCE {
    //     OBJECT IDENTIFIER 1.3.101.112 (Ed25519)
    //   }
    //   OCTET STRING {
    //     OCTET STRING (the 32-byte seed)
    //   }
    // }
    let mut pkcs8 = vec![
        0x30, 0x2e, // SEQUENCE, 46 bytes
        0x02, 0x01, 0x00, // INTEGER 0 (version)
        0x30, 0x05, // SEQUENCE, 5 bytes
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x04, 0x22, // OCTET STRING, 34 bytes
        0x04, 0x20, // OCTET STRING, 32 bytes (the seed)
    ];
    pkcs8.extend_from_slice(seed);
    pkcs8
}

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
mod tests {
    use super::*;
    use crate::{
        delegation::{builder::DelegationBuilder, subject::DelegatedSubject},
        did::Ed25519Did,
        invocation::builder::InvocationBuilder,
    };
    use signature::Verifier;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn generate_signer_succeeds() {
        let signer = WebCryptoEd25519Signer::generate().await;
        assert!(
            signer.is_ok(),
            "Failed to generate signer: {:?}",
            signer.err()
        );
    }

    #[wasm_bindgen_test]
    async fn generated_signer_has_valid_did() {
        let signer = WebCryptoEd25519Signer::generate().await.unwrap();
        let did_string = signer.did().to_string();

        // DID should start with did:key:z
        assert!(
            did_string.starts_with("did:key:z"),
            "DID should start with 'did:key:z', got: {}",
            did_string
        );

        // Should be parseable back to Ed25519Did
        let parsed: Result<Ed25519Did, _> = did_string.parse();
        assert!(parsed.is_ok(), "DID should be parseable");
        assert_eq!(parsed.unwrap(), *signer.did());
    }

    #[wasm_bindgen_test]
    async fn sign_and_verify_message() {
        let signer = WebCryptoEd25519Signer::generate().await.unwrap();
        let msg = b"test message for WebCrypto signing";

        // Sign the message
        let signature = signer.sign_async(msg).await;
        assert!(signature.is_ok(), "Signing failed: {:?}", signature.err());
        let signature = signature.unwrap();

        // Verify with the public key from the DID
        let verifier = signer.did().verifier();
        let result = verifier.verify(msg, &signature);
        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
    }

    #[wasm_bindgen_test]
    async fn sign_different_messages_produces_different_signatures() {
        let signer = WebCryptoEd25519Signer::generate().await.unwrap();
        let msg1 = b"first message";
        let msg2 = b"second message";

        let sig1 = signer.sign_async(msg1).await.unwrap();
        let sig2 = signer.sign_async(msg2).await.unwrap();

        assert_ne!(
            sig1, sig2,
            "Different messages should produce different signatures"
        );
    }

    #[wasm_bindgen_test]
    async fn wrong_message_fails_verification() {
        let signer = WebCryptoEd25519Signer::generate().await.unwrap();
        let msg = b"original message";
        let wrong_msg = b"tampered message";

        let signature = signer.sign_async(msg).await.unwrap();

        let verifier = signer.did().verifier();
        let result = verifier.verify(wrong_msg, &signature);
        assert!(
            result.is_err(),
            "Verification should fail for wrong message"
        );
    }

    #[wasm_bindgen_test]
    async fn different_signers_produce_different_signatures() {
        let signer1 = WebCryptoEd25519Signer::generate().await.unwrap();
        let signer2 = WebCryptoEd25519Signer::generate().await.unwrap();
        let msg = b"same message";

        let sig1 = signer1.sign_async(msg).await.unwrap();
        let sig2 = signer2.sign_async(msg).await.unwrap();

        // Different keys should produce different signatures
        assert_ne!(sig1, sig2);

        // Each signature should verify with its own key
        assert!(signer1.did().verifier().verify(msg, &sig1).is_ok());
        assert!(signer2.did().verifier().verify(msg, &sig2).is_ok());

        // Cross-verification should fail
        assert!(signer1.did().verifier().verify(msg, &sig2).is_err());
        assert!(signer2.did().verifier().verify(msg, &sig1).is_err());
    }

    #[wasm_bindgen_test]
    async fn generate_with_extractable_true() {
        let signer = WebCryptoEd25519Signer::generate_with_extractable(true).await;
        assert!(signer.is_ok(), "Should be able to generate extractable key");

        // Should still work for signing
        let signer = signer.unwrap();
        let msg = b"test";
        let sig = signer.sign_async(msg).await;
        assert!(sig.is_ok());
    }

    #[wasm_bindgen_test]
    async fn generate_with_extractable_false() {
        let signer = WebCryptoEd25519Signer::generate_with_extractable(false).await;
        assert!(
            signer.is_ok(),
            "Should be able to generate non-extractable key"
        );

        // Should still work for signing
        let signer = signer.unwrap();
        let msg = b"test";
        let sig = signer.sign_async(msg).await;
        assert!(sig.is_ok());
    }

    #[wasm_bindgen_test]
    async fn build_delegation_with_webcrypto_signer() {
        let signer = WebCryptoEd25519Signer::generate().await.unwrap();

        // Create another DID for the audience
        let aud_signer = WebCryptoEd25519Signer::generate().await.unwrap();
        let aud = aud_signer.did().clone();

        // Build a delegation using the async builder
        let delegation = DelegationBuilder::new()
            .issuer(signer.clone())
            .audience(aud.clone())
            .subject(DelegatedSubject::Any)
            .command(vec!["test".to_string(), "command".to_string()])
            .try_build(&signer)
            .await;

        assert!(
            delegation.is_ok(),
            "Failed to build delegation: {:?}",
            delegation.err()
        );

        let delegation = delegation.unwrap();

        // Verify fields
        assert_eq!(delegation.issuer(), signer.did());
        assert_eq!(delegation.audience(), &aud);
        assert_eq!(delegation.subject(), &DelegatedSubject::Any);

        // Verify signature
        let signature = &delegation.0 .0;
        let header = &delegation.0 .1.header;
        let payload = &delegation.0 .1.payload;
        let verifier = signer.did().verifier();

        let verify_result = header.try_verify(&verifier, payload, signature);
        assert!(
            verify_result.is_ok(),
            "Delegation signature verification failed: {:?}",
            verify_result.err()
        );
    }

    #[wasm_bindgen_test]
    async fn delegation_serialization_roundtrip() {
        let signer = WebCryptoEd25519Signer::generate().await.unwrap();
        let aud_signer = WebCryptoEd25519Signer::generate().await.unwrap();

        let delegation = DelegationBuilder::new()
            .issuer(signer.clone())
            .audience(aud_signer.did().clone())
            .subject(DelegatedSubject::Any)
            .command(vec!["roundtrip".to_string()])
            .try_build(&signer)
            .await
            .unwrap();

        // Serialize to CBOR
        let bytes = serde_ipld_dagcbor::to_vec(&delegation).unwrap();

        // Deserialize back
        let roundtripped: crate::delegation::Delegation<Ed25519Did> =
            serde_ipld_dagcbor::from_slice(&bytes).unwrap();

        // Verify fields match
        assert_eq!(roundtripped.issuer(), delegation.issuer());
        assert_eq!(roundtripped.audience(), delegation.audience());
        assert_eq!(roundtripped.subject(), delegation.subject());
        assert_eq!(roundtripped.command(), delegation.command());
    }

    #[wasm_bindgen_test]
    async fn build_invocation_with_webcrypto_signer() {
        let operator_signer = WebCryptoEd25519Signer::generate()
            .await
            .expect("Failed to generate operator signer");
        let subject_signer = WebCryptoEd25519Signer::generate()
            .await
            .expect("Failed to generate subject signer");
        let subject_did = *subject_signer.did();

        let invocation = InvocationBuilder::new()
            .issuer(operator_signer.clone())
            .audience(subject_did)
            .subject(subject_did)
            .command(vec!["storage".to_string(), "get".to_string()])
            .arguments(std::collections::BTreeMap::new())
            .proofs(vec![])
            .try_build(&operator_signer)
            .await
            .expect("Failed to build invocation");

        assert_eq!(invocation.issuer(), operator_signer.did());
        assert_eq!(invocation.audience(), &subject_did);
        assert_eq!(invocation.subject(), &subject_did);

        invocation
            .verify_signature()
            .expect("Signature verification failed");
    }

    #[wasm_bindgen_test]
    async fn invocation_serialization_roundtrip() {
        let signer = WebCryptoEd25519Signer::generate()
            .await
            .expect("Failed to generate signer");
        let subject_did = *signer.did();

        let invocation = InvocationBuilder::new()
            .issuer(signer.clone())
            .audience(subject_did)
            .subject(subject_did)
            .command(vec!["archive".to_string(), "get".to_string()])
            .arguments(std::collections::BTreeMap::new())
            .proofs(vec![])
            .try_build(&signer)
            .await
            .expect("Failed to build invocation");

        // Test serialization roundtrip
        let bytes =
            serde_ipld_dagcbor::to_vec(&invocation).expect("Failed to serialize invocation");

        let roundtripped: crate::Invocation<Ed25519Did> =
            serde_ipld_dagcbor::from_slice(&bytes).expect("Failed to deserialize invocation");

        assert_eq!(roundtripped.issuer(), invocation.issuer());
        assert_eq!(roundtripped.command(), invocation.command());
    }
}

//! Ed25519 DID and signer implementations.

use base58::ToBase58;
use serde::{Deserialize, Deserializer, Serialize};
use std::str::FromStr;
use thiserror::Error;
use varsig::{
    signature::eddsa::{Ed25519, Ed25519SigningKey, Ed25519VerifyingKey},
    signer::Sign,
};

use super::{Did, DidSigner};

// Re-export WebCrypto types on WASM
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub use varsig::signature::eddsa::web::{ExtractableCryptoKey, WebCryptoError};

/// Error type for [`Ed25519Signer`] operations.
///
/// On WASM this wraps [`WebCryptoError`]; on native this wraps
/// [`getrandom::Error`] (the only thing that can fail is RNG for `generate`).
#[derive(Debug, Clone)]
#[allow(missing_copy_implementations)] // Not Copy on WASM (WebCryptoError contains String)
pub enum Ed25519SignerError {
    /// Random number generation failed (native only, from `generate`).
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    Rng(getrandom::Error),

    /// `WebCrypto` operation failed (WASM only).
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    WebCrypto(WebCryptoError),
}

impl std::fmt::Display for Ed25519SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            Self::Rng(e) => write!(f, "RNG error: {e}"),
            #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
            Self::WebCrypto(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Ed25519SignerError {}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
impl From<getrandom::Error> for Ed25519SignerError {
    fn from(e: getrandom::Error) -> Self {
        Self::Rng(e)
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
impl From<WebCryptoError> for Ed25519SignerError {
    fn from(e: WebCryptoError) -> Self {
        Self::WebCrypto(e)
    }
}

/// An `Ed25519` `did:key`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Ed25519Did(pub ed25519_dalek::VerifyingKey, Ed25519);

impl From<ed25519_dalek::VerifyingKey> for Ed25519Did {
    fn from(key: ed25519_dalek::VerifyingKey) -> Self {
        Ed25519Did(key, Ed25519::new())
    }
}

impl From<ed25519_dalek::SigningKey> for Ed25519Did {
    fn from(key: ed25519_dalek::SigningKey) -> Self {
        let verifying_key = key.verifying_key();
        Ed25519Did(verifying_key, Ed25519::new())
    }
}

impl std::fmt::Display for Ed25519Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut raw_bytes = Vec::with_capacity(34);
        raw_bytes.push(0xed);
        raw_bytes.push(0x01);
        raw_bytes.extend_from_slice(self.0.as_bytes());
        let b58 = ToBase58::to_base58(raw_bytes.as_slice());
        write!(f, "did:key:z{b58}")
    }
}

impl FromStr for Ed25519Did {
    type Err = Ed25519DidFromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        let did_tag = *parts
            .first()
            .ok_or(Ed25519DidFromStrError::InvalidDidHeader)?;
        let key_tag = *parts
            .get(1)
            .ok_or(Ed25519DidFromStrError::InvalidDidHeader)?;

        if parts.len() != 3 || did_tag != "did" || key_tag != "key" {
            return Err(Ed25519DidFromStrError::InvalidDidHeader);
        }
        let b58 = parts
            .get(2)
            .ok_or(Ed25519DidFromStrError::InvalidDidHeader)?
            .strip_prefix('z')
            .ok_or(Ed25519DidFromStrError::MissingBase58Prefix)?;
        let key_bytes =
            base58::FromBase58::from_base58(b58).map_err(|_| Ed25519DidFromStrError::InvalidKey)?;
        let raw_arr = <[u8; 34]>::try_from(key_bytes.as_slice())
            .map_err(|_| Ed25519DidFromStrError::InvalidKey)?;
        if raw_arr[0] != 0xed || raw_arr[1] != 0x01 {
            return Err(Ed25519DidFromStrError::InvalidKey);
        }
        let key_arr: [u8; 32] = raw_arr[2..]
            .try_into()
            .map_err(|_| Ed25519DidFromStrError::InvalidKey)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&key_arr)
            .map_err(|_| Ed25519DidFromStrError::InvalidKey)?;
        Ok(Ed25519Did(key, Ed25519::new()))
    }
}

/// Errors that can occur when parsing an `Ed25519Did` from a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Error)]
pub enum Ed25519DidFromStrError {
    /// The DID header is invalid.
    #[error("invalid did header")]
    InvalidDidHeader,

    /// The base58 prefix 'z' is missing.
    #[error("missing base58 prefix 'z'")]
    MissingBase58Prefix,

    /// The base58 encoding is invalid.
    #[error("invalid base58 encoding")]
    InvalidBase58,

    /// The key bytes are invalid.
    #[error("invalid key bytes")]
    InvalidKey,
}

impl Did for Ed25519Did {
    type VarsigConfig = Ed25519;

    fn did_method(&self) -> &'static str {
        "key"
    }

    fn varsig_config(&self) -> &Self::VarsigConfig {
        &self.1
    }

    fn verifier(&self) -> Ed25519VerifyingKey {
        Ed25519VerifyingKey(self.0)
    }
}

impl Serialize for Ed25519Did {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Ed25519Did {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DidKeyVisitor;

        impl serde::de::Visitor<'_> for DidKeyVisitor {
            type Value = Ed25519Did;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a did:key string containing an ed25519 public key")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                const DID_PREFIX: &str = "did:key:z";
                const ED25519_PUB: [u8; 2] = [0xED, 0x01];

                if !v.starts_with(DID_PREFIX) {
                    return Err(E::custom("expected did:key with base58btc (did:key:z…)"));
                }

                let b58_payload = &v[DID_PREFIX.len()..];
                let decoded = base58::FromBase58::from_base58(b58_payload)
                    .map_err(|e| E::custom(format!("base58 decode failed: {e:?}")))?;

                if decoded.len() != 34 {
                    return Err(E::custom(format!(
                        "unexpected byte length: got {}, want 34 (2-byte header + 32-byte key)",
                        decoded.len()
                    )));
                }

                let leading = decoded.get(0..2).ok_or_else(|| {
                    E::custom("decoded did:key payload too short to contain multicodec header")
                })?;

                if leading != ED25519_PUB {
                    return Err(E::custom("not an ed25519-pub multicodec (0xED 0x01)"));
                }

                let remainder = decoded.get(2..).ok_or_else(|| {
                    E::custom("decoded did:key payload too short to contain ed25519 public key")
                })?;

                #[allow(clippy::expect_used)]
                let key_bytes: [u8; 32] =
                    remainder.try_into().expect("slice length verified above");

                let vk = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
                    E::custom(format!(
                        "failed to construct ed25519 public key from bytes: {e:?}"
                    ))
                })?;

                Ok(Ed25519Did(vk, Ed25519::new()))
            }
        }

        deserializer.deserialize_str(DidKeyVisitor)
    }
}

/// An `Ed25519` `did:key` signer.
///
/// This is the unified signer that works on both native and WASM platforms.
/// On native platforms, it wraps an `ed25519_dalek::SigningKey`.
/// On WASM, it can also wrap a `WebCrypto` `CryptoKey` for non-extractable key support.
#[derive(Debug, Clone)]
pub struct Ed25519Signer {
    did: Ed25519Did,
    signer: Ed25519SigningKey,
}

impl Ed25519Signer {
    /// Build an `Ed25519Signer` from an already-constructed `Ed25519SigningKey`.
    #[must_use]
    fn from_signing_key(signer: Ed25519SigningKey) -> Self {
        let verifying_key = signer.verifying_key();
        let did = Ed25519Did(verifying_key, Ed25519::new());
        Self { did, signer }
    }

    /// Generate a new Ed25519 keypair.
    ///
    /// On WASM, uses the `WebCrypto` API (non-extractable key by default).
    /// On native, uses `ed25519_dalek` with random bytes from `getrandom`.
    ///
    /// # Errors
    ///
    /// On WASM, returns an error if key generation fails or the browser
    /// doesn't support Ed25519. On native, returns an error if the RNG fails.
    #[allow(clippy::unused_async)] // async is needed on WASM
    pub async fn generate() -> Result<Self, Ed25519SignerError> {
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        let signing_key = {
            use varsig::signature::eddsa::web;
            web::SigningKey::generate().await?
        };

        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        let signing_key = {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed)?;
            ed25519_dalek::SigningKey::from_bytes(&seed)
        };

        Ok(Self::from_signing_key(Ed25519SigningKey::from(signing_key)))
    }

    /// Import a keypair from raw seed bytes.
    ///
    /// On WASM, uses the `WebCrypto` API (non-extractable key by default).
    /// On native, uses `ed25519_dalek`.
    ///
    /// # Errors
    ///
    /// On WASM, returns an error if the `WebCrypto` import fails.
    /// On native, this cannot fail.
    #[allow(clippy::unused_async)] // async is needed on WASM
    pub async fn import(seed: &[u8; 32]) -> Result<Self, Ed25519SignerError> {
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        let signing_key = {
            use varsig::signature::eddsa::web;
            web::SigningKey::import(seed).await?
        };

        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);

        Ok(Self::from_signing_key(Ed25519SigningKey::from(signing_key)))
    }

    /// Get the associated DID.
    #[must_use]
    pub const fn did(&self) -> &Ed25519Did {
        &self.did
    }

    /// Get the associated signer.
    #[must_use]
    pub const fn signer(&self) -> &Ed25519SigningKey {
        &self.signer
    }
}

impl From<ed25519_dalek::SigningKey> for Ed25519Signer {
    fn from(key: ed25519_dalek::SigningKey) -> Self {
        Self::from_signing_key(Ed25519SigningKey::from(key))
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
impl From<varsig::signature::eddsa::web::SigningKey> for Ed25519Signer {
    fn from(key: varsig::signature::eddsa::web::SigningKey) -> Self {
        Self::from_signing_key(Ed25519SigningKey::from(key))
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
impl ExtractableCryptoKey for Ed25519Signer {
    async fn generate() -> Result<Self, WebCryptoError> {
        use varsig::signature::eddsa::web;
        let key = <web::SigningKey as ExtractableCryptoKey>::generate().await?;
        Ok(Self::from_signing_key(Ed25519SigningKey::from(key)))
    }

    async fn import(seed: &[u8; 32]) -> Result<Self, WebCryptoError> {
        use varsig::signature::eddsa::web;
        let key = <web::SigningKey as ExtractableCryptoKey>::import(seed).await?;
        Ok(Self::from_signing_key(Ed25519SigningKey::from(key)))
    }
}

impl std::fmt::Display for Ed25519Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.did)
    }
}

impl DidSigner for Ed25519Signer {
    type Did = Ed25519Did;

    fn did(&self) -> &Self::Did {
        &self.did
    }

    fn signer(&self) -> &<<Self::Did as Did>::VarsigConfig as Sign>::Signer {
        &self.signer
    }
}

impl Serialize for Ed25519Signer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.did.serialize(serializer)
    }
}

// ==========================================================================
// Tests
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use async_signature::AsyncSigner;
    use signature::Verifier;

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test_configure;

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    wasm_bindgen_test_configure!(run_in_browser);

    /// Create a deterministic test signer from a seed.
    ///
    /// Uses `Ed25519Signer::import` so that on WASM the `WebCrypto` backend
    /// is exercised, while on native the `ed25519_dalek` backend is used.
    async fn test_signer(seed: u8) -> Ed25519Signer {
        Ed25519Signer::import(&[seed; 32]).await.unwrap()
    }

    #[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        wasm_bindgen_test::wasm_bindgen_test
    )]
    async fn ed25519_did_round_trip() {
        let signer = test_signer(0).await;
        let did_string = signer.did().to_string();
        let parsed: Ed25519Did = did_string.parse().unwrap();
        assert_eq!(parsed, *signer.did());
    }

    #[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        wasm_bindgen_test::wasm_bindgen_test
    )]
    async fn ed25519_async_signer_produces_valid_signature() {
        let signer = test_signer(42).await;
        let msg = b"test message for async signing";

        let signature = signer.signer().sign_async(msg).await.unwrap();

        let verifier = signer.did().verifier();
        verifier.verify(msg, &signature).unwrap();
    }

    #[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        wasm_bindgen_test::wasm_bindgen_test
    )]
    async fn ed25519_async_signer_different_messages_different_signatures() {
        let signer = test_signer(7).await;
        let msg1 = b"first message";
        let msg2 = b"second message";

        let sig1 = signer.signer().sign_async(msg1).await.unwrap();
        let sig2 = signer.signer().sign_async(msg2).await.unwrap();

        assert_ne!(
            sig1, sig2,
            "Different messages should produce different signatures"
        );

        let verifier = signer.did().verifier();
        verifier.verify(msg1, &sig1).unwrap();
        verifier.verify(msg2, &sig2).unwrap();
    }

    #[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        wasm_bindgen_test::wasm_bindgen_test
    )]
    async fn ed25519_async_signer_wrong_message_fails_verification() {
        let signer = test_signer(99).await;
        let msg = b"original message";
        let wrong_msg = b"tampered message";

        let signature = signer.signer().sign_async(msg).await.unwrap();

        let verifier = signer.did().verifier();
        assert!(
            verifier.verify(wrong_msg, &signature).is_err(),
            "Verification should fail for wrong message"
        );
    }

    #[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        wasm_bindgen_test::wasm_bindgen_test
    )]
    async fn different_signers_produce_different_signatures() {
        let signer1 = test_signer(1).await;
        let signer2 = test_signer(2).await;
        let msg = b"same message";

        let sig1 = signer1.signer().sign_async(msg).await.unwrap();
        let sig2 = signer2.signer().sign_async(msg).await.unwrap();

        assert_ne!(sig1, sig2);

        assert!(signer1.did().verifier().verify(msg, &sig1).is_ok());
        assert!(signer2.did().verifier().verify(msg, &sig2).is_ok());

        // Cross-verification should fail
        assert!(signer1.did().verifier().verify(msg, &sig2).is_err());
        assert!(signer2.did().verifier().verify(msg, &sig1).is_err());
    }

    #[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        wasm_bindgen_test::wasm_bindgen_test
    )]
    async fn build_delegation_with_signer() {
        use crate::delegation::{builder::DelegationBuilder, subject::DelegatedSubject};

        let signer = test_signer(10).await;
        let aud_signer = test_signer(20).await;
        let aud = *aud_signer.did();

        let delegation = DelegationBuilder::new()
            .issuer(signer.clone())
            .audience(aud)
            .subject(DelegatedSubject::Any)
            .command(vec!["test".to_string(), "command".to_string()])
            .try_build()
            .await
            .expect("Failed to build delegation");

        assert_eq!(delegation.issuer(), signer.did());
        assert_eq!(delegation.audience(), &aud);
        assert_eq!(delegation.subject(), &DelegatedSubject::Any);
    }

    #[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        wasm_bindgen_test::wasm_bindgen_test
    )]
    async fn delegation_serialization_roundtrip() {
        use crate::delegation::{builder::DelegationBuilder, subject::DelegatedSubject};

        let signer = test_signer(10).await;
        let aud_signer = test_signer(20).await;

        let delegation = DelegationBuilder::new()
            .issuer(signer.clone())
            .audience(*aud_signer.did())
            .subject(DelegatedSubject::Any)
            .command(vec!["roundtrip".to_string()])
            .try_build()
            .await
            .unwrap();

        let bytes = serde_ipld_dagcbor::to_vec(&delegation).unwrap();

        let roundtripped: crate::delegation::Delegation<Ed25519Did> =
            serde_ipld_dagcbor::from_slice(&bytes).unwrap();

        assert_eq!(roundtripped.issuer(), delegation.issuer());
        assert_eq!(roundtripped.audience(), delegation.audience());
        assert_eq!(roundtripped.subject(), delegation.subject());
        assert_eq!(roundtripped.command(), delegation.command());
    }

    #[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        wasm_bindgen_test::wasm_bindgen_test
    )]
    async fn build_invocation_with_signer() {
        use crate::invocation::builder::InvocationBuilder;

        let operator_signer = test_signer(30).await;
        let subject_signer = test_signer(40).await;
        let subject_did = *subject_signer.did();

        let invocation = InvocationBuilder::new()
            .issuer(operator_signer.clone())
            .audience(subject_did)
            .subject(subject_did)
            .command(vec!["storage".to_string(), "get".to_string()])
            .arguments(std::collections::BTreeMap::new())
            .proofs(vec![])
            .try_build()
            .await
            .expect("Failed to build invocation");

        assert_eq!(invocation.issuer(), operator_signer.did());
        assert_eq!(invocation.audience(), &subject_did);
        assert_eq!(invocation.subject(), &subject_did);

        invocation
            .verify_signature()
            .await
            .expect("Signature verification failed");
    }

    #[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        wasm_bindgen_test::wasm_bindgen_test
    )]
    async fn invocation_serialization_roundtrip() {
        use crate::invocation::builder::InvocationBuilder;

        let signer = test_signer(50).await;
        let subject_did = *signer.did();

        let invocation = InvocationBuilder::new()
            .issuer(signer.clone())
            .audience(subject_did)
            .subject(subject_did)
            .command(vec!["archive".to_string(), "get".to_string()])
            .arguments(std::collections::BTreeMap::new())
            .proofs(vec![])
            .try_build()
            .await
            .expect("Failed to build invocation");

        let bytes =
            serde_ipld_dagcbor::to_vec(&invocation).expect("Failed to serialize invocation");

        let roundtripped: crate::Invocation<Ed25519Did> =
            serde_ipld_dagcbor::from_slice(&bytes).expect("Failed to deserialize invocation");

        assert_eq!(roundtripped.issuer(), invocation.issuer());
        assert_eq!(roundtripped.command(), invocation.command());
    }
}

// WebCrypto-only tests (extractable keys, non-extractable public key extraction)
#[cfg(all(test, target_arch = "wasm32", target_os = "unknown"))]
mod wasm_tests {
    use super::*;
    use async_signature::AsyncSigner;
    use signature::Verifier;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn generate_signer_succeeds() {
        let signer = Ed25519Signer::generate().await;
        assert!(
            signer.is_ok(),
            "Failed to generate signer: {:?}",
            signer.err()
        );
    }

    #[wasm_bindgen_test]
    async fn generated_signer_has_valid_did() {
        let signer = Ed25519Signer::generate().await.unwrap();
        let did_string = signer.did().to_string();

        assert!(
            did_string.starts_with("did:key:z"),
            "DID should start with 'did:key:z', got: {}",
            did_string
        );

        let parsed: Result<Ed25519Did, _> = did_string.parse();
        assert!(parsed.is_ok(), "DID should be parseable");
        assert_eq!(parsed.unwrap(), *signer.did());
    }

    #[wasm_bindgen_test]
    async fn generate_extractable_key() {
        let signer = <Ed25519Signer as ExtractableCryptoKey>::generate().await;
        assert!(signer.is_ok(), "Should be able to generate extractable key");

        let signer = signer.unwrap();
        let msg = b"test";
        let sig = signer.signer().sign_async(msg).await;
        assert!(sig.is_ok());
    }

    #[wasm_bindgen_test]
    async fn import_extractable_key() {
        let seed = [42u8; 32];

        let signer = <Ed25519Signer as ExtractableCryptoKey>::import(&seed).await;
        assert!(
            signer.is_ok(),
            "Should be able to import extractable key: {:?}",
            signer.err()
        );

        let signer = signer.unwrap();
        let msg = b"test";
        let sig = signer.signer().sign_async(msg).await;
        assert!(sig.is_ok());
    }

    #[wasm_bindgen_test]
    async fn non_extractable_key_can_extract_public_key() {
        let signer = Ed25519Signer::generate().await.unwrap();
        let did = signer.did();
        let did_string = did.to_string();

        assert!(
            did_string.starts_with("did:key:z"),
            "DID should be valid: {}",
            did_string
        );

        let verifier = did.verifier();
        let msg = b"test message for non-extractable key";
        let signature = signer.signer().sign_async(msg).await.unwrap();

        let result = verifier.verify(msg, &signature);
        assert!(
            result.is_ok(),
            "Public key from non-extractable key should verify signatures: {:?}",
            result.err()
        );
    }

    #[wasm_bindgen_test]
    async fn imported_non_extractable_key_matches_native_public_key() {
        let seed = [42u8; 32];

        let web_signer = Ed25519Signer::import(&seed).await.unwrap();

        let native_signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let native_public_key = native_signing_key.verifying_key();

        let web_did = web_signer.did();
        let web_verifier = web_did.verifier();

        assert_eq!(
            web_verifier.0, native_public_key,
            "Public key from WebCrypto import should match native derivation"
        );

        let msg = b"cross-platform verification test";
        let signature = web_signer.signer().sign_async(msg).await.unwrap();

        assert!(
            native_public_key.verify(msg, &signature.into()).is_ok(),
            "Native verifier should verify WebCrypto signature"
        );
    }
}

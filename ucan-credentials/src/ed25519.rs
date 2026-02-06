//! Ed25519 key types, DID, and signer implementations.

use base58::ToBase58;
use serde::{Deserialize, Deserializer, Serialize};
use std::str::FromStr;
use thiserror::Error;
use ucan::{issuer::Issuer, principal::Principal};
use varsig::{
    algorithm::eddsa::{Ed25519, Ed25519Signature},
    signature::{signer::Signer, verifier::Verifier},
};

// Platform-specific implementations
pub mod native;

// WebCrypto is only available in web browsers (wasm32 + unknown OS)
// Not available in WASI or other WASM environments
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod web;

// Re-export WebCrypto types on WASM
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub use web::{ExtractableCryptoKey, WebCryptoError};

// ============================================================================
// Key material types (moved from varsig::algorithm::eddsa)
// ============================================================================

/// Ed25519 key material for import/export.
///
/// On native platforms, only the `Extractable` variant is available.
/// On WASM (`wasm32-unknown-unknown`), a `NonExtractable` variant is also
/// available for opaque `WebCrypto` key pairs whose key material cannot be read.
#[derive(Debug, Clone)]
pub enum KeyExport {
    /// Raw seed bytes — the key material is accessible.
    Extractable(Vec<u8>),

    /// Opaque WebCrypto key pair — key material is NOT accessible.
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    NonExtractable {
        /// The WebCrypto private key.
        private_key: web_sys::CryptoKey,
        /// The WebCrypto public key.
        public_key: web_sys::CryptoKey,
    },
}

impl From<&[u8; 32]> for KeyExport {
    fn from(seed: &[u8; 32]) -> Self {
        KeyExport::Extractable(seed.to_vec())
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
impl From<web_sys::CryptoKeyPair> for KeyExport {
    fn from(pair: web_sys::CryptoKeyPair) -> Self {
        KeyExport::NonExtractable {
            private_key: pair.get_private_key(),
            public_key: pair.get_public_key(),
        }
    }
}

/// Ed25519 verifying key.
///
/// This enum abstracts over different Ed25519 verification implementations:
/// - `Native`: Uses `ed25519_dalek::VerifyingKey` for native platforms
/// - `WebCrypto`: Uses the browser's `WebCrypto` API (web WASM only)
#[derive(Debug, Clone)]
#[allow(missing_copy_implementations)] // CryptoKey is not Copy on WASM
pub enum Ed25519VerifyingKey {
    /// Native verifying key using `ed25519_dalek`.
    Native(native::VerifyingKey),

    /// WebCrypto verifying key (web WASM only).
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    WebCrypto(web::VerifyingKey),
}

impl From<native::VerifyingKey> for Ed25519VerifyingKey {
    fn from(key: native::VerifyingKey) -> Self {
        Self::Native(key)
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
impl From<web::VerifyingKey> for Ed25519VerifyingKey {
    fn from(key: web::VerifyingKey) -> Self {
        Self::WebCrypto(key)
    }
}

impl Ed25519VerifyingKey {
    /// Get the raw public key bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        match self {
            Self::Native(key) => key.to_bytes(),
            #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
            Self::WebCrypto(key) => key.to_bytes(),
        }
    }
}

impl Ed25519VerifyingKey {
    /// Verify a signature for the given message asynchronously.
    ///
    /// # Errors
    ///
    /// Returns `signature::Error` if verification fails.
    #[allow(clippy::unused_async)]
    pub async fn verify_signature(
        &self,
        msg: &[u8],
        signature: &Ed25519Signature,
    ) -> Result<(), signature::Error> {
        match self {
            Self::Native(key) => {
                use signature::Verifier;
                let dalek_sig = ed25519_dalek::Signature::from(*signature);
                key.verify(msg, &dalek_sig)
            }
            #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
            Self::WebCrypto(key) => web::verify(key.crypto_key(), msg, signature).await,
        }
    }
}

impl PartialEq for Ed25519VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for Ed25519VerifyingKey {}

/// Ed25519 signing key.
///
/// This enum abstracts over different Ed25519 signing implementations:
/// - `Native`: Uses `ed25519_dalek::SigningKey` for native platforms
/// - `WebCrypto`: Uses the browser's `WebCrypto` API (web WASM only)
#[derive(Debug, Clone)]
pub enum Ed25519SigningKey {
    /// Native signing key using `ed25519_dalek`.
    Native(native::SigningKey),

    /// WebCrypto signing key (web WASM only).
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    WebCrypto(web::SigningKey),
}

/// Errors from [`Ed25519SigningKey::import`] or [`Ed25519SigningKey::export`].
#[derive(Debug, Clone)]
#[allow(missing_copy_implementations)]
pub enum Ed25519KeyError {
    /// The seed bytes have the wrong length (expected 32).
    InvalidSeedLength(usize),

    /// Random number generation failed (native only).
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    Rng(getrandom::Error),

    /// WebCrypto operation failed (WASM only).
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    WebCrypto(web::WebCryptoError),
}

impl std::fmt::Display for Ed25519KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSeedLength(n) => write!(f, "expected 32 seed bytes, got {n}"),
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            Self::Rng(e) => write!(f, "RNG error: {e}"),
            #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
            Self::WebCrypto(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Ed25519KeyError {}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
impl From<web::WebCryptoError> for Ed25519KeyError {
    fn from(e: web::WebCryptoError) -> Self {
        Self::WebCrypto(e)
    }
}

impl Ed25519SigningKey {
    /// Get the verifying (public) key.
    #[must_use]
    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        match self {
            Self::Native(key) => Ed25519VerifyingKey::Native(key.verifying_key()),
            #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
            Self::WebCrypto(key) => Ed25519VerifyingKey::WebCrypto(key.verifying_key()),
        }
    }

    /// Generate a new Ed25519 signing key.
    ///
    /// On WASM, uses the `WebCrypto` API (non-extractable key by default).
    /// On native, uses `ed25519_dalek` with random bytes from `getrandom`.
    ///
    /// # Errors
    ///
    /// On WASM, returns an error if key generation fails or the browser
    /// doesn't support Ed25519. On native, returns an error if the RNG fails.
    #[allow(clippy::unused_async)]
    pub async fn generate() -> Result<Self, Ed25519KeyError> {
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            Ok(Self::WebCrypto(web::SigningKey::generate().await?))
        }

        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(Ed25519KeyError::Rng)?;
            Ok(Self::Native(ed25519_dalek::SigningKey::from_bytes(&seed)))
        }
    }

    /// Export the key material.
    ///
    /// For `Native` keys, returns `KeyExport::Extractable` with the raw seed bytes.
    /// For `WebCrypto` keys, delegates to [`web::SigningKey::export`].
    ///
    /// # Errors
    ///
    /// On WASM with a non-extractable `WebCrypto` key, returns
    /// `KeyExport::NonExtractable` (not an error). Errors only if the
    /// `WebCrypto` export operation itself fails.
    #[allow(clippy::unused_async)]
    pub async fn export(&self) -> Result<KeyExport, Ed25519KeyError> {
        match self {
            Self::Native(key) => Ok(KeyExport::Extractable(key.to_bytes().to_vec())),
            #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
            Self::WebCrypto(key) => Ok(key.export().await?),
        }
    }

    /// Import from a [`KeyExport`].
    ///
    /// On native, `Extractable(bytes)` constructs a native `ed25519_dalek::SigningKey`.
    ///
    /// On WASM, both variants are routed through [`web::SigningKey::import`] so
    /// that `Extractable` seeds produce a **non-extractable** `WebCrypto` key
    /// (matching the security default of [`web::SigningKey::import`]).
    ///
    /// # Errors
    ///
    /// Returns an error if the seed has the wrong length or the `WebCrypto` import fails.
    #[allow(clippy::unused_async)] // async is needed on WASM
    pub async fn import(key: impl Into<KeyExport>) -> Result<Self, Ed25519KeyError> {
        let key = key.into();

        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            Ok(Self::WebCrypto(web::SigningKey::import(key).await?))
        }

        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            match key {
                KeyExport::Extractable(ref bytes) => {
                    let seed: [u8; 32] = bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| Ed25519KeyError::InvalidSeedLength(bytes.len()))?;
                    Ok(Self::Native(ed25519_dalek::SigningKey::from_bytes(&seed)))
                }
            }
        }
    }
}

impl From<ed25519_dalek::SigningKey> for Ed25519SigningKey {
    fn from(key: ed25519_dalek::SigningKey) -> Self {
        Self::Native(key)
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
impl From<web::SigningKey> for Ed25519SigningKey {
    fn from(key: web::SigningKey) -> Self {
        Self::WebCrypto(key)
    }
}

impl Ed25519SigningKey {
    /// Sign a message asynchronously.
    ///
    /// # Errors
    ///
    /// Returns `signature::Error` if signing fails.
    #[allow(clippy::unused_async)]
    pub async fn sign_bytes(&self, msg: &[u8]) -> Result<Ed25519Signature, signature::Error> {
        match self {
            Self::Native(key) => {
                use signature::Signer;
                let sig = key.try_sign(msg)?;
                Ok(Ed25519Signature::from(sig))
            }
            #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
            Self::WebCrypto(key) => key.sign_bytes(msg).await,
        }
    }
}

// ============================================================================
// DID and Signer types (moved from ucan::principal::ed25519)
// ============================================================================

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

    /// Key import/export error.
    Key(Ed25519KeyError),
}

impl std::fmt::Display for Ed25519SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            Self::Rng(e) => write!(f, "RNG error: {e}"),
            #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
            Self::WebCrypto(e) => write!(f, "{e}"),
            Self::Key(e) => write!(f, "{e}"),
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

impl From<Ed25519KeyError> for Ed25519SignerError {
    fn from(e: Ed25519KeyError) -> Self {
        Self::Key(e)
    }
}

/// An `Ed25519` `did:key`.
#[derive(Debug, Clone, PartialEq)]
#[allow(missing_copy_implementations)] // Ed25519VerifyingKey is not Copy on WASM
pub struct Ed25519Did(pub Ed25519VerifyingKey);

impl From<Ed25519VerifyingKey> for Ed25519Did {
    fn from(key: Ed25519VerifyingKey) -> Self {
        Ed25519Did(key)
    }
}

impl From<ed25519_dalek::VerifyingKey> for Ed25519Did {
    fn from(key: ed25519_dalek::VerifyingKey) -> Self {
        Ed25519Did(Ed25519VerifyingKey::Native(key))
    }
}

impl From<ed25519_dalek::SigningKey> for Ed25519Did {
    fn from(key: ed25519_dalek::SigningKey) -> Self {
        let verifying_key = Ed25519VerifyingKey::Native(key.verifying_key());
        Ed25519Did(verifying_key)
    }
}

impl std::fmt::Display for Ed25519Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut raw_bytes = Vec::with_capacity(34);
        raw_bytes.push(0xed);
        raw_bytes.push(0x01);
        raw_bytes.extend_from_slice(&self.0.to_bytes());
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
        Ok(Ed25519Did(Ed25519VerifyingKey::Native(key)))
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

// === Verifier impl for Ed25519Did ===
impl Verifier for Ed25519Did {
    type Signature = Ed25519Signature;

    async fn verify(
        &self,
        msg: &[u8],
        signature: &Ed25519Signature,
    ) -> Result<(), signature::Error> {
        self.0.verify_signature(msg, signature).await
    }
}

impl Principal for Ed25519Did {
    type Algorithm = Ed25519;
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

                Ok(Ed25519Did(Ed25519VerifyingKey::Native(vk)))
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

impl From<Ed25519SigningKey> for Ed25519Signer {
    fn from(signer: Ed25519SigningKey) -> Self {
        let did = Ed25519Did::from(signer.verifying_key());
        Self { did, signer }
    }
}

impl Ed25519Signer {
    /// Generate a new Ed25519 keypair.
    ///
    /// On WASM, uses the `WebCrypto` API (non-extractable key by default).
    /// On native, uses `ed25519_dalek` with random bytes from `getrandom`.
    ///
    /// # Errors
    ///
    /// On WASM, returns an error if key generation fails or the browser
    /// doesn't support Ed25519. On native, returns an error if the RNG fails.
    pub async fn generate() -> Result<Self, Ed25519SignerError> {
        Ok(Ed25519SigningKey::generate().await?.into())
    }

    /// Import a keypair from a [`KeyExport`].
    ///
    /// Accepts anything that converts `Into<KeyExport>`, including `&[u8; 32]`.
    ///
    /// # Errors
    ///
    /// Returns an error if the seed has the wrong length or the `WebCrypto` import fails.
    pub async fn import(key: impl Into<KeyExport>) -> Result<Self, Ed25519SignerError> {
        let signing_key = Ed25519SigningKey::import(key).await?;
        Ok(signing_key.into())
    }

    /// Export the key material.
    ///
    /// # Errors
    ///
    /// Returns an error if the `WebCrypto` export operation fails.
    pub async fn export(&self) -> Result<KeyExport, Ed25519SignerError> {
        Ok(self.signer.export().await?)
    }

    /// Get the associated DID.
    #[must_use]
    pub const fn did(&self) -> &Ed25519Did {
        &self.did
    }

    /// Get the inner signing key.
    #[must_use]
    pub const fn signing_key(&self) -> &Ed25519SigningKey {
        &self.signer
    }
}

impl From<ed25519_dalek::SigningKey> for Ed25519Signer {
    fn from(key: ed25519_dalek::SigningKey) -> Self {
        Ed25519SigningKey::from(key).into()
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
impl From<web::SigningKey> for Ed25519Signer {
    fn from(key: web::SigningKey) -> Self {
        Ed25519SigningKey::from(key).into()
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
impl ExtractableCryptoKey for Ed25519Signer {
    async fn generate() -> Result<Self, WebCryptoError> {
        let key = <web::SigningKey as ExtractableCryptoKey>::generate().await?;
        Ok(Ed25519SigningKey::from(key).into())
    }

    async fn import(key: impl Into<KeyExport>) -> Result<Self, WebCryptoError> {
        let key = <web::SigningKey as ExtractableCryptoKey>::import(key).await?;
        Ok(Ed25519SigningKey::from(key).into())
    }

    async fn export(&self) -> Result<KeyExport, WebCryptoError> {
        match &self.signer {
            Ed25519SigningKey::WebCrypto(key) => {
                <web::SigningKey as ExtractableCryptoKey>::export(key).await
            }
            Ed25519SigningKey::Native(key) => Ok(KeyExport::Extractable(key.to_bytes().to_vec())),
        }
    }
}

impl std::fmt::Display for Ed25519Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.did)
    }
}

// === Signer impl for Ed25519Signer ===
impl Signer for Ed25519Signer {
    type Signature = Ed25519Signature;

    async fn sign(&self, msg: &[u8]) -> Result<Ed25519Signature, signature::Error> {
        self.signer.sign_bytes(msg).await
    }
}

impl Issuer for Ed25519Signer {
    type Principal = Ed25519Did;

    fn principal(&self) -> &Self::Principal {
        &self.did
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
        assert_eq!(parsed, signer.did().clone());
    }

    #[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        wasm_bindgen_test::wasm_bindgen_test
    )]
    async fn ed25519_varsig_signer_produces_valid_signature() {
        let signer = test_signer(42).await;
        let msg = b"test message for async signing";

        let signature = Signer::sign(&signer, msg).await.unwrap();

        let did = signer.did();
        Verifier::verify(did, msg, &signature).await.unwrap();
    }

    #[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        wasm_bindgen_test::wasm_bindgen_test
    )]
    async fn ed25519_varsig_signer_different_messages_different_signatures() {
        let signer = test_signer(7).await;
        let msg1 = b"first message";
        let msg2 = b"second message";

        let sig1 = Signer::sign(&signer, msg1).await.unwrap();
        let sig2 = Signer::sign(&signer, msg2).await.unwrap();

        assert_ne!(
            sig1, sig2,
            "Different messages should produce different signatures"
        );

        let did = signer.did();
        Verifier::verify(did, msg1, &sig1).await.unwrap();
        Verifier::verify(did, msg2, &sig2).await.unwrap();
    }

    #[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        wasm_bindgen_test::wasm_bindgen_test
    )]
    async fn ed25519_varsig_signer_wrong_message_fails_verification() {
        let signer = test_signer(99).await;
        let msg = b"original message";
        let wrong_msg = b"tampered message";

        let signature = Signer::sign(&signer, msg).await.unwrap();

        let did = signer.did();
        assert!(
            Verifier::verify(did, wrong_msg, &signature).await.is_err(),
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

        let sig1 = Signer::sign(&signer1, msg).await.unwrap();
        let sig2 = Signer::sign(&signer2, msg).await.unwrap();

        assert_ne!(sig1, sig2);

        assert!(Verifier::verify(signer1.did(), msg, &sig1).await.is_ok());
        assert!(Verifier::verify(signer2.did(), msg, &sig2).await.is_ok());

        // Cross-verification should fail
        assert!(Verifier::verify(signer1.did(), msg, &sig2).await.is_err());
        assert!(Verifier::verify(signer2.did(), msg, &sig1).await.is_err());
    }

    #[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        wasm_bindgen_test::wasm_bindgen_test
    )]
    async fn export_import_roundtrip_preserves_did() {
        let signer = test_signer(77).await;
        let original_did = signer.did().to_string();

        let exported = signer.export().await.unwrap();
        let restored = Ed25519Signer::import(exported).await.unwrap();

        assert_eq!(
            restored.did().to_string(),
            original_did,
            "Restored signer should have the same DID"
        );
    }

    #[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        wasm_bindgen_test::wasm_bindgen_test
    )]
    async fn export_import_roundtrip_produces_valid_signatures() {
        let signer = test_signer(88).await;
        let msg = b"roundtrip signing test";

        let exported = signer.export().await.unwrap();
        let restored = Ed25519Signer::import(exported).await.unwrap();

        let signature = Signer::sign(&restored, msg).await.unwrap();
        Verifier::verify(signer.did(), msg, &signature)
            .await
            .expect("Original verifier should accept signature from restored signer");
    }

    #[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        wasm_bindgen_test::wasm_bindgen_test
    )]
    async fn export_import_roundtrip_seed_bytes_match() {
        let seed = [55u8; 32];
        let signer = Ed25519Signer::import(&seed).await.unwrap();

        let exported = signer.export().await.unwrap();
        match exported {
            KeyExport::Extractable(ref bytes) => {
                assert_eq!(
                    bytes.as_slice(),
                    &seed,
                    "Exported seed should match original"
                );
            }
            #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
            KeyExport::NonExtractable { .. } => {
                // On the web the default import creates non-extractable keys,
                // so we just verify the DID roundtrips instead.
                let restored = Ed25519Signer::import(exported).await.unwrap();
                assert_eq!(restored.did().to_string(), signer.did().to_string());
            }
        }
    }

    #[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        wasm_bindgen_test::wasm_bindgen_test
    )]
    async fn double_export_import_roundtrip() {
        let signer = test_signer(66).await;

        let exported1 = signer.export().await.unwrap();
        let restored1 = Ed25519Signer::import(exported1).await.unwrap();

        let exported2 = restored1.export().await.unwrap();
        let restored2 = Ed25519Signer::import(exported2).await.unwrap();

        assert_eq!(
            restored2.did().to_string(),
            signer.did().to_string(),
            "Double roundtrip should preserve DID"
        );

        let msg = b"double roundtrip";
        let sig = Signer::sign(&restored2, msg).await.unwrap();
        Verifier::verify(signer.did(), msg, &sig)
            .await
            .expect("Original verifier should accept double-roundtripped signature");
    }

    #[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        wasm_bindgen_test::wasm_bindgen_test
    )]
    async fn build_delegation_with_signer() {
        use ucan::delegation::{builder::DelegationBuilder, subject::DelegatedSubject};

        let signer = test_signer(10).await;
        let aud_signer = test_signer(20).await;
        let aud = aud_signer.did().clone();

        let delegation = DelegationBuilder::new()
            .issuer(signer.clone())
            .audience(aud.clone())
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
        use ucan::delegation::{builder::DelegationBuilder, subject::DelegatedSubject};

        let signer = test_signer(10).await;
        let aud_signer = test_signer(20).await;

        let delegation = DelegationBuilder::new()
            .issuer(signer.clone())
            .audience(aud_signer.did().clone())
            .subject(DelegatedSubject::Any)
            .command(vec!["roundtrip".to_string()])
            .try_build()
            .await
            .unwrap();

        let bytes = serde_ipld_dagcbor::to_vec(&delegation).unwrap();

        let roundtripped: ucan::delegation::Delegation<Ed25519Did> =
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
        use ucan::invocation::builder::InvocationBuilder;

        let operator_signer = test_signer(30).await;
        let subject_signer = test_signer(40).await;
        let subject_did = subject_signer.did().clone();

        let invocation = InvocationBuilder::new()
            .issuer(operator_signer.clone())
            .audience(subject_did.clone())
            .subject(subject_did.clone())
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
        use ucan::invocation::builder::InvocationBuilder;

        let signer = test_signer(50).await;
        let subject_did = signer.did().clone();

        let invocation = InvocationBuilder::new()
            .issuer(signer.clone())
            .audience(subject_did.clone())
            .subject(subject_did.clone())
            .command(vec!["archive".to_string(), "get".to_string()])
            .arguments(std::collections::BTreeMap::new())
            .proofs(vec![])
            .try_build()
            .await
            .expect("Failed to build invocation");

        let bytes =
            serde_ipld_dagcbor::to_vec(&invocation).expect("Failed to serialize invocation");

        let roundtripped: ucan::Invocation<Ed25519Did> =
            serde_ipld_dagcbor::from_slice(&bytes).expect("Failed to deserialize invocation");

        assert_eq!(roundtripped.issuer(), invocation.issuer());
        assert_eq!(roundtripped.command(), invocation.command());
    }
}

// WebCrypto-only tests (extractable keys, non-extractable public key extraction)
#[cfg(all(test, target_arch = "wasm32", target_os = "unknown"))]
mod wasm_tests {
    use super::*;
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
        assert_eq!(parsed.unwrap(), signer.did().clone());
    }

    #[wasm_bindgen_test]
    async fn generate_extractable_key() {
        let signer = <Ed25519Signer as ExtractableCryptoKey>::generate().await;
        assert!(signer.is_ok(), "Should be able to generate extractable key");

        let signer = signer.unwrap();
        let msg = b"test";
        let sig = Signer::sign(&signer, msg).await;
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
        let sig = Signer::sign(&signer, msg).await;
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

        let msg = b"test message for non-extractable key";
        let signature = Signer::sign(&signer, msg).await.unwrap();

        let result = Verifier::verify(did, msg, &signature).await;
        assert!(
            result.is_ok(),
            "Public key from non-extractable key should verify signatures: {:?}",
            result.err()
        );
    }

    #[wasm_bindgen_test]
    async fn extractable_export_import_roundtrip_preserves_seed() {
        let seed = [42u8; 32];
        let signer = <Ed25519Signer as ExtractableCryptoKey>::import(&seed)
            .await
            .unwrap();

        let exported = <Ed25519Signer as ExtractableCryptoKey>::export(&signer)
            .await
            .unwrap();
        match &exported {
            KeyExport::Extractable(bytes) => {
                assert_eq!(
                    bytes.as_slice(),
                    &seed,
                    "Extractable export should return the original seed"
                );
            }
            _ => panic!("Extractable key should export as Extractable"),
        }

        let restored = Ed25519Signer::import(exported).await.unwrap();
        assert_eq!(restored.did().to_string(), signer.did().to_string());
    }

    #[wasm_bindgen_test]
    async fn extractable_export_import_roundtrip_signs_correctly() {
        let seed = [99u8; 32];
        let signer = <Ed25519Signer as ExtractableCryptoKey>::import(&seed)
            .await
            .unwrap();
        let msg = b"extractable roundtrip signing test";

        let exported = <Ed25519Signer as ExtractableCryptoKey>::export(&signer)
            .await
            .unwrap();
        let restored = Ed25519Signer::import(exported).await.unwrap();

        let sig = Signer::sign(&restored, msg).await.unwrap();
        Verifier::verify(signer.did(), msg, &sig)
            .await
            .expect("Original verifier should accept signature from restored signer");
    }

    #[wasm_bindgen_test]
    async fn non_extractable_export_import_roundtrip() {
        let signer = Ed25519Signer::import(&[33u8; 32]).await.unwrap();
        let original_did = signer.did().to_string();
        let msg = b"non-extractable roundtrip test";

        let exported = signer.export().await.unwrap();
        match &exported {
            KeyExport::NonExtractable { .. } => { /* expected */ }
            KeyExport::Extractable(_) => {
                panic!("Default import should create non-extractable key on WASM")
            }
        }

        let restored = Ed25519Signer::import(exported).await.unwrap();
        assert_eq!(
            restored.did().to_string(),
            original_did,
            "Non-extractable roundtrip should preserve DID"
        );

        let sig = Signer::sign(&restored, msg).await.unwrap();
        Verifier::verify(signer.did(), msg, &sig)
            .await
            .expect("Original verifier should accept non-extractable roundtrip signature");
    }

    #[wasm_bindgen_test]
    async fn imported_non_extractable_key_matches_native_public_key() {
        let seed = [42u8; 32];

        let web_signer = Ed25519Signer::import(&seed).await.unwrap();

        let native_signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let native_did: Ed25519Did = native_signing_key.verifying_key().into();

        let web_did = web_signer.did();

        assert_eq!(
            web_did, &native_did,
            "DID from WebCrypto import should match native derivation"
        );

        let msg = b"cross-platform verification test";
        let signature = Signer::sign(&web_signer, msg).await.unwrap();

        assert!(
            Verifier::verify(&native_did, msg, &signature).await.is_ok(),
            "Native verifier should verify WebCrypto signature"
        );
    }
}

//! `EdDSA` signature algorithms.

use crate::{
    curve::Edwards25519,
    hash::{Multihasher, Sha2_512},
    signer::Sign,
    verify::Verify,
};
use signature::SignatureEncoding;
use std::marker::PhantomData;

// Platform-specific implementations
#[cfg(feature = "edwards25519")]
pub mod native;

// WebCrypto is only available in web browsers (wasm32 + unknown OS)
// Not available in WASI or other WASM environments
#[cfg(all(
    feature = "edwards25519",
    target_arch = "wasm32",
    target_os = "unknown"
))]
pub mod web;

/// The `EdDSA` signature algorithm.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EdDsa<C: EdDsaCurve, H: Multihasher>(PhantomData<(C, H)>);

impl<C: EdDsaCurve, H: Multihasher> EdDsa<C, H> {
    /// Create a new `EdDsa` instance.
    #[must_use]
    pub const fn new() -> Self {
        EdDsa(PhantomData)
    }
}

/// The EdDSA-compatible curves
pub trait EdDsaCurve: Sized {}
impl EdDsaCurve for Edwards25519 {}

// TODO waiting on ed448_goldilocks to cut a stable release with signing
// impl EdDsaCurve for Edwards448 {}

/// The Ed25519 signature algorithm.
///
/// The `EdDSA` signing algorithm with the Edwards25519 curve with SHA2-512 hashing.
#[cfg(all(feature = "edwards25519", feature = "sha2_512"))]
pub type Ed25519 = EdDsa<Edwards25519, Sha2_512>;

/// Ed25519 signature bytes (64 bytes).
///
/// This is a platform-agnostic representation of an Ed25519 signature.
/// It can be produced by either native (`ed25519_dalek`) or `WebCrypto` signers,
/// and can be converted to/from `ed25519_dalek::Signature` for verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Ed25519Signature(#[serde(with = "serde_bytes")] pub [u8; 64]);

impl Ed25519Signature {
    /// Create a new signature from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Get the raw signature bytes.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
}

impl From<[u8; 64]> for Ed25519Signature {
    fn from(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

impl From<Ed25519Signature> for [u8; 64] {
    fn from(sig: Ed25519Signature) -> Self {
        sig.0
    }
}

#[cfg(feature = "edwards25519")]
impl From<ed25519_dalek::Signature> for Ed25519Signature {
    fn from(sig: ed25519_dalek::Signature) -> Self {
        Self(sig.to_bytes())
    }
}

#[cfg(feature = "edwards25519")]
impl From<Ed25519Signature> for ed25519_dalek::Signature {
    fn from(sig: Ed25519Signature) -> Self {
        ed25519_dalek::Signature::from_bytes(&sig.0)
    }
}

impl SignatureEncoding for Ed25519Signature {
    type Repr = [u8; 64];
}

impl TryFrom<&[u8]> for Ed25519Signature {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 64] = bytes.try_into().map_err(|_| signature::Error::new())?;
        Ok(Self(bytes))
    }
}

/// Ed25519 verifying key.
///
/// This enum abstracts over different Ed25519 verification implementations:
/// - `Native`: Uses `ed25519_dalek::VerifyingKey` for native platforms
/// - `WebCrypto`: Uses the browser's `WebCrypto` API (web WASM only)
#[cfg(feature = "edwards25519")]
#[derive(Debug, Clone)]
#[allow(missing_copy_implementations)] // CryptoKey is not Copy on WASM
pub enum Ed25519VerifyingKey {
    /// Native verifying key using `ed25519_dalek`.
    Native(native::VerifyingKey),

    /// WebCrypto verifying key (web WASM only).
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    WebCrypto(web::VerifyingKey),
}

#[cfg(feature = "edwards25519")]
impl From<native::VerifyingKey> for Ed25519VerifyingKey {
    fn from(key: native::VerifyingKey) -> Self {
        Self::Native(key)
    }
}

#[cfg(all(
    feature = "edwards25519",
    target_arch = "wasm32",
    target_os = "unknown"
))]
impl From<web::VerifyingKey> for Ed25519VerifyingKey {
    fn from(key: web::VerifyingKey) -> Self {
        Self::WebCrypto(key)
    }
}

#[cfg(feature = "edwards25519")]
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

#[cfg(feature = "edwards25519")]
impl crate::verify::AsyncVerifier<Ed25519Signature> for Ed25519VerifyingKey {
    async fn verify_async(
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

#[cfg(feature = "edwards25519")]
impl PartialEq for Ed25519VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

#[cfg(feature = "edwards25519")]
impl Eq for Ed25519VerifyingKey {}

/// Ed25519 signing key.
///
/// This enum abstracts over different Ed25519 signing implementations:
/// - `Native`: Uses `ed25519_dalek::SigningKey` for native platforms
/// - `WebCrypto`: Uses the browser's `WebCrypto` API (web WASM only)
#[cfg(feature = "edwards25519")]
#[derive(Debug, Clone)]
pub enum Ed25519SigningKey {
    /// Native signing key using `ed25519_dalek`.
    Native(native::SigningKey),

    /// WebCrypto signing key (web WASM only).
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    WebCrypto(web::SigningKey),
}

#[cfg(feature = "edwards25519")]
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
}

#[cfg(feature = "edwards25519")]
impl From<ed25519_dalek::SigningKey> for Ed25519SigningKey {
    fn from(key: ed25519_dalek::SigningKey) -> Self {
        Self::Native(key)
    }
}

#[cfg(all(
    feature = "edwards25519",
    target_arch = "wasm32",
    target_os = "unknown"
))]
impl From<web::SigningKey> for Ed25519SigningKey {
    fn from(key: web::SigningKey) -> Self {
        Self::WebCrypto(key)
    }
}

#[cfg(feature = "edwards25519")]
impl async_signature::AsyncSigner<Ed25519Signature> for Ed25519SigningKey {
    async fn sign_async(&self, msg: &[u8]) -> Result<Ed25519Signature, signature::Error> {
        match self {
            Self::Native(key) => {
                use signature::Signer;
                let sig = key.try_sign(msg)?;
                Ok(Ed25519Signature::from(sig))
            }
            #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
            Self::WebCrypto(key) => key.sign_async(msg).await,
        }
    }
}

#[cfg(all(feature = "edwards25519", feature = "sha2_512"))]
impl Verify for Ed25519 {
    type Signature = Ed25519Signature;
    type Verifier = Ed25519VerifyingKey;

    fn prefix(&self) -> u64 {
        0xed
    }

    fn config_tags(&self) -> Vec<u64> {
        vec![0xed, 0x13]
    }

    fn try_from_tags(bytes: &[u64]) -> Option<(Self, &[u64])> {
        if *bytes.get(0..=2)? == [0xed, 0xed, 0x13] {
            Some((EdDsa(PhantomData), bytes.get(3..)?))
        } else {
            None
        }
    }
}

#[cfg(all(feature = "edwards25519", feature = "sha2_512"))]
impl Sign for Ed25519 {
    type Signer = Ed25519SigningKey;
    type SignError = signature::Error;
}

//! WebCrypto-based Ed25519 signing implementation.
//!
//! This module provides Ed25519 signing for WASM environments using
//! the Web Crypto API. It supports non-extractable keys for enhanced
//! security in browser and service worker environments.
//!
//! # Security
//!
//! By default, all keys are created as **non-extractable**, meaning the private
//! key material cannot be accessed directly from JavaScript/WASM code. This
//! provides defense-in-depth: even if an attacker gains code execution in your
//! service worker, they cannot exfiltrate the private key material.

use super::Ed25519Signature;
use ed25519_dalek::VerifyingKey;
use js_sys::{Object, Reflect, Uint8Array};
use thiserror::Error;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{CryptoKey, SubtleCrypto};

/// WebCrypto-based Ed25519 signing key.
///
/// This wraps a WebCrypto `CryptoKey` which is non-extractable by default,
/// meaning the private key material cannot be accessed directly from
/// JavaScript/WASM code.
///
/// # Creating Keys
///
/// Use [`SigningKey::generate()`] to create a new non-extractable keypair:
///
/// ```ignore
/// // Generate a new non-extractable key (secure default)
/// let key = SigningKey::generate().await?;
///
/// // Import from seed bytes (non-extractable)
/// let key = SigningKey::import(&seed).await?;
/// ```
#[derive(Debug, Clone)]
pub struct SigningKey {
    /// The WebCrypto private key.
    private_key: CryptoKey,
    /// The verified public key (validated eagerly at construction time).
    public_key: VerifyingKey,
}

impl SigningKey {
    /// Create a `SigningKey` from a `CryptoKey` and a verified public key.
    fn new(private_key: CryptoKey, public_key: VerifyingKey) -> Self {
        Self {
            private_key,
            public_key,
        }
    }

    /// Generate a new Ed25519 keypair using WebCrypto.
    ///
    /// The private key is created as **non-extractable** for security.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails or the browser doesn't support Ed25519.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let key = SigningKey::generate().await?;
    /// ```
    pub async fn generate() -> Result<Self, WebCryptoError> {
        generate(false).await
    }

    /// Import a keypair from raw seed bytes.
    ///
    /// The imported key is **non-extractable** for security.
    ///
    /// # Arguments
    ///
    /// * `seed` - The 32-byte Ed25519 private key seed
    ///
    /// # Errors
    ///
    /// Returns an error if the seed bytes are invalid or import fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let seed: [u8; 32] = /* ... */;
    /// let key = SigningKey::import(&seed).await?;
    /// ```
    pub async fn import(seed: &[u8; 32]) -> Result<Self, WebCryptoError> {
        import(seed, false).await
    }

    /// Get the verifying (public) key.
    ///
    /// This is infallible because the public key bytes are validated at construction time.
    #[must_use]
    pub const fn verifying_key(&self) -> VerifyingKey {
        self.public_key
    }
}

impl async_signature::AsyncSigner<Ed25519Signature> for SigningKey {
    async fn sign_async(&self, msg: &[u8]) -> Result<Ed25519Signature, signature::Error> {
        sign(&self.private_key, msg).await
    }
}

// ============================================================================
// Internal implementation
// ============================================================================

/// Generate a keypair with the specified extractability.
async fn generate(extractable: bool) -> Result<SigningKey, WebCryptoError> {
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

    // Export public key to get the raw bytes and validate eagerly
    let public_key_bytes = export_public_key_raw(&subtle, &public_key).await?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|e| WebCryptoError::InvalidPublicKey(e.to_string()))?;

    Ok(SigningKey::new(private_key, verifying_key))
}

/// Import a keypair from seed bytes with the specified extractability.
async fn import(seed: &[u8; 32], extractable: bool) -> Result<SigningKey, WebCryptoError> {
    let subtle = get_subtle_crypto()?;

    // Import as PKCS#8 - Ed25519 private keys need proper formatting
    let pkcs8 = Pkcs8::from(seed);

    let algorithm = Object::new();
    Reflect::set(&algorithm, &"name".into(), &"Ed25519".into())
        .map_err(|e| WebCryptoError::JsError(format!("{e:?}")))?;

    let key_usages = js_sys::Array::new();
    key_usages.push(&"sign".into());

    let pkcs8_array = Uint8Array::from(pkcs8.as_bytes());

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

    // Derive public key from seed using ed25519_dalek
    let verifying_key = ed25519_dalek::SigningKey::from_bytes(seed).verifying_key();

    Ok(SigningKey::new(private_key, verifying_key))
}

/// Sign a message using WebCrypto.
async fn sign(key: &CryptoKey, msg: &[u8]) -> Result<Ed25519Signature, signature::Error> {
    let global = js_sys::global();

    let crypto = Reflect::get(&global, &"crypto".into())
        .map_err(|e| signature::Error::from_source(format!("crypto not found: {e:?}")))?;

    let subtle: SubtleCrypto = Reflect::get(&crypto, &"subtle".into())
        .map_err(|e| signature::Error::from_source(format!("subtle not found: {e:?}")))?
        .unchecked_into();

    let algorithm = Object::new();
    Reflect::set(&algorithm, &"name".into(), &"Ed25519".into())
        .map_err(|e| signature::Error::from_source(format!("failed to set algorithm: {e:?}")))?;

    let msg_array = Uint8Array::from(msg);

    let promise = subtle
        .sign_with_object_and_buffer_source(&algorithm, key, &msg_array)
        .map_err(|e| signature::Error::from_source(format!("sign failed: {e:?}")))?;

    let signature_buffer = JsFuture::from(promise)
        .await
        .map_err(|e| signature::Error::from_source(format!("sign await failed: {e:?}")))?;

    let signature_array = Uint8Array::new(&signature_buffer);
    let mut signature_bytes = [0u8; 64];

    if signature_array.length() != 64 {
        return Err(signature::Error::from_source(format!(
            "expected 64 bytes, got {}",
            signature_array.length()
        )));
    }

    signature_array.copy_to(&mut signature_bytes);

    Ok(Ed25519Signature::from_bytes(signature_bytes))
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

    /// Invalid public key.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// JavaScript error.
    #[error("JS error: {0}")]
    JsError(String),
}

/// Get the SubtleCrypto interface.
fn get_subtle_crypto() -> Result<SubtleCrypto, WebCryptoError> {
    let global = js_sys::global();

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

/// PKCS#8 wrapper for Ed25519 private key.
///
/// WebCrypto requires PKCS#8 format for importing Ed25519 private keys.
/// This type wraps the DER-encoded PKCS#8 structure.
struct Pkcs8([u8; 48]);

impl Pkcs8 {
    /// Get the PKCS#8 bytes as a slice.
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8; 32]> for Pkcs8 {
    fn from(seed: &[u8; 32]) -> Self {
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
        let mut pkcs8 = [0u8; 48];
        // Header (16 bytes)
        pkcs8[..16].copy_from_slice(&[
            0x30, 0x2e, // SEQUENCE, 46 bytes
            0x02, 0x01, 0x00, // INTEGER 0 (version)
            0x30, 0x05, // SEQUENCE, 5 bytes
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
            0x04, 0x22, // OCTET STRING, 34 bytes
            0x04, 0x20, // OCTET STRING, 32 bytes (the seed)
        ]);
        // Seed (32 bytes)
        pkcs8[16..].copy_from_slice(seed);
        Self(pkcs8)
    }
}

// ============================================================================
// Extractable key support
// ============================================================================

/// Trait for creating WebCrypto keys with extractable private key material.
///
/// By default, [`SigningKey::generate()`] and [`SigningKey::import()`] create
/// **non-extractable** keys for security. Use this trait when you need
/// extractable keys (e.g., for key backup or export).
///
/// # ⚠️ Security Warning
///
/// Extractable keys allow the private key material to be exported from
/// WebCrypto. Only use extractable keys when you have a specific need
/// for key export functionality.
///
/// # Example
///
/// ```ignore
/// use varsig::signature::eddsa::web::{SigningKey, ExtractableCryptoKey};
///
/// // Generate an extractable key
/// let key = <SigningKey as ExtractableCryptoKey>::generate().await?;
/// ```
pub trait ExtractableCryptoKey: Sized {
    /// Generate a new keypair with extractable private key.
    fn generate() -> impl std::future::Future<Output = Result<Self, WebCryptoError>>;

    /// Import a keypair from seed bytes with extractable private key.
    fn import(seed: &[u8; 32]) -> impl std::future::Future<Output = Result<Self, WebCryptoError>>;
}

impl ExtractableCryptoKey for SigningKey {
    async fn generate() -> Result<Self, WebCryptoError> {
        generate(true).await
    }

    async fn import(seed: &[u8; 32]) -> Result<Self, WebCryptoError> {
        import(seed, true).await
    }
}

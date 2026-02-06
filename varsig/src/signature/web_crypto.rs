//! `WebCrypto`-compatible signature types and verifiers.
//!
//! This module provides a unified enum type that can represent any of the
//! `WebCrypto`-compatible signature algorithms (RS256, ES256, ES384, ES512, Ed25519).

#[cfg(feature = "web_crypto")]
use crate::signature::ecdsa::{self, P521VerifyingKey};
#[cfg(feature = "web_crypto")]
use crate::signature::eddsa;
#[cfg(feature = "web_crypto")]
use crate::signature::rsa;
#[cfg(feature = "web_crypto")]
use crate::verify::{Verify, VarsigHeader};
#[cfg(feature = "web_crypto")]
use signature::{SignatureEncoding, Verifier};

/// The WebCrypto-compatible signature algorithm configuration.
///
/// This enum represents the different signature algorithms supported by `WebCrypto`.
/// Each variant contains the algorithm configuration (not the actual signature bytes).
#[cfg(feature = "web_crypto")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebCrypto {
    /// 2048-bit RSA signature type (256 bytes)
    Rs256_2048(rsa::Rs256<256>),

    /// 4096-bit RSA signature type (512 bytes)
    Rs256_4096(rsa::Rs256<512>),

    /// ES256 signature type (P-256 curve with SHA-256)
    Es256(ecdsa::Es256),

    /// ES384 signature type (P-384 curve with SHA-384)
    Es384(ecdsa::Es384),

    /// ES512 signature type (P-521 curve with SHA-512)
    Es512(ecdsa::Es512),

    /// Ed25519 signature type
    Ed25519(eddsa::Ed25519),
}

/// WebCrypto-compatible signature bytes.
///
/// This enum wraps the actual signature bytes from each supported algorithm.
#[cfg(feature = "web_crypto")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebCryptoSignature {
    /// RSA signature bytes
    Rsa(::rsa::pkcs1v15::Signature),

    /// ES256 signature bytes (P-256)
    Es256(p256::ecdsa::Signature),

    /// ES384 signature bytes (P-384)
    Es384(p384::ecdsa::Signature),

    /// ES512 signature bytes (P-521)
    Es512(p521::ecdsa::Signature),

    /// Ed25519 signature bytes
    Ed25519(ed25519_dalek::Signature),
}

#[cfg(feature = "web_crypto")]
impl SignatureEncoding for WebCryptoSignature {
    type Repr = Vec<u8>;
}

#[cfg(feature = "web_crypto")]
impl TryFrom<&[u8]> for WebCryptoSignature {
    type Error = signature::Error;

    fn try_from(_bytes: &[u8]) -> Result<Self, Self::Error> {
        // Cannot determine signature type from bytes alone without context
        // This would need to be called with knowledge of the algorithm
        Err(signature::Error::new())
    }
}

#[cfg(feature = "web_crypto")]
impl From<WebCryptoSignature> for Vec<u8> {
    fn from(sig: WebCryptoSignature) -> Self {
        match sig {
            WebCryptoSignature::Rsa(s) => s.to_vec(),
            WebCryptoSignature::Es256(s) => s.to_bytes().to_vec(),
            WebCryptoSignature::Es384(s) => s.to_bytes().to_vec(),
            WebCryptoSignature::Es512(s) => s.to_bytes().to_vec(),
            WebCryptoSignature::Ed25519(s) => s.to_bytes().to_vec(),
        }
    }
}

/// WebCrypto-compatible verifier (public key).
///
/// This enum wraps the verifying keys for each supported algorithm.
#[cfg(feature = "web_crypto")]
pub enum WebCryptoVerifier {
    /// RSA 2048-bit verifying key
    Rs256_2048(::rsa::pkcs1v15::VerifyingKey<::rsa::sha2::Sha256>),

    /// RSA 4096-bit verifying key
    Rs256_4096(::rsa::pkcs1v15::VerifyingKey<::rsa::sha2::Sha256>),

    /// ES256 verifying key (P-256)
    Es256(p256::ecdsa::VerifyingKey),

    /// ES384 verifying key (P-384)
    Es384(p384::ecdsa::VerifyingKey),

    /// ES512 verifying key (P-521)
    Es512(P521VerifyingKey),

    /// Ed25519 verifying key
    Ed25519(ed25519_dalek::VerifyingKey),
}

#[cfg(feature = "web_crypto")]
impl std::fmt::Debug for WebCryptoVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rs256_2048(_) => f.debug_tuple("Rs256_2048").finish(),
            Self::Rs256_4096(_) => f.debug_tuple("Rs256_4096").finish(),
            Self::Es256(key) => f.debug_tuple("Es256").field(key).finish(),
            Self::Es384(key) => f.debug_tuple("Es384").field(key).finish(),
            Self::Es512(key) => f.debug_tuple("Es512").field(key).finish(),
            Self::Ed25519(key) => f.debug_tuple("Ed25519").field(key).finish(),
        }
    }
}

#[cfg(feature = "web_crypto")]
impl Verifier<WebCryptoSignature> for WebCryptoVerifier {
    fn verify(&self, msg: &[u8], signature: &WebCryptoSignature) -> Result<(), signature::Error> {
        match (self, signature) {
            (
                WebCryptoVerifier::Rs256_2048(key) | WebCryptoVerifier::Rs256_4096(key),
                WebCryptoSignature::Rsa(sig),
            ) => key.verify(msg, sig),
            (WebCryptoVerifier::Es256(key), WebCryptoSignature::Es256(sig)) => key.verify(msg, sig),
            (WebCryptoVerifier::Es384(key), WebCryptoSignature::Es384(sig)) => key.verify(msg, sig),
            (WebCryptoVerifier::Es512(key), WebCryptoSignature::Es512(sig)) => key.verify(msg, sig),
            (WebCryptoVerifier::Ed25519(key), WebCryptoSignature::Ed25519(sig)) => {
                key.verify(msg, sig)
            }
            _ => Err(signature::Error::new()), // Mismatched key and signature types
        }
    }
}

#[cfg(feature = "web_crypto")]
impl VarsigHeader for WebCrypto {
    type Signature = WebCryptoSignature;

    fn prefix(&self) -> u64 {
        match self {
            WebCrypto::Rs256_2048(rs256) => rs256.prefix(),
            WebCrypto::Rs256_4096(rs512) => rs512.prefix(),
            WebCrypto::Es256(es256) => es256.prefix(),
            WebCrypto::Es384(es384) => es384.prefix(),
            WebCrypto::Es512(es512) => es512.prefix(),
            WebCrypto::Ed25519(ed25519) => ed25519.prefix(),
        }
    }

    fn config_tags(&self) -> Vec<u64> {
        match self {
            WebCrypto::Rs256_2048(rs256) => rs256.config_tags(),
            WebCrypto::Rs256_4096(rs512) => rs512.config_tags(),
            WebCrypto::Es256(es256) => es256.config_tags(),
            WebCrypto::Es384(es384) => es384.config_tags(),
            WebCrypto::Es512(es512) => es512.config_tags(),
            WebCrypto::Ed25519(ed25519) => ed25519.config_tags(),
        }
    }

    fn try_from_tags(bytes: &[u64]) -> Option<(Self, &[u64])> {
        let first = *bytes.first()?;
        let rest = bytes.get(3..)?;

        match first {
            0x1205 => match bytes.get(1..=2)? {
                [0x12, 0x0100] => Some((WebCrypto::Rs256_2048(rsa::Rs256::<256>::default()), rest)),
                [0x12, 0x0200] => Some((WebCrypto::Rs256_4096(rsa::Rs256::<512>::default()), rest)),
                _ => None,
            },
            0xec => match bytes.get(1..=2)? {
                [0x1201, 0x15] => Some((WebCrypto::Es256(ecdsa::Es256::default()), rest)),
                [0x1201, 0x20] => Some((WebCrypto::Es384(ecdsa::Es384::default()), rest)),
                [0x1201, 0x25] => Some((WebCrypto::Es512(ecdsa::Es512::default()), rest)),
                _ => None,
            },
            0xed => {
                if bytes.get(1..=2)? != [0xed, 0x13] {
                    return None;
                }
                Some((WebCrypto::Ed25519(eddsa::Ed25519::default()), rest))
            }
            _ => None,
        }
    }
}

#[cfg(feature = "web_crypto")]
impl Verify for WebCrypto {
    type Verifier = WebCryptoVerifier;
}

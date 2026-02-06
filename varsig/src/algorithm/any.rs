//! Unified signature algorithm enum.
//!
//! This module provides `Algorithm`, an enum that can represent any of the
//! supported signature algorithms. Each variant is gated behind its own
//! feature flag so that only the algorithms you need are compiled in.

use super::SignatureAlgorithm;
use signature::SignatureEncoding;

/// Unified signature algorithm configuration.
///
/// Each variant wraps the corresponding algorithm type and is only available
/// when the matching feature flag is enabled. At least one algorithm feature
/// must be enabled for this type to have any variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    /// 2048-bit RSA signature (256 bytes)
    #[cfg(feature = "rs256_2048")]
    Rs256_2048(super::rsa::Rs256<256>),

    /// 4096-bit RSA signature (512 bytes)
    #[cfg(feature = "rs256_4096")]
    Rs256_4096(super::rsa::Rs256<512>),

    /// ES256 (P-256 curve with SHA-256)
    #[cfg(feature = "es256")]
    Es256(super::ecdsa::Es256),

    /// ES384 (P-384 curve with SHA-384)
    #[cfg(feature = "es384")]
    Es384(super::ecdsa::Es384),

    /// ES512 (P-521 curve with SHA-512)
    #[cfg(feature = "es512")]
    Es512(super::ecdsa::Es512),

    /// ES256K (secp256k1 curve with SHA-256)
    #[cfg(feature = "es256k")]
    Es256k(super::ecdsa::Es256k),

    /// Ed25519
    #[cfg(feature = "ed25519")]
    Ed25519(super::eddsa::Ed25519),
}

impl Default for Algorithm {
    fn default() -> Self {
        // Pick the first available algorithm as default.
        // Ed25519 is preferred when available.
        #[cfg(feature = "ed25519")]
        {
            return Algorithm::Ed25519(super::eddsa::Ed25519::default());
        }
        #[cfg(all(not(feature = "ed25519"), feature = "es256"))]
        {
            return Algorithm::Es256(super::ecdsa::Es256::default());
        }
        #[cfg(all(not(feature = "ed25519"), not(feature = "es256"), feature = "es256k"))]
        {
            return Algorithm::Es256k(super::ecdsa::Es256k::default());
        }
        #[cfg(all(
            not(feature = "ed25519"),
            not(feature = "es256"),
            not(feature = "es256k"),
            feature = "es384"
        ))]
        {
            return Algorithm::Es384(super::ecdsa::Es384::default());
        }
        #[cfg(all(
            not(feature = "ed25519"),
            not(feature = "es256"),
            not(feature = "es256k"),
            not(feature = "es384"),
            feature = "es512"
        ))]
        {
            return Algorithm::Es512(super::ecdsa::Es512::default());
        }
        #[cfg(all(
            not(feature = "ed25519"),
            not(feature = "es256"),
            not(feature = "es256k"),
            not(feature = "es384"),
            not(feature = "es512"),
            feature = "rs256_2048"
        ))]
        {
            return Algorithm::Rs256_2048(super::rsa::Rs256::<256>::default());
        }
        #[cfg(all(
            not(feature = "ed25519"),
            not(feature = "es256"),
            not(feature = "es256k"),
            not(feature = "es384"),
            not(feature = "es512"),
            not(feature = "rs256_2048"),
            feature = "rs256_4096"
        ))]
        {
            return Algorithm::Rs256_4096(super::rsa::Rs256::<512>::default());
        }
        // If no algorithm feature is enabled, this is the only reachable path.
        #[allow(unreachable_code, clippy::panic)]
        {
            panic!("No algorithm feature enabled; enable at least one algorithm feature")
        }
    }
}

/// Unified signature bytes.
///
/// Each variant wraps the signature type for the corresponding algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Signature {
    /// RSA signature bytes
    #[cfg(any(feature = "rs256_2048", feature = "rs256_4096"))]
    Rsa(::rsa::pkcs1v15::Signature),

    /// ES256 signature bytes (P-256)
    #[cfg(feature = "es256")]
    Es256(p256::ecdsa::Signature),

    /// ES384 signature bytes (P-384)
    #[cfg(feature = "es384")]
    Es384(p384::ecdsa::Signature),

    /// ES512 signature bytes (P-521)
    #[cfg(feature = "es512")]
    Es512(p521::ecdsa::Signature),

    /// ES256K signature bytes (secp256k1)
    #[cfg(feature = "es256k")]
    Es256k(k256::ecdsa::Signature),

    /// Ed25519 signature bytes
    #[cfg(feature = "ed25519")]
    Ed25519(super::eddsa::Ed25519Signature),
}

impl SignatureEncoding for Signature {
    type Repr = Vec<u8>;
}

impl TryFrom<&[u8]> for Signature {
    type Error = signature::Error;

    fn try_from(_bytes: &[u8]) -> Result<Self, Self::Error> {
        // Cannot determine signature type from bytes alone without context.
        Err(signature::Error::new())
    }
}

impl From<Signature> for Vec<u8> {
    fn from(sig: Signature) -> Self {
        match sig {
            #[cfg(any(feature = "rs256_2048", feature = "rs256_4096"))]
            Signature::Rsa(s) => s.to_vec(),
            #[cfg(feature = "es256")]
            Signature::Es256(s) => s.to_bytes().to_vec(),
            #[cfg(feature = "es384")]
            Signature::Es384(s) => s.to_bytes().to_vec(),
            #[cfg(feature = "es512")]
            Signature::Es512(s) => s.to_bytes().to_vec(),
            #[cfg(feature = "es256k")]
            Signature::Es256k(s) => s.to_bytes().to_vec(),
            #[cfg(feature = "ed25519")]
            Signature::Ed25519(s) => s.to_bytes().to_vec(),
        }
    }
}

impl SignatureAlgorithm for Algorithm {
    type Signature = Signature;

    fn prefix(&self) -> u64 {
        match self {
            #[cfg(feature = "rs256_2048")]
            Algorithm::Rs256_2048(a) => a.prefix(),
            #[cfg(feature = "rs256_4096")]
            Algorithm::Rs256_4096(a) => a.prefix(),
            #[cfg(feature = "es256")]
            Algorithm::Es256(a) => a.prefix(),
            #[cfg(feature = "es384")]
            Algorithm::Es384(a) => a.prefix(),
            #[cfg(feature = "es512")]
            Algorithm::Es512(a) => a.prefix(),
            #[cfg(feature = "es256k")]
            Algorithm::Es256k(a) => a.prefix(),
            #[cfg(feature = "ed25519")]
            Algorithm::Ed25519(a) => a.prefix(),
        }
    }

    fn config_tags(&self) -> Vec<u64> {
        match self {
            #[cfg(feature = "rs256_2048")]
            Algorithm::Rs256_2048(a) => a.config_tags(),
            #[cfg(feature = "rs256_4096")]
            Algorithm::Rs256_4096(a) => a.config_tags(),
            #[cfg(feature = "es256")]
            Algorithm::Es256(a) => a.config_tags(),
            #[cfg(feature = "es384")]
            Algorithm::Es384(a) => a.config_tags(),
            #[cfg(feature = "es512")]
            Algorithm::Es512(a) => a.config_tags(),
            #[cfg(feature = "es256k")]
            Algorithm::Es256k(a) => a.config_tags(),
            #[cfg(feature = "ed25519")]
            Algorithm::Ed25519(a) => a.config_tags(),
        }
    }

    fn try_from_tags(bytes: &[u64]) -> Option<(Self, &[u64])> {
        let first = *bytes.first()?;
        let rest = bytes.get(3..)?;

        match first {
            #[cfg(any(feature = "rs256_2048", feature = "rs256_4096"))]
            0x1205 => match bytes.get(1..=2)? {
                #[cfg(feature = "rs256_2048")]
                [0x12, 0x0100] => Some((
                    Algorithm::Rs256_2048(super::rsa::Rs256::<256>::default()),
                    rest,
                )),
                #[cfg(feature = "rs256_4096")]
                [0x12, 0x0200] => Some((
                    Algorithm::Rs256_4096(super::rsa::Rs256::<512>::default()),
                    rest,
                )),
                _ => None,
            },
            #[cfg(any(
                feature = "es256",
                feature = "es384",
                feature = "es512",
                feature = "es256k"
            ))]
            0xec => match bytes.get(1..=2)? {
                #[cfg(feature = "es256")]
                [0x1201, 0x15] => Some((Algorithm::Es256(super::ecdsa::Es256::default()), rest)),
                #[cfg(feature = "es384")]
                [0x1201, 0x20] => Some((Algorithm::Es384(super::ecdsa::Es384::default()), rest)),
                #[cfg(feature = "es512")]
                [0x1201, 0x25] => Some((Algorithm::Es512(super::ecdsa::Es512::default()), rest)),
                #[cfg(feature = "es256k")]
                [0xe7, 0x12] => Some((Algorithm::Es256k(super::ecdsa::Es256k::default()), rest)),
                _ => None,
            },
            #[cfg(feature = "ed25519")]
            0xed => {
                if bytes.get(1..=2)? != [0xed, 0x13] {
                    return None;
                }
                Some((Algorithm::Ed25519(super::eddsa::Ed25519::default()), rest))
            }
            _ => None,
        }
    }
}

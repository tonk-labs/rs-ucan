//! Signature configuration.

pub mod ecdsa;
pub mod eddsa;
pub mod rsa;

use crate::hash::Multihasher;

/// The WebCrypto-compatible signature types.
#[cfg(feature = "webcrypto")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebCrypto {
    /// 2048-bit RSA signature type
    Rs256_2048(rsa::Rs256<2048>),

    /// 4096-bit RSA signature type
    Rs256_4096(rsa::Rs256<4096>),

    /// ES256 signature type
    Es256(ecdsa::Es256),

    /// ES384 signature type
    Es384(ecdsa::Es384),

    /// ES512 signature type
    Es512(ecdsa::Es512),

    /// Ed25519 signature type
    Ed25519(eddsa::Ed25519),
}

/// The most common signature types used in most contexts.
#[cfg(feature = "common")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Common {
    /// ES256 signature type
    Es256(ecdsa::Es256),

    /// ES256K signature type
    Es256k(ecdsa::Es256k),

    /// Ed25519 signature type
    Ed25519(eddsa::Ed25519),
}

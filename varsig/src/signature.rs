//! Signature configuration. // FIXME config?

use serde::{Deserialize, Serialize};

use crate::{
    curve::{Edwards448, Secp256k1, Secp256r1},
    hash::{Sha2_256, Sha2_512},
    verify::Verify,
};
use std::marker::PhantomData;

#[cfg(feature = "sha2_384")]
use crate::hash::Sha2_384;

/// The RS256 signature algorithm.
///
/// RSA with 2048-bit keys and SHA2-256 hash.
pub type Rs256<const L: usize> = Rsa<L, Sha2_256>;

/// The ES256 signature algorithm.
///
/// ECDSA with the P-256 (`secp256r1`) curve and SHA2-256 hash.
pub type Es256 = EcDsa<Secp256r1, Sha2_256>;

/// The ES384 signature algorithm.
///
/// ECDSA with the P-256 (`secp256r1`) curve and SHA2-384 hash.
#[cfg(feature = "sha2_384")]
pub type Es384 = EcDsa<Secp256r1, Sha2_384>;

/// The ES512 signature algorithm.
///
/// ECDSA with the P-256 (`secp256r1`) curve and SHA2-512 hash.
pub type Es512 = EcDsa<Secp256r1, Sha2_512>;

/// The ES256K signature algorithm.
///
/// ECDSA with the `secp256k1` curve and SHA2-256 hash.
pub type Es256k = EcDsa<Secp256k1, Sha2_256>;

/// The Ed25519 signature algorithm.
///
/// The EdDSA signing algorithm with the Edwards25519 curve with SHA2-512 hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ed25519;

impl Verify for Ed25519 {
    type Signature = ed25519_dalek::Signature;
    type Verifier = ed25519_dalek::VerifyingKey;

    fn prefix(&self) -> u64 {
        0xed
    }

    fn config_tags(&self) -> Vec<u64> {
        vec![0xed]
    }

    fn try_from_tags(bytes: &[u64]) -> Option<(Self, &[u64])> {
        if bytes[0..=2] == [0xed, 0xed, 0x13] {
            Some((Ed25519, &bytes[3..]))
        } else {
            None
        }
    }
}

// FIXME have a big list and enable with features
/// The WebCrypto-compatible signature types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebCrypto {
    /// 2048-bit RSA signature type
    Rs256_2048(Rs256<2048>),

    /// 4096-bit RSA signature type
    Rs256_4096(Rs256<4096>),

    /// ES256 signature type
    Es256(Es256),

    /// ES384 signature type
    #[cfg(feature = "sha2_384")]
    Es384(Es384),

    /// ES512 signature type
    Es512(Es512),

    /// Ed25519 signature type
    Ed25519(Ed25519),
}

/// The most common signature types used in most contexts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Common {
    /// ES256 signature type
    Es256(Es256),

    /// ES256K signature type
    Es256k(Es256k),

    /// Ed25519 signature type
    Ed25519(Ed25519),
}

/// Twisted Edwards Curve25519
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Edwards25519;

/// BLS12-381-compatible curves
pub trait BlsCurve {}
impl BlsCurve for G1 {}
impl BlsCurve for G2 {}

/// Minimal public key size
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct G1;

/// Minimal signature size
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct G2;

/// The BLS signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bls<PkCurve: BlsCurve, H: Multihasher>(PhantomData<(PkCurve, H)>);

/// Multihash Prefix
pub trait Multihasher {
    /// Multihash tag for this hasher.
    const MULTIHASH_TAG: u64;
}

impl Multihasher for Sha2_256 {
    const MULTIHASH_TAG: u64 = 0x12;
}

#[cfg(feature = "sha2_384")]
impl Multihasher for Sha2_384 {
    const MULTIHASH_TAG: u64 = 0x15;
}

impl Multihasher for Sha2_512 {
    const MULTIHASH_TAG: u64 = 0x13;
}

/// The RSA signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rsa<const L: usize, H: Multihasher>(PhantomData<H>);

/// The `EdDSA` signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EdDsa<C: EdDsaCurve, H: Multihasher>(PhantomData<(C, H)>);

/// The EdDSA-compatible curves
pub trait EdDsaCurve: Sized {}
impl EdDsaCurve for Edwards25519 {}
impl EdDsaCurve for Edwards448 {}

/// The ECDSA signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EcDsa<C: EcDsaCurve, H: Multihasher>(PhantomData<(C, H)>);

/// ECDSA-compatible curves
pub trait EcDsaCurve {}
impl EcDsaCurve for Secp256k1 {}
impl EcDsaCurve for Secp256r1 {}

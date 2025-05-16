//! Varsig header

pub mod traits;

use std::marker::PhantomData;

use crate::{
    curve::{Edwards448, Secp256k1, Secp256r1},
    hash::{Sha2_256, Sha2_384, Sha2_512},
};

type Rs256<const L: usize> = Rsa<L, Sha2_256>;
type Es256 = EcDsa<Secp256r1, Sha2_256>;
type Es384 = EcDsa<Secp256r1, Sha2_384>;
type Es512 = EcDsa<Secp256r1, Sha2_512>;
type Es256k = EcDsa<Secp256k1, Sha2_256>;
type Ed25519 = EdDsa<Edwards25519, Sha2_512>;

/// FIXME have a big list and enable with features
pub enum WebCrypto {
    Rs256_2048(Rs256<2048>),
    Rs256_4096(Rs256<4096>),

    Es256(Es256),
    Es384(Es384),
    Es512(Es512),

    Ed25519(Ed25519),
}

pub enum Common {
    Es256(Es256),
    Es256k(Es256k),
    Ed25519(Ed25519),
}

/// Twisted Edwards Curve25519
pub struct Edwards25519;

pub trait BlsCurve {}
impl BlsCurve for G1 {}
impl BlsCurve for G2 {}

/// Minimal public key size
pub struct G1;

/// Minimal signature size
pub struct G2;

/// The BLS signature algorithm.
#[derive(Debug, Clone)]
pub struct Bls<PkCurve: BlsCurve, H: Multihasher>(PhantomData<(PkCurve, H)>);

/// Multihash Prefix
pub trait Multihasher {
    const MULTIHASH_CODE: u64;
}

impl Multihasher for Sha2_256 {
    const MULTIHASH_CODE: u64 = 0x12;
}

impl Multihasher for Sha2_512 {
    const MULTIHASH_CODE: u64 = 0x13;
}

/// The RSA signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rsa<const L: usize, H: Multihasher>(PhantomData<H>);

/// The EdDSA signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EdDsa<C: EdDsaCurve, H: Multihasher>(PhantomData<(C, H)>);

pub trait EdDsaCurve {}
impl EdDsaCurve for Edwards25519 {}
impl EdDsaCurve for Edwards448 {}

/// The ECDSA signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EcDsa<C: EcDsaCurve, H: Multihasher>(PhantomData<(C, H)>);

pub trait EcDsaCurve {}
impl EcDsaCurve for Secp256k1 {}
impl EcDsaCurve for Secp256r1 {}

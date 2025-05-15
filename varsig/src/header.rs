//! Varsig header

pub mod traits;

use crate::{
    curve::{P256, P521},
    encoding::Encoding,
    hash::{HashAlgorithm, Sha2_256, Sha2_512},
};
use ipld_core::codec::Codec;

#[derive(Debug, Clone)]
pub struct Header<T, A = SignatureAlgorithm, C: Codec<T> = Encoding> {
    /// Signature algorithm.
    pub sig_algo: A,

    /// The codec used to encode the payload.
    pub codec: C,

    _marker: std::marker::PhantomData<T>,
}

type Es256 = EcDsa<P256, Sha2_256>;

type Es512 = EcDsa<P521, Sha2_512>;

type Ed25519 = EdDsa(Edwards25519);

/// The signature algorithm used in the header.
#[derive(Debug, Clone)]
pub enum SignatureAlgorithm<C, H> {
    /// EdDSA signature algorithm.
    EdDsa(EdDsa),

    /// ECDSA signature algorithm.
    EcDsa(EcDsa<C, H>),

    /// RSA signature algorithm.
    Rsa(Rsa<H>),

    /// BLS signature algorithm.
    Bls(Bls12_381),
}

/// The BLS signature algorithm.
#[derive(Debug, Clone)]
pub struct Bls12_381 {
    /// The curve used for BLS.
    pub bls_sig_field: BlsField,

    /// The hash algorithm used for BLS.
    pub hash: HashAlgorithm,
}

#[derive(Debug, Clone, Copy)]
pub enum BlsField {
    MinimalPublicKeySize,
    MinimalSignatureSize,
}

/// The RSA signature algorithm.
#[derive(Debug, Clone)]
pub struct Rsa<H: HashTrait> {
    /// The key size in bits.
    pub hash: H,

    /// The key size in bytes.
    pub key_length: u16,
}

/// The EdDSA signature algorithm.
#[derive(Debug, Clone)]
pub struct EdDsa {
    /// The curve used for EdDSA.
    pub curve: EdDsaCurve,

    /// The hash algorithm used for EdDSA.
    pub hash: HashAlgorithm,
}

/// The EdDSA curves.
#[derive(Debug, Clone, Copy)]
pub enum EdDsaCurve {
    /// edwards25519 Curve
    Edwards25519,

    /// edwards448 Curve
    Edwards448,
}

/// The ECDSA signature algorithm.
#[derive(Debug, Clone)]
pub struct EcDsa<C, H> {
    /// ECDSA parity bit.
    pub parity_bit: bool,

    _marker: std::marker::PhantomData<(C, H)>,
}

/// The elliptic curves used for ECDSA.
#[derive(Debug, Clone, Copy)]
pub enum EcDsaCurve {
    /// P-256 curve
    P256,

    /// P-384 curve
    P384,

    /// P-521 curve
    P521,
}

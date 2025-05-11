//! Varsig header

pub mod traits;

use ipld_core::codec::Codec;

use crate::encoding::Encoding;

#[derive(Debug, Clone)]
pub struct Header<T, A = SignatureAlgorithm, C: Codec<T> = Encoding> {
    pub sig_algo: A,
    pub codec: C,
    _marker: std::marker::PhantomData<T>,
}

/// The signature algorithm used in the header.
#[derive(Debug, Clone)]
pub enum SignatureAlgorithm {
    /// EdDSA signature algorithm.
    EdDsa(EdDsa),

    /// ECDSA signature algorithm.
    EcDsa(EcDsa),

    /// RSA signature algorithm.
    Rsa(Rsa),

    /// BLS signature algorithm.
    Bls(Bls),
}

/// The BLS signature algorithm.
#[derive(Debug, Clone)]
pub struct Bls {
    /// The curve used for BLS.
    pub bls_sig_field: BlsField,

    /// The hash algorithm used for BLS.
    pub hash: HashAlgorithm,
}

#[derive(Debug, Clone, Copy)]
pub enum BlsField {
    MinimalPublicKeySize_G1G2,
    MinimalSignatureSize_G2G1,
}

/// The RSA signature algorithm.
#[derive(Debug, Clone)]
pub struct Rsa {
    /// The key size in bits.
    pub hash: HashAlgorithm,

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
pub struct EcDsa {
    /// The curve used for ECDSA.
    pub curve: EcDsaCurve,

    /// The hash algorithm used for ECDSA.
    pub hash: HashAlgorithm,

    /// ECDSA parity bit.
    pub parity_bit: bool,
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

/// Hash algorithms.
#[derive(Debug, Clone, Copy)]
pub enum HashAlgorithm {
    Sha2_256,
    Sha2_384,
    Sha2_512,
    Shake256,
    Sha3_256,
    Sha3_512,
    Blake2b,
    Blake3,
    Keccak256,
    Keccak384,
    Keccak512,
}

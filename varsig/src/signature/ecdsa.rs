//! ECDSA signature algorithms.

use crate::{
    curve::{Secp256k1, Secp256r1},
    hash::{Sha2_256, Sha2_512},
    signature::Multihasher,
    verify::Verify,
};
use std::marker::PhantomData;

#[cfg(feature = "sha2_384")]
use crate::hash::Sha2_384;

/// The ECDSA signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EcDsa<C: EcDsaCurve, H: Multihasher>(PhantomData<(C, H)>);

/// ECDSA-compatible curves
pub trait EcDsaCurve {}

#[cfg(feature = "secp256k1")]
impl EcDsaCurve for Secp256k1 {}

#[cfg(feature = "secp256r1")]
impl EcDsaCurve for Secp256r1 {}

/// The ES256 signature algorithm.
#[cfg(all(feature = "secp256r1", feature = "sha2_256"))]
pub type Es256 = EcDsa<Secp256r1, Sha2_256>;

/// The ES384 signature algorithm.
#[cfg(all(feature = "secp256r1", feature = "sha2_384"))]
pub type Es384 = EcDsa<Secp256r1, Sha2_384>;

/// The ES512 signature algorithm.
#[cfg(all(feature = "secp256r1", feature = "sha2_512"))]
pub type Es512 = EcDsa<Secp256r1, Sha2_512>;

/// The ES256K signature algorithm.
#[cfg(all(feature = "secp256k1", feature = "sha2_256"))]
pub type Es256k = EcDsa<Secp256k1, Sha2_256>;

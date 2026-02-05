//! ECDSA signature algorithms.

#[cfg(feature = "secp384r1")]
use crate::curve::Secp384r1;
#[cfg(feature = "secp521r1")]
use crate::curve::Secp521r1;
use crate::{
    curve::{Secp256k1, Secp256r1},
    hash::Multihasher,
    verify::Verify,
};
use std::marker::PhantomData;

/// The ECDSA signature algorithm.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EcDsa<C: EcDsaCurve, H: Multihasher>(PhantomData<(C, H)>);

/// ECDSA-compatible curves
pub trait EcDsaCurve {}

#[cfg(feature = "secp256k1")]
impl EcDsaCurve for Secp256k1 {}

#[cfg(feature = "secp256r1")]
impl EcDsaCurve for Secp256r1 {}

#[cfg(feature = "secp384r1")]
impl EcDsaCurve for Secp384r1 {}

#[cfg(feature = "secp521r1")]
impl EcDsaCurve for Secp521r1 {}

/// The ES256 signature algorithm.
#[cfg(all(feature = "secp256r1", feature = "sha2_256"))]
pub type Es256 = EcDsa<Secp256r1, crate::hash::Sha2_256>;

#[cfg(all(feature = "secp256r1", feature = "sha2_256"))]
impl Verify for Es256 {
    type Signature = p256::ecdsa::Signature;
    type Verifier = p256::ecdsa::VerifyingKey;

    fn prefix(&self) -> u64 {
        0xec
    }

    fn config_tags(&self) -> Vec<u64> {
        vec![0x1201, 0x15]
    }

    fn try_from_tags(bytes: &[u64]) -> Option<(Self, &[u64])> {
        if bytes.get(0..=2)? == [0xec, 0x1201, 0x15] {
            Some((Self::default(), bytes.get(3..)?))
        } else {
            None
        }
    }
}

/// The ES384 signature algorithm.
#[cfg(all(feature = "secp384r1", feature = "sha2_384"))]
pub type Es384 = EcDsa<Secp384r1, crate::hash::Sha2_384>;

#[cfg(all(feature = "secp384r1", feature = "sha2_384"))]
impl Verify for Es384 {
    type Signature = p384::ecdsa::Signature;
    type Verifier = p384::ecdsa::VerifyingKey;

    fn prefix(&self) -> u64 {
        0xec
    }

    fn config_tags(&self) -> Vec<u64> {
        vec![0x1201, 0x20]
    }

    fn try_from_tags(bytes: &[u64]) -> Option<(Self, &[u64])> {
        if bytes.get(0..=2)? == [0xec, 0x1202, 0x20] {
            Some((Self::default(), bytes.get(3..)?))
        } else {
            None
        }
    }
}

/// The ES512 signature algorithm.
#[cfg(all(feature = "secp521r1", feature = "sha2_512"))]
pub type Es512 = EcDsa<Secp521r1, crate::hash::Sha2_512>;

/// Wrapper for `p521::ecdsa::VerifyingKey` that implements `Debug`.
///
/// The upstream `p521` crate doesn't implement `Debug` for `VerifyingKey`,
/// so we wrap it to satisfy the `Verify` trait bounds.
#[cfg(all(feature = "secp521r1", feature = "sha2_512"))]
pub struct P521VerifyingKey(pub p521::ecdsa::VerifyingKey);

#[cfg(all(feature = "secp521r1", feature = "sha2_512"))]
impl std::fmt::Debug for P521VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("P521VerifyingKey")
            .field(&self.0.to_encoded_point(true).as_bytes())
            .finish()
    }
}

#[cfg(all(feature = "secp521r1", feature = "sha2_512"))]
impl signature::Verifier<p521::ecdsa::Signature> for P521VerifyingKey {
    fn verify(
        &self,
        msg: &[u8],
        signature: &p521::ecdsa::Signature,
    ) -> Result<(), signature::Error> {
        self.0.verify(msg, signature)
    }
}

#[cfg(all(feature = "secp521r1", feature = "sha2_512"))]
impl Verify for Es512 {
    type Signature = p521::ecdsa::Signature;
    type Verifier = P521VerifyingKey;

    fn prefix(&self) -> u64 {
        0xec
    }

    fn config_tags(&self) -> Vec<u64> {
        vec![0x1202, 0x13]
    }

    fn try_from_tags(bytes: &[u64]) -> Option<(Self, &[u64])> {
        if bytes.get(0..=2)? == [0xec, 0x1202, 0x13] {
            Some((Self::default(), bytes.get(3..)?))
        } else {
            None
        }
    }
}

/// The ES256K signature algorithm.
#[cfg(all(feature = "secp256k1", feature = "sha2_256"))]
pub type Es256k = EcDsa<Secp256k1, crate::hash::Sha2_256>;

#[cfg(all(feature = "secp256k1", feature = "sha2_256"))]
impl Verify for Es256k {
    type Signature = k256::ecdsa::Signature;
    type Verifier = k256::ecdsa::VerifyingKey;

    fn prefix(&self) -> u64 {
        0xec
    }

    fn config_tags(&self) -> Vec<u64> {
        vec![0xe7, 0x12]
    }

    fn try_from_tags(bytes: &[u64]) -> Option<(Self, &[u64])> {
        if *bytes.get(0..=2)? == [0xec, 0xe7, 0x12] {
            Some((Self::default(), bytes.get(3..)?))
        } else {
            None
        }
    }
}

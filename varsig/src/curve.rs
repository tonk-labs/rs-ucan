//! This module defines various elliptic curves headers.

/// `secp256k1` curve
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Secp256k1;

/// `secp256r1` curve
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Secp256r1;

/// NIST alias for the `secp256r1` curve
pub type P256 = Secp256r1;

/// `secp384r1` curve
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Secp384r1;

/// NIST alias for the `secp384r1` curve
pub type P384 = Secp384r1;

/// `secp521r1` curve
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Secp521r1;

/// NIST alias for the `secp521r1` curve
pub type P521 = Secp521r1;

/// The Twisted Edwards 25519 curve
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Edwards25519;

/// The Twisted Edwards 448 curve
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Edwards448;

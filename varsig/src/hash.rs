//! Multihash algorithms.
//!
//! This is separate from the `multihash-codetable` crate
//! becuase we don't need any of the actual hashing functionality.

/// Default set of hash algorithms.
///
/// This list can be configured via Cargo features.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashAlgorithm {
    /// SHA2-256
    #[cfg(feature = "sha2_256")]
    Sha2_256,

    /// SHA2-384
    #[cfg(feature = "sha2_384")]
    Sha2_384,

    /// SHA2-512
    #[cfg(feature = "sha2_512")]
    Sha2_512,

    /// SHAKE256
    #[cfg(feature = "shake_256")]
    Shake256,

    /// SHA3-256
    #[cfg(feature = "sha3_256")]
    Sha3_256,

    /// SHA3-512
    #[cfg(feature = "sha3_512")]
    Sha3_512,

    /// BLAKE2b
    #[cfg(feature = "blake2b")]
    Blake2b,

    /// BLAKE3
    #[cfg(feature = "blake3")]
    Blake3,

    /// Keccak256
    #[cfg(feature = "keccak256")]
    Keccak256,

    /// Keccak384
    #[cfg(feature = "keccak384")]
    Keccak384,

    /// Keccak512
    #[cfg(feature = "keccak512")]
    Keccak512,
}

/// SHA2-256 hash algorithm.
#[cfg(feature = "sha2_256")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha2_256;

/// SHA2-384 hash algorithm.
#[cfg(feature = "sha2_384")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha2_384;

/// SHA2-512 hash algorithm.
#[cfg(feature = "sha2_512")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha2_512;

/// Shake256 hash algorithm.
#[cfg(feature = "shake_256")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Shake256;

/// Blake2b hash algorithm.
#[cfg(feature = "blake2b")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Blake2b;

/// Blake3 hash algorithm.
#[cfg(feature = "blake3")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Blake3;

/// Keccak256 hash algorithm.
#[cfg(feature = "keccak256")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Keccak256;

/// Keccak384 hash algorithm.
#[cfg(feature = "keccak384")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Keccak384;

/// Keccak512 hash algorithm.
#[cfg(feature = "keccak512")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Keccak512;

/// SHA3-256 hash algorithm.
#[cfg(feature = "sha3_256")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha3_256;

/// SHA3-384 hash algorithm.
#[cfg(feature = "sha3_384")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha3_384;

/// SHA3-512 hash algorithm.
#[cfg(feature = "sha3_512")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha3_512;

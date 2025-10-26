//! Decentralized Identifier (DID) helpers.

use serde::{Deserialize, Serialize};
use std::{fmt::Debug, str::FromStr};
use thiserror::Error;
use varsig::{signature::eddsa::Ed25519, signer::Sign, verify::Verify};

/// A trait for [DID]s.
///
/// [DID]: https://en.wikipedia.org/wiki/Decentralized_identifier
pub trait Did: PartialEq + ToString + FromStr + Verify {
    /// Get the DID method header (e.g. `key` for `did-keys`)
    fn did_method(&self) -> &str;
}

/// A trait for DID signers.
pub trait DidSigner: Sign + Debug {
    /// The associated DID type.
    type Did: Did;

    /// Get the associated DID.
    fn did(&self) -> &Self::Did;

    /// Get the associated signer.
    fn signer(&self) -> &Self::Signer;
}

/// An `Ed25519` `did:key`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Ed25519Did(pub ed25519_dalek::VerifyingKey, Ed25519);

impl std::fmt::Display for Ed25519Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:key:FIXME")
    }
}

impl FromStr for Ed25519Did {
    type Err = Ed25519DidFromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 || parts[0] != "did" || parts[1] != "key" {
            return Err(Ed25519DidFromStrError::InvalidDidHeader);
        }
        let b58 = parts[2]
            .strip_prefix('z')
            .ok_or(Ed25519DidFromStrError::MissingBase58Prefix)?;
        let key_bytes =
            base58::FromBase58::from_base58(b58).map_err(|_| Ed25519DidFromStrError::InvalidKey)?;
        let raw_arr = <[u8; 34]>::try_from(key_bytes.as_slice())
            .map_err(|_| Ed25519DidFromStrError::InvalidKey)?;
        if raw_arr[0] != 0xed || raw_arr[1] != 0x01 {
            return Err(Ed25519DidFromStrError::InvalidKey);
        }
        let key_arr: [u8; 32] = raw_arr[2..]
            .try_into()
            .map_err(|_| Ed25519DidFromStrError::InvalidKey)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&key_arr)
            .map_err(|_| Ed25519DidFromStrError::InvalidKey)?;
        Ok(Ed25519Did(key, Ed25519::new()))
    }
}

/// Errors that can occur when parsing an `Ed25519Did` from a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Error)]
pub enum Ed25519DidFromStrError {
    /// The DID header is invalid.
    #[error("invalid did header")]
    InvalidDidHeader,

    /// The base58 prefix 'z' is missing.
    #[error("missing base58 prefix 'z'")]
    MissingBase58Prefix,

    /// The base58 encoding is invalid.
    #[error("invalid base58 encoding")]
    InvalidBase58,

    /// The key bytes are invalid.
    #[error("invalid key bytes")]
    InvalidKey,
}

impl Verify for Ed25519Did {
    type Signature = ed25519_dalek::Signature;
    type Verifier = ed25519_dalek::VerifyingKey;

    fn prefix(&self) -> u64 {
        self.1.prefix()
    }

    fn config_tags(&self) -> Vec<u64> {
        self.1.config_tags()
    }

    fn try_from_tags(bytes: &[u64]) -> Option<(Self, &[u64])> {
        let (v, rest) = Ed25519::try_from_tags(bytes)?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32]).ok()?; // FIXME
        Some((Ed25519Did(vk, v), rest)) // FIXME that [0u8; 32] should be the actual key
    }
}

impl Did for Ed25519Did {
    fn did_method(&self) -> &'static str {
        "key"
    }
}

impl Serialize for Ed25519Did {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Ed25519Did {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse()
            .map_err(|_| serde::de::Error::custom(format!("unable to parse did from string: {s}")))
    }
}

/// An `Ed25519` `did:key` signer.
#[derive(Debug, Clone)]
pub struct Ed25519Signer {
    did: Ed25519Did,
    signer: ed25519_dalek::SigningKey,
}

impl Verify for Ed25519Signer {
    type Signature = ed25519_dalek::Signature;
    type Verifier = ed25519_dalek::VerifyingKey;

    fn prefix(&self) -> u64 {
        self.did.prefix()
    }

    fn config_tags(&self) -> Vec<u64> {
        self.did.config_tags()
    }

    fn try_from_tags(bytes: &[u64]) -> Option<(Self, &[u64])> {
        Ed25519Did::try_from_tags(bytes).map(|(did, r)| {
            let signer = ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]);
            (Ed25519Signer { did, signer }, r)
        })
    }
}

impl Sign for Ed25519Signer {
    type Signer = ed25519_dalek::SigningKey;
    type SignError = signature::Error;
}

impl DidSigner for Ed25519Signer {
    type Did = Ed25519Did;

    fn did(&self) -> &Self::Did {
        &self.did
    }

    fn signer(&self) -> &Self::Signer {
        &self.signer
    }
}

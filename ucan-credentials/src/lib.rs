//! Concrete key types for UCAN authentication.
//!
//! This crate provides concrete implementations of the UCAN principal and
//! issuer traits for specific signature algorithms. Currently supports:
//!
//! - **Ed25519** (`ed25519` feature, enabled by default) — `Ed25519Did` and `Ed25519Signer`

#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "ed25519")]
pub mod ed25519;

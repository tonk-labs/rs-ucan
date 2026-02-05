//! Native Ed25519 signing implementation using `ed25519_dalek`.
//!
//! This module provides Ed25519 signing for non-WASM platforms using
//! the `ed25519_dalek` crate.

/// Native Ed25519 signing key.
///
/// This is a type alias to `ed25519_dalek::SigningKey`.
pub type SigningKey = ed25519_dalek::SigningKey;

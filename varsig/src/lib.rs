//! [Varsig] implementation.
//!
//! This includes signature metadata and helpers for signing, verifying,
//! and encoding payloads per a given [Varsig] configuration.
//!
//! [Varsig]: https://github.com/ChainAgnostic/varsig

#![allow(clippy::multiple_crate_versions)] // syn
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod codec;
pub mod curve;
pub mod encoding;
pub mod hash;
pub mod header;
pub mod signature;
pub mod verify;

pub use header::Varsig;

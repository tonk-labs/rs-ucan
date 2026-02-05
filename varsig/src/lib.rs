//! [Varsig] implementation.
//!
//! This includes both signature metadata and helpers for signing, verifying,
//! and encoding payloads per a given [Varsig] configuration.
//!
//! [Varsig]: https://github.com/ChainAgnostic/varsig
//!
//! # Example
//!
//! ```rust,no_run
//! use varsig::{Varsig, signature::eddsa::{Ed25519, Ed25519SigningKey, Ed25519VerifyingKey}};
//! use serde_ipld_dagcbor::codec::DagCborCodec;
//! use serde::{Serialize, Deserialize};
//!
//! // Your data type
//! #[derive(Debug, Serialize, Deserialize)]
//! struct Character {
//!     name: String,
//!     hp: u16,
//!     mp: u16,
//! }
//!
//! # tokio_test::block_on(async {
//! let payload = Character {
//!     name: "Terra Branford".to_string(),
//!     hp: 100,
//!     mp: 20,
//! };
//!
//! // ✨ Varsig configuration for Ed25519 and DAG-CBOR ✨
//! let varsig: Varsig<Ed25519, DagCborCodec, Character> = Varsig::default();
//!
//! // Signing the payload with enforced Ed25519 and DAG-CBOR
//! let dalek_sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
//! let sk: Ed25519SigningKey = dalek_sk.clone().into();
//! let vk: Ed25519VerifyingKey = dalek_sk.verifying_key().into();
//! let (sig, _) = varsig.try_sign(&sk, &payload).await.unwrap();
//! varsig.try_verify(&vk, &payload, &sig).unwrap();
//! # })
//! ```

#![allow(clippy::multiple_crate_versions)] // syn
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod codec;
pub mod curve;
pub mod encoding;
pub mod hash;
pub mod header;
pub mod signature;
pub mod signer;
pub mod verify;

pub use header::Varsig;

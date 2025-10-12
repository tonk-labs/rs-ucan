//! Core UCAN functionality.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(
    clippy::dbg_macro,
    clippy::expect_used,
    clippy::missing_const_for_fn,
    clippy::panic,
    clippy::todo,
    clippy::unwrap_used,
    future_incompatible,
    let_underscore,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    nonstandard_style,
    rust_2021_compatibility
)]
#![deny(
    clippy::all,
    clippy::cargo,
    clippy::pedantic,
    rust_2018_idioms,
    unreachable_pub,
    unused_extern_crates
)]
#![forbid(unsafe_code)]

pub mod collection;
pub mod crypto;
pub mod delegation;
pub mod did;
pub mod envelope;
pub mod invocation;
pub mod number;
pub mod promise;
// pub mod receipt; TODO Reenable after first release
pub mod task;
pub mod time;
pub mod unset;

// Internal modules
mod ipld;
mod sealed;

pub use delegation::{builder::DelegationBuilder, Delegation};
pub use invocation::{builder::InvocationBuilder, Invocation};

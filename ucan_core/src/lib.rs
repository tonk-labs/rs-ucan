#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(
    missing_debug_implementations,
    future_incompatible,
    let_underscore,
    missing_docs,
    rust_2021_compatibility,
    nonstandard_style
)]
#![deny(unreachable_pub)]

pub mod collection;
pub mod crypto;
pub mod delegation;
pub mod did;
pub mod invocation;
pub mod number;
pub mod promise;
pub mod receipt;
pub mod task;
pub mod time;

// Internal modules
pub(crate) mod ipld;

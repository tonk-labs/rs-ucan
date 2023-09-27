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

use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    future::Future,
    str::FromStr,
};

use ipld_core::ipld::Ipld;
use serde::de::Error;

pub mod collection;
pub mod crypto;
pub mod delegation;
pub mod did;
pub mod number;
pub mod time;

//////////////////
//////////////////
//////////////////
//////////////////

pub trait Call: From<HashMap<String, Ipld>> + From<HashMap<String, Ipld>> + Debug {
    type Command: ToString + FromStr + Debug + Display;

    type CallError: Error;

    fn call(&self) -> impl Future<Output = Result<Ipld, Self::CallError>>;
    fn to_command(&self) -> Self::Command;
}

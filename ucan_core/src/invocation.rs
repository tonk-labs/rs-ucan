//! UCAN Invocation

use crate::{crypto::nonce::Nonce, did::Did, promise::Promised, time::timestamp::Timestamp};
use ipld_core::{cid::Cid, ipld::Ipld};
use std::collections::BTreeMap;

// FIXME tag the spec and link to taht instead
/// UCAN Invocation
///
/// Invoke a UCAN capability. This type implements the
/// [UCAN Invocation spec](https://github.com/ucan-wg/invocation/README.md).
#[derive(Debug, Clone, PartialEq)]
pub struct Invocation<D: Did> {
    pub(crate) issuer: D,
    pub(crate) audience: D,

    pub(crate) subject: D,
    pub(crate) command: Vec<String>,
    pub(crate) arguments: BTreeMap<String, Promised>,

    pub(crate) proofs: Vec<Cid>,
    pub(crate) cause: Option<Cid>,

    pub(crate) issued_at: Option<Timestamp>,
    pub(crate) expiration: Option<Timestamp>,

    pub(crate) meta: BTreeMap<String, Ipld>,
    pub(crate) nonce: Nonce,
}

impl<D: Did> Invocation<D> {}

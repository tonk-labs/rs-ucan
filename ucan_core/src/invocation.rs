use crate::{crypto::nonce::Nonce, did::Did, promise::Promised, time::timestamp::Timestamp};
use ipld_core::{cid::Cid, ipld::Ipld};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub struct Invocation<D: Did> {
    issuer: D,
    audience: D,

    subject: D,
    command: Vec<String>,
    arguments: BTreeMap<String, Promised>,

    proofs: Vec<Cid>,
    cause: Option<Cid>,

    issued_at: Option<Timestamp>,
    expiration: Option<Timestamp>,

    meta: BTreeMap<String, Ipld>,
    nonce: Nonce,
}

impl<D: Did> Invocation<D> {}

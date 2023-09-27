pub mod policy;
pub mod subject;

use self::subject::DelegatedSubject;
use crate::{crypto::nonce::Nonce, did::Did, time::timestamp::Timestamp, Call};
use ipld_core::ipld::Ipld;
use std::collections::HashMap;
use typed_builder::TypedBuilder;

#[derive(Debug, Clone, TypedBuilder)]
pub struct Delegation<D: Did, C: Call> {
    issuer: D,
    audience: D,

    subject: DelegatedSubject<D>,
    command: C::Command,
    policy: (),

    expiration: Option<Timestamp>,
    not_before: Option<Timestamp>,

    meta: HashMap<String, Ipld>,
    nonce: Nonce,
}

impl<D: Did, C: Call> Delegation<D, C> {
    pub fn new(
        issuer: D,
        audience: D,
        subject: DelegatedSubject<D>,
        command: C::Command,
        policy: (),
        expiration: Option<Timestamp>,
        not_before: Option<Timestamp>,
        meta: HashMap<String, Ipld>,
    ) -> Self {
        Self {
            issuer,
            audience,
            subject,
            command,
            policy,
            expiration,
            not_before,
            meta,
            nonce: Nonce::generate_16(),
        }
    }
}

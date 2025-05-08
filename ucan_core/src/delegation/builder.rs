use super::{policy::predicate::Predicate, subject::DelegatedSubject};
use crate::{crypto::nonce::Nonce, did::Did, time::timestamp::Timestamp};
use ipld_core::ipld::Ipld;
use std::{collections::BTreeMap, marker::PhantomData};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Unset;

// FIXME move
mod sealed {
    use super::*;

    pub trait DidOrUnset {}
    impl DidOrUnset for Unset {}
    impl<D: Did> DidOrUnset for D {}

    pub trait DelegatedSubjectOrUnset {}
    impl DelegatedSubjectOrUnset for Unset {}
    impl<D: Did> DelegatedSubjectOrUnset for DelegatedSubject<D> {}

    pub trait CommandOrUnset {}
    impl CommandOrUnset for Unset {}
    impl CommandOrUnset for Vec<String> {}
}

use sealed::{CommandOrUnset, DelegatedSubjectOrUnset, DidOrUnset};

#[derive(Default, Debug, Clone)]
pub struct DelegationBuilder<
    D: Did,
    Issuer: DidOrUnset = Unset,
    Audience: DidOrUnset = Unset,
    Subject: DelegatedSubjectOrUnset = Unset,
    Command: CommandOrUnset = Unset,
> {
    pub issuer: Issuer,
    pub audience: Audience,

    pub subject: Subject,
    pub command: Command,
    pub policy: Vec<Predicate>,

    pub expiration: Option<Timestamp>,
    pub not_before: Option<Timestamp>,

    pub meta: BTreeMap<String, Ipld>,
    pub nonce: Option<Nonce>,

    pub(crate) _did: PhantomData<D>,
}

impl<D: Did> DelegationBuilder<D, Unset, Unset, Unset, Unset> {
    pub fn new() -> Self {
        Self {
            issuer: Unset,
            audience: Unset,
            subject: Unset,
            command: Unset,
            policy: Vec::new(),
            expiration: None,
            not_before: None,
            meta: BTreeMap::new(),
            nonce: None,
            _did: PhantomData,
        }
    }
}

impl<
        D: Did,
        Issuer: DidOrUnset,
        Audience: DidOrUnset,
        Subject: DelegatedSubjectOrUnset,
        Command: CommandOrUnset,
    > DelegationBuilder<D, Issuer, Audience, Subject, Command>
{
    pub fn issuer(self, issuer: D) -> DelegationBuilder<D, D, Audience, Subject, Command> {
        DelegationBuilder {
            issuer,
            audience: self.audience,
            subject: self.subject,
            command: self.command,
            policy: self.policy,
            expiration: self.expiration,
            not_before: self.not_before,
            meta: self.meta,
            nonce: self.nonce,
            _did: PhantomData,
        }
    }

    pub fn audience(self, audience: D) -> DelegationBuilder<D, Issuer, D, Subject, Command> {
        DelegationBuilder {
            issuer: self.issuer,
            audience,
            subject: self.subject,
            command: self.command,
            policy: self.policy,
            expiration: self.expiration,
            not_before: self.not_before,
            meta: self.meta,
            nonce: self.nonce,
            _did: PhantomData,
        }
    }

    pub fn subject(
        self,
        subject: DelegatedSubject<D>,
    ) -> DelegationBuilder<D, Issuer, Audience, DelegatedSubject<D>, Command> {
        DelegationBuilder {
            issuer: self.issuer,
            audience: self.audience,
            subject,
            command: self.command,
            policy: self.policy,
            expiration: self.expiration,
            not_before: self.not_before,
            meta: self.meta,
            nonce: self.nonce,
            _did: PhantomData,
        }
    }

    pub fn command(
        self,
        command: Vec<String>,
    ) -> DelegationBuilder<D, Issuer, Audience, Subject, Vec<String>> {
        DelegationBuilder {
            issuer: self.issuer,
            audience: self.audience,
            subject: self.subject,
            command,
            policy: self.policy,
            expiration: self.expiration,
            not_before: self.not_before,
            meta: self.meta,
            nonce: self.nonce,
            _did: PhantomData,
        }
    }

    pub fn policy(
        self,
        policy: Vec<Predicate>,
    ) -> DelegationBuilder<D, Issuer, Audience, Subject, Command> {
        DelegationBuilder {
            issuer: self.issuer,
            audience: self.audience,
            subject: self.subject,
            command: self.command,
            policy,
            expiration: self.expiration,
            not_before: self.not_before,
            meta: self.meta,
            nonce: self.nonce,
            _did: PhantomData,
        }
    }

    pub fn expiration(
        self,
        expiration: Timestamp,
    ) -> DelegationBuilder<D, Issuer, Audience, Subject, Command> {
        DelegationBuilder {
            issuer: self.issuer,
            audience: self.audience,
            subject: self.subject,
            command: self.command,
            policy: self.policy,
            expiration: Some(expiration),
            not_before: self.not_before,
            meta: self.meta,
            nonce: self.nonce,
            _did: PhantomData,
        }
    }

    pub fn not_before(
        self,
        not_before: Timestamp,
    ) -> DelegationBuilder<D, Issuer, Audience, Subject, Command> {
        DelegationBuilder {
            issuer: self.issuer,
            audience: self.audience,
            subject: self.subject,
            command: self.command,
            policy: self.policy,
            expiration: self.expiration,
            not_before: Some(not_before),
            meta: self.meta,
            nonce: self.nonce,
            _did: PhantomData,
        }
    }

    pub fn meta(
        self,
        meta: BTreeMap<String, Ipld>,
    ) -> DelegationBuilder<D, Issuer, Audience, Subject, Command> {
        DelegationBuilder {
            issuer: self.issuer,
            audience: self.audience,
            subject: self.subject,
            command: self.command,
            policy: self.policy,
            expiration: self.expiration,
            not_before: self.not_before,
            meta,
            nonce: self.nonce,
            _did: PhantomData,
        }
    }

    pub fn nonce(self, nonce: Nonce) -> DelegationBuilder<D, Issuer, Audience, Subject, Command> {
        DelegationBuilder {
            issuer: self.issuer,
            audience: self.audience,
            subject: self.subject,
            command: self.command,
            policy: self.policy,
            expiration: self.expiration,
            not_before: self.not_before,
            meta: self.meta,
            nonce: Some(nonce),
            _did: PhantomData,
        }
    }
}

impl<D: Did> DelegationBuilder<D, D, D, DelegatedSubject<D>, Vec<String>> {
    pub fn build(self) -> super::Delegation<D> {
        super::Delegation {
            issuer: self.issuer,
            audience: self.audience,
            subject: self.subject,
            command: self.command,
            policy: self.policy,
            expiration: self.expiration,
            not_before: self.not_before,
            meta: self.meta,
            nonce: self
                .nonce
                .unwrap_or_else(|| Nonce::generate_16().expect("failed to generate nonce")),
        }
    }

    // pub fn try_sign(self) -> Signed<Delegation> {
    //     todo!()
    // }
}

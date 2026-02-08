use crate::{
    command::Command, delegation::subject::DelegatedSubject, issuer::Issuer, principal::Principal,
    unset::Unset,
};
use ipld_core::cid::Cid;

#[doc(hidden)]
pub trait PrincipalOrUnset {}
impl PrincipalOrUnset for Unset {}
impl<D: Principal> PrincipalOrUnset for D {}

#[doc(hidden)]
pub trait IssuerOrUnset {}
impl IssuerOrUnset for Unset {}
impl<D: Issuer> IssuerOrUnset for D {}

#[doc(hidden)]
pub trait DelegatedSubjectOrUnset {}
impl DelegatedSubjectOrUnset for Unset {}
impl<D: Principal> DelegatedSubjectOrUnset for DelegatedSubject<D> {}

#[doc(hidden)]
pub trait CommandOrUnset {}
impl CommandOrUnset for Unset {}
impl CommandOrUnset for Command {}

#[doc(hidden)]
#[allow(dead_code)]
pub(crate) trait ProofsOrUnset {}
impl ProofsOrUnset for Unset {}
impl ProofsOrUnset for Vec<Cid> {}

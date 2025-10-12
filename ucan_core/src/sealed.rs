use crate::{
    delegation::subject::DelegatedSubject,
    did::{Did, DidSigner},
    unset::Unset,
};
use ipld_core::cid::Cid;

#[doc(hidden)]
pub trait DidOrUnset {}
impl DidOrUnset for Unset {}
impl<D: Did> DidOrUnset for D {}

#[doc(hidden)]
pub trait DidSignerOrUnset {}
impl DidSignerOrUnset for Unset {}
impl<D: DidSigner> DidSignerOrUnset for D {}

#[doc(hidden)]
pub trait DelegatedSubjectOrUnset {}
impl DelegatedSubjectOrUnset for Unset {}
impl<D: Did> DelegatedSubjectOrUnset for DelegatedSubject<D> {}

#[doc(hidden)]
pub trait CommandOrUnset {}
impl CommandOrUnset for Unset {}
impl CommandOrUnset for Vec<String> {}

#[doc(hidden)]
pub(crate) trait ProofsOrUnset {}
impl ProofsOrUnset for Unset {}
impl ProofsOrUnset for Vec<Cid> {}

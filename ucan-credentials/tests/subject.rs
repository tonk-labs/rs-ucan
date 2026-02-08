//! DelegatedSubject tests using Ed25519 concrete types.
//!
//! These tests were moved from `ucan/src/delegation/subject.rs` since they
//! depend on concrete Ed25519 key types from `ucan-credentials`.

use serde_ipld_dagcbor::{from_slice, to_vec};
use ucan::delegation::subject::DelegatedSubject;
use ucan_credentials::ed25519::Ed25519Did;

#[test]
fn any_serializes_to_null() {
    let subject: DelegatedSubject<Ed25519Did> = DelegatedSubject::Any;
    let bytes = to_vec(&subject).unwrap();
    // CBOR null is encoded as 0xf6
    assert_eq!(bytes, vec![0xf6]);
}

#[test]
fn any_deserializes_from_null() {
    // CBOR null is encoded as 0xf6
    let bytes = vec![0xf6];
    let subject: DelegatedSubject<Ed25519Did> = from_slice(&bytes).unwrap();
    assert_eq!(subject, DelegatedSubject::Any);
}

#[test]
fn any_roundtrip() {
    let subject: DelegatedSubject<Ed25519Did> = DelegatedSubject::Any;
    let bytes = to_vec(&subject).unwrap();
    let decoded: DelegatedSubject<Ed25519Did> = from_slice(&bytes).unwrap();
    assert_eq!(decoded, DelegatedSubject::Any);
}

#[test]
fn specific_roundtrip() {
    let key = ed25519_dalek::VerifyingKey::from_bytes(&[
        215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243,
        218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
    ])
    .unwrap();
    let did: Ed25519Did = key.into();
    let subject = DelegatedSubject::Specific(did.clone());

    let bytes = to_vec(&subject).unwrap();
    let decoded: DelegatedSubject<Ed25519Did> = from_slice(&bytes).unwrap();

    assert_eq!(decoded, DelegatedSubject::Specific(did));
}

//! Subject tests using Ed25519 concrete types.

use serde_ipld_dagcbor::{from_slice, to_vec};
use ucan::subject::Subject;
use varsig::did::Did;

#[test]
fn any_serializes_to_null() {
    let subject = Subject::Any;
    let bytes = to_vec(&subject).unwrap();
    // CBOR null is encoded as 0xf6
    assert_eq!(bytes, vec![0xf6]);
}

#[test]
fn any_deserializes_from_null() {
    // CBOR null is encoded as 0xf6
    let bytes = vec![0xf6];
    let subject: Subject = from_slice(&bytes).unwrap();
    assert_eq!(subject, Subject::Any);
}

#[test]
fn any_roundtrip() {
    let subject = Subject::Any;
    let bytes = to_vec(&subject).unwrap();
    let decoded: Subject = from_slice(&bytes).unwrap();
    assert_eq!(decoded, Subject::Any);
}

#[test]
fn specific_roundtrip() {
    let key = ed25519_dalek::VerifyingKey::from_bytes(&[
        215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243,
        218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
    ])
    .unwrap();
    let did: ucan_credentials::ed25519::Ed25519Principal = key.into();
    let did_key: Did = Did::new(did.to_string());
    let subject = Subject::Specific(did_key.clone());

    let bytes = to_vec(&subject).unwrap();
    let decoded: Subject = from_slice(&bytes).unwrap();

    assert_eq!(decoded, Subject::Specific(did_key));
}

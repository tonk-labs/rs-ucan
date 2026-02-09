//! Subject serialization tests.

use serde_ipld_dagcbor::{from_slice, to_vec};
use ucan::subject::Subject;
use ucan_credentials::ed25519::Ed25519Signer;
use varsig::{did::Did, principal::Principal};

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test;

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

#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), tokio::test)]
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
async fn specific_roundtrip() {
    let signer = Ed25519Signer::import(&[55u8; 32]).await.unwrap();
    let did_key: Did = signer.did();
    let subject = Subject::Specific(did_key.clone());

    let bytes = to_vec(&subject).unwrap();
    let decoded: Subject = from_slice(&bytes).unwrap();

    assert_eq!(decoded, Subject::Specific(did_key));
}

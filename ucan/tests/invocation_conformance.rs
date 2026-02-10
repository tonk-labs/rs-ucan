//! Tests for invocation conformance to the UCAN specification.
mod invocation_conformance {
    use std::sync::OnceLock;

    use ipld_core::ipld::Ipld;
    use testresult::TestResult;
    use ucan::{Delegation, Invocation};
    use varsig::eddsa::Ed25519Signature;

    const INVOCATION_FIXTURE_STR: &str = include_str!("./fixtures/invocation.json");
    static INVOCATION_FIXTURE: OnceLock<serde_json::Value> = OnceLock::new();
    fn invocation_fixture() -> &'static serde_json::Value {
        INVOCATION_FIXTURE.get_or_init(|| {
            serde_json::from_str(INVOCATION_FIXTURE_STR).expect("fixture is invalid JSON")
        })
    }

    /// Decode a DAG-JSON bytes value `{"/": {"bytes": "..."}}` into raw bytes
    /// using `serde_ipld_dagjson`.
    fn decode_dag_json_bytes(val: &serde_json::Value) -> Vec<u8> {
        let json_bytes = serde_json::to_vec(val).expect("value is valid JSON");
        let ipld: Ipld =
            serde_ipld_dagjson::from_slice(&json_bytes).expect("value is valid DAG-JSON");
        match ipld {
            Ipld::Bytes(bytes) => bytes,
            other => panic!("expected DAG-JSON bytes, got: {other:?}"),
        }
    }

    #[test]
    fn test_expected_version() -> TestResult {
        assert_eq!(
            invocation_fixture()
                .get("version")
                .expect("fixture has version key")
                .clone(),
            "1.0.0-rc.1".to_string()
        );
        Ok(())
    }

    mod valid {
        use super::*;

        fn parse_valid_invocation(idx: usize) -> (String, Invocation<Ed25519Signature>) {
            let entry = &invocation_fixture()["valid"][idx];
            let name = entry["name"].as_str().unwrap().to_string();
            let inv_bytes = decode_dag_json_bytes(&entry["invocation"]);
            let invocation: Invocation<Ed25519Signature> =
                serde_ipld_dagcbor::from_slice(&inv_bytes)
                    .unwrap_or_else(|e| panic!("failed to decode valid invocation '{name}': {e}"));
            (name, invocation)
        }

        fn parse_valid_proofs(idx: usize) -> Vec<Delegation<Ed25519Signature>> {
            let entry = &invocation_fixture()["valid"][idx];
            let proofs_json = entry["proofs"].as_array().expect("proofs is an array");
            proofs_json
                .iter()
                .map(|p| {
                    let bytes = decode_dag_json_bytes(p);
                    serde_ipld_dagcbor::from_slice(&bytes).expect("failed to decode proof")
                })
                .collect()
        }

        #[test]
        fn test_self_signed_parses() -> TestResult {
            let (name, inv) = parse_valid_invocation(0);
            assert_eq!(name, "self signed");
            assert!(inv.proofs().is_empty());
            Ok(())
        }

        #[test]
        fn test_single_non_time_bounded_proof_parses() -> TestResult {
            let (name, inv) = parse_valid_invocation(1);
            assert_eq!(name, "single non-time bounded proof");
            assert_eq!(inv.proofs().len(), 1);
            let proofs = parse_valid_proofs(1);
            assert_eq!(proofs.len(), 1);
            Ok(())
        }

        #[test]
        fn test_single_active_non_expired_proof_parses() -> TestResult {
            let (name, inv) = parse_valid_invocation(2);
            assert_eq!(name, "single active non-expired proof");
            assert_eq!(inv.proofs().len(), 1);
            let proofs = parse_valid_proofs(2);
            assert_eq!(proofs.len(), 1);
            Ok(())
        }

        #[test]
        fn test_multiple_proofs_parses() -> TestResult {
            let (name, inv) = parse_valid_invocation(3);
            assert_eq!(name, "multiple proofs");
            assert_eq!(inv.proofs().len(), 2);
            let proofs = parse_valid_proofs(3);
            assert_eq!(proofs.len(), 2);
            Ok(())
        }

        #[test]
        fn test_multiple_active_proofs_parses() -> TestResult {
            let (name, inv) = parse_valid_invocation(4);
            assert_eq!(name, "multiple active proofs");
            assert_eq!(inv.proofs().len(), 2);
            let proofs = parse_valid_proofs(4);
            assert_eq!(proofs.len(), 2);
            Ok(())
        }

        #[test]
        fn test_powerline_parses() -> TestResult {
            let (name, inv) = parse_valid_invocation(5);
            assert_eq!(name, "powerline");
            assert_eq!(inv.proofs().len(), 2);
            let proofs = parse_valid_proofs(5);
            assert_eq!(proofs.len(), 2);
            Ok(())
        }

        #[test]
        fn test_policy_match_parses() -> TestResult {
            let (name, inv) = parse_valid_invocation(6);
            assert_eq!(name, "policy match");
            assert_eq!(inv.proofs().len(), 1);
            let proofs = parse_valid_proofs(6);
            assert_eq!(proofs.len(), 1);
            Ok(())
        }

        #[test]
        fn test_all_valid_invocations_parse() -> TestResult {
            let valid = invocation_fixture()["valid"]
                .as_array()
                .expect("valid is an array");
            for (idx, _) in valid.iter().enumerate() {
                let (name, _inv) = parse_valid_invocation(idx);
                let _proofs = parse_valid_proofs(idx);
                eprintln!("parsed valid invocation: {name}");
            }
            Ok(())
        }
    }

    mod roundtrip {
        use super::*;

        #[test]
        fn test_all_valid_invocations_roundtrip() -> TestResult {
            let valid = invocation_fixture()["valid"]
                .as_array()
                .expect("valid is an array");
            for (idx, entry) in valid.iter().enumerate() {
                let name = entry["name"].as_str().unwrap();
                let original_bytes = decode_dag_json_bytes(&entry["invocation"]);
                let invocation: Invocation<Ed25519Signature> =
                    serde_ipld_dagcbor::from_slice(&original_bytes)
                        .unwrap_or_else(|e| panic!("failed to decode '{name}': {e}"));
                let re_encoded = serde_ipld_dagcbor::to_vec(&invocation)
                    .unwrap_or_else(|e| panic!("failed to re-encode '{name}': {e}"));
                assert_eq!(
                    original_bytes, re_encoded,
                    "roundtrip mismatch for valid invocation '{name}' (idx={idx})"
                );
            }
            Ok(())
        }

        #[test]
        fn test_all_valid_proofs_roundtrip() -> TestResult {
            let valid = invocation_fixture()["valid"]
                .as_array()
                .expect("valid is an array");
            for (idx, entry) in valid.iter().enumerate() {
                let name = entry["name"].as_str().unwrap();
                let proofs_json = entry["proofs"].as_array().expect("proofs is an array");
                for (pidx, proof_json) in proofs_json.iter().enumerate() {
                    let original_bytes = decode_dag_json_bytes(proof_json);
                    let delegation: Delegation<Ed25519Signature> =
                        serde_ipld_dagcbor::from_slice(&original_bytes).unwrap_or_else(|e| {
                            panic!("failed to decode proof {pidx} of '{name}': {e}")
                        });
                    let re_encoded = serde_ipld_dagcbor::to_vec(&delegation).unwrap_or_else(|e| {
                        panic!("failed to re-encode proof {pidx} of '{name}': {e}")
                    });
                    assert_eq!(
                        original_bytes, re_encoded,
                        "roundtrip mismatch for proof {pidx} of '{name}' (idx={idx})"
                    );
                }
            }
            Ok(())
        }

        #[test]
        fn test_proof_cids_match() -> TestResult {
            let valid = invocation_fixture()["valid"]
                .as_array()
                .expect("valid is an array");
            for (idx, entry) in valid.iter().enumerate() {
                let name = entry["name"].as_str().unwrap();
                let inv_bytes = decode_dag_json_bytes(&entry["invocation"]);
                let invocation: Invocation<Ed25519Signature> =
                    serde_ipld_dagcbor::from_slice(&inv_bytes)
                        .unwrap_or_else(|e| panic!("failed to decode '{name}': {e}"));
                let proofs_json = entry["proofs"].as_array().expect("proofs is an array");
                assert_eq!(
                    invocation.proofs().len(),
                    proofs_json.len(),
                    "proof count mismatch for '{name}' (idx={idx})"
                );
                for (pidx, proof_json) in proofs_json.iter().enumerate() {
                    let proof_bytes = decode_dag_json_bytes(proof_json);
                    let delegation: Delegation<Ed25519Signature> =
                        serde_ipld_dagcbor::from_slice(&proof_bytes).unwrap_or_else(|e| {
                            panic!("failed to decode proof {pidx} of '{name}': {e}")
                        });
                    let computed_cid = delegation.to_cid();
                    let referenced_cid = &invocation.proofs()[pidx];
                    assert_eq!(
                        &computed_cid, referenced_cid,
                        "CID mismatch for proof {pidx} of '{name}' (idx={idx}): \
                         computed={computed_cid}, referenced={referenced_cid}"
                    );
                }
            }
            Ok(())
        }
    }

    mod invalid {
        use super::*;

        fn parse_invalid_entry(idx: usize) -> (String, String) {
            let entry = &invocation_fixture()["invalid"][idx];
            let name = entry["name"].as_str().unwrap().to_string();
            let error_name = entry["error"]["name"].as_str().unwrap().to_string();
            (name, error_name)
        }

        fn try_parse_invocation(idx: usize) -> Result<Invocation<Ed25519Signature>, String> {
            let entry = &invocation_fixture()["invalid"][idx];
            let inv_bytes = decode_dag_json_bytes(&entry["invocation"]);
            serde_ipld_dagcbor::from_slice(&inv_bytes).map_err(|e| e.to_string())
        }

        fn try_parse_proofs(idx: usize) -> Vec<Result<Delegation<Ed25519Signature>, String>> {
            let entry = &invocation_fixture()["invalid"][idx];
            let proofs_json = entry["proofs"].as_array().expect("proofs is an array");
            proofs_json
                .iter()
                .map(|p| {
                    let bytes = decode_dag_json_bytes(p);
                    serde_ipld_dagcbor::from_slice(&bytes).map_err(|e| e.to_string())
                })
                .collect()
        }

        #[test]
        fn test_all_invalid_invocations_are_present() -> TestResult {
            let invalid = invocation_fixture()["invalid"]
                .as_array()
                .expect("invalid is an array");
            assert_eq!(invalid.len(), 13);

            let expected_names = [
                "no proof",
                "missing proof",
                "expired proof",
                "inactive proof",
                "proof principal alignment",
                "invocation principal alignment",
                "proof subject alignment",
                "invocation subject alignment",
                "expired invocation",
                "invalid proof signature",
                "invalid invocation signature",
                "invalid powerline",
                "policy violation",
            ];

            for (idx, expected_name) in expected_names.iter().enumerate() {
                let (name, _error) = parse_invalid_entry(idx);
                assert_eq!(&name, expected_name, "invalid entry {idx} name mismatch");
            }

            Ok(())
        }

        #[test]
        fn test_invalid_invocations_decode() -> TestResult {
            let invalid = invocation_fixture()["invalid"]
                .as_array()
                .expect("invalid is an array");

            for (idx, entry) in invalid.iter().enumerate() {
                let name = entry["name"].as_str().unwrap();
                let error_name = entry["error"]["name"].as_str().unwrap();

                // Most invalid invocations should still parse (the error
                // is in validation, not encoding), except those with
                // invalid signatures which may use bad signature bytes.
                let inv_result = try_parse_invocation(idx);
                let _proof_results = try_parse_proofs(idx);

                match error_name {
                    "InvalidSignature" => {
                        // These may fail at parse time due to bad signature
                        // bytes, or may parse but fail signature verification.
                        eprintln!(
                            "invalid[{idx}] '{name}': parse result = {}",
                            inv_result.is_ok()
                        );
                    }
                    _ => {
                        // All other invalid cases should parse successfully;
                        // the error occurs during validation/checking.
                        assert!(
                            inv_result.is_ok(),
                            "invalid[{idx}] '{name}' (error={error_name}) should parse but got: {:?}",
                            inv_result.err()
                        );
                    }
                }
            }

            Ok(())
        }

        #[test]
        fn test_no_proof_has_correct_error_type() -> TestResult {
            let (name, error) = parse_invalid_entry(0);
            assert_eq!(name, "no proof");
            assert_eq!(error, "InvalidClaim");
            Ok(())
        }

        #[test]
        fn test_missing_proof_has_correct_error_type() -> TestResult {
            let (name, error) = parse_invalid_entry(1);
            assert_eq!(name, "missing proof");
            assert_eq!(error, "UnavailableProof");
            Ok(())
        }

        #[test]
        fn test_expired_proof_has_correct_error_type() -> TestResult {
            let (name, error) = parse_invalid_entry(2);
            assert_eq!(name, "expired proof");
            assert_eq!(error, "Expired");
            Ok(())
        }

        #[test]
        fn test_inactive_proof_has_correct_error_type() -> TestResult {
            let (name, error) = parse_invalid_entry(3);
            assert_eq!(name, "inactive proof");
            assert_eq!(error, "TooEarly");
            Ok(())
        }

        #[test]
        fn test_proof_principal_alignment_has_correct_error_type() -> TestResult {
            let (name, error) = parse_invalid_entry(4);
            assert_eq!(name, "proof principal alignment");
            assert_eq!(error, "InvalidAudience");
            Ok(())
        }

        #[test]
        fn test_invocation_principal_alignment_has_correct_error_type() -> TestResult {
            let (name, error) = parse_invalid_entry(5);
            assert_eq!(name, "invocation principal alignment");
            assert_eq!(error, "InvalidAudience");
            Ok(())
        }

        #[test]
        fn test_proof_subject_alignment_has_correct_error_type() -> TestResult {
            let (name, error) = parse_invalid_entry(6);
            assert_eq!(name, "proof subject alignment");
            assert_eq!(error, "InvalidSubject");
            Ok(())
        }

        #[test]
        fn test_invocation_subject_alignment_has_correct_error_type() -> TestResult {
            let (name, error) = parse_invalid_entry(7);
            assert_eq!(name, "invocation subject alignment");
            assert_eq!(error, "InvalidSubject");
            Ok(())
        }

        #[test]
        fn test_expired_invocation_has_correct_error_type() -> TestResult {
            let (name, error) = parse_invalid_entry(8);
            assert_eq!(name, "expired invocation");
            assert_eq!(error, "Expired");
            Ok(())
        }

        #[test]
        fn test_invalid_proof_signature_has_correct_error_type() -> TestResult {
            let (name, error) = parse_invalid_entry(9);
            assert_eq!(name, "invalid proof signature");
            assert_eq!(error, "InvalidSignature");
            Ok(())
        }

        #[test]
        fn test_invalid_invocation_signature_has_correct_error_type() -> TestResult {
            let (name, error) = parse_invalid_entry(10);
            assert_eq!(name, "invalid invocation signature");
            assert_eq!(error, "InvalidSignature");
            Ok(())
        }

        #[test]
        fn test_invalid_powerline_has_correct_error_type() -> TestResult {
            let (name, error) = parse_invalid_entry(11);
            assert_eq!(name, "invalid powerline");
            assert_eq!(error, "InvalidClaim");
            Ok(())
        }

        #[test]
        fn test_policy_violation_has_correct_error_type() -> TestResult {
            let (name, error) = parse_invalid_entry(12);
            assert_eq!(name, "policy violation");
            assert_eq!(error, "MatchError");
            Ok(())
        }
    }
}

//! Fixed public synthetic presentations, not network identities or approvals.
use serde_json::{json, Value};
use synergy_rpc::r1_read::{
    self, AccountArgs, BlockArgs, BlockRead, NetworkCoordinateWire, TransactionArgs,
};

fn coordinate() -> Value {
    json!({"chain_id":"18446744073709551614",
        "network_incarnation_commitment":{"algorithm":"SHA3-512","encoding":"lowercase-hex","value":"11".repeat(64)},
        "genesis_commitment":{"profile":{"name":"SYNERGY-GENESIS-R1","revision":1},"algorithm":"SHA3-384","encoding":"lowercase-hex","value":"22".repeat(48)},
        "activated_profiles":{"profile":{"name":"SYNTHETIC-NONPRODUCTION-PROFILES","revision":1},"algorithm":"SHA3-512","encoding":"lowercase-hex","value":"33".repeat(64)},
        "identity_profile":{"name":"APQE-NATIVE-ID","revision":1},"presentation_version":2})
}
fn request(args: Value) -> Value {
    json!({"api_version":1,"request_id":"public-synthetic-read-only","caller_scope":"public_read","network":coordinate(),"args":args})
}
fn expected() -> synergy_protocol_types::R1NetworkCoordinate {
    serde_json::from_value::<NetworkCoordinateWire>(coordinate())
        .unwrap()
        .typed()
        .unwrap()
}

#[test]
fn account_families_and_contract_preserve_all48_bytes_and_case() {
    for family in ["synw", "syns", "syna", "synm", "synu", "synq"] {
        let text =
            format!("{family}.2.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v");
        // Independent fixed raw00..2f RFC4648 presentation.
        let parsed = r1_read::decode::<AccountArgs>(
            request(json!({"address":text,"at_height":"18446744073709551615"})),
            &expected(),
        )
        .unwrap();
        assert_eq!(parsed.args.identity.to_text(), text);
        assert_eq!(
            parsed.args.identity.raw48(),
            &std::array::from_fn::<_, 48, _>(|i| i as u8)
        );
        assert_eq!(parsed.args.at_height, Some(u64::MAX));
    }
}

#[test]
fn account_read_refuses_wrong_families_legacy_unicode_padding_and_shortening() {
    for text in [
        format!("synv1.2.{}", "A".repeat(64)),
        format!("synb1.2.{}", "A".repeat(64)),
        "syn00000000000000000000000000000000000700".into(),
        "syna1historical".into(),
        format!("synw.2.{}", "A".repeat(63)),
        format!("synw.2.{}=", "A".repeat(64)),
        format!("synw.2.{}\n", "A".repeat(64)),
        format!("synw.2.{}é", "A".repeat(62)),
    ] {
        assert!(
            r1_read::decode::<AccountArgs>(request(json!({"address":text})), &expected()).is_err()
        );
    }
}

#[test]
fn transaction_uses_exact_native70_not_cross_chain_or_historical32() {
    let text = format!("syntxn{}", "A".repeat(64));
    let parsed =
        r1_read::decode::<TransactionArgs>(request(json!({"transaction_id":text})), &expected())
            .unwrap();
    assert_eq!(parsed.args.digest48(), &[0; 48]);
    assert_eq!(parsed.args.to_text(), text);
    for text in [
        format!("synxxn{}", "A".repeat(64)),
        "a".repeat(64),
        format!("syntxn.2.{}", "A".repeat(64)),
        format!("syntxn{}\n", "A".repeat(64)),
    ] {
        assert!(r1_read::decode::<TransactionArgs>(
            request(json!({"transaction_id":text})),
            &expected()
        )
        .is_err());
    }
}

#[test]
fn block_selector_is_exactly_one_height_or_full_profile_bound_commitment() {
    let c = json!({"profile":{"name":"SYNTHETIC-BLOCK-PROFILE","revision":1},"algorithm":"SHA3-384","encoding":"lowercase-hex","value":format!("{}ff", "00".repeat(47))});
    let parsed =
        r1_read::decode::<BlockArgs>(request(json!({"block_commitment":c})), &expected()).unwrap();
    match parsed.args {
        BlockRead::Commitment { profile, digest } => {
            assert_eq!(digest[47], 255);
            assert_eq!(profile.revision, 1);
        }
        _ => panic!(),
    }
    assert!(matches!(
        r1_read::decode::<BlockArgs>(request(json!({"height":"0"})), &expected())
            .unwrap()
            .args,
        BlockRead::Height(0)
    ));
    for args in [
        json!({}),
        json!({"height":"1","block_commitment":c}),
        json!({"hash":"a".repeat(64)}),
        json!({"height":1}),
    ] {
        assert!(r1_read::decode::<BlockArgs>(request(args), &expected()).is_err());
    }
}

#[test]
fn network_chain_nic_genesis_and_each_profile_are_independently_bound() {
    for (pointer, value) in [
        ("/chain_id", json!("18446744073709551615")),
        (
            "/network_incarnation_commitment/value",
            json!("44".repeat(64)),
        ),
        ("/genesis_commitment/value", json!("55".repeat(48))),
        ("/activated_profiles/value", json!("66".repeat(64))),
        ("/activated_profiles/profile/revision", json!(2)),
        (
            "/activated_profiles/profile/name",
            json!("OTHER-SYNTHETIC-PROFILES"),
        ),
    ] {
        let mut req = request(json!({"height":"1"}));
        *req["network"].pointer_mut(pointer).unwrap() = value;
        assert_eq!(
            r1_read::decode::<BlockArgs>(req, &expected())
                .unwrap_err()
                .code,
            -32010
        );
    }
}

#[test]
fn malformed_widths_algorithms_versions_and_noncanonical_decimal_are_rejected() {
    for (pointer, value) in [
        ("/chain_id", json!("0")),
        ("/chain_id", json!("09969")),
        ("/chain_id", json!("9969\n")),
        ("/chain_id", json!("18446744073709551616")),
        ("/chain_id", json!(9969)),
        (
            "/network_incarnation_commitment/value",
            json!("11".repeat(48)),
        ),
        ("/genesis_commitment/value", json!("22".repeat(32))),
        (
            "/genesis_commitment/value",
            json!(format!("{}\n", "22".repeat(48))),
        ),
        ("/genesis_commitment/algorithm", json!("SHA-256")),
        ("/genesis_commitment/profile/revision", json!(2)),
        ("/presentation_version", json!(1)),
        ("/identity_profile/name", json!("legacy")),
    ] {
        let mut req = request(json!({"height":"1"}));
        *req["network"].pointer_mut(pointer).unwrap() = value;
        assert_eq!(
            r1_read::decode::<BlockArgs>(req, &expected())
                .unwrap_err()
                .code,
            -32602
        );
    }
}

#[test]
fn unknown_fields_and_scope_escalation_fail_without_reflecting_input() {
    for path in [
        "",
        "/network",
        "/network/genesis_commitment",
        "/network/genesis_commitment/profile",
        "/args",
    ] {
        let mut req = request(json!({"height":"1"}));
        req.pointer_mut(path).unwrap()["private_key"] = json!("SECRET_SENTINEL");
        let error = r1_read::decode::<BlockArgs>(req, &expected()).unwrap_err();
        assert_eq!(error.code, -32602);
        assert!(!error.message.contains("SECRET_SENTINEL"));
        assert!(error.data.is_none());
    }
    for scope in ["admin", "validator", "public_read\n"] {
        let mut req = request(json!({"height":"1"}));
        req["caller_scope"] = json!(scope);
        assert!(r1_read::decode::<BlockArgs>(req, &expected()).is_err());
    }
}

#[test]
fn context_is_checked_before_argument_interpretation_and_never_uses_wildcards() {
    let mut req = request(json!({"height":"not-a-height"}));
    req["network"]["genesis_commitment"]["value"] = json!("00".repeat(48));
    assert_eq!(
        r1_read::decode::<BlockArgs>(req, &expected())
            .unwrap_err()
            .code,
        -32010
    );
}

#[test]
fn positional_arrays_cannot_bypass_the_named_object_wire_contract() {
    for (pointer, array) in [
        ("/args", json!(["1", null])),
        ("/network/identity_profile", json!(["APQE-NATIVE-ID", 1])),
        (
            "/network/genesis_commitment/profile",
            json!(["SYNERGY-GENESIS-R1", 1]),
        ),
        (
            "/network/network_incarnation_commitment",
            json!(["SHA3-512", "lowercase-hex", "11".repeat(64)]),
        ),
    ] {
        let mut req = request(json!({"height":"1"}));
        *req.pointer_mut(pointer).unwrap() = array;
        assert_eq!(
            r1_read::decode::<BlockArgs>(req, &expected())
                .unwrap_err()
                .code,
            -32602
        );
    }
    assert!(r1_read::decode::<r1_read::EmptyArgs>(request(json!({})), &expected()).is_ok());
    assert!(
        r1_read::decode::<r1_read::EmptyArgs>(request(json!({"unknown":1})), &expected()).is_err()
    );
}

#[test]
fn consumer_schema_method_bindings_equal_the_exact_native_read_adapter_set() {
    let schema: Value =
        serde_json::from_str(include_str!("../schemas/native_read_r1.schema.json")).unwrap();
    let bindings = schema["x-method-contracts"].as_object().unwrap();
    assert_eq!(bindings.len(), r1_read::METHODS.len());
    for method in r1_read::METHODS {
        assert!(bindings.contains_key(*method));
        assert!(r1_read::is_method(method));
    }
    for private in [
        "synergy_signTransaction",
        "synergy_createWalletFromKeypair",
        "synergy_getAccountAuthNonce",
        "synergy_rotateKeys",
    ] {
        assert!(!r1_read::is_method(private));
        assert!(!bindings.contains_key(private));
    }
}

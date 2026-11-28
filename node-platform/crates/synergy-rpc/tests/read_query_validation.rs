use serde_json::{json, Value};
use synergy_rpc::methods::{AccountQuery, BlockQuery, TransactionQuery, ValidatedReadQuery};

#[test]
fn existing_historical_queries_preserve_values_without_normalization() {
    let account =
        AccountQuery::from_params(json!({"address":"syna1historical","at_height":1})).unwrap();
    assert_eq!(account.address, "syna1historical");
    assert_eq!(account.at_height, Some(1));
    let hash = "ab".repeat(32);
    assert_eq!(
        BlockQuery::from_params(json!({"hash":hash}))
            .unwrap()
            .hash
            .as_deref(),
        Some(hash.as_str())
    );
    assert_eq!(
        TransactionQuery::from_params(json!({"transaction_id":hash}))
            .unwrap()
            .transaction_id,
        hash
    );
    assert_eq!(
        BlockQuery::from_params(json!({"height":0})).unwrap().height,
        Some(0)
    );
}

#[test]
fn unrecognized_coordinates_authority_and_secret_fields_are_not_ignored_or_echoed() {
    for field in ["network_coordinate", "authority", "private_key"] {
        for mut params in [
            json!({"address":"syna1historical"}),
            json!({"height":1}),
            json!({"transaction_id":"a".repeat(64)}),
        ] {
            params[field] = json!("PRIVATE_SENTINEL_DO_NOT_REFLECT");
            let errors = [
                AccountQuery::from_params(params.clone()).err(),
                BlockQuery::from_params(params.clone()).err(),
                TransactionQuery::from_params(params).err(),
            ];
            for error in errors {
                let error = error.expect("closed query accepted unknown input");
                assert_eq!(error.code, -32602);
                assert!(!error.message.contains("PRIVATE_SENTINEL"));
                assert!(error.data.is_none());
            }
        }
    }
}

#[test]
fn invalid_block_selectors_are_rejected_before_storage_search() {
    for params in [
        json!({}),
        json!({"height":1,"hash":"a".repeat(64)}),
        json!({"height":-1}),
        json!({"hash":"A".repeat(64)}),
        json!({"hash":"g".repeat(64)}),
        json!({"hash":"a".repeat(63)}),
        json!({"hash":format!("{}\n", "a".repeat(64))}),
        json!({"hash":"syntxnAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
        Value::Null,
        json!([]),
    ] {
        assert_eq!(BlockQuery::from_params(params).unwrap_err().code, -32602);
    }
}

#[test]
fn account_and_transaction_validation_cannot_be_skipped_by_a_read_provider() {
    for params in [
        json!({"address":" "}),
        json!({"address":"a".repeat(257)}),
        json!({"address":"syna1historical","at_height":0}),
    ] {
        assert_eq!(AccountQuery::from_params(params).unwrap_err().code, -32602);
    }
    // A candidate R1 transaction presentation is never silently truncated or
    // reinterpreted as this historical provider's 32-byte transaction key.
    for tx in [
        "a".repeat(63),
        "A".repeat(64),
        format!("syntxn{}", "A".repeat(64)),
        format!("{}\n", "a".repeat(64)),
    ] {
        assert_eq!(
            TransactionQuery::from_params(json!({"transaction_id":tx}))
                .unwrap_err()
                .code,
            -32602
        );
    }
}

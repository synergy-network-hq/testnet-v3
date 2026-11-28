//! Actual public signed fixture + private verified context + real typed store.
//! Synthetic projections deliberately do not qualify PoSy finality or exposure.
use super::*;
#[path = "../../../synergy-genesis/tests/common/mod.rs"]
mod genesis_support;
use genesis_support::{bytes, catalog, engine};
use std::sync::{Mutex, RwLock};
use synergy_address_engine::apqe::{
    bootstrap_approvals_r1::{IndexedRootApproval, PinnedBootstrapAuthority, PinnedBootstrapInput},
    network_birth_r1::{BootstrapKeyRecord, NetworkBirth, ProfileRef},
};
use synergy_state::{r1::R1StateOwner, r1_finalized::publish_nonproduction_projection};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        Self(std::env::temp_dir().join(
            format!("rpc-r1-public-only-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()),
        ))
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        if self.0.exists() {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
}
fn verified_genesis() -> Arc<VerifiedR1Genesis> {
    let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../21-Aegis-Engine/synergy-address-engine/tests/fixtures/r1_compiled_genesis_public.json");
    let input = std::fs::read(path).expect("public signed fixture required, never skip");
    assert!(input.len() <= 1024 * 1024);
    let f: Value = serde_json::from_slice(&input).unwrap();
    assert_eq!(
        f["purpose"],
        "PUBLIC_SYNTHETIC_COMPILED_GENESIS_FIXTURE_ONLY"
    );
    assert_eq!(f["production_import_permitted"], false);
    assert_eq!(f["chain_id"], u64::MAX - 1);
    let catalog = catalog();
    assert_eq!(
        catalog.canonical_frame().unwrap(),
        bytes(f["profile_catalog_frame_hex"].as_str().unwrap())
    );
    let commitment = catalog.commitment().unwrap();
    let keys: Vec<_> = f["roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| bytes(r["public_key_hex"].as_str().unwrap()))
        .collect();
    let roots: Vec<_> = f["roots"]
        .as_array()
        .unwrap()
        .iter()
        .zip(&keys)
        .map(|(r, k)| BootstrapKeyRecord {
            role: r["role"].as_str().unwrap(),
            algorithm: r["algorithm"].as_str().unwrap(),
            key_generation: r["key_generation"].as_u64().unwrap(),
            full_public_key: k,
        })
        .collect();
    let birth = NetworkBirth {
        chain_id: u64::MAX - 1,
        incarnation_nonce: &[3; 32],
        genesis_schema: ProfileRef {
            name: "SYNERGY-GENESIS-R1",
            revision: 1,
        },
        initial_profile_set_commitment: &commitment,
        bootstrap_roots: &roots,
        network_label: "PUBLIC-SYNTHETIC-COMPILED-GENESIS-ONLY",
    };
    let authority = PinnedBootstrapAuthority::from_preparation_pins(
        &PinnedBootstrapInput {
            birth,
            threshold: 2,
        },
        &birth,
    )
    .unwrap();
    let signatures: Vec<_> = f["approvals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| bytes(a["signature_hex"].as_str().unwrap()))
        .collect();
    assert_eq!(signatures.len(), 4);
    let approvals = |offset: usize| {
        (0..2)
            .map(|i| IndexedRootApproval {
                root_index: i as u32,
                signature: signatures[offset + i].as_slice(),
            })
            .collect::<Vec<_>>()
    };
    Arc::new(
        synergy_genesis::r1::verify_bytes(
            &bytes(f["genesis_core_c14n02_hex"].as_str().unwrap()),
            &catalog,
            &authority,
            &approvals(0),
            &approvals(2),
            &engine(),
        )
        .unwrap(),
    )
}
fn runtime(chain_id: u64) -> RuntimeView {
    Arc::new(RwLock::new(synergy_node_core::RuntimeSnapshot {
        node_name: "public-synthetic-read-fixture".into(),
        role: "observer".into(),
        chain_id,
        lifecycle: synergy_node_core::NodeLifecycleState::Starting,
        services: vec![],
    }))
}
fn capacity() -> R1ReadCapacity {
    R1ReadCapacity {
        request_timeout: Duration::from_secs(20),
        maximum_hashes: 10_000_000,
        maximum_response_bytes: 1024 * 1024,
    }
}
fn params(genesis: &VerifiedR1Genesis, args: Value) -> Value {
    json!({"api_version":1,"request_id":"public-synthetic-read-only","caller_scope":"public_read",
        "network":coordinate(genesis.coordinate()),"args":args})
}

#[test]
fn actual_private_genesis_context_drives_all_29_typed_read_adapters() {
    let temp = Temp::new();
    let genesis = verified_genesis();
    let state = &genesis.compiled().state().state;
    let identity = state
        .entries()
        .find_map(|(key, _)| match &key.owner {
            R1StateOwner::Native { identity }
                if key.domain == synergy_state::r1::R1StateDomain::NativeBalance =>
            {
                Some(identity.clone())
            }
            _ => None,
        })
        .unwrap();
    let tx_id = format!(
        "syntxn{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xa5; 48])
    );
    // These projection rows are explicitly synthetic, not an executed block or
    // receipt proof. This checks factual read serialization; the response must
    // retain original unverified proof bytes and must never certify finality.
    let anchor = R1FinalizedAnchor {
        coordinate: genesis.coordinate().clone(),
        height: 0,
        block_digest: [0x5a; 48],
        state_root: *genesis.initial_state_root(),
    };
    let block = StoredBlockRead {
        anchor: anchor.clone(),
        parent_block_digest: [0; 48],
        epoch: 0,
        transactions: vec![tx_id.clone()],
        receipts_root: *genesis.initial_receipts_root(),
        public_finality_proof: b"PUBLIC_SYNTHETIC_UNVERIFIED_PROOF_ONLY".to_vec(),
        block_profile: genesis.block_profile().clone(),
        receipt_profile: genesis.receipt_profile().clone(),
    };
    let tx = synergy_state::r1_finalized::R1TransactionRead {
        anchor,
        transaction_id: tx_id.clone(),
        status: R1TransactionStatus::ResourceExhausted,
        gas_used: 7,
        fee_paid_nwei: 11,
        events_commitment: [0x2a; 48],
        error_code: Some("PUBLIC_SYNTHETIC_RESOURCE_LIMIT".into()),
    };
    publish_nonproduction_projection(&temp.0, &block, state, &[tx]).unwrap();
    let budget = WorldResourceBudget::new(256 * 1024 * 1024);
    let provider = Arc::new(
        CanonicalR1QueryStore::open(
            temp.0.clone(),
            Arc::clone(&genesis),
            runtime(u64::MAX - 1),
            Arc::clone(&budget),
            capacity(),
        )
        .unwrap(),
    );
    let server = synergy_rpc::server::RpcServer::new(
        Arc::new(super::super::RuntimeDispatcher {
            runtime: Arc::clone(&provider.runtime),
            query_store: provider.clone(),
            admission: None,
            preparation: None,
            network_identity: None,
            telemetry_samples: Mutex::new(super::super::TelemetrySamples::default()),
            proof_throttle: Mutex::new(super::super::proofs::ProofThrottle::default()),
        }),
        Arc::new(ManagedReadAuthenticator::new(provider.read_contract())),
        synergy_rpc::middleware::RpcLimits {
            max_body_bytes: 65536,
            max_concurrent_requests: 8,
            request_timeout_ms: 5000,
        },
        synergy_rpc::rate_limit::RpcRateLimiter::new(
            synergy_rpc::rate_limit::RateLimit {
                requests: 64,
                window_ms: 1000,
            },
            4,
        )
        .unwrap(),
    )
    .unwrap();
    for method in r1_read::METHODS {
        let args = match *method {
            "synergy_getAccount"
            | "synergy_getBalance"
            | "synergy_getNonce"
            | "synergy_getAccountNonce" => json!({"address":identity}),
            "synergy_getTransaction"
            | "synergy_getTransactionByHash"
            | "synergy_getReceipt"
            | "synergy_getTransactionReceipt"
            | "synergy_getTransactionStatus"
            | "synergy_getTransactionFees" => json!({"transaction_id":tx_id}),
            "synergy_getBlockByHash" => {
                json!({"block_commitment":commitment(genesis.block_profile(),&block.anchor.block_digest)})
            }
            "synergy_getBlock"
            | "synergy_getBlockByNumber"
            | "synergy_getBlockTransactionCount"
            | "synergy_getTransactionsInBlock" => json!({"height":"0"}),
            _ => json!({}),
        };
        let body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":"public-synthetic-read-only",
            "method":method,"params":params(&genesis,args)}))
        .unwrap();
        let (wire, permit) = server
            .handle_bytes_reserved("public-synthetic-client", None, 0, &body)
            .into_parts();
        assert!(permit.is_some());
        assert!(budget.used() >= 24 * 1024 * 1024);
        let outer: Value = serde_json::from_slice(&wire).unwrap();
        assert!(outer.get("error").is_none(), "{method}: {outer}");
        assert_eq!(outer["id"], "public-synthetic-read-only");
        drop(wire);
        drop(permit);
        let response = &outer["result"];
        assert_eq!(response["request_id"], "public-synthetic-read-only");
        assert_eq!(response["network"], coordinate(genesis.coordinate()));
        assert_eq!(response["finality_verified_by_rpc"], false);
        assert_ne!(response["result"], Value::Null, "{method}");
        assert_eq!(budget.used(), 0, "snapshot permit leaked by {method}");
        match *method {
            "synergy_getAccount" => {
                assert_eq!(response["result"]["identity"], identity);
                assert_eq!(response["result"]["balance_nwei"], "2");
                assert_eq!(response["result"]["nonce"], "0");
                assert_eq!(response["result"]["policy_epoch"], "1");
            }
            "synergy_getTransactionReceipt" => {
                assert_eq!(response["result"]["transaction_id"], tx_id);
                assert_eq!(response["result"]["status"], "resource_exhausted");
                assert_eq!(response["result"]["gas_used"], "7");
                assert_eq!(
                    response["result"]["events_commitment"]["value"],
                    "2a".repeat(48)
                );
            }
            "synergy_getBlockByHash" => {
                assert_eq!(
                    response["result"]["stored_anchor"]["block_commitment"]["value"],
                    "5a".repeat(48)
                );
                assert_eq!(response["result"]["transactions"], json!([tx_id]));
                assert_eq!(
                    response["result"]["public_finality_proof"]["value"],
                    BASE64.encode(&block.public_finality_proof)
                );
            }
            _ => {}
        }
    }
    let permit = provider.reserve_response_capacity().unwrap().unwrap();
    assert!(budget.used() >= 24 * 1024 * 1024);
    drop(permit);
    assert_eq!(budget.used(), 0);
    assert!(
        provider.latest_finalized_height().is_err(),
        "no historical fallback"
    );
}

#[test]
fn managed_read_access_is_narrow_and_does_not_change_historical_or_privileged_scopes() {
    use synergy_rpc::auth::RpcAuthenticator;
    let selected = ManagedReadAuthenticator::new(ReadContract::NativeR1V1);
    let historical = ManagedReadAuthenticator::new(ReadContract::HistoricalV1);
    for method in r1_read::METHODS {
        assert!(selected.authorize(method, None).is_ok(), "{method}");
        assert_eq!(
            historical.authorize(method, None).is_ok(),
            synergy_rpc::methods::method_access(method) == synergy_rpc::auth::RpcAccess::Public
        );
    }
    for method in [
        "synergy_signTransaction",
        "synergy_getAccountAuthNonce",
        "synergy_getPeers",
        "synergy_getValidator",
        synergy_rpc::methods::PEERS_LIST,
        synergy_rpc::methods::VALIDATOR_GET,
        "synergy_generateIdentity",
        "synergy_getBlock\n",
    ] {
        assert!(
            selected
                .authorize(method, Some("caller-supplied-not-authority"))
                .is_err(),
            "{method}"
        );
    }
}

#[test]
fn actual_verified_context_checks_before_store_io_and_cannot_fake_missing_state() {
    let temp = Temp::new();
    let genesis = verified_genesis();
    let budget = WorldResourceBudget::new(64 * 1024 * 1024);
    assert!(CanonicalR1QueryStore::open(
        temp.0.clone(),
        Arc::clone(&genesis),
        runtime(9969),
        Arc::clone(&budget),
        capacity()
    )
    .is_err());
    let provider = CanonicalR1QueryStore::open(
        temp.0.clone(),
        Arc::clone(&genesis),
        runtime(u64::MAX - 1),
        budget,
        capacity(),
    )
    .unwrap();
    assert!(!temp.0.exists());
    for field in [
        "network_incarnation_commitment",
        "genesis_commitment",
        "activated_profiles",
    ] {
        let mut request = params(&genesis, json!({}));
        request["network"][field]["value"] = json!("00".repeat(if field == "genesis_commitment" {
            48
        } else {
            64
        }));
        assert_eq!(
            provider
                .r1_read("synergy_getFinalizedHead", request)
                .unwrap_err()
                .code,
            -32010
        );
        assert!(
            !temp.0.exists(),
            "context mismatch must precede filesystem effects"
        );
    }
    assert!(provider
        .r1_read("synergy_getFinalizedHead", params(&genesis, json!({})))
        .is_err());
    let health = provider
        .r1_read("synergy_getHealth", params(&genesis, json!({})))
        .unwrap();
    assert_eq!(
        health["proof_profile_status"],
        "NOT_APPLICABLE_RUNTIME_OBSERVATION"
    );
    assert_eq!(health["result"]["ready"], false);
    assert!(
        !temp.0.exists(),
        "read-only missing store cannot create a chain"
    );
}

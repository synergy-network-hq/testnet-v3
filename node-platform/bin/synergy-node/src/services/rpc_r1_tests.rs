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
pub(crate) fn verified_genesis() -> Arc<VerifiedR1Genesis> {
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
    assert!(
        catalog.canonical_frame().unwrap()==bytes(f["profile_catalog_frame_hex"].as_str().unwrap()),
        "public compiled fixture profile catalog differs from current source; refresh the genuine signed fixture, never bypass verification"
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
        services: vec![
            synergy_node_core::ServiceObservation {
                id: synergy_node_core::ServiceId::new("public-synthetic-rpc").unwrap(),
                state: synergy_node_core::ServiceState::Running,
                health: synergy_node_core::ServiceHealth::Degraded { reason: "PUBLIC_TEST_PRIVATE_REASON_SENTINEL".into() },
                readiness: synergy_node_core::ServiceReadiness::Pending { reason: "PUBLIC_TEST_PRIVATE_REASON_SENTINEL".into() },
            },
            synergy_node_core::ServiceObservation {
                id: synergy_node_core::ServiceId::new("public-synthetic-execution").unwrap(),
                state: synergy_node_core::ServiceState::Starting,
                health: synergy_node_core::ServiceHealth::Unhealthy { reason: "PUBLIC_TEST_PRIVATE_REASON_SENTINEL".into() },
                readiness: synergy_node_core::ServiceReadiness::Blocked { reason: "PUBLIC_TEST_PRIVATE_REASON_SENTINEL".into() },
            },
            synergy_node_core::ServiceObservation {
                id:synergy_node_core::ServiceId::new("sync").unwrap(),state:synergy_node_core::ServiceState::Starting,
                health:synergy_node_core::ServiceHealth::Degraded{reason:"PUBLIC_TEST_PRIVATE_REASON_SENTINEL".into()},
                readiness:synergy_node_core::ServiceReadiness::Pending{reason:"PUBLIC_TEST_PRIVATE_REASON_SENTINEL".into()},
            },
            synergy_node_core::ServiceObservation {
                id:synergy_node_core::ServiceId::new("posy").unwrap(),state:synergy_node_core::ServiceState::Registered,
                health:synergy_node_core::ServiceHealth::Unhealthy{reason:"PUBLIC_TEST_PRIVATE_REASON_SENTINEL".into()},
                readiness:synergy_node_core::ServiceReadiness::Blocked{reason:"PUBLIC_TEST_PRIVATE_REASON_SENTINEL".into()},
            },
            synergy_node_core::ServiceObservation {
                id:synergy_node_core::ServiceId::new("etdag").unwrap(),state:synergy_node_core::ServiceState::Running,
                health:synergy_node_core::ServiceHealth::Healthy,readiness:synergy_node_core::ServiceReadiness::Ready,
            },
        ],
    }))
}
fn capacity() -> R1ReadCapacity {
    R1ReadCapacity {
        request_timeout: Duration::from_secs(20),
        maximum_hashes: 10_000_000,
        maximum_response_bytes: 1024 * 1024,
        public_quota_bytes: 192 * 1024 * 1024,
        protected_world_headroom_bytes: 64 * 1024 * 1024,
    }
}
fn params(genesis: &VerifiedR1Genesis, args: Value) -> Value {
    json!({"api_version":1,"request_id":"public-synthetic-read-only","caller_scope":"public_read",
        "network":coordinate(genesis.coordinate()),"args":args})
}

fn native_server(provider: &Arc<CanonicalR1QueryStore>) -> synergy_rpc::server::RpcServer<super::super::RuntimeDispatcher, ManagedReadAuthenticator> {
    synergy_rpc::server::RpcServer::new(
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
    .unwrap()
}

#[test]
fn actual_private_genesis_context_drives_all_registered_typed_read_adapters() {
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
    let mut block = StoredBlockRead {
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
    let receipt = synergy_state::r1_receipts::R1ReceiptCore {
        transaction: synergy_address::r1_public::TransactionIdentifierPresentation::parse(&tx_id)
            .unwrap(),
        sequence_index: 0,
        result: tx.status,
        gas_used: tx.gas_used,
        paid_nwei: tx.fee_paid_nwei,
        refunded_nwei: 123,
        events_commitment: tx.events_commitment,
        permitted_return_commitment: [77; 48],
        error_code: tx.error_code.clone(),
        operation_outcome: vec![9, 8, 7],
    };
    block.receipts_root = synergy_state::r1_receipts::receipts_root(&[receipt.clone()]).unwrap();
    synergy_state::r1_finalized::publish_nonproduction_projection_with_receipts(
        &temp.0,
        &block,
        state,
        &[tx.clone()],
        &[receipt.clone()],
    )
    .unwrap();
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
    let budget = provider.world_budget.clone();
    let server = native_server(&provider);
    for method in r1_read::METHODS {
        let args = match *method {
            "synergy_getFinalizedProofPageV1"=>json!({"kind":"finality","height":"0","offset":"0","limit":"65536"}),
            "synergy_getAccount"
            | "synergy_getProof"
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
            | "synergy_getBlockReceipts"
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
        assert!(budget.used() >= synergy_rpc::current_batch::response_ceiling(method).unwrap() * 3);
        let outer: Value = serde_json::from_slice(&wire).unwrap();
        assert!(outer.get("error").is_none(), "{method}: {outer}");
        assert_eq!(outer["id"], "public-synthetic-read-only");
        // Opt-in ephemeral cross-language qualification: only this test's
        // asserted public synthetic network, never a production endpoint/key.
        if std::env::var_os("SYNERGY_R1_PUBLIC_CONSUMER_FIXTURE").as_deref()
            == Some(std::ffi::OsStr::new("1"))

        {
            let mut consumer_profiles=json!({"block_profile":profile(genesis.block_profile()),"state_profile":profile(genesis.state_profile())});
            if *method=="synergy_getFinalizedProofPageV1" {
                use synergy_genesis::r1::profiles::ProfileKind;
                for (key,kind) in [("finality_profile",ProfileKind::PoSyFinality),("codec_profile",ProfileKind::PoSyCodec)] {
                    let definition=genesis.compiled().catalog().definitions().iter().find(|d|d.kind==kind).unwrap();
                    consumer_profiles[key]=json!({"name":definition.kind.name(),"revision":definition.kind.revision()});
                }
            }
            println!(
                "R1_PUBLIC_READ_FIXTURE {}",
                json!({
                    "purpose":"PUBLIC_SYNTHETIC_CONSUMER_QUALIFICATION_ONLY","production_import_permitted":false,
                    "request":serde_json::from_slice::<Value>(&body).unwrap(),"response":outer,
                    "expected_profiles":consumer_profiles,
                })
            );
        }
        drop(wire);
        drop(permit);
        let response = &outer["result"];
        assert_eq!(response["request_id"], "public-synthetic-read-only");
        assert_eq!(response["network"], coordinate(genesis.coordinate()));
        assert_eq!(response["finality_verified_by_rpc"], false);
        assert_ne!(response["result"], Value::Null, "{method}");
        assert_eq!(budget.used(), 0, "snapshot permit leaked by {method}");
        match *method {
            "synergy_getFinalizedProofPageV1"=>{
                assert_eq!(BASE64.decode(response["result"]["page"]["value"].as_str().unwrap()).unwrap(),block.public_finality_proof);
                assert_eq!(response["result"]["next_offset"],Value::Null);
                assert_eq!(response["result"]["proof_profile"]["name"],"POSY-FINALITY-R1");
                assert_eq!(response["result"]["codec_profile"]["name"],"POSY-CODEC-1");
                assert_eq!(response["result"]["source"],"ORIGINAL_STORED_BYTES_NOT_VERIFIED_BY_RPC");
            }
            "synergy_getProof" => {
                assert_eq!(response["result"]["identity"], identity);
                let leaves = response["result"]["leaves"].as_array().unwrap();
                assert_eq!(leaves.len(), 3);
                for leaf in leaves {
                    let domain = match leaf["domain"].as_str().unwrap() {
                        "native_balance" => synergy_state::r1::R1StateDomain::NativeBalance,
                        "replay_coordinate" => synergy_state::r1::R1StateDomain::ReplayCoordinate,
                        "account_authorization" => {
                            synergy_state::r1::R1StateDomain::AccountAuthorization
                        }
                        _ => panic!("unexpected domain"),
                    };
                    let key = synergy_state::r1::R1StateKey::native(domain, &identity).unwrap();
                    assert_eq!(
                        BASE64
                            .decode(leaf["key"]["value"].as_str().unwrap())
                            .unwrap(),
                        key.canonical_bytes().unwrap()
                    );
                    let value = state.get(&key).unwrap();
                    assert_eq!(
                        BASE64
                            .decode(leaf["value"]["value"].as_str().unwrap())
                            .unwrap(),
                        value.canonical_bytes().unwrap()
                    );
                    let proof = synergy_state::r1_smt::R1PointProof {
                        bitmap: bytes(leaf["proof"]["bitmap"].as_str().unwrap())
                            .try_into()
                            .unwrap(),
                        siblings: leaf["proof"]["siblings"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|s| bytes(s.as_str().unwrap()).try_into().unwrap())
                            .collect(),
                    };
                    synergy_state::r1_smt::verify(
                        genesis.initial_state_root(),
                        &key,
                        Some(value),
                        &proof,
                    )
                    .unwrap();
                }
            }
            "synergy_getBlockReceipts" => {
                let cores = response["result"]["canonical_receipt_cores"]
                    .as_array()
                    .unwrap();
                assert_eq!(cores.len(), 1);
                let encoded = BASE64.decode(cores[0]["value"].as_str().unwrap()).unwrap();
                assert_eq!(encoded, receipt.canonical_bytes().unwrap());
                let original =
                    synergy_state::r1_receipts::R1ReceiptCore::decode_canonical(&encoded).unwrap();
                assert_eq!(original.refunded_nwei, 123);
                assert_eq!(original.permitted_return_commitment, [77; 48]);
                assert_eq!(original.operation_outcome, vec![9, 8, 7]);
                assert_eq!(
                    synergy_state::r1_receipts::receipts_root(&[original]).unwrap(),
                    block.receipts_root
                );
                assert_eq!(
                    response["result"]["block"]["receipts_commitment"]["value"],
                    hex(&block.receipts_root)
                );
            }
            "synergy_getHealth" | "synergy_getHealthCheck" | "synergy_getReadiness"
            | "synergy_getNodeStatus" | "synergy_nodeInfo" => {
                assert_eq!(response["proof_profile_status"], "NOT_APPLICABLE_RUNTIME_OBSERVATION");
                assert_eq!(response["result"]["ready"], false);
                assert_eq!(response["result"]["services"][0]["health"], "degraded");
                assert_eq!(response["result"]["services"][0]["readiness"], "pending");
                assert_eq!(response["result"]["services"][1]["health"], "unhealthy");
                assert_eq!(response["result"]["services"][1]["readiness"], "blocked");
                assert!(!response.to_string().contains("PUBLIC_TEST_PRIVATE_REASON_SENTINEL"));
            }
            "synergy_ping" => {
                assert_eq!(response["result"], json!({"scope":"RPC_LIVENESS_ONLY","responding":true}));
            }
            "synergy_systemVersion"=>{
                assert_eq!(response["result"],json!({"node":env!("CARGO_PKG_VERSION"),"rpc":"1"}));
                assert_eq!(response["proof_profile_status"],"NOT_APPLICABLE_RUNTIME_OBSERVATION");
            }
            "synergy_nodeStatus"|"synergy_chainStatus"=>{
                assert_eq!(response["result"]["chain_id"],(u64::MAX-1).to_string());
                assert_eq!(response["result"]["lifecycle"],"starting");assert_eq!(response["result"]["ready"],false);
                assert!(response["result"].get("services").is_none());
            }
            "synergy_syncStatus"|"synergy_posyStatus"|"synergy_etdagStatus"=>{
                let(id,health,readiness)=match *method {"synergy_syncStatus"=>("sync","degraded","pending"),
                    "synergy_posyStatus"=>("posy","unhealthy","blocked"),_=>("etdag","healthy","ready")};
                assert_eq!(response["result"]["id"],id);assert_eq!(response["result"]["health"],health);
                assert_eq!(response["result"]["readiness"],readiness);
                assert!(!response.to_string().contains("PUBLIC_TEST_PRIVATE_REASON_SENTINEL"));
            }
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
    // Reassemble every original byte through the actual registered RpcServer;
    // a checksum detects page mix-up but supplies no PoSy verification authority.
    let mut assembled=Vec::new(); let mut offset=0usize;
    let mut digest=Value::Null; let total=block.public_finality_proof.len().to_string();
    loop {
        let args=if offset==0 {json!({"kind":"finality","height":"0","offset":"0","limit":"7"})}
            else {json!({"kind":"finality","block_commitment":commitment(genesis.block_profile(),&block.anchor.block_digest),
                "offset":offset.to_string(),"limit":"7","expected_total_bytes":total,"expected_transport_digest":digest})};
        let body=serde_json::to_vec(&json!({"jsonrpc":"2.0","id":"page","method":"synergy_getFinalizedProofPageV1","params":params(&genesis,args.clone())})).unwrap();
        let output=server.handle_bytes_reserved("public-page-client",None,0,&body);
        let (wire,guard)=output.into_parts();
        let page:Value=serde_json::from_slice(&wire).unwrap();
        assert!(page.get("error").is_none(),"{page}");
        assert_eq!(page["result"]["finality_verified_by_rpc"],false);
        let result=&page["result"]["result"];
        assembled.extend(BASE64.decode(result["page"]["value"].as_str().unwrap()).unwrap());
        digest=result["transport_digest"].clone();
        let next=result["next_offset"].as_str().map(|s|s.parse::<usize>().unwrap());
        drop(wire); drop(guard); assert_eq!(budget.used(),0);
        if let Some(next)=next {offset=next;} else {break;}
    }
    assert_eq!(assembled,block.public_finality_proof);
    let bound=json!({"kind":"finality","block_commitment":commitment(genesis.block_profile(),&block.anchor.block_digest),
        "offset":"7","limit":"7","expected_total_bytes":total,"expected_transport_digest":digest});
    for (field,bad) in [("expected_total_bytes",json!("999")),("expected_transport_digest",json!({"algorithm":"SHA3-384","encoding":"lowercase-hex","value":"00".repeat(48)})),
        ("offset",json!(total)),("limit",json!("65537")),("kind",json!("world_state"))] {
        let mut args=bound.clone();args[field]=bad;
        assert_eq!(provider.r1_read("synergy_getFinalizedProofPageV1",params(&genesis,args)).unwrap_err().code,-32602);
    }
    let mut wrong=params(&genesis,bound.clone()); wrong["network"]["network_incarnation_commitment"]["value"]=json!("00".repeat(64));
    assert_eq!(provider.r1_read("synergy_getFinalizedProofPageV1",wrong).unwrap_err().code,-32010);
    assert!(provider.r1_read("synergy_getFinalizedProofPageV1",params(&genesis,json!({"kind":"finality","height":"1","offset":"0","limit":"7"}))).is_err());
    let absent_temp=Temp::new();let mut absent_block=block.clone();absent_block.public_finality_proof.clear();
    synergy_state::r1_finalized::publish_nonproduction_projection_with_receipts(&absent_temp.0,&absent_block,state,&[tx.clone()],&[receipt.clone()]).unwrap();
    let absent_provider=Arc::new(CanonicalR1QueryStore::open(absent_temp.0.clone(),Arc::clone(&genesis),runtime(u64::MAX-1),WorldResourceBudget::new(256*1024*1024),capacity()).unwrap());
    let absent_server=native_server(&absent_provider);
    let body=serde_json::to_vec(&json!({"jsonrpc":"2.0","id":"missing-proof","method":"synergy_getFinalizedProofPageV1", "params":params(&genesis,json!({"kind":"finality","height":"0","offset":"0","limit":"7"}))})).unwrap();
    let (wire,guard)=absent_server.handle_bytes_reserved("public-absent-proof-client",None,0,&body).into_parts();
    let unavailable:Value=serde_json::from_slice(&wire).unwrap();assert_eq!(unavailable["error"]["code"],-32000);
    assert!(unavailable.get("result").is_none());drop(wire);drop(guard);
    assert_eq!(absent_provider.world_budget.used(),0);
    let permit = provider.reserve_response_capacity().unwrap().unwrap();
    assert!(budget.used() >= 24 * 1024 * 1024);
    drop(permit);
    assert_eq!(budget.used(), 0);
    assert!(
        provider.latest_finalized_height().is_err(),
        "no historical fallback"
    );
    for namespace in ["synq", "syns"] {
        let absent =
            synergy_address::r1_public::NativeIdentityPresentation::from_raw(namespace, [42; 48])
                .unwrap();
        let read = provider
            .r1_read(
                "synergy_getProof",
                params(&genesis, json!({"address":absent.to_text()})),
            )
            .unwrap();
        let leaves = read["result"]["leaves"].as_array().unwrap();
        assert_eq!(leaves.len(), if namespace == "synq" { 2 } else { 3 });
        assert!(leaves.iter().all(|leaf| leaf["value"].is_null()));
    }
    assert!(
        provider
            .r1_read(
                "synergy_getProof",
                params(&genesis, json!({"address":identity,"at_height":"1"}))
            )
            .is_err(),
        "missing historical proof is unavailable, never nonmembership"
    );
    assert!(
        provider
            .r1_read(
                "synergy_getBlockReceipts",
                params(&genesis, json!({"height":"1"}))
            )
            .is_err(),
        "missing original receipt evidence is unavailable, never an empty list"
    );
    let by_hash=provider.r1_read("synergy_getBlockReceipts",params(&genesis,json!({"block_commitment":commitment(genesis.block_profile(),&block.anchor.block_digest)}))).unwrap();
    assert_eq!(
        by_hash["result"]["canonical_receipt_cores"][0]["value"],
        BASE64.encode(receipt.canonical_bytes().unwrap())
    );
    let compact = Temp::new();
    publish_nonproduction_projection(&compact.0, &block, state, &[tx]).unwrap();
    let unavailable = CanonicalR1QueryStore::open(
        compact.0.clone(),
        Arc::clone(&genesis),
        runtime(u64::MAX - 1),
        WorldResourceBudget::new(256 * 1024 * 1024),
        capacity(),
    )
    .unwrap();
    assert!(
        unavailable
            .r1_read(
                "synergy_getBlockReceipts",
                params(&genesis, json!({"height":"0"}))
            )
            .is_err(),
        "compact receipt cannot invent original fields"
    );
    let larger = provider
        .reserve_response_capacity_for("synergy_getBlockReceipts")
        .unwrap()
        .unwrap();
    assert!(budget.used() >= 48 * 1024 * 1024);
    drop(larger);
    assert_eq!(budget.used(), 0);
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
    for limits in [R1ReadCapacity{public_quota_bytes:0,..capacity()},
        R1ReadCapacity{protected_world_headroom_bytes:0,..capacity()}] {
        assert!(CanonicalR1QueryStore::open(temp.0.clone(),genesis.clone(),runtime(u64::MAX-1),budget.clone(),limits).is_err());
        assert_eq!(budget.used(),0);assert!(!temp.0.exists());
    }
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
        R1ReadCapacity { public_quota_bytes:48*1024*1024, protected_world_headroom_bytes:16*1024*1024, ..capacity() },
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
    let wrong_profile = R1ProfileRef {
        name: "UNAPPROVED-BLOCK-PROFILE".into(),
        revision: 1,
    };
    assert_eq!(
        provider
            .r1_read(
                "synergy_getBlockReceipts",
                params(
                    &genesis,
                    json!({"block_commitment":commitment(&wrong_profile,&[0x5a;48])})
                )
            )
            .unwrap_err()
            .code,
        -32602,
        "selector profile must be checked before missing-store access"
    );
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
    provider.runtime.write().unwrap().services.clear();
    for method in ["synergy_syncStatus","synergy_posyStatus","synergy_etdagStatus"] {
        assert_eq!(provider.r1_read(method,params(&genesis,json!({}))).unwrap_err().code,-32000);
    }

}

#[test]
fn actual_shared_native_pool_prepares_current_batches_and_retains_all_delivery_guards() {
    let genesis = verified_genesis();
    let temp = Temp::new();
    let parent_budget = WorldResourceBudget::new(256 * 1024 * 1024);
    let provider = Arc::new(CanonicalR1QueryStore::open(temp.0.clone(),genesis.clone(),
        runtime(u64::MAX-1),parent_budget.clone(),capacity()).unwrap());
    let budget=provider.world_budget.clone();
    assert_eq!(parent_budget.used(),capacity().public_quota_bytes);
    let mandatory=parent_budget.reserve(capacity().protected_world_headroom_bytes).unwrap();
    let server = native_server(&provider);
    let calls = (0..32).map(|index| {
        let id=format!("public-synthetic-batch-{index}");
        let mut parameters=params(&genesis,json!({}));parameters["request_id"]=json!(id);
        json!({"jsonrpc":"2.0","id":id,"method":if index%2==0{"synergy_ping"}else{"synergy_chainId"},"params":parameters})
    }).collect::<Vec<_>>();
    let body=serde_json::to_vec(&calls).unwrap();
    let output=server.handle_current_read_document_reserved("public-synthetic-batch-client",None,0,&body,
        genesis.coordinate(),synergy_protocol_types::r1_rpc_response::MAX_TOTAL_BYTES).unwrap();
    let (bytes,guard)=output.into_parts();
    let responses:Value=serde_json::from_slice(&bytes).unwrap();
    assert_eq!(responses.as_array().unwrap().len(),32);
    for(index,response)in responses.as_array().unwrap().iter().enumerate(){
        assert_eq!(response["id"],calls[index]["id"]);
        assert_eq!(response["result"]["network"],coordinate(genesis.coordinate()));
        assert_eq!(response["result"]["finality_verified_by_rpc"],false);
        assert!(response.get("error").is_none());
    }
    assert_eq!(guard.as_ref().unwrap().maximum_encoded_bytes(),32*4096+33);
    assert!(budget.used()>1024*1024,"actual input/whole/method leases must remain charged");
    assert!(!temp.0.exists(),"metadata batch cannot create chain storage");
    drop(bytes);assert!(budget.used()>0);drop(guard);assert_eq!(budget.used(),0);
    // Actual native HTTP prepare/queue/write owner uses this same current batch
    // entry, expected private context and pool, without starting any service.
    let listener=std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client=std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let(stream,_)=listener.accept().unwrap();stream.set_nonblocking(true).unwrap();
    let service=super::super::RpcService {
        listen_address:listener.local_addr().unwrap(),limits:synergy_rpc::middleware::RpcLimits {
            max_body_bytes:65536,max_concurrent_requests:8,request_timeout_ms:5000 },
        runtime:provider.runtime.clone(),query_store:provider.clone(),
        websocket_hub:Arc::new(super::super::WsServer::new(16,16,1024*1024).unwrap()),
        admission:None,preparation:None,network_identity:None,websocket_connections:vec![],pending_http:vec![],
        next_websocket_id:0,listener:None,reserved_listener:None,server:Some(native_server(&provider)),
    };
    let mut http=format!("POST /rpc HTTP/1.1\r\nContent-Length: {}\r\n\r\n",body.len()).into_bytes();
    http.extend_from_slice(&body);
    let mut pending=super::super::PendingHttp { stream,client_id:"public-synthetic-http-batch".into(),
        deadline:Instant::now()+Duration::from_secs(5),bytes:http,response:None,response_capacity:None,
        offset:0,upgrade:None,#[cfg(feature="qualification-timing")]diagnostic_request:None };
    let prepared=service.prepare_http_response_with_budget(&mut pending,256*1024).unwrap().unwrap();
    assert!(prepared.starts_with(b"HTTP/1.1 200"));assert!(pending.response_capacity.is_some());
    assert!(budget.used()>0);pending.response=Some(prepared);
    assert!(service.poll_http_connection(&mut pending,65536,256*1024).unwrap());
    assert!(budget.used()>0,"actual final write retains guard until queue removal");
    drop(pending);assert_eq!(budget.used(),0);
    let mut delivered=Vec::new();std::io::Read::read_to_end(&mut client,&mut delivered).unwrap();
    let split=delivered.windows(4).position(|b|b==b"\r\n\r\n").unwrap()+4;
    let delivered:Value=serde_json::from_slice(&delivered[split..]).unwrap();
    assert_eq!(delivered.as_array().unwrap().len(),32);
    for(index,item)in delivered.as_array().unwrap().iter().enumerate(){assert_eq!(item["id"],calls[index]["id"]);}
    drop(service);
    assert_eq!(parent_budget.used(),parent_budget.limit());
    drop(mandatory);assert_eq!(parent_budget.available(),capacity().protected_world_headroom_bytes);

    let selected=provider.reserve_response_capacity_for("synergy_getBlockReceipts").unwrap().unwrap();
    assert_eq!(selected.maximum_encoded_bytes(),capacity().maximum_response_bytes,
        "source scratch floor must not silently lift the configured encoded limit");
    drop(selected);assert_eq!(budget.used(),0);
    let mut bad_profile=params(&genesis,json!({"block_commitment":commitment(&R1ProfileRef{name:"UNAPPROVED-BLOCK-PROFILE".into(),revision:1},&[0x5a;48])}));
    bad_profile["request_id"]=json!("public-synthetic-bad-profile");
    let mixed=serde_json::to_vec(&json!([calls[0],{"jsonrpc":"2.0","id":"bad-profile","method":"synergy_getBlockByHash","params":bad_profile}])).unwrap();
    let rejected=native_server(&provider);
    assert_eq!(rejected.handle_current_read_document_reserved("public-synthetic-profile-refusal",None,0,&mixed,
        genesis.coordinate(),64*1024*1024).err().unwrap().code,-32602);
    assert_eq!(rejected.metrics().unwrap().total_requests,0);
    let mut forged=genesis.coordinate().clone();forged.network.nic[0]^=1;
    let mut forged_request=calls[0].clone();forged_request["params"]["network"]=coordinate(&forged);
    assert_eq!(rejected.handle_current_read_document_reserved("public-synthetic-context-refusal",None,0,
        &serde_json::to_vec(&forged_request).unwrap(),&forged,64*1024*1024).err().unwrap().code,-32010);
    assert_eq!(rejected.metrics().unwrap().total_requests,0);assert_eq!(budget.used(),0);
    let too_large=native_server(&provider).handle_current_read_document_reserved("public-synthetic-refusal",None,0,&body,
        genesis.coordinate(),1024);
    assert!(too_large.is_err());assert_eq!(budget.used(),0);
    assert!(!temp.0.exists());
    let small_budget=WorldResourceBudget::new(4*1024*1024);
    let constrained=Arc::new(CanonicalR1QueryStore::open(temp.0.clone(),genesis.clone(),runtime(u64::MAX-1),
        small_budget.clone(),R1ReadCapacity{public_quota_bytes:2*1024*1024,protected_world_headroom_bytes:1024*1024,..capacity()}).unwrap());
    let large_call=serde_json::to_vec(&json!({"jsonrpc":"2.0","id":"public-only","method":"synergy_getBlockReceipts",
        "params":params(&genesis,json!({"height":"0"}))})).unwrap();
    assert!(native_server(&constrained).handle_current_read_document_reserved("public-synthetic-refusal",None,0,
        &large_call,genesis.coordinate(),64*1024*1024).is_err());
    assert_eq!(constrained.world_budget.used(),0);
    assert_eq!(small_budget.used(),2*1024*1024);drop(constrained);assert_eq!(small_budget.used(),0);
    assert!(!temp.0.exists());
    drop(rejected);drop(server);drop(provider);drop(budget);assert_eq!(parent_budget.used(),0);
}

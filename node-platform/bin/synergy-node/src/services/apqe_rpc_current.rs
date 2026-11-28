//! Stateless current native-read policy layered on the common carrier parser.
//! Caller authenticates/confirms the context before and after actual session I/O.
use super::*;
use synergy_address_engine::apqe::current_session::{
    CurrentSessionContext, SessionHop, SessionPurpose,
};
use synergy_protocol_types::{
    R1GenesisReference, R1NetworkCoordinate, R1NetworkRef, R1ProfileRef, R1ProfileSetReference,
};

pub(super) fn validate(bytes: &[u8], confirmed: &CurrentSessionContext) -> Result<(), String> {
    if confirmed.purpose != SessionPurpose::PublicRpc
        || !matches!(
            confirmed.hop,
            SessionHop::GatewayToSentry | SessionHop::SentryToValidator
        )
    {
        return Err("current RPC carrier requires the confirmed public RPC hop".into());
    }
    confirmed
        .canonical_bytes()
        .map_err(|_| "invalid current RPC session context")?;
    // PQ-VSESSION-01/2 explicitly pins these exact profile refs in its canonical
    // context. These are selected codec constants, not names inferred from width.
    let expected = R1NetworkCoordinate {
        network: R1NetworkRef {
            chain_id: confirmed.network.chain_id,
            nic: confirmed.network.nic,
        },
        genesis: R1GenesisReference {
            profile: R1ProfileRef {
                name: "SYNERGY-GENESIS-R1".into(),
                revision: 1,
            },
            digest: confirmed.genesis,
        },
        activated_profiles: R1ProfileSetReference {
            profile: R1ProfileRef {
                name: "APQE-PROFILE-SET".into(),
                revision: 1,
            },
            commitment: confirmed.activated_profiles,
        },
    };
    synergy_rpc::current_batch::validate_document(bytes, &expected)
        .map_err(|_| "current RPC read method, arguments or network context rejected".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_address::r1_public::NativeIdentityPresentation;
    use synergy_address_engine::apqe::current_session::{SessionEndpoint, TransportRole};

    // Context/data policy only; no fake crypto confirmation or live authority.
    fn context() -> CurrentSessionContext {
        CurrentSessionContext {
            network: synergy_address_engine::apqe::r1_framing::NetworkRef {
                chain_id: u64::MAX - 1,
                nic: [0x11; 64],
            },
            genesis: [0x22; 48],
            activated_profiles: [0x33; 64],
            registry_epoch: 1,
            registry_commitment: [0x44; 64],
            hop: SessionHop::GatewayToSentry,
            purpose: SessionPurpose::PublicRpc,
            initiator: SessionEndpoint {
                role: TransportRole::Gateway,
                node: NativeIdentityPresentation::from_raw("synv5", [0x55; 48])
                    .unwrap()
                    .to_text(),
                transport_key_id: "PUBLIC-SYNTHETIC-GATEWAY-KEY".into(),
                key_generation: 1,
            },
            responder: SessionEndpoint {
                role: TransportRole::Sentry,
                node: NativeIdentityPresentation::from_raw("synv1", [0x66; 48])
                    .unwrap()
                    .to_text(),
                transport_key_id: "PUBLIC-SYNTHETIC-SENTRY-KEY".into(),
                key_generation: 1,
            },
        }
    }
    fn request(method: &str, id: serde_json::Value) -> serde_json::Value {
        let address = NativeIdentityPresentation::from_raw("synw", [0xa5; 48])
            .unwrap()
            .to_text();
        let args = match method {
            "synergy_getBlockRange"=>json!({"from_height":"0","limit":"1"}),
            "synergy_getTransactionByBlockHashAndIndex"=>json!({"index":"0","block_commitment":{"profile":{"name":"POSY-BLOCK-R1","revision":1},"algorithm":"SHA3-384","encoding":"lowercase-hex","value":"44".repeat(48)}}),
            "synergy_getTransactionByBlockNumberAndIndex"=>json!({"height":"0","index":"0"}),
            "synergy_getFinalizedProofPageV1"=>json!({"kind":"finality","height":"0","offset":"0","limit":"65536"}),
            "synergy_getAccount"
            | "synergy_getProof"
            | "synergy_getBalance"
            | "synergy_getAccountNonce"
            | "synergy_getNonce" => json!({"address":address}),
            "synergy_getTransaction"
            | "synergy_getTransactionByHash"
            | "synergy_getTransactionReceipt"
            | "synergy_getReceipt"
            | "synergy_getTransactionStatus"
            | "synergy_getTransactionFees" => {
                json!({"transaction_id":format!("syntxn{}","A".repeat(64))})
            }
            "synergy_getBlockByHash" => {
                json!({"block_commitment":{"profile":{"name":"POSY-BLOCK-R1","revision":1},"algorithm":"SHA3-384","encoding":"lowercase-hex","value":"44".repeat(48)}})
            }
            "synergy_getBlock"
            | "synergy_getBlockReceipts"
            | "synergy_getBlockByNumber"
            | "synergy_getBlockTransactionCount"
            | "synergy_getTransactionsInBlock" => json!({"height":"0"}),
            _ => json!({}),
        };
        json!({"jsonrpc":"2.0","id":id,"method":method,"params":{"api_version":1,"request_id":"public-synthetic-read-only","caller_scope":"public_read",
            "network":{"chain_id":(u64::MAX-1).to_string(),"network_incarnation_commitment":{"algorithm":"SHA3-512","encoding":"lowercase-hex","value":"11".repeat(64)},
                "genesis_commitment":{"profile":{"name":"SYNERGY-GENESIS-R1","revision":1},"algorithm":"SHA3-384","encoding":"lowercase-hex","value":"22".repeat(48)},
                "activated_profiles":{"profile":{"name":"APQE-PROFILE-SET","revision":1},"algorithm":"SHA3-512","encoding":"lowercase-hex","value":"33".repeat(64)},
                "identity_profile":{"name":"APQE-NATIVE-ID","revision":1},"presentation_version":2},"args":args}})
    }
    fn bytes(v: &serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(v).unwrap()
    }
    #[test]
    fn exact_41_current_aliases_use_shared_typed_preflight_without_changing_legacy_access() {
        let c = context();
        let mut differs = false;
        for method in synergy_rpc::r1_read::METHODS {
            let raw = bytes(&request(method, json!(1)));
            validate(&raw, &c).unwrap_or_else(|e| panic!("{method}: {e}"));
            differs |= validate_public_carrier(&raw).is_err();
        }
        assert!(
            differs,
            "current-only aliases must not silently enter the legacy global allowlist"
        );
        for method in [
            "eth_chainId",
            "synergy_signTransaction",
            "synergy_getPeers",
            "synergy_getAccountAuthNonce",
            "synergy_getProof\n",
        ] {
            assert!(validate(&bytes(&request(method, json!(1))), &c).is_err());
        }
    }
    #[test]
    fn current_network_scope_selectors_and_duplicate_parameters_fail_closed() {
        let c = context();
        for part in [
            "chain_id",
            "network_incarnation_commitment",
            "genesis_commitment",
            "activated_profiles",
        ] {
            let mut v = request("synergy_getProof", json!(1));
            if part == "chain_id" {
                v["params"]["network"][part] = json!("9969");
            } else {
                v["params"]["network"][part]["value"] =
                    json!("00".repeat(if part == "genesis_commitment" { 48 } else { 64 }));
            }
            assert!(validate(&bytes(&v), &c).is_err());
        }
        for method in ["synergy_getBlockByHash", "synergy_getBlockByNumber"] {
            let mut v = request(method, json!(1));
            v["params"]["args"] = if method.ends_with("ByHash") {
                json!({"height":"0"})
            } else {
                request("synergy_getBlockByHash", json!(1))["params"]["args"].clone()
            };
            assert!(validate(&bytes(&v), &c).is_err());
        }
        let raw = String::from_utf8(bytes(&request("synergy_ping", json!(1))))
            .unwrap()
            .replace(
                "\"caller_scope\":\"public_read\"",
                "\"caller_scope\":\"public_read\",\"caller_scope\":\"PUBLIC_TEST_SENTINEL\"",
            );
        let error = validate(raw.as_bytes(), &c).unwrap_err();
        assert!(!error.contains("PUBLIC_TEST_SENTINEL"));
        let mut v = request("synergy_getProof", json!(1));
        v["params"]["private_key"] = json!("PUBLIC_TEST_SENTINEL");
        assert!(validate(&bytes(&v), &c).is_err());
    }
    #[test]
    fn current_batches_share_legacy_exact_count_id_and_body_bounds() {
        let c = context();
        let a = request("synergy_getProof", json!("one"));
        let b = request("synergy_getBlockReceipts", json!(2));
        validate(&bytes(&json!([a, b])), &c).unwrap();
        for ids in [[json!("same"), json!("same")], [json!(1), json!(1)]] {
            assert!(validate(
                &bytes(&json!([
                    request("synergy_ping", ids[0].clone()),
                    request("synergy_ping", ids[1].clone())
                ])),
                &c
            )
            .is_err());
        }
        assert!(validate(b"[]", &c).is_err());
        let tuple = json!([[
            "2.0",
            "synergy_ping",
            "synergy_signTransaction",
            request("synergy_ping", json!(1))["params"].clone()
        ]]);
        assert!(
            validate(&bytes(&tuple), &c).is_err(),
            "positional envelope cannot change method meaning across parsers"
        );
        let oversized = (0..33)
            .map(|id| request("synergy_ping", json!(id)))
            .collect::<Vec<_>>();
        assert!(validate(&bytes(&json!(oversized)), &c).is_err());
        for id in [
            serde_json::Value::Null,
            json!(true),
            json!({}),
            json!("x".repeat(257)),
        ] {
            assert!(validate(&bytes(&request("synergy_ping", id)), &c).is_err());
        }
        assert!(validate(&vec![b' '; MAX_BODY + 1], &c).is_err());
    }
    #[test]
    fn carrier_is_public_rpc_hop_data_only_and_never_accepts_peer_relay_scope() {
        let raw = bytes(&request("synergy_ping", json!(1)));
        let mut c = context();
        c.purpose = SessionPurpose::PeerRelay;
        assert!(validate(&raw, &c).is_err());
        let mut c = context();
        c.hop = SessionHop::ValidatorToValidator;
        assert!(validate(&raw, &c).is_err());
        let mut c = context();
        c.responder.role = TransportRole::Gateway;
        assert!(validate(&raw, &c).is_err());
        let mut c = context();
        c.initiator.role = TransportRole::Sentry;
        c.initiator.node = NativeIdentityPresentation::from_raw("synv1", [0x55; 48])
            .unwrap()
            .to_text();
        c.responder.role = TransportRole::Validator;
        c.hop = SessionHop::SentryToValidator;
        validate(&raw, &c).unwrap();
    }
}

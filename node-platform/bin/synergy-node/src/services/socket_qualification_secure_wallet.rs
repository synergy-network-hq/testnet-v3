//! Verify that five independently running native owners keep the exact signed
//! Wallet release pending until the certified first autonomous epoch closes.
use super::*;
use synergy_etdag::admission::PW13_SPONSOR_CANDIDATE_PROFILE_ID;
use synergy_rpc::methods::{EPOCH_TRANSITION_PROOF_V1, PROCESSING_CONTEXT_V1};

pub(super) fn qualify_pending(configs: &[NodeConfiguration]) {
    assert_eq!(configs.len(), 5);
    // Each normal child verifies the release against its own executable. The
    // harness uses independently signed Genesis to compare their public scope.
    let genesis = crate::commands::selected_network::verified_genesis(&configs[0]).unwrap();
    let network = &genesis.unsigned.network;
    assert_eq!(
        network.autonomous_epoch_protocol.as_deref(),
        Some(synergy_genesis::network::AUTONOMOUS_EPOCH_PROTOCOL_V1)
    );
    let addresses: Vec<_> = configs
        .iter()
        .map(|config| config.rpc.listen_address.unwrap())
        .collect();
    let deadline = Instant::now() + Duration::from_secs(180);
    let finalized = loop {
        let observations = addresses
            .iter()
            .map(|&address| {
                process_rpc(
                    address,
                    "synergy_chainTelemetry",
                    serde_json::json!({"at_height":1}),
                )
                .map(|value| value["common_finalized_commitment"].clone())
            })
            .collect::<Result<Vec<_>, _>>();
        if let Ok(observations) = &observations {
            if !observations[0].is_null()
                && observations.iter().all(|value| value == &observations[0])
            {
                break observations[0].clone();
            }
        }
        assert!(
            Instant::now() < deadline,
            "managed release E1 failed to finalize the first common block: {observations:?}"
        );
        std::thread::sleep(Duration::from_secs(1));
    };
    assert_eq!(finalized["height"], 1);
    for address in addresses {
        let ordinary = process_rpc(address, PROCESSING_CONTEXT_V1, serde_json::json!({})).unwrap();
        assert_eq!(ordinary["profile_id"], synergy_etdag::PROCESSING_PROFILE_ID);
        assert_eq!(ordinary["context"]["authority"]["epoch"], 1);
        assert_eq!(
            ordinary["context"]["authority"]["chain_id"],
            network.chain_id
        );
        assert_eq!(
            ordinary["context"]["authority"]["network_id"],
            network.network_id
        );
        assert!(ordinary["wallet_dispatch_policy"].is_null());
        let protected = process_rpc(
            address,
            PROCESSING_CONTEXT_V1,
            serde_json::json!({"profile_id":PW13_SPONSOR_CANDIDATE_PROFILE_ID}),
        );
        assert!(
            protected.is_err(),
            "E1 exposed unactivated protected source: {protected:?}"
        );
        assert!(process_rpc(
            address,
            EPOCH_TRANSITION_PROOF_V1,
            serde_json::json!({"epoch":2})
        )
        .unwrap()
        .is_null());
    }
    eprintln!("five actual native processes verified the signed pending release and finalized E1 H1 with protected admission closed");
}

//! Actual process replacement using the same custody, durable history and journal.
use super::*;
use std::process::{Child, Command};
use synergy_transaction::SignedTransaction;

fn account_effects(
    config: &NodeConfiguration,
    height: u64,
    transaction: &SignedTransaction,
) -> Result<serde_json::Value, String> {
    let address = config
        .rpc
        .listen_address
        .ok_or("restart RPC address missing")?;
    let mut effects = Vec::new();
    for account in [&transaction.unsigned.sender, &transaction.unsigned.receiver] {
        let value = process_rpc(
            address,
            "synergy_getAccount",
            serde_json::json!({
                "address":account,"at_height":height
            }),
        )?;
        if !value["nonce"].is_u64() || !value["balance_nwei"].is_string() {
            return Err("restart account observation lacks nonce/balance".into());
        }
        effects.push(serde_json::json!({
            "address":account,"nonce":value["nonce"],"balance_nwei":value["balance_nwei"]
        }));
    }
    Ok(serde_json::Value::Array(effects))
}

pub(super) fn qualify_restart(
    binary: &Path,
    children: &mut [Child],
    configs: &[NodeConfiguration],
    prior_height: u64,
    transaction: &SignedTransaction,
) {
    assert_eq!(children.len(), 5);
    assert_eq!(configs.len(), 5);
    let baseline = account_effects(&configs[0], prior_height, transaction).unwrap();
    assert_eq!(
        baseline[0]["nonce"], 1,
        "restart begins after one execution"
    );
    assert_eq!(
        baseline[1]["balance_nwei"],
        transaction.unsigned.amount_nwei.to_string()
    );
    for config in configs {
        assert_eq!(
            account_effects(config, prior_height, transaction).unwrap(),
            baseline
        );
    }
    let restarted = 4;
    let old_pid = children[restarted].id();
    let node_dir = configs[restarted]
        .apqe_transport
        .as_ref()
        .unwrap()
        .enrollment_path
        .parent()
        .unwrap();
    let config_path = node_dir.join("config.json");
    assert!(config_path.is_file());
    let output = fs::OpenOptions::new()
        .append(true)
        .open(node_dir.join("process.log"))
        .unwrap();
    let started = Instant::now();
    let deadline = started + Duration::from_secs(180);
    children[restarted].kill().unwrap();
    children[restarted].wait().unwrap();
    children[restarted] = Command::new(binary)
        .args(["start", "--config"])
        .arg(config_path)
        .stdout(output.try_clone().unwrap())
        .stderr(output)
        .spawn()
        .unwrap();
    let new_pid = children[restarted].id();
    assert_ne!(old_pid, new_pid, "recovery must use a replacement process");
    loop {
        for (index, child) in children.iter_mut().enumerate() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "node {index} exited during restart recovery"
            );
        }
        let observation = (|| -> Result<Option<(u64, serde_json::Value)>, String> {
            let mut telemetry = Vec::new();
            for config in configs {
                telemetry.push(process_rpc(
                    config.rpc.listen_address.unwrap(),
                    "synergy_chainTelemetry",
                    serde_json::json!({}),
                )?);
            }
            if telemetry.iter().any(|v| {
                v["transport"]["apqe_session_count"].as_u64() != Some(4)
                    || v["transport"]["authenticated_peer_count"].as_u64() != Some(4)
            }) {
                return Ok(None);
            }
            let height = telemetry
                .iter()
                .map(|v| v["finalized_height"].as_u64().unwrap_or(0))
                .min()
                .unwrap();
            if height <= prior_height {
                return Ok(None);
            }
            let mut commitment = None;
            for config in configs {
                let at = process_rpc(
                    config.rpc.listen_address.unwrap(),
                    "synergy_chainTelemetry",
                    serde_json::json!({"at_height":height}),
                )?;
                let current = &at["common_finalized_commitment"];
                if current.is_null() {
                    return Ok(None);
                }
                if let Some(expected) = &commitment {
                    assert_eq!(
                        current, expected,
                        "restart produced conflicting finalized state at height {height}"
                    );
                } else {
                    commitment = Some(current.clone());
                }
                assert_eq!(
                    account_effects(config, height, transaction)?,
                    baseline,
                    "restart changed already-finalized transaction effects at height {height}"
                );
            }
            Ok(Some((height, commitment.unwrap())))
        })();
        if let Ok(Some((height, commitment))) = &observation {
            eprintln!("APQE actual five-process restart PASS old_pid={old_pid} new_pid={new_pid} height={height} commitment={commitment} elapsed={:?}", started.elapsed());
            return;
        }
        assert!(Instant::now() < deadline, "actual restart recovery deadline: old_pid={old_pid} new_pid={new_pid} prior_height={prior_height} last={observation:?}");
        std::thread::sleep(Duration::from_millis(1000));
    }
}

use std::process::Command;
use synergy_transaction::{FeeLimit, NetworkBinding, TransactionClass, UnsignedTransaction};

#[test]
fn python_tps_transcript_matches_native_selected_chain() {
    let harness = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/validator/run-posy-tps-baseline.py");
    let script = r#"
import importlib.util, sys
spec = importlib.util.spec_from_file_location('native_transcript_test', sys.argv[1])
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
args = ('selected-network', sys.argv[2], sys.argv[3], 7, 2, 21000, 3, 1700000000)
chain = int(sys.argv[4])
print(h.canonical_unsigned_signing_bytes(*args, chain_id=chain).hex())
print(h.transaction_id(*args, chain_id=chain))
"#;
    let mut tx = UnsignedTransaction {
        network: NetworkBinding::new(9001, "selected-network").unwrap(),
        class: TransactionClass::User,
        sender: synergy_address::derive_object_address("synq", b"tps-domain-sender").unwrap(),
        receiver: synergy_address::derive_object_address("synq", b"tps-domain-receiver").unwrap(),
        amount_nwei: 7,
        nonce: 2,
        fee_limit: FeeLimit {
            gas_limit: 21000,
            max_fee_per_gas_nwei: 3,
        },
        timestamp_unix: 1_700_000_000,
        payload: vec![],
    };
    let mut ids = Vec::new();
    for chain_id in [9001, 9002, 1266, u64::MAX] {
        tx.network.chain_id = chain_id;
        let result = Command::new("python3")
            .arg("-c")
            .arg(script)
            .arg(&harness)
            .arg(&tx.sender)
            .arg(&tx.receiver)
            .arg(chain_id.to_string())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let output = String::from_utf8(result.stdout).unwrap();
        let mut lines = output.lines();
        let bytes: String = tx
            .signing_bytes()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(lines.next(), Some(bytes.as_str()));
        let id = tx.id().unwrap().0;
        assert_eq!(lines.next(), Some(id.as_str()));
        assert!(lines.next().is_none());
        assert!(
            !ids.contains(&id),
            "different chain domains must have distinct IDs"
        );
        ids.push(id);
    }
}

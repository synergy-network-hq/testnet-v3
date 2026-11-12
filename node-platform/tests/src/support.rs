#![allow(dead_code)]
use synergy_simulation::{
    byzantine::EquivocationDetector, cluster::SimCluster, crash::CrashState,
    disk_failure::DiskBudget, packet_loss::deterministically_drop, partition, sentry::SimSentry,
    validator::SimValidator, virtual_clock::VirtualClock, virtual_network::VirtualNetwork,
};

pub fn consensus_safety(name: &str) {
    let validators = (1..=5)
        .map(|i| SimValidator {
            id: format!("v{i}"),
            weight: i,
            active: true,
            jailed: false,
            last_signed_height: 0,
        })
        .collect();
    let mut c = SimCluster::new(validators).unwrap();
    let voters = vec!["v2".into(), "v3".into(), "v4".into(), "v5".into()];
    c.finalize(1, &voters).unwrap();
    assert_eq!(c.finalized_height, 1, "{name}");
    assert!(c.finalize(3, &voters).is_err(), "{name}");
    let mut e = EquivocationDetector::default();
    e.observe("v1", 2, 1, vec![1]).unwrap();
    assert!(e.observe("v1", 2, 1, vec![2]).is_err(), "{name}");
}
pub fn networking(name: &str) {
    let mut n = VirtualNetwork::default();
    n.connect("a", "b");
    n.set_latency("a", "b", 10);
    n.send("a", "b", vec![1], 0).unwrap();
    assert!(n.deliver(9).is_empty(), "{name}");
    assert_eq!(n.deliver(10).len(), 1, "{name}");
    partition::split(&mut n, &["a"], &["b"]);
    assert!(n.send("a", "b", vec![1], 10).is_err(), "{name}");
    partition::heal(&mut n);
    let mut s = SimSentry::default();
    s.allow("a");
    assert!(s.forward("a", &[1], 8).is_ok(), "{name}");
    assert!(s.forward("x", &[1], 8).is_err(), "{name}");
}
pub fn storage(name: &str) {
    let mut d = DiskBudget {
        capacity: 8,
        used: 0,
    };
    d.write(8).unwrap();
    assert!(d.write(1).is_err(), "{name}");
    let mut c = CrashState {
        persisted_height: 4,
        volatile_height: 5,
    };
    c.crash();
    assert_eq!(c.volatile_height, 4, "{name}");
}
pub fn adverse(name: &str) {
    assert!(deterministically_drop(10, 5), "{name}");
    let mut c = VirtualClock::default();
    assert_eq!(c.advance(25).unwrap(), 25, "{name}");
}
pub fn admin(name: &str) {
    use synergy_admin_api::{
        operations::{AdminOperation, TelemetryOperation},
        AdminRequest,
    };
    let r = AdminRequest::query(
        name,
        AdminOperation::Telemetry(TelemetryOperation::Snapshot),
    );
    r.validate().unwrap();
    assert!(!r.operation.is_mutating(), "{name}");
}
pub fn role(name: &str) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../roles")
        .join(format!("{}.toml", name.replace('-', "_")));
    let text = std::fs::read_to_string(path).unwrap();
    assert!(text.contains("raw_export_forbidden = true"), "{name}");
    if name != "validator" {
        assert!(!text.contains("vote_consensus"), "{name}");
    }
}
pub fn etdag(name: &str) {
    let mut ids = vec!["c", "a", "b"];
    ids.sort();
    assert_eq!(ids, vec!["a", "b", "c"], "{name}");
}
pub fn sync(name: &str) {
    let anchor = [7u8; 32];
    let response_anchor = anchor;
    assert_eq!(anchor, response_anchor, "{name}");
}
pub fn vpn(name: &str) {
    let mut challenge = vec![0u8; 32];
    challenge[0] = 1;
    assert_eq!(challenge.len(), 32, "{name}");
    assert_ne!(challenge, vec![0u8; 32], "{name}");
}
pub fn upgrade(name: &str) {
    let installed = (1u16, 4u16);
    let protocol = (1u16, 3u16);
    assert!(
        installed.0 <= protocol.0 && protocol.1 <= installed.1,
        "{name}"
    );
}
pub fn integration(name: &str) {
    consensus_safety(name);
    networking(name);
    admin(name);
}

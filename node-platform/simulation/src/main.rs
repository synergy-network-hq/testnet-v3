use synergy_simulation::{cluster::SimCluster, report::SimulationReport, validator::SimValidator};
fn main() {
    let validators = (1..=5)
        .map(|i| SimValidator {
            id: format!("v{i}"),
            weight: i,
            active: true,
            jailed: false,
            last_signed_height: 0,
        })
        .collect();
    let mut cluster = SimCluster::new(validators).expect("valid cluster");
    let voters = vec!["v2".into(), "v3".into(), "v4".into(), "v5".into()];
    cluster.finalize(1, &voters).expect("quorum");
    let report = SimulationReport {
        name: "baseline".into(),
        passed: true,
        finalized_height: cluster.finalized_height,
        faults_injected: 0,
        notes: vec![],
    };
    println!("{}", serde_json::to_string(&report).expect("serialize"));
}

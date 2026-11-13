use std::sync::atomic::{AtomicU64, Ordering};

use crate::etdag::{self, EtdagDigest, EtdagParameters, ProtectedBatchSource};

use super::protected_pipeline::{
    ProtectedOrderSeedEvidence, ProtectedPipelineEvidenceVerifier, ProtectedPipelineObservation,
    ProtectedPipelineReconcileContext,
};
use super::protected_pipeline_runtime::{
    AuthenticatedProtectedPipelineEvent, NormalProtectedPipelineCoordinator,
    ProtectedPipelineRuntime,
};

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct AcceptAllEvidence;

impl ProtectedPipelineEvidenceVerifier for AcceptAllEvidence {
    fn verify_order_seed(
        &self,
        _target: &crate::etdag::TargetAdmissionContext,
        _evidence: &ProtectedOrderSeedEvidence,
    ) -> Result<(), String> {
        Ok(())
    }

    fn verify_observation(
        &self,
        _target: &crate::etdag::TargetAdmissionContext,
        _expected_commitment: &crate::etdag::NextProtectedBatchCommitment,
        _observation: &ProtectedPipelineObservation,
    ) -> Result<(), String> {
        Ok(())
    }
}

fn test_directory(label: &str) -> std::path::PathBuf {
    let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    crate::utils::test_temp_root(format!(
        "protected-pipeline-runtime-{label}-{}-{sequence}",
        std::process::id(),
    ))
}

fn order_seed_event(label: &str) -> AuthenticatedProtectedPipelineEvent {
    AuthenticatedProtectedPipelineEvent::OrderSeed(ProtectedOrderSeedEvidence {
        order_seed: EtdagDigest::from_domain_bytes("runtime-order-seed", label.as_bytes()),
        authority_root: EtdagDigest::from_domain_bytes("runtime-authority", label.as_bytes()),
    })
}

#[test]
fn normal_coordinator_binds_one_target_to_one_durable_runtime() {
    let fixture = etdag::tests::fixture(5, None);
    let verifier = fixture.signer.verifier();
    let parameters = EtdagParameters::default();
    let coordinator = NormalProtectedPipelineCoordinator::new(
        test_directory("normal-coordinator"),
        verifier,
        fixture.validator_set.clone(),
        fixture.cluster_map.clone(),
        parameters,
    )
    .expect("construct immutable normal coordinator");
    let root = fixture.context.root().expect("target root");

    let first = coordinator
        .register_target(fixture.context.clone())
        .expect("register exact target");
    let duplicate = coordinator
        .register_target(fixture.context.clone())
        .expect("idempotently register exact target");
    let routed = coordinator
        .runtime_for_target(fixture.context.target_height, root)
        .expect("read target registry")
        .expect("registered target runtime");

    assert_eq!(first.record_path_ref(), duplicate.record_path_ref());
    assert_eq!(first.record_path_ref(), routed.record_path_ref());
    assert_eq!(
        routed.source(),
        ProtectedBatchSource::NormalEtdagSteadyState,
        "fixture target is H4+ and cannot regress to the H3 source class",
    );
}

#[test]
fn r11_runtime_restart_duplicate_and_reordered_events_are_idempotent() {
    let fixture = etdag::tests::fixture(5, None);
    let verifier = fixture.signer.verifier();
    let parameters = EtdagParameters::default();
    let inputs = ProtectedPipelineReconcileContext {
        target: &fixture.context,
        verifier: &verifier,
        validator_set: &fixture.validator_set,
        cluster_map: &fixture.cluster_map,
        parameters: &parameters,
    };
    let evidence = AcceptAllEvidence;

    let directory = test_directory("restart");
    let runtime = ProtectedPipelineRuntime::open(
        &directory,
        fixture.context.clone(),
        ProtectedBatchSource::NormalEtdagSteadyState,
    )
    .expect("open runtime");
    let first = runtime
        .ingest_authenticated_event(order_seed_event("restart"), &evidence, &inputs)
        .expect("persist seed");
    assert!(first.changed);
    let duplicate = runtime
        .ingest_authenticated_event(order_seed_event("restart"), &evidence, &inputs)
        .expect("accept duplicate seed");
    assert!(!duplicate.changed);
    let before_restart = runtime.snapshot().expect("snapshot before restart");
    drop(runtime);

    let recovered = ProtectedPipelineRuntime::open(
        &directory,
        fixture.context.clone(),
        ProtectedBatchSource::NormalEtdagSteadyState,
    )
    .expect("recover runtime");
    let startup = recovered
        .reconcile_on_startup(&inputs)
        .expect("idempotent startup reconcile");
    assert!(!startup.changed);
    assert_eq!(
        recovered.snapshot().expect("recovered snapshot"),
        before_restart
    );

    let left_directory = test_directory("reorder-left");
    let left = ProtectedPipelineRuntime::open(
        &left_directory,
        fixture.context.clone(),
        ProtectedBatchSource::NormalEtdagSteadyState,
    )
    .expect("open left runtime");
    left.ingest_authenticated_event(
        AuthenticatedProtectedPipelineEvent::EtdagEvidence {
            certified_vertices: Vec::new(),
            cutoff_marker_digests: Vec::new(),
        },
        &evidence,
        &inputs,
    )
    .expect("empty ETDAG evidence is idempotent");
    left.ingest_authenticated_event(order_seed_event("reorder"), &evidence, &inputs)
        .expect("left seed");

    let right_directory = test_directory("reorder-right");
    let right = ProtectedPipelineRuntime::open(
        &right_directory,
        fixture.context.clone(),
        ProtectedBatchSource::NormalEtdagSteadyState,
    )
    .expect("open right runtime");
    right
        .ingest_authenticated_event(order_seed_event("reorder"), &evidence, &inputs)
        .expect("right seed");
    right
        .ingest_authenticated_event(
            AuthenticatedProtectedPipelineEvent::EtdagEvidence {
                certified_vertices: Vec::new(),
                cutoff_marker_digests: Vec::new(),
            },
            &evidence,
            &inputs,
        )
        .expect("empty ETDAG evidence is idempotent");

    assert_eq!(
        left.snapshot().expect("left snapshot"),
        right.snapshot().expect("right snapshot"),
        "authenticated event arrival order must not alter the durable semantic state",
    );
}

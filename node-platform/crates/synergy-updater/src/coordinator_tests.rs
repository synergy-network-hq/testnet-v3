use std::sync::Mutex;

use super::*;
use crate::RollbackReceipt;

struct Runtime(Result<HealthObservation, String>);
impl UpdateRuntime for Runtime {
    fn versions(&self) -> Result<RuntimeVersions, String> {
        unreachable!()
    }
    fn preflight(&self) -> Result<PreflightObservation, String> {
        unreachable!()
    }
    fn health_after_install(&self) -> Result<HealthObservation, String> {
        self.0.clone()
    }
}
struct Recovery {
    result: Result<RollbackReceipt, String>,
    calls: Mutex<Vec<InstallReceipt>>,
}
impl RollbackCoordinator for Recovery {
    fn rollback(&self, install: &InstallReceipt) -> Result<RollbackReceipt, String> {
        self.calls.lock().unwrap().push(install.clone());
        self.result.clone()
    }
}
#[derive(Default)]
struct Audit {
    failure: Option<String>,
    fail_phase: Option<UpdatePhase>,
    events: Mutex<Vec<AuditEvent>>,
}
impl AuditSink for Audit {
    fn record(&self, event: &AuditEvent) -> Result<(), String> {
        self.events.lock().unwrap().push(event.clone());
        match &self.failure {
            Some(reason) if self.fail_phase.is_none() || self.fail_phase == Some(event.phase) => {
                Err(reason.clone())
            }
            _ => Ok(()),
        }
    }
}
fn installed() -> InstallReceipt {
    InstallReceipt {
        release_id: "synthetic-new".into(),
        previous_release_id: "synthetic-old".into(),
    }
}
fn recovery(result: Result<RollbackReceipt, String>) -> Recovery {
    Recovery {
        result,
        calls: Mutex::new(Vec::new()),
    }
}
fn restored() -> Result<RollbackReceipt, String> {
    Ok(RollbackReceipt {
        restored_release_id: "synthetic-old".into(),
    })
}
fn healthy() -> HealthObservation {
    HealthObservation {
        process_running: true,
        ready: true,
        storage_healthy: true,
        protocol_compatible: true,
    }
}
#[test]
fn probe_error_restores_exact_install_receipt_and_preserves_original_failure() {
    let rollback = recovery(restored());
    let audit = Audit::default();
    let error = check_installed_health(
        &Runtime(Err("probe disconnected".into())),
        &rollback,
        &audit,
        &installed(),
        7,
        11,
    )
    .unwrap_err();
    assert!(
        matches!(&error, UpdateError::PostInstallHealth { reason, recovery: Ok(receipt), rollback_audit_error: None }
        if reason == "probe disconnected" && receipt.restored_release_id == "synthetic-old")
    );
    assert_eq!(*rollback.calls.lock().unwrap(), vec![installed()]);
    assert_eq!(
        *audit.events.lock().unwrap(),
        vec![AuditEvent {
            sequence: 7,
            release_id: "synthetic-new".into(),
            phase: UpdatePhase::RolledBack,
            outcome: AuditOutcome::Succeeded,
            timestamp_unix_seconds: 11
        }]
    );
}
#[test]
fn unhealthy_observation_also_restores_previous_release() {
    let rollback = recovery(restored());
    let health = HealthObservation {
        ready: false,
        ..healthy()
    };
    let error = check_installed_health(
        &Runtime(Ok(health)),
        &rollback,
        &Audit::default(),
        &installed(),
        7,
        11,
    )
    .unwrap_err();
    assert!(
        matches!(error, UpdateError::PostInstallHealth { reason, recovery: Ok(_), .. } if reason == "post-install health gate failed")
    );
    assert_eq!(rollback.calls.lock().unwrap().len(), 1);
}
#[test]
fn failed_recovery_retains_health_and_rollback_errors_and_failed_audit() {
    let rollback = recovery(Err("restore refused".into()));
    let audit = Audit::default();
    let error = check_installed_health(
        &Runtime(Err("probe timeout".into())),
        &rollback,
        &audit,
        &installed(),
        7,
        11,
    )
    .unwrap_err();
    assert!(
        matches!(&error, UpdateError::PostInstallHealth { reason, recovery: Err(recovery), .. } if reason == "probe timeout" && recovery == "restore refused")
    );
    assert_eq!(
        audit.events.lock().unwrap()[0].outcome,
        AuditOutcome::Failed {
            reason: "restore refused".into()
        }
    );
    assert!(error.to_string().contains("probe timeout"));
    assert!(error.to_string().contains("restore refused"));
}
#[test]
fn audit_failure_does_not_hide_successful_recovery_or_original_probe_error() {
    let rollback = recovery(restored());
    let audit = Audit {
        failure: Some("audit disk full".into()),
        ..Audit::default()
    };
    let error = check_installed_health(
        &Runtime(Err("probe failed".into())),
        &rollback,
        &audit,
        &installed(),
        7,
        11,
    )
    .unwrap_err();
    assert!(
        matches!(error, UpdateError::PostInstallHealth { reason, recovery: Ok(_), rollback_audit_error: Some(audit) } if reason == "probe failed" && audit == "audit disk full")
    );
    assert_eq!(rollback.calls.lock().unwrap().len(), 1);
}
#[test]
fn healthy_install_neither_rolls_back_nor_writes_recovery_audit() {
    let rollback = recovery(restored());
    let audit = Audit::default();
    assert!(check_installed_health(
        &Runtime(Ok(healthy())),
        &rollback,
        &audit,
        &installed(),
        7,
        11
    )
    .is_ok());
    assert!(rollback.calls.lock().unwrap().is_empty());
    assert!(audit.events.lock().unwrap().is_empty());
}

#[test]
fn installed_audit_failure_rolls_back_before_unchecked_release_can_be_retained() {
    let rollback = recovery(restored());
    let audit = Audit {
        failure: Some("installed journal failed".into()),
        fail_phase: Some(UpdatePhase::Installed),
        ..Audit::default()
    };
    let error = finish_installed_release(
        &Runtime(Ok(healthy())),
        &rollback,
        &audit,
        &installed(),
        7,
        11,
    )
    .unwrap_err();
    assert!(
        matches!(&error, UpdateError::PostInstallAudit { reason, recovery: Ok(_), rollback_audit_error: None } if reason == "installed journal failed")
    );
    assert_eq!(*rollback.calls.lock().unwrap(), vec![installed()]);
    let phases: Vec<_> = audit
        .events
        .lock()
        .unwrap()
        .iter()
        .map(|event| event.phase)
        .collect();
    assert_eq!(
        phases,
        vec![UpdatePhase::Installed, UpdatePhase::RolledBack]
    );
    assert!(error.to_string().contains("post-install audit failed"));
}
#[test]
fn installed_audit_failure_preserves_failed_rollback_and_failed_recovery_audit() {
    let rollback = recovery(Err("restore disk failed".into()));
    let audit = Audit {
        failure: Some("audit unavailable".into()),
        ..Audit::default()
    };
    let error = finish_installed_release(
        &Runtime(Ok(healthy())),
        &rollback,
        &audit,
        &installed(),
        7,
        11,
    )
    .unwrap_err();
    assert!(
        matches!(error, UpdateError::PostInstallAudit { reason, recovery: Err(recovery), rollback_audit_error: Some(audit) } if reason == "audit unavailable" && recovery == "restore disk failed" && audit == "audit unavailable")
    );
    assert_eq!(
        audit.events.lock().unwrap()[1].outcome,
        AuditOutcome::Failed {
            reason: "restore disk failed".into()
        }
    );
}
#[test]
fn final_audit_failure_after_passed_health_requires_reconciliation_without_rollback() {
    let rollback = recovery(restored());
    let audit = Audit {
        failure: Some("healthy journal failed".into()),
        fail_phase: Some(UpdatePhase::Healthy),
        ..Audit::default()
    };
    let error = finish_installed_release(
        &Runtime(Ok(healthy())),
        &rollback,
        &audit,
        &installed(),
        7,
        11,
    )
    .unwrap_err();
    assert!(matches!(error, UpdateError::Audit(reason) if reason == "healthy journal failed"));
    assert!(rollback.calls.lock().unwrap().is_empty());
    let phases: Vec<_> = audit
        .events
        .lock()
        .unwrap()
        .iter()
        .map(|event| event.phase)
        .collect();
    assert_eq!(phases, vec![UpdatePhase::Installed, UpdatePhase::Healthy]);
}
#[test]
fn complete_healthy_install_audits_both_phases_without_recovery() {
    let rollback = recovery(restored());
    let audit = Audit::default();
    assert!(finish_installed_release(
        &Runtime(Ok(healthy())),
        &rollback,
        &audit,
        &installed(),
        7,
        11
    )
    .is_ok());
    assert!(rollback.calls.lock().unwrap().is_empty());
    let phases: Vec<_> = audit
        .events
        .lock()
        .unwrap()
        .iter()
        .map(|event| event.phase)
        .collect();
    assert_eq!(phases, vec![UpdatePhase::Installed, UpdatePhase::Healthy]);
}

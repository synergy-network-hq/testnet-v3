import { useCallback, useEffect, useMemo, useState } from 'react';
import { SNRGButton } from '../../styles/SNRGButton';
import { invoke } from '../../lib/desktopClient';
import {
  MetricCard,
  PanelCard,
  SectionHeader,
  StatusPill,
} from './ControlPanelShared';

const CURRENT_NETWORK_ID = 'synergy-testnet-v3';
const CURRENT_CHAIN_ID = '1264';

const WIZARD_STEPS = [
  { key: 'welcome', title: 'Welcome', command: 'validator.lifecycle.status', args: { lifecycle_state: 'pending' } },
  { key: 'machine', title: 'Machine Check', command: 'validator.machine.preflight', args: { p2p_open: true } },
  { key: 'network', title: 'Network Check', command: 'validator.onboarding.verify', args: { archive_state: 'CANONICAL' } },
  { key: 'token', title: 'Enrollment Token', command: 'validator.package.verify', args: {} },
  { key: 'package', title: 'Package Verify', command: 'validator.package.verify', args: {} },
  { key: 'identity', title: 'Identity', command: 'validator.identity.create', args: {} },
  { key: 'backup', title: 'Backup Verify', command: 'validator.identity.backup.verify', args: {} },
  { key: 'cluster', title: 'Cluster Assignment', command: 'validator.cluster.previewAssignment', args: { fixture: 'six-validator' } },
  { key: 'config', title: 'Config Render', command: 'validator.config.render', args: {} },
  { key: 'state', title: 'State Source', command: 'validator.state.verify', args: { archive_state: 'CANONICAL' } },
  { key: 'observer', title: 'Observer Sync', command: 'validator.stateSync.dryRun', args: { quorum_verified: true } },
  { key: 'stake', title: 'Stake', command: 'validator.stake.preflight', args: {} },
  { key: 'vote-only', title: 'Vote-only', command: 'validator.lifecycle.requestVoteOnly', args: {} },
  { key: 'probation', title: 'Proposer Probation', command: 'validator.lifecycle.promoteProbation', args: { lifecycle_state: 'vote-only' } },
  { key: 'active-promotion', title: 'Active Promotion', command: 'validator.lifecycle.promoteVoteOnlyToActive', args: { lifecycle_state: 'vote-only', quorum_verified: true, quorum_count: 4, quorum_threshold: 4, quorum_height: 651000, quorum_hash: 'd5858605c2f47a929d200918fa63b40b38a83d8ff92a6b3bb10a07007894af55', finalized_height: 651542, probation_blocks_observed: 100, probation_blocks_required: 100, fresh_vote_locks_above_finalized: 0, stale_vote_locks_above_finalized: 0, conflicting_vote_lock_heights: 0 } },
  { key: 'activation', title: 'Activation', command: 'validator.activation.preflight', args: { archive_state: 'CANONICAL' } },
  { key: 'success', title: 'Success', command: 'validator.onboarding.verify', args: { archive_state: 'CANONICAL' } },
];

const DETAIL_TABS = [
  { key: 'overview', label: 'Overview', command: 'validator.lifecycle.status', args: { lifecycle_state: 'pending' } },
  { key: 'lifecycle', label: 'Lifecycle', command: 'validator.lifecycle.status', args: { lifecycle_state: 'vote-only' } },
  { key: 'state-integrity', label: 'State Integrity', command: 'validator.state.verify', args: {} },
  { key: 'peers', label: 'Peers', command: 'validator.machine.preflight', args: { p2p_open: true } },
  { key: 'cluster', label: 'Cluster', command: 'validator.cluster.previewAssignment', args: { fixture: 'six-validator' } },
  { key: 'consensus-duties', label: 'Consensus Duties', command: 'validator.lifecycle.status', args: { lifecycle_state: 'observer' } },
  { key: 'state-sync', label: 'State Sync', command: 'validator.stateSync.plan', args: { quorum_verified: false } },
  { key: 'recovery', label: 'Recovery', command: 'validator.recovery.plan', args: { lifecycle_state: 'suspect', quorum_verified: false, service_stopped: false, quarantine_marker_present: false } },
  { key: 'snapshots', label: 'Snapshots', command: 'archive.snapshot.listUnsafe', args: {} },
  { key: 'stake', label: 'Stake', command: 'validator.stake.preflight', args: {} },
  { key: 'logs', label: 'Logs', command: 'validator.doctor.run', args: {} },
  { key: 'evidence', label: 'Evidence', command: 'validator.doctor.run', args: {} },
  { key: 'actions', label: 'Actions', command: 'validator.activation.preflight', args: { archive_state: 'CANONICAL' } },
];

const ARCHIVE_REJECTION_MESSAGES = [
  ['SNAPSHOT_VERIFIER_CRASHED', 'Snapshot verifier crashed before canonical proof completed.'],
  ['SNAPSHOT_QUORUM_BELOW_THRESHOLD', 'Validator quorum is below threshold.'],
  ['ARCHIVE_NOT_CANONICAL', 'Archive hash or validator-set digest is not canonical.'],
  ['PACKAGE_ARCHIVE_NOT_CANONICAL', 'Manifest requires canonical archive state.'],
  ['SNAPSHOT_HASH_MISSING', 'Snapshot checksum or manifest hash is missing.'],
  ['PACKAGE_HASH_MISMATCH', 'Manifest hash does not match the expected release hash.'],
  ['PACKAGE_STALE', 'Validator Appliance Package is older than the minimum accepted version.'],
  ['PACKAGE_SCHEMA_INCOMPATIBLE', 'Config or state schema is incompatible with the v2 appliance model.'],
  ['PACKAGE_UNSIGNED', 'Manifest signature failed or is absent.'],
  ['PACKAGE_NO_GO_DENYLIST', 'Snapshot branch or package is on the NO-GO denylist.'],
  ['IDENTITY_BACKUP_MISSING', 'Validator identity backup proof is required before assignment.'],
  ['UNSAFE_CLUSTER_ASSIGNMENT', 'Cluster assignment is disabled when liveness margin is exhausted.'],
];

const FALLBACK_STATE_SYNC_DETAILS = {
  source_peers: ['validator-1', 'validator-2', 'validator-3'],
  quorum_agreement: 'missing',
  repair_range: 'latest finalized checkpoint through requested head',
  repair_reason: 'local state root divergence or missing range',
  estimated_download_mb: 512,
  mutation_summary: 'Replace only quorum-verified consensus state ranges after backup.',
  backup_path: 'state/quarantine/pre-repair-consensus-db',
  dry_run_result: 'blocked',
  repair_receipt: 'evidence/state-sync/repair-receipt.json',
};

const FALLBACK_RECOVERY_ARGS = {
  lifecycle_state: 'quarantined',
  quorum_verified: true,
  quorum_count: 4,
  quorum_threshold: 4,
  quorum_height: 651000,
  quorum_hash: 'd5858605c2f47a929d200918fa63b40b38a83d8ff92a6b3bb10a07007894af55',
  finalized_height: 651542,
  min_age_secs: 30,
  transient_vote_locks_above_finalized: 2,
  local_height: 650470,
  peer_height: 651015,
  service_stopped: true,
  quarantine_marker_present: true,
  archive_state: 'CANONICAL',
  signed_snapshot_available: false,
  signed_snapshot_verified: false,
  state_sync_plan_available: false,
};

const FALLBACK_ACTIVE_PROMOTION_ARGS = {
  lifecycle_state: 'vote-only',
  quorum_verified: true,
  quorum_count: 4,
  quorum_threshold: 4,
  quorum_height: FALLBACK_RECOVERY_ARGS.quorum_height,
  quorum_hash: FALLBACK_RECOVERY_ARGS.quorum_hash,
  finalized_height: FALLBACK_RECOVERY_ARGS.finalized_height,
  probation_blocks_observed: 100,
  probation_blocks_required: 100,
  fresh_vote_locks_above_finalized: 0,
  stale_vote_locks_above_finalized: 0,
  conflicting_vote_lock_heights: 0,
};

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function statusTone(envelope) {
  if (!envelope) {
    return 'neutral';
  }
  if (safeArray(envelope.blockers).length) {
    return 'bad';
  }
  if (safeArray(envelope.warnings).length) {
    return 'warn';
  }
  if (envelope.mutated) {
    return 'purple';
  }
  return 'good';
}

function clusterLifecycleCounts(clusters) {
  return safeArray(clusters).reduce((counts, cluster) => {
    safeArray(cluster.validators).forEach((validator) => {
      const state = validator.lifecycle_state || 'unknown';
      counts.total += 1;
      counts[state] = (counts[state] || 0) + 1;
    });
    return counts;
  }, {
    total: 0,
    'pending-assignment': 0,
    quarantined: 0,
    'vote-only': 0,
    'proposer-probation': 0,
  });
}

function clusterExpansionRecommendation(clusters) {
  if (!safeArray(clusters).length) {
    return 'Registry data is pending.';
  }
  if (clusters.some((cluster) => Number(cluster.liveness_margin) < 1)) {
    return 'Add validator capacity before approving new assignments.';
  }
  if (clusters.some((cluster) => Number(cluster.validator_count) < 7)) {
    return 'Next expansion can add a seventh validator or create a second cluster after capacity proof.';
  }
  return 'Current topology has assignment headroom; keep quorum and lifecycle proof current.';
}

function commandPhase(command) {
  return String(command || '').split('.')[0] || 'control';
}

function blockedEnvelope(command, error) {
  return {
    ok: false,
    command,
    phase: commandPhase(command),
    lifecycle_state: 'unknown',
    status: 'BLOCKED',
    safe_to_continue: false,
    mutated: false,
    checks: [],
    blockers: [{
      code: 'CONTROL_SERVICE_UNAVAILABLE',
      severity: 'fatal',
      message: error?.message || 'Control service is unavailable.',
      remediation: 'Start the desktop control service and rerun the page action.',
    }],
    warnings: [],
    next_actions: [],
    operator_message: 'The action is blocked until the control service responds.',
    developer_details: {},
  };
}

function useControlEnvelope(command, args = {}, options = {}) {
  const [envelope, setEnvelope] = useState(null);
  const [loading, setLoading] = useState(false);
  const serializedArgs = JSON.stringify(args);

  const run = useCallback(async (overrideArgs = null) => {
    const nextArgs = overrideArgs || args;
    setLoading(true);
    try {
      const payload = await invoke(command, {
        network_id: CURRENT_NETWORK_ID,
        chain_id: CURRENT_CHAIN_ID,
        ...nextArgs,
      });
      setEnvelope(payload);
      options.onEnvelope?.(payload);
      return payload;
    } catch (error) {
      const payload = blockedEnvelope(command, error);
      setEnvelope(payload);
      options.onEnvelope?.(payload);
      return payload;
    } finally {
      setLoading(false);
    }
  }, [command, serializedArgs]);

  useEffect(() => {
    run();
  }, [run]);

  return { envelope, loading, run };
}

function EnvelopeSummary({ envelope, loading }) {
  const checks = safeArray(envelope?.checks);
  const blockers = safeArray(envelope?.blockers);
  const warnings = safeArray(envelope?.warnings);
  return (
    <div className="cp-v2-summary-grid">
      <MetricCard
        label="Phase"
        value={loading ? 'Loading' : envelope?.phase || 'Pending'}
        detail={envelope?.command || 'Waiting for control-service'}
        tone={statusTone(envelope)}
        icon="rule"
      />
      <MetricCard
        label="Lifecycle"
        value={envelope?.lifecycle_state || 'unknown'}
        detail={envelope?.status || 'No status'}
        tone={statusTone(envelope)}
        icon="verified_user"
      />
      <MetricCard
        label="Checks"
        value={`${checks.filter((check) => check.status === 'pass').length}/${checks.length}`}
        detail={`${blockers.length} blockers, ${warnings.length} warnings`}
        tone={blockers.length ? 'bad' : warnings.length ? 'warn' : 'good'}
        icon="fact_check"
      />
      <MetricCard
        label="Mutation"
        value={envelope?.mutated ? 'Recorded' : envelope?.safe_to_continue ? 'None' : 'Disabled'}
        detail={envelope?.rollback_path || envelope?.evidence_path || 'Evidence pending'}
        tone={envelope?.mutated ? 'purple' : envelope?.safe_to_continue ? 'good' : 'bad'}
        icon="admin_panel_settings"
      />
    </div>
  );
}

function EnvelopePanel({ envelope, loading, title = 'Control envelope' }) {
  const checks = safeArray(envelope?.checks);
  const blockers = safeArray(envelope?.blockers);
  const warnings = safeArray(envelope?.warnings);
  const nextActions = safeArray(envelope?.next_actions);
  return (
    <PanelCard
      className="cp-v2-envelope"
      eyebrow={envelope?.status || 'Envelope'}
      title={title}
      detail={loading ? 'Refreshing' : envelope?.operator_message}
    >
      <div className="cp-v2-envelope-layout">
        <div className="cp-v2-list">
          <h4>Checks</h4>
          {checks.length ? checks.map((check) => (
            <div key={check.id} className={`cp-v2-row tone-${check.status === 'pass' ? 'good' : check.status === 'warn' ? 'warn' : 'bad'}`}>
              <StatusPill tone={check.status === 'pass' ? 'good' : check.status === 'warn' ? 'warn' : 'bad'}>{check.status}</StatusPill>
              <div>
                <strong>{check.label}</strong>
                <span>{check.detail}</span>
              </div>
            </div>
          )) : <div className="cp-empty-inline">No checks emitted yet.</div>}
        </div>

        <div className="cp-v2-list">
          <h4>Blockers</h4>
          {blockers.length ? blockers.map((blocker) => (
            <div key={`${blocker.code}-${blocker.message}`} className="cp-v2-row tone-bad">
              <StatusPill tone="bad">{blocker.severity}</StatusPill>
              <div>
                <strong>{blocker.code}</strong>
                <span>{blocker.message}</span>
                <small>{blocker.remediation}</small>
              </div>
            </div>
          )) : <div className="cp-empty-inline">No blockers.</div>}
        </div>

        <div className="cp-v2-list">
          <h4>Next Actions</h4>
          {nextActions.length ? nextActions.map((action) => (
            <div key={`${action.command}-${action.label}`} className={`cp-v2-row tone-${action.disabled_reason ? 'bad' : action.mutates ? 'warn' : 'good'}`}>
              <span className="material-icons" aria-hidden="true">{action.mutates ? 'lock' : 'arrow_forward'}</span>
              <div>
                <strong>{action.label}</strong>
                <span>{action.command}</span>
                {action.disabled_reason ? <small>{action.disabled_reason}</small> : null}
              </div>
            </div>
          )) : <div className="cp-empty-inline">No follow-up action required.</div>}
        </div>

        <div className="cp-v2-list">
          <h4>Evidence</h4>
          <div className="cp-v2-path-row">
            <strong>Evidence path</strong>
            <span>{envelope?.evidence_path || 'Not written for this read-only action'}</span>
          </div>
          <div className="cp-v2-path-row">
            <strong>Rollback path</strong>
            <span>{envelope?.rollback_path || 'No mutation rollback required'}</span>
          </div>
          {warnings.length ? warnings.map((warning) => (
            <div key={warning.code} className="cp-v2-row tone-warn">
              <StatusPill tone="warn">warn</StatusPill>
              <div>
                <strong>{warning.code}</strong>
                <span>{warning.message}</span>
              </div>
            </div>
          )) : null}
        </div>
      </div>
    </PanelCard>
  );
}

function ConfirmedActionButton({ envelope, command, args, label, onResult }) {
  const [running, setRunning] = useState(false);
  const blockers = safeArray(envelope?.blockers);
  const safetyBlockers = blockers.filter((blocker) => blocker.code !== 'CONFIRMATION_REQUIRED');
  const blocked = !envelope || safetyBlockers.length > 0;
  const disabledReason = safetyBlockers[0]?.message || 'Safety checks are still running.';

  const run = async () => {
    setRunning(true);
    try {
      const payload = await invoke(command, {
        network_id: CURRENT_NETWORK_ID,
        chain_id: CURRENT_CHAIN_ID,
        ...args,
        confirmed: true,
        confirmation: 'CONFIRM',
      });
      onResult?.(payload);
    } catch (error) {
      onResult?.(blockedEnvelope(command, error));
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="cp-v2-action-wrap">
      <SNRGButton
        variant={blocked ? 'red' : 'cyan'}
        size="sm"
        disabled={blocked || running}
        onClick={run}
      >
        <span className="material-icons" aria-hidden="true">task_alt</span>
        {running ? 'Running' : label}
      </SNRGButton>
      {blocked ? <small>{disabledReason}</small> : null}
    </div>
  );
}

export function ValidatorOnboardingV2Page() {
  const [stepIndex, setStepIndex] = useState(0);
  const [actionEnvelope, setActionEnvelope] = useState(null);
  const step = WIZARD_STEPS[stepIndex];
  const { envelope, loading, run } = useControlEnvelope(step.command, step.args, {
    onEnvelope: setActionEnvelope,
  });
  const canAdvance = envelope?.safe_to_continue && safeArray(envelope?.blockers).length === 0;
  const mutatingNextAction = safeArray(envelope?.next_actions).find((action) => action.mutates) || null;

  return (
    <main className="cp-v2-page">
      <SectionHeader
        eyebrow="Validator onboarding v2"
        title="Validator Onboarding"
        copy="Sixteen controlled phases with evidence, rollback paths, and disabled unsafe actions."
        actions={(
          <SNRGButton variant="cyan" size="sm" onClick={() => run()}>
            <span className="material-icons" aria-hidden="true">refresh</span>
            Refresh
          </SNRGButton>
        )}
      />

      <div className="cp-v2-wizard-grid">
        <PanelCard title="Phases" detail={`${stepIndex + 1} of ${WIZARD_STEPS.length}`}>
          <div className="cp-v2-step-list">
            {WIZARD_STEPS.map((entry, index) => (
              <button
                key={entry.key}
                type="button"
                className={`cp-v2-step ${index === stepIndex ? 'is-active' : ''} ${index < stepIndex ? 'is-complete' : ''}`}
                onClick={() => setStepIndex(index)}
              >
                <span>{index + 1}</span>
                <strong>{entry.title}</strong>
              </button>
            ))}
          </div>
        </PanelCard>

        <section className="cp-v2-main-stack">
          <PanelCard
            eyebrow={step.command}
            title={step.title}
            detail={envelope?.operator_message || 'Waiting for envelope'}
            action={<StatusPill tone={statusTone(envelope)}>{envelope?.status || 'PENDING'}</StatusPill>}
          >
            <EnvelopeSummary envelope={envelope} loading={loading} />
            <div className="cp-v2-button-row">
              <SNRGButton
                variant="whitepaper"
                size="sm"
                disabled={stepIndex === 0}
                onClick={() => setStepIndex((value) => Math.max(0, value - 1))}
              >
                <span className="material-icons" aria-hidden="true">arrow_back</span>
                Back
              </SNRGButton>
              <SNRGButton
                variant={canAdvance ? 'green' : 'red'}
                size="sm"
                disabled={!canAdvance || stepIndex >= WIZARD_STEPS.length - 1}
                onClick={() => setStepIndex((value) => Math.min(WIZARD_STEPS.length - 1, value + 1))}
              >
                <span className="material-icons" aria-hidden="true">arrow_forward</span>
                Next
              </SNRGButton>
              {mutatingNextAction ? (
                <ConfirmedActionButton
                  envelope={envelope}
                  command={mutatingNextAction.command}
                  args={step.args}
                  label={mutatingNextAction.label}
                  onResult={setActionEnvelope}
                />
              ) : null}
            </div>
          </PanelCard>
          <EnvelopePanel envelope={actionEnvelope || envelope} loading={loading} title="Current phase evidence" />
        </section>
      </div>
    </main>
  );
}

export function ValidatorDetailV2Page() {
  const [activeTab, setActiveTab] = useState(DETAIL_TABS[0].key);
  const [actionEnvelope, setActionEnvelope] = useState(null);
  const tab = DETAIL_TABS.find((entry) => entry.key === activeTab) || DETAIL_TABS[0];
  const { envelope, loading, run } = useControlEnvelope(tab.command, tab.args, {
    onEnvelope: setActionEnvelope,
  });

  const actionCommands = [
    { command: 'validator.stateSync.dryRun', label: 'Dry-run State Sync', args: { quorum_verified: true } },
    { command: 'validator.recovery.plan', label: 'Plan Recovery', args: FALLBACK_RECOVERY_ARGS },
    { command: 'validator.recovery.quarantineStopped', label: 'Quarantine Stopped Validator', args: FALLBACK_RECOVERY_ARGS },
    { command: 'validator.recovery.transientVoteLockRecover', label: 'Recover Transient Locks', args: FALLBACK_RECOVERY_ARGS },
    { command: 'validator.recovery.snapshotRepair', label: 'Repair From Snapshot', args: { ...FALLBACK_RECOVERY_ARGS, signed_snapshot_available: true, signed_snapshot_verified: false } },
    { command: 'validator.onboarding.run', label: 'Run Onboarding', args: { archive_state: 'CANONICAL' } },
    { command: 'validator.lifecycle.requestVoteOnly', label: 'Vote-only Rejoin', args: {} },
    { command: 'validator.lifecycle.promoteProbation', label: 'Promote Probation', args: { lifecycle_state: 'vote-only' } },
    { command: 'validator.lifecycle.promoteVoteOnlyToActive', label: 'Restore Proposer Duties', args: FALLBACK_ACTIVE_PROMOTION_ARGS },
    { command: 'validator.activation.submit', label: 'Submit Activation', args: { archive_state: 'CANONICAL' } },
  ];

  return (
    <main className="cp-v2-page">
      <SectionHeader
        eyebrow="Validator detail v2"
        title="Validator Detail"
        copy="Lifecycle-aware recovery, state proof, cluster context, duties, snapshots, logs, evidence, and actions."
        actions={<StatusPill tone={statusTone(envelope)} live>{envelope?.lifecycle_state || 'pending'}</StatusPill>}
      />

      <div className="cp-v2-tab-strip">
        {DETAIL_TABS.map((entry) => (
          <button
            key={entry.key}
            type="button"
            className={entry.key === activeTab ? 'is-active' : ''}
            onClick={() => setActiveTab(entry.key)}
          >
            {entry.label}
          </button>
        ))}
      </div>

      <EnvelopeSummary envelope={envelope} loading={loading} />

      {activeTab === 'recovery' ? (
        <PanelCard title="Recovery proof" detail="Containment, quorum proof, archive state, and repair source must all pass before repair can run.">
          <div className="cp-v2-detail-grid">
            <div className="cp-v2-path-row">
              <strong>Quorum height</strong>
              <span>{envelope?.developer_details?.quorum_height || FALLBACK_RECOVERY_ARGS.quorum_height}</span>
            </div>
            <div className="cp-v2-path-row">
              <strong>Quorum hash</strong>
              <span>{envelope?.developer_details?.quorum_hash || FALLBACK_RECOVERY_ARGS.quorum_hash}</span>
            </div>
            <div className="cp-v2-path-row">
              <strong>Finalized height</strong>
              <span>{envelope?.developer_details?.finalized_height || FALLBACK_RECOVERY_ARGS.finalized_height}</span>
            </div>
            <div className="cp-v2-path-row">
              <strong>Transient locks</strong>
              <span>{envelope?.developer_details?.transient_vote_locks_above_finalized ?? FALLBACK_RECOVERY_ARGS.transient_vote_locks_above_finalized}</span>
            </div>
            <div className="cp-v2-path-row">
              <strong>Local height</strong>
              <span>{envelope?.developer_details?.local_height || FALLBACK_RECOVERY_ARGS.local_height}</span>
            </div>
            <div className="cp-v2-path-row">
              <strong>Peer height</strong>
              <span>{envelope?.developer_details?.peer_height || FALLBACK_RECOVERY_ARGS.peer_height}</span>
            </div>
            <div className="cp-v2-path-row">
              <strong>Repair source</strong>
              <span>{envelope?.developer_details?.signed_snapshot_verified ? 'verified snapshot' : envelope?.developer_details?.state_sync_plan_available ? 'state-sync plan' : 'missing'}</span>
            </div>
            <div className="cp-v2-path-row">
              <strong>Manual state edits</strong>
              <span>{envelope?.developer_details?.manual_state_surgery_allowed ? 'allowed' : 'blocked'}</span>
            </div>
          </div>
        </PanelCard>
      ) : null}

      <div className="cp-v2-two-column">
        <EnvelopePanel envelope={actionEnvelope || envelope} loading={loading} title={`${tab.label} envelope`} />
        <PanelCard title="Actions" detail="Actions follow lifecycle safety gates; restart is not a primary recovery path.">
          <div className="cp-v2-action-stack">
            <SNRGButton variant="cyan" size="sm" onClick={() => run()}>
              <span className="material-icons" aria-hidden="true">refresh</span>
              Refresh Tab
            </SNRGButton>
            {actionCommands.map((action) => (
              <ConfirmedActionButton
                key={action.command}
                envelope={envelope}
                command={action.command}
                args={action.args}
                label={action.label}
                onResult={setActionEnvelope}
              />
            ))}
          </div>
        </PanelCard>
      </div>
    </main>
  );
}

export function ClusterManagerV2Page() {
  const [fixture, setFixture] = useState('six-validator');
  const [actionEnvelope, setActionEnvelope] = useState(null);
  const { envelope, loading, run } = useControlEnvelope('fleet.status.strict', { fixture }, {
    onEnvelope: setActionEnvelope,
  });
  const registry = envelope?.developer_details?.registry;
  const clusters = safeArray(registry?.clusters);
  const lifecycleCounts = useMemo(() => clusterLifecycleCounts(clusters), [clusters]);
  const expansionRecommendation = useMemo(() => clusterExpansionRecommendation(clusters), [clusters]);

  return (
    <main className="cp-v2-page">
      <SectionHeader
        eyebrow="Dynamic registry"
        title="Cluster Manager"
        copy="Registry-driven clusters, quorum, liveness margin, capacity, and safe assignment preview."
      />

      <PanelCard title="Registry fixture" detail="Topology is dynamic; six validators is only the current cluster shape.">
        <div className="cp-v2-segmented">
          {['six-validator', 'seven-validator', 'two-cluster', 'three-cluster', 'pending-assignment', 'quarantined', 'vote-only', 'proposer-probation'].map((item) => (
            <button
              key={item}
              type="button"
              className={fixture === item ? 'is-active' : ''}
              onClick={() => setFixture(item)}
            >
              {item}
            </button>
          ))}
          <SNRGButton variant="cyan" size="sm" onClick={() => run({ fixture })}>
            <span className="material-icons" aria-hidden="true">refresh</span>
            Refresh
          </SNRGButton>
        </div>
      </PanelCard>

      <div className="cp-v2-summary-grid">
        <MetricCard
          label="Pending"
          value={lifecycleCounts['pending-assignment']}
          detail="Validators waiting for assignment"
          tone={lifecycleCounts['pending-assignment'] ? 'warn' : 'good'}
          icon="pending_actions"
        />
        <MetricCard
          label="Vote-only"
          value={lifecycleCounts['vote-only']}
          detail="Voting without proposer duties"
          tone={lifecycleCounts['vote-only'] ? 'warn' : 'neutral'}
          icon="how_to_vote"
        />
        <MetricCard
          label="Probation"
          value={lifecycleCounts['proposer-probation']}
          detail="Proposer eligibility under observation"
          tone={lifecycleCounts['proposer-probation'] ? 'purple' : 'neutral'}
          icon="verified"
        />
        <MetricCard
          label="Quarantined"
          value={lifecycleCounts.quarantined}
          detail="Assignment and activation disabled"
          tone={lifecycleCounts.quarantined ? 'bad' : 'good'}
          icon="gpp_bad"
        />
      </div>

      <PanelCard
        title="Expansion recommendation"
        detail={expansionRecommendation}
        action={<StatusPill tone={clusters.some((cluster) => Number(cluster.liveness_margin) < 1) ? 'bad' : 'good'}>{registry?.network_id || CURRENT_NETWORK_ID}</StatusPill>}
      >
        <div className="cp-v2-detail-grid">
          <div className="cp-v2-path-row">
            <strong>Current model</strong>
            <span>Dynamic registry supports one-cluster, seven-validator, two-cluster, and three-cluster topologies.</span>
          </div>
          <div className="cp-v2-path-row">
            <strong>Unsafe assignment gate</strong>
            <span>Assignment is disabled when a cluster has no liveness margin or contains quarantined validators.</span>
          </div>
        </div>
      </PanelCard>

      <div className="cp-v2-cluster-grid">
        {clusters.map((cluster) => (
          <PanelCard
            key={cluster.cluster_id}
            eyebrow={cluster.status}
            title={cluster.cluster_id}
            detail={`${cluster.active_count}/${cluster.validator_count} active, quorum ${cluster.quorum_threshold}, margin ${cluster.liveness_margin}`}
            action={<StatusPill tone={cluster.liveness_margin >= 1 ? 'good' : 'bad'}>{cluster.fault_tolerance_target}</StatusPill>}
          >
            <div className="cp-v2-validator-list">
              {safeArray(cluster.validators).map((validator) => (
                <div key={validator.node_id} className="cp-v2-validator-row">
                  <span className={`cp-v2-dot tone-${validator.proposer_eligible ? 'good' : validator.voting_eligible ? 'warn' : 'bad'}`}></span>
                  <div>
                    <strong>{validator.node_id}</strong>
                    <span>{validator.lifecycle_state}</span>
                  </div>
                  <small>{validator.proposer_eligible ? 'proposer' : validator.voting_eligible ? 'vote-only' : 'blocked'}</small>
                </div>
              ))}
            </div>
            <div className="cp-v2-button-row">
              <SNRGButton
                variant="whitepaper"
                size="sm"
                onClick={async () => {
                  const payload = await invoke('validator.cluster.previewAssignment', {
                    network_id: CURRENT_NETWORK_ID,
                    chain_id: CURRENT_CHAIN_ID,
                    fixture,
                    cluster_id: cluster.cluster_id,
                  }).catch((error) => blockedEnvelope('validator.cluster.previewAssignment', error));
                  setActionEnvelope(payload);
                }}
              >
                <span className="material-icons" aria-hidden="true">preview</span>
                Preview
              </SNRGButton>
              <ConfirmedActionButton
                envelope={actionEnvelope || envelope}
                command="validator.cluster.assign"
                args={{ fixture, cluster_id: cluster.cluster_id }}
                label="Approve Assignment"
                onResult={setActionEnvelope}
              />
            </div>
          </PanelCard>
        ))}
      </div>

      <EnvelopePanel envelope={actionEnvelope || envelope} loading={loading} title="Cluster safety envelope" />
    </main>
  );
}

export function StateSyncV2Page() {
  const [quorumVerified, setQuorumVerified] = useState(false);
  const [actionEnvelope, setActionEnvelope] = useState(null);
  const { envelope, loading, run } = useControlEnvelope('validator.stateSync.plan', { quorum_verified: quorumVerified }, {
    onEnvelope: setActionEnvelope,
  });
  const stateSyncDetails = {
    ...FALLBACK_STATE_SYNC_DETAILS,
    ...(envelope?.developer_details || {}),
  };
  const sourcePeers = safeArray(stateSyncDetails.source_peers?.length ? stateSyncDetails.source_peers : stateSyncDetails.source_candidates);

  return (
    <main className="cp-v2-page">
      <SectionHeader
        eyebrow="Quorum-verified repair"
        title="State Sync"
        copy="Peer sources, quorum agreement, repair range, backup path, dry-run result, and repair receipt."
      />

      <PanelCard title="Repair gate" detail="Repair remains disabled until peer quorum proof passes.">
        <div className="cp-v2-toggle-row">
          <label>
            <input
              type="checkbox"
              checked={quorumVerified}
              onChange={(event) => setQuorumVerified(event.target.checked)}
            />
            <span>Peer quorum agreement present</span>
          </label>
          <SNRGButton variant="cyan" size="sm" onClick={() => run({ quorum_verified: quorumVerified })}>
            <span className="material-icons" aria-hidden="true">refresh</span>
            Replan
          </SNRGButton>
        </div>
      </PanelCard>

      <EnvelopeSummary envelope={envelope} loading={loading} />

      <PanelCard title="Repair proof details" detail="State repair is shown as a proof bundle before any mutation can run.">
        <div className="cp-v2-detail-grid">
          <div className="cp-v2-path-row">
            <strong>Source peers</strong>
            <span>{sourcePeers.join(', ') || 'Peer source list pending'}</span>
          </div>
          <div className="cp-v2-path-row">
            <strong>Quorum agreement</strong>
            <span>{stateSyncDetails.quorum_agreement || (quorumVerified ? 'verified' : 'missing')}</span>
          </div>
          <div className="cp-v2-path-row">
            <strong>Repair range</strong>
            <span>{stateSyncDetails.repair_range}</span>
          </div>
          <div className="cp-v2-path-row">
            <strong>Repair reason</strong>
            <span>{stateSyncDetails.repair_reason}</span>
          </div>
          <div className="cp-v2-path-row">
            <strong>Estimated download</strong>
            <span>{stateSyncDetails.estimated_download_mb} MB</span>
          </div>
          <div className="cp-v2-path-row">
            <strong>Mutation summary</strong>
            <span>{stateSyncDetails.mutation_summary}</span>
          </div>
          <div className="cp-v2-path-row">
            <strong>Backup path</strong>
            <span>{stateSyncDetails.backup_path}</span>
          </div>
          <div className="cp-v2-path-row">
            <strong>Dry-run result</strong>
            <span>{stateSyncDetails.dry_run_result}</span>
          </div>
          <div className="cp-v2-path-row">
            <strong>Repair receipt</strong>
            <span>{stateSyncDetails.repair_receipt}</span>
          </div>
        </div>
      </PanelCard>

      <div className="cp-v2-two-column">
        <EnvelopePanel envelope={actionEnvelope || envelope} loading={loading} title="State-sync proof" />
        <PanelCard title="Repair controls" detail="Dry-run first, then confirmed repair with rollback evidence.">
          <div className="cp-v2-action-stack">
            <SNRGButton
              variant="whitepaper"
              size="sm"
              onClick={async () => {
                const payload = await invoke('validator.stateSync.dryRun', {
                  network_id: CURRENT_NETWORK_ID,
                  chain_id: CURRENT_CHAIN_ID,
                  quorum_verified: quorumVerified,
                }).catch((error) => blockedEnvelope('validator.stateSync.dryRun', error));
                setActionEnvelope(payload);
              }}
            >
              <span className="material-icons" aria-hidden="true">science</span>
              Dry-run
            </SNRGButton>
            <ConfirmedActionButton
              envelope={envelope}
              command="validator.stateSync.repair"
              args={{ quorum_verified: quorumVerified }}
              label="Repair State"
              onResult={setActionEnvelope}
            />
          </div>
        </PanelCard>
      </div>
    </main>
  );
}

export function ArchiveManagerV2Page() {
  const [archiveState, setArchiveState] = useState('CONTAINED');
  const [actionEnvelope, setActionEnvelope] = useState(null);
  const { envelope, loading, run } = useControlEnvelope('archive.status', { archive_state: archiveState }, {
    onEnvelope: setActionEnvelope,
  });

  const verifyArgs = {
    archive_state: archiveState,
    quorum_count: archiveState === 'CANONICAL' ? 4 : 2,
    quorum_threshold: 4,
    snapshot_hash: archiveState === 'CANONICAL' ? '0123456789abcdef0123456789abcdef' : '',
  };

  return (
    <main className="cp-v2-page">
      <SectionHeader
        eyebrow="Archive safety"
        title="Archive Manager"
        copy="Canonical verification, unsafe snapshot catalog, reseed plan, and disabled publish controls."
      />

      <PanelCard title="Archive state" detail="Archive services stay contained unless separately authorized.">
        <div className="cp-v2-segmented">
          {['CONTAINED', 'VERIFYING', 'CANONICAL', 'NONCANONICAL', 'RESEED_REQUIRED', 'PUBLISH_DISABLED', 'PUBLISH_ELIGIBLE'].map((state) => (
            <button
              key={state}
              type="button"
              className={archiveState === state ? 'is-active' : ''}
              onClick={() => setArchiveState(state)}
            >
              {state}
            </button>
          ))}
          <SNRGButton variant="cyan" size="sm" onClick={() => run({ archive_state: archiveState })}>
            <span className="material-icons" aria-hidden="true">refresh</span>
            Refresh
          </SNRGButton>
        </div>
      </PanelCard>

      <EnvelopeSummary envelope={envelope} loading={loading} />

      <div className="cp-v2-two-column">
        <EnvelopePanel envelope={actionEnvelope || envelope} loading={loading} title="Archive envelope" />
        <PanelCard title="Snapshot safety" detail="Publish controls are disabled while archive state is noncanonical or contained.">
          <div className="cp-v2-rejection-list">
            {ARCHIVE_REJECTION_MESSAGES.map(([code, message]) => (
              <div key={code} className="cp-v2-row tone-warn">
                <StatusPill tone="warn">{code}</StatusPill>
                <span>{message}</span>
              </div>
            ))}
          </div>
          <div className="cp-v2-action-stack">
            <SNRGButton
              variant="whitepaper"
              size="sm"
              onClick={async () => {
                const payload = await invoke('archive.verifyCanonical', {
                  network_id: CURRENT_NETWORK_ID,
                  chain_id: CURRENT_CHAIN_ID,
                  ...verifyArgs,
                }).catch((error) => blockedEnvelope('archive.verifyCanonical', error));
                setActionEnvelope(payload);
              }}
            >
              <span className="material-icons" aria-hidden="true">verified</span>
              Verify Canonical
            </SNRGButton>
            <SNRGButton
              variant="whitepaper"
              size="sm"
              onClick={async () => {
                const payload = await invoke('archive.reseed.plan', {
                  network_id: CURRENT_NETWORK_ID,
                  chain_id: CURRENT_CHAIN_ID,
                  archive_state: archiveState,
                }).catch((error) => blockedEnvelope('archive.reseed.plan', error));
                setActionEnvelope(payload);
              }}
            >
              <span className="material-icons" aria-hidden="true">account_tree</span>
              Reseed Plan
            </SNRGButton>
            <SNRGButton
              variant="whitepaper"
              size="sm"
              onClick={async () => {
                const payload = await invoke('archive.snapshot.listUnsafe', {
                  network_id: CURRENT_NETWORK_ID,
                  chain_id: CURRENT_CHAIN_ID,
                  archive_state: archiveState,
                }).catch((error) => blockedEnvelope('archive.snapshot.listUnsafe', error));
                setActionEnvelope(payload);
              }}
            >
              <span className="material-icons" aria-hidden="true">inventory_2</span>
              Unsafe Snapshots
            </SNRGButton>
            <ConfirmedActionButton
              envelope={actionEnvelope || envelope}
              command="archive.snapshot.quarantine"
              args={{ archive_state: archiveState }}
              label="Quarantine Snapshot"
              onResult={setActionEnvelope}
            />
          </div>
        </PanelCard>
      </div>
    </main>
  );
}

export function IncidentsEvidenceV2Page() {
  const [events, setEvents] = useState([]);
  const { envelope, loading, run } = useControlEnvelope('validator.machine.preflight', { p2p_open: false }, {
    onEnvelope: (payload) => {
      const blocker = safeArray(payload.blockers)[0];
      const nextAction = safeArray(payload.next_actions)[0];
      const timestamp = new Date().toISOString();
      setEvents((current) => [{
        id: globalThis.crypto?.randomUUID?.() || `${payload.command}-${timestamp}-${current.length}`,
        incidentId: payload.developer_details?.incident?.incident_id || `local-${Date.now()}`,
        command: payload.command,
        status: payload.status,
        category: safeArray(payload.blockers).length ? 'safety-gate' : 'read-only',
        severity: blocker?.severity || 'info',
        nodeId: payload.node_id || 'local-validator',
        clusterId: payload.cluster_id || 'cluster-a',
        rootCause: blocker?.code || 'NONE',
        lifecycleState: payload.lifecycle_state || 'unknown',
        mutated: payload.mutated ? 'yes' : 'no',
        rollbackComplete: payload.mutated ? 'pending' : 'not required',
        resolved: payload.ok && !safeArray(payload.blockers).length ? 'yes' : 'no',
        recommendedNextAction: blocker?.remediation || nextAction?.label || 'No follow-up action is required.',
        evidencePath: payload.evidence_path || blocker?.evidence_path || '',
        summary: payload.operator_message,
        createdAt: timestamp,
        updatedAt: timestamp,
      }, ...current].slice(0, 8));
    },
  });

  return (
    <main className="cp-v2-page">
      <SectionHeader
        eyebrow="Incident evidence"
        title="Incidents"
        copy="Safety gates and mutations generate evidence with incident id, node, cluster, cause, lifecycle, rollback, resolution, recommendation, timestamps, and path."
        actions={(
          <SNRGButton variant="cyan" size="sm" onClick={() => run({ p2p_open: false })}>
            <span className="material-icons" aria-hidden="true">refresh</span>
            Refresh
          </SNRGButton>
        )}
      />

      <EnvelopeSummary envelope={envelope} loading={loading} />
      <PanelCard title="Evidence fields" detail="Every stored incident record carries these fields for audit and handoff.">
        <div className="cp-v2-detail-grid">
          {[
            ['Incident id', 'Unique evidence identifier.'],
            ['Node', 'Validator node id when available.'],
            ['Cluster', 'Cluster id when available.'],
            ['Root cause', 'First structured blocker or NONE.'],
            ['Lifecycle', 'Lifecycle state when evidence was emitted.'],
            ['Mutated', 'Whether the command changed local validator state.'],
            ['Rollback complete', 'Rollback completion or not-required status.'],
            ['Resolved', 'Whether the envelope finished without blockers.'],
            ['Recommended next action', 'Operator remediation or next command.'],
            ['Created', 'UTC creation timestamp.'],
            ['Updated', 'UTC last-update timestamp.'],
            ['Evidence path', 'Local JSON receipt path when written.'],
          ].map(([label, detail]) => (
            <div key={label} className="cp-v2-path-row">
              <strong>{label}</strong>
              <span>{detail}</span>
            </div>
          ))}
        </div>
      </PanelCard>
      <div className="cp-v2-two-column">
        <PanelCard title="Evidence stream" detail="Most recent v2 safety evidence emitted in this session.">
          <div className="cp-v2-incident-list">
            {events.map((event) => (
              <div key={event.id} className={`cp-v2-row tone-${event.severity === 'fatal' ? 'bad' : 'good'}`}>
                <StatusPill tone={event.severity === 'fatal' ? 'bad' : 'good'}>{event.category}</StatusPill>
                <div>
                  <strong>{event.incidentId}</strong>
                  <span>{event.summary}</span>
                  <small>{event.command}</small>
                  <dl className="cp-v2-incident-fields">
                    <div>
                      <dt>Incident id</dt>
                      <dd>{event.incidentId}</dd>
                    </div>
                    <div>
                      <dt>Node</dt>
                      <dd>{event.nodeId}</dd>
                    </div>
                    <div>
                      <dt>Cluster</dt>
                      <dd>{event.clusterId}</dd>
                    </div>
                    <div>
                      <dt>Root cause</dt>
                      <dd>{event.rootCause}</dd>
                    </div>
                    <div>
                      <dt>Lifecycle</dt>
                      <dd>{event.lifecycleState}</dd>
                    </div>
                    <div>
                      <dt>Mutated</dt>
                      <dd>{event.mutated}</dd>
                    </div>
                    <div>
                      <dt>Rollback complete</dt>
                      <dd>{event.rollbackComplete}</dd>
                    </div>
                    <div>
                      <dt>Resolved</dt>
                      <dd>{event.resolved}</dd>
                    </div>
                    <div>
                      <dt>Recommended next action</dt>
                      <dd>{event.recommendedNextAction}</dd>
                    </div>
                    <div>
                      <dt>Created</dt>
                      <dd>{event.createdAt}</dd>
                    </div>
                    <div>
                      <dt>Updated</dt>
                      <dd>{event.updatedAt}</dd>
                    </div>
                    <div>
                      <dt>Evidence path</dt>
                      <dd>{event.evidencePath || 'Evidence path pending'}</dd>
                    </div>
                  </dl>
                </div>
              </div>
            ))}
          </div>
        </PanelCard>
        <EnvelopePanel envelope={envelope} loading={loading} title="Latest incident envelope" />
      </div>
    </main>
  );
}

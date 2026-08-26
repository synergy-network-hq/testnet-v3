import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  captureValidatorDiagnosticSnapshot,
  controlValidatorLifecycle,
  getValidatorHostPreflight,
  getValidatorOperationsCluster,
  getValidatorStructuredLogs,
} from '../../services/validatorOperationsService';

const shortHash = (value) => value ? `${String(value).slice(0, 10)}…${String(value).slice(-8)}` : '—';
const mib = (bytes) => `${(Number(bytes || 0) / 1048576).toFixed(0)} MiB`;

export default function ValidatorOperationsPanel({ selectedNodeId }) {
  const [cluster, setCluster] = useState(null);
  const [preflight, setPreflight] = useState(null);
  const [logs, setLogs] = useState(null);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const validators = cluster?.validators || [];
  const selected = useMemo(
    () => validators.find((entry) => entry.discovery?.validator_id === selectedNodeId)
      || (!selectedNodeId ? validators[0] : null),
    [validators, selectedNodeId],
  );
  const targetId = selected?.discovery?.validator_id || selectedNodeId;

  const refresh = useCallback(async () => {
    setError('');
    try {
      setCluster(await getValidatorOperationsCluster());
    } catch (requestError) {
      setError(String(requestError?.message || requestError));
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const run = async (operation) => {
    if (!targetId || busy) return;
    setBusy(true);
    setError('');
    setNotice('');
    try { await operation(); } catch (requestError) { setError(String(requestError?.message || requestError)); }
    finally { setBusy(false); }
  };

  const runControl = (action) => run(async () => {
    if (!window.confirm(`${action} ${targetId}? This audited action uses the validator host local agent.`)) return;
    const result = await controlValidatorLifecycle(targetId, action, `Node Control Panel operator requested ${action.toLowerCase()}.`);
    setNotice(`${action}: ${result.message}`);
    await refresh();
  });

  return (
    <section className="validator-operations-panel" aria-label="Validator operations control plane">
      <div className="validator-operations-heading">
        <div><strong>Testnet-v3 Validator Operations</strong><span>Read-only protocol evidence; never a consensus authority.</span></div>
        <button type="button" onClick={refresh} disabled={busy}>Refresh five validators</button>
      </div>
      {error ? <div className="validator-live-error">{error}</div> : null}
      {notice ? <div className="validator-operations-notice">{notice}</div> : null}
      <div className="validator-operations-grid">
        {validators.map((status) => {
          const id = status.discovery.validator_id;
          const missing = status.liveness?.first_missing_transition;
          return (
            <article key={id} className={`validator-operations-node ${id === targetId ? 'is-selected' : ''}`}>
              <header><strong>{id}</strong><span>{status.health.classification}</span></header>
              <dl>
                <div><dt>Release / binary</dt><dd>{status.release.release_id} · {shortHash(status.release.binary_sha256)}</dd></div>
                <div><dt>Service / uptime</dt><dd>{status.service.state} · {status.service.uptime_seconds}s</dd></div>
                <div><dt>Peers</dt><dd>{status.peers.authenticated_validator_peer_count}/{status.peers.expected_validator_peer_count}</dd></div>
                <div><dt>Head / finalized</dt><dd>{status.chain.head_height} / {status.chain.finalized_height}</dd></div>
                <div><dt>PoSy</dt><dd>view {status.posy.current_view} · VC {status.posy.vc_status} · QC {status.posy.qc_status}</dd></div>
                <div><dt>ProtectedPipeline</dt><dd>{status.protected_pipeline.source} · {status.protected_pipeline.phase}</dd></div>
                <div><dt>Resources</dt><dd>CPU {status.resources.cpu_percent}% · memory {mib(status.resources.memory_bytes)} ({status.resources.memory_percent}%)</dd></div>
                <div><dt>Release match</dt><dd>{status.release_consistency.matches_expected ? 'MATCH' : `MISMATCH: ${status.release_consistency.mismatch_fields.map((field) => field.field).join(', ')}`}</dd></div>
                {missing ? <div><dt>First missing transition</dt><dd>{missing.from} → {missing.to}: {missing.reason}</dd></div> : null}
              </dl>
            </article>
          );
        })}
      </div>
      {cluster ? <div className="validator-operations-cluster-line">Discovered {validators.length}/5 · unavailable {cluster.unavailable_validator_ids?.length || 0} · cluster release {cluster.release_consistency?.consistent ? 'consistent' : 'mismatch'}</div> : null}
      <div className="validator-operations-actions">
        <button type="button" disabled={!targetId || busy} onClick={() => run(async () => { const value = await getValidatorHostPreflight(targetId); setPreflight(value); setNotice(value.ready ? 'Host preflight passed.' : `Host preflight blocked: ${value.blocking_check_ids.join(', ')}`); })}>Run host preflight</button>
        {['START', 'STOP', 'RESTART'].map((action) => <button key={action} type="button" disabled={!targetId || busy} onClick={() => runControl(action)}>{action}</button>)}
        <button type="button" disabled={!targetId || busy} onClick={() => run(async () => { const value = await captureValidatorDiagnosticSnapshot(targetId); setNotice(`Diagnostic snapshot captured: ${value.snapshot_id}`); })}>Capture diagnostic snapshot</button>
        <button type="button" disabled={!targetId || busy} onClick={() => run(async () => setLogs(await getValidatorStructuredLogs(targetId, 100)))}>Load structured logs</button>
      </div>
      {preflight ? <details><summary>Host preflight ({preflight.ready ? 'ready' : 'blocked'})</summary><ul>{preflight.checks.map((check) => <li key={check.id}>{check.id}: {check.status} — {check.detail}</li>)}</ul></details> : null}
      {logs ? <details open><summary>Structured logs ({logs.entries.length})</summary><div className="validator-operations-logs">{logs.entries.map((entry) => <div key={entry.sequence}><span>{entry.severity} · {entry.subsystem}</span>{entry.message}</div>)}</div></details> : null}
    </section>
  );
}

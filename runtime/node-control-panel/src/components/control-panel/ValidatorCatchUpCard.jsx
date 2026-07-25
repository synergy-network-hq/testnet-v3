import { SNRGButton } from '../../styles/SNRGButton';
import {
  formatNumber,
  nodeBlockHeightDetail,
  nodeBlockHeightValue,
  nodeRuntimeTone,
  safeArray,
  statusTone,
} from './controlPanelModel';
import { MetricCard, PanelCard, StatusPill } from './ControlPanelShared';

function isValidatorNode(node) {
  return String(node?.role_id || node?.role_type || '').trim().toLowerCase() === 'validator';
}

function checkToRepairAction(check, mode) {
  switch (check?.id) {
    case 'process-running':
    case 'local-rpc':
      return { id: 'start-node', label: 'Start Node', detail: 'Start or restart the runtime.', action: 'start' };
    case 'sync-gap':
      return { id: 'sync-catch-up', label: 'Sync Catch Up', detail: 'Request live peer catch-up without stopping the validator.', action: 'sync-catch-up' };
    case 'peers-visible':
    case 'seed-registration':
      return { id: 'register-seeds', label: 'Refresh Peers', detail: 'Refresh seed registration and peer targets.', action: 'register-seeds' };
    case 'liquid-balance':
    case 'bonded-stake':
      return { id: 'open-rewards', label: 'Open Rewards', detail: 'Fund or stake the validator wallet.', action: 'rewards' };
    case 'local-signing-key':
    case 'runtime-wallet-loaded':
      return { id: 'restart-node', label: 'Restart Node', detail: 'Reload local identity and wallet files.', action: 'restart' };
    default:
      return mode === 'developer'
        ? { id: 'open-diagnostics', label: 'Open Diagnostics', detail: 'Inspect runtime and machine checks.', action: 'diagnostics' }
        : { id: 'open-settings', label: 'Open Settings', detail: 'Enable Developer View for deep diagnostics.', action: 'settings' };
  }
}

function repairActionsFromPreflight(preflight, mode) {
  const seen = new Set();
  return safeArray(preflight?.checks)
    .filter((check) => check?.status && check.status !== 'pass')
    .map((check) => checkToRepairAction(check, mode))
    .filter((action) => {
      if (seen.has(action.id)) {
        return false;
      }
      seen.add(action.id);
      return true;
    });
}

function normalizeRepairActions(result, preflight, mode) {
  const backendActions = safeArray(result?.repairActions || result?.repair_actions);
  if (backendActions.length) {
    return backendActions;
  }
  return repairActionsFromPreflight(preflight, mode);
}

function defaultSteps(isBehind) {
  return [
    {
      id: 'runtime-online',
      label: 'Verify runtime',
      status: 'pending',
      detail: 'Keeps the validator running and checks local RPC.',
    },
    {
      id: 'live-sync',
      label: 'Sync to chain tip',
      status: isBehind ? 'ready' : 'pending',
      detail: isBehind ? 'Ready to request missing blocks from connected peers.' : 'Used when the node falls behind.',
    },
    {
      id: 'preflight',
      label: 'Run preflight',
      status: 'pending',
      detail: 'Checks RPC, peers, stake, wallet, and signing identity.',
    },
    {
      id: 'rejoin-consensus',
      label: 'Rejoin consensus',
      status: 'pending',
      detail: 'Activates consensus participation after checks pass.',
    },
  ];
}

export default function ValidatorCatchUpCard({
  node,
  nodeLive,
  liveStatus,
  preflight,
  lastResult,
  actionBusy,
  mode = 'advanced',
  onRun,
  onRepair,
}) {
  if (!isValidatorNode(node)) {
    return null;
  }

  const syncGap = Number(nodeLive?.sync_gap ?? 0);
  const isBehind = syncGap > 2;
  const isBusy = actionBusy === 'sync-catch-up';
  const steps = safeArray(lastResult?.steps).length ? safeArray(lastResult.steps) : defaultSteps(isBehind);
  const repairActions = normalizeRepairActions(lastResult, preflight, mode);
  const failingChecks = safeArray(preflight?.checks).filter((check) => check?.status && check.status !== 'pass');
  const preflightPassing = preflight?.canActivate === true || preflight?.can_activate === true;
  const consensusActive = lastResult?.consensusActive === true || lastResult?.consensus_active === true;
  const tone = consensusActive || (!isBehind && preflightPassing) ? 'good' : isBehind ? 'warn' : 'cyan';

  return (
    <PanelCard
      className="cp-catchup-card"
      eyebrow="Validator recovery"
      title="Sync Catch Up"
      detail="Requests live peer catch-up while the validator keeps running, then checks readiness when the chain reaches the verified tip."
      action={<StatusPill tone={tone}>{isBehind ? `${formatNumber(syncGap)} blocks behind` : 'In range'}</StatusPill>}
    >
      <div className="cp-metric-grid cp-metric-grid-dashboard cp-catchup-metrics">
        <MetricCard
          label="Local height"
          value={formatNumber(nodeBlockHeightValue(nodeLive, liveStatus))}
          detail={nodeBlockHeightDetail(nodeLive, liveStatus)}
          tone={nodeRuntimeTone(nodeLive)}
          icon="data_usage"
        />
        <MetricCard
          label="Block gap"
          value={`${formatNumber(syncGap)} blocks`}
          detail={isBehind ? 'Catch-up recommended' : 'Within validator range'}
          tone={isBehind ? 'warn' : 'good'}
          icon="sync"
        />
        <MetricCard
          label="Consensus"
          value={consensusActive ? 'Active' : preflightPassing ? 'Ready' : 'Blocked'}
          detail={preflightPassing ? 'Preflight can activate' : 'Preflight repair needed'}
          tone={consensusActive || preflightPassing ? 'good' : 'warn'}
          icon="verified"
        />
      </div>

      <div className="cp-catchup-action-row">
        <SNRGButton
          variant={isBehind ? 'purple' : 'blue'}
          size="sm"
          disabled={Boolean(actionBusy)}
          onClick={() => onRun?.()}
        >
          {isBusy ? 'Catching up...' : 'Sync Catch Up'}
        </SNRGButton>
        {lastResult?.message ? <p>{lastResult.message}</p> : null}
      </div>

      <div className="cp-catchup-steps">
        {steps.map((step) => (
          <article key={`${step.id}-${step.status}`} className={`cp-catchup-step tone-${statusTone(step.status)} status-${step.status}`}>
            <span>{step.status === 'pass' ? '✓' : step.status === 'fail' ? '!' : '•'}</span>
            <div>
              <strong>{step.label}</strong>
              <p>{step.detail}</p>
            </div>
          </article>
        ))}
      </div>

      {failingChecks.length ? (
        <div className="cp-preflight-repair-list">
          <div>
            <strong>Preflight repairs</strong>
            <p>{formatNumber(failingChecks.length)} check(s) need attention before consensus rejoin.</p>
          </div>
          <div className="cp-button-grid">
            {repairActions.slice(0, 4).map((action) => (
              <SNRGButton
                key={action.id}
                variant={action.action === 'rewards' ? 'purple' : 'blue'}
                size="sm"
                disabled={Boolean(actionBusy)}
                onClick={() => onRepair?.(action.action)}
              >
                {action.label}
              </SNRGButton>
            ))}
          </div>
        </div>
      ) : null}
    </PanelCard>
  );
}

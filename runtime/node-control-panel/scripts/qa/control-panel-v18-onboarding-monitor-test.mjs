import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const jsx = fs.readFileSync(
  path.join(root, 'src/components/control-panel-v18/ControlPanelV18.jsx'),
  'utf8',
);

function extractFunction(name) {
  const start = jsx.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `ControlPanelV18.jsx must define ${name}`);
  const bodyStart = jsx.indexOf('{', start);
  let depth = 0;
  for (let index = bodyStart; index < jsx.length; index += 1) {
    if (jsx[index] === '{') depth += 1;
    if (jsx[index] === '}') depth -= 1;
    if (depth === 0) return jsx.slice(start, index + 1);
  }
  throw new Error(`Could not extract ${name}`);
}

const continuableActionsDeclaration = jsx.match(
  /const CONTINUABLE_ONBOARDING_ACTIONS = new Set\(\[[\s\S]*?\]\);/,
)?.[0];
assert.ok(continuableActionsDeclaration, 'ControlPanelV18.jsx must define continuable onboarding actions');

const context = {};
vm.runInNewContext([
  continuableActionsDeclaration,
  extractFunction('readObject'),
  extractFunction('stringValue'),
  extractFunction('onboardingPolicy'),
  extractFunction('shadowProgressFromOnboarding'),
  extractFunction('onboardingNextAction'),
  extractFunction('onboardingCanContinue'),
  extractFunction('onboardingStepStatuses'),
  extractFunction('onboardingMonitorMessage'),
  extractFunction('provisioningStageForNextAction'),
  extractFunction('finiteNumberFrom'),
  extractFunction('extractSyncMetrics'),
  extractFunction('syncStatusIsVerified'),
  extractFunction('secureNetworkTruth'),
  'globalThis.qa = { onboardingCanContinue, onboardingStepStatuses, onboardingMonitorMessage, provisioningStageForNextAction, extractSyncMetrics, syncStatusIsVerified, secureNetworkTruth };',
].join('\n\n'), context);

const {
  onboardingCanContinue,
  onboardingStepStatuses,
  onboardingMonitorMessage,
  provisioningStageForNextAction,
  extractSyncMetrics,
  syncStatusIsVerified,
  secureNetworkTruth,
} = context.qa;

test('only explicit monitoring actions continue blocked onboarding', () => {
  assert.equal(onboardingCanContinue({ status: 'blocked', next_action: 'continue_full_shadow_epoch' }), true);
  assert.equal(onboardingCanContinue({ status: 'blocked', nextAction: 'wait_for_epoch_boundary' }), true);
  assert.equal(onboardingCanContinue({ status: 'blocked', next_action: 'review_activation_preflight' }), false);
  assert.equal(onboardingCanContinue({ status: 'blocked', next_action: 'repair_validator_preflight' }), false);
  assert.equal(onboardingCanContinue({ status: 'blocked', next_action: 'recover_local_fork' }), false);
  assert.equal(onboardingCanContinue({ status: 'blocked', next_action: 'wait_for_unjail_epoch_validator_set' }), false);
});

test('blocked continuable results keep onboarding and shadow steps running', () => {
  for (const nextAction of ['continue_full_shadow_epoch', 'wait_for_epoch_boundary']) {
    const statuses = onboardingStepStatuses({ status: 'blocked', next_action: nextAction });
    assert.equal(statuses.onboarding, 'running', `${nextAction} must keep profile registration running`);
    assert.equal(statuses.shadow, 'running', `${nextAction} must keep shadow monitoring running`);
  }

  const failedPreflight = onboardingStepStatuses({
    status: 'blocked',
    next_action: 'review_activation_preflight',
  });
  assert.equal(failedPreflight.onboarding, 'error');
  assert.equal(failedPreflight.shadow, null);
});

test('near-complete shadow progress is observation, not a preflight failure', () => {
  const result = {
    status: 'blocked',
    next_action: 'continue_full_shadow_epoch',
    message: 'Activation preflight is still blocked. Review the failed checks.',
    policy: {
      shadow_epoch: {
        status: 'blocked',
        detail: 'Shadow proof refreshed: completed=false, observed=998, required=1000.',
      },
    },
  };

  const message = onboardingMonitorMessage(result);
  assert.equal(
    message,
    'Shadow epoch observation in progress: 998/1000 blocks observed. Monitoring will continue automatically.',
  );
  assert.doesNotMatch(message, /preflight|fail/i);
  assert.equal(provisioningStageForNextAction('wait_for_epoch_boundary'), 'shadow');
});

test('local fork recovery is surfaced as a sync recovery step', () => {
  const result = {
    status: 'blocked',
    next_action: 'recover_local_fork',
    message: 'Local canonical lock conflict detected.',
  };

  assert.equal(onboardingCanContinue(result), false);
  assert.equal(provisioningStageForNextAction('recover_local_fork'), 'sync');
});

test('launch screen exposes local fork recovery action', () => {
  assert.match(jsx, /canRecoverLocalFork = nextAction === 'recover_local_fork'/);
  assert.match(jsx, /invokeOnboarding\('recoverLocalFork'/);
  assert.match(jsx, /Recover Local Fork/);
  assert.match(jsx, /Keeps validator keys, wallet, stake, and VPN enrollment/);
});

test('setup sync verification falls back to verified live heights when explicit gap is absent', () => {
  const liveStatus = {
    latest_finalized_height: 1_250_000,
    best_network_height: 1_250_000,
    sync_target_verified: true,
    local_rpc_ready: true,
  };

  const metrics = extractSyncMetrics(liveStatus);
  assert.equal(metrics.liveGap, 0);
  assert.equal(metrics.targetHeight, 1_250_000);
  assert.equal(metrics.localHeight, 1_250_000);
  assert.equal(syncStatusIsVerified(liveStatus, 'normal'), true);
});

test('setup sync verification still blocks when fallback heights show a real gap', () => {
  const liveStatus = {
    latest_finalized_height: 1_249_998,
    best_network_height: 1_250_000,
    local_rpc_ready: true,
  };

  const metrics = extractSyncMetrics(liveStatus);
  assert.equal(metrics.liveGap, 2);
  assert.equal(metrics.targetHeight, 1_250_000);
  assert.equal(metrics.localHeight, 1_249_998);
  assert.equal(syncStatusIsVerified(liveStatus, 'normal'), false);
});

test('normal sync setup path reconciles evidence before launch', () => {
  const source = jsx.slice(
    jsx.indexOf('const continueToLaunchAndActivate = async () => {'),
    jsx.indexOf('if (step === SETUP_STEP.nodeRole)', jsx.indexOf('const continueToLaunchAndActivate = async () => {')),
  );
  assert.match(source, /if \(snapshotState\.status === 'success'\) \{/);
  assert.doesNotMatch(
    source,
    /snapshotState\.status === 'success' \|\| snapshotState\.status === 'normal-sync'/,
    'normal sync must not jump to Launch & Activate before setup sync evidence is recorded',
  );
  assert.match(source, /waitForVerifiedSetupSync\('normal', \{ targetId, nodeId \}\)/);
  assert.match(source, /reconciledFromLiveStatus:\s*true/);
});

test('secure network truth accepts existing applied enrollment with local handshake evidence', () => {
  const status = secureNetworkTruth({
    status: 'applied',
    vpn_ip: '10.70.10.8',
    local_interface_evidence: {
      handshakeConfirmed: true,
      assignedIp: '10.70.10.8',
    },
  }, {});

  assert.equal(status.confirmed, true);
  assert.equal(status.coordinatorConfirmed, true);
  assert.equal(status.handshakeConfirmed, true);
  assert.equal(status.assignedIp, '10.70.10.8');
});

test('device network step passively refreshes existing VPN status evidence', () => {
  const source = jsx.slice(
    jsx.indexOf('const refreshExistingVpnStatus = async () => {'),
    jsx.indexOf('useEffect(() => {', jsx.indexOf('if (step !== SETUP_STEP.validatorIdentity')),
  );
  assert.match(source, /nodeService\.getValidatorVpnStatus\(nodeId\)/);
  assert.match(source, /secureNetworkTruth\(result, context\.selectedNodeLive\)/);
  assert.match(source, /setVpnSetupState\(\(current\) => \{/);
  assert.match(source, /current\.status === 'running'/);
  assert.match(source, /Secure validator network confirmed from the existing enrollment and live peer evidence/);
});

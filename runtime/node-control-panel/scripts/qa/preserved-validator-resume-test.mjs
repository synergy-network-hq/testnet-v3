import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const source = await readFile(
  new URL('../../src/components/TestnetJarvisSetup.jsx', import.meta.url),
  'utf8',
);

const resumeStart = source.indexOf('const continueExistingValidatorSetup = useCallback');
const resumeEnd = source.indexOf('\n\n  const handoffToDashboard', resumeStart);
assert.ok(resumeStart >= 0, 'existing-validator resume callback must remain present');
assert.ok(resumeEnd > resumeStart, 'existing-validator resume callback boundary must remain stable');
const resumeSource = source.slice(resumeStart, resumeEnd);

const missingNodeStart = resumeSource.indexOf('if (!node?.id)');
const provisionStart = resumeSource.indexOf('setProvisionResult({', missingNodeStart);
assert.ok(missingNodeStart >= 0, 'resume must guard a missing registry node');
assert.ok(provisionStart > missingNodeStart, 'successful recovery must return to the existing-node path');
const missingNodeSource = resumeSource.slice(missingNodeStart, provisionStart);

assert.match(
  source,
  /const reconcileExistingValidatorRegistry = useCallback\(async \(\) => \{[\s\S]*?const data = await refreshState\(false\)/,
  'resume must await the existing backend state/reconciliation route',
);
assert.match(
  missingNodeSource,
  /state = await reconcileExistingValidatorRegistry\(\)/,
  'a missing registry node must trigger backend reconciliation before surfacing recovery state',
);
assert.doesNotMatch(
  missingNodeSource,
  /testnet_erase_local_machine_data|eraseLocalValidatorSetupState|setProvisionResult\(null\)|setPhase\('select_node_type'\)/,
  'missing-node resume must not erase, clear, or jump to setup reset',
);
assert.match(
  missingNodeSource,
  /setPhase\('existing_validator_recovery'\)/,
  'unresolved registry recovery must remain recoverable in the setup UI',
);
assert.match(
  missingNodeSource,
  /identity, keys, chain state, funding, VPN receipt, or evidence/,
  'the recoverable state must explicitly preserve validator artifacts',
);

assert.ok(
  resumeSource.indexOf('setProvisionResult({') > resumeSource.indexOf('state = await reconcileExistingValidatorRegistry()'),
  'a recovered registry node must flow into the normal continuation path',
);
assert.match(resumeSource, /const preflight = await getValidatorPreflight\(node\)/);
assert.match(resumeSource, /preflightHasBondedStake\(preflight\)/);
assert.match(resumeSource, /preflightHasFunding\(preflight\)/);
assert.match(resumeSource, /const activationResult = await runActivationAfterStake\(node, setupSyncMode\)/);

const promptConfigStart = source.indexOf('const promptConfig = useMemo');
const recoveryPromptStart = source.indexOf("if (phase === 'existing_validator_recovery')", promptConfigStart);
const recoveryPromptEnd = source.indexOf("if (phase === 'review_device')", recoveryPromptStart);
assert.ok(promptConfigStart >= 0, 'prompt configuration must remain present');
assert.ok(recoveryPromptStart >= 0 && recoveryPromptEnd > recoveryPromptStart, 'recovery prompt must be defined');
const recoveryPromptSource = source.slice(recoveryPromptStart, recoveryPromptEnd);
assert.match(recoveryPromptSource, /Retry Registry Recovery/);
assert.doesNotMatch(recoveryPromptSource, /Start Over|Restart Setup|select_node_type/);

console.log('Preserved-validator resume QA passed: reconciliation is awaited, resume is non-destructive, and recovered synced/funded validators retain the normal continuation path.');

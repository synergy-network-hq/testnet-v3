const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

class MemoryStorage {
  constructor() {
    this.values = new Map();
  }

  getItem(key) {
    return this.values.has(key) ? this.values.get(key) : null;
  }

  setItem(key, value) {
    this.values.set(key, String(value));
  }

  removeItem(key) {
    this.values.delete(key);
  }
}

async function main() {
  const {
    CONTROL_PANEL_WALLET_SESSION_STORAGE_KEY: key,
    clearPersistedWalletSession,
    persistWalletSession,
    readPersistedWalletSession,
  } = await import('../../src/components/wallet/walletSessionPersistence.js');

  const durableStorage = new MemoryStorage();
  const legacyStorage = new MemoryStorage();
  const legacyRecord = {
    wallet: { address: 'synw1owner', chainId: 1264, chainIdHex: '0x4f0' },
    session: {
      sessionId: 'session-1',
      pollUrl: 'https://relay.example/sessions/session-1',
      relayUrl: 'https://relay.example',
      expiresAt: '2099-01-01T00:00:00Z',
    },
  };
  legacyStorage.setItem(key, JSON.stringify(legacyRecord));
  const migrated = readPersistedWalletSession({ storage: durableStorage, legacyStorage, now: Date.parse('2026-07-11T00:00:00Z') });
  assert.equal(migrated.wallet.address, 'synw1owner');
  assert.equal(durableStorage.getItem(key), JSON.stringify(legacyRecord));
  assert.equal(legacyStorage.getItem(key), null);

  assert.equal(persistWalletSession({
    storage: durableStorage,
    wallet: { address: 'synw1new', chainId: 1264, chainIdHex: '0x4f0' },
    session: { sessionId: 'session-2', pollUrl: 'https://relay.example/sessions/session-2', relayUrl: 'https://relay.example' },
  }), true);
  assert.equal(readPersistedWalletSession({ storage: durableStorage }).wallet.address, 'synw1new');

  durableStorage.setItem(key, JSON.stringify({
    ...legacyRecord,
    session: { ...legacyRecord.session, expiresAt: '2020-01-01T00:00:00Z' },
  }));
  assert.equal(readPersistedWalletSession({ storage: durableStorage, now: Date.parse('2026-07-11T00:00:00Z') }), null);
  assert.equal(durableStorage.getItem(key), null);
  clearPersistedWalletSession({ storage: durableStorage, legacyStorage });

  const { validatorVpnPeerName } = await import('../../src/services/validatorVpnPeerName.js');
  assert.equal(
    validatorVpnPeerName({ nodeId: 'Node / 7', peerName: 'My First Validator!' }),
    'validator-node-7',
  );
  assert.equal(
    validatorVpnPeerName({ peerName: '  Community Validator #1  ' }),
    'validator-community-validator-1',
  );
  assert.match(
    validatorVpnPeerName({ nodeId: 'node-name-with-a-very-long-identifier-that-must-not-overflow-the-innernet-peer-name-boundary' }),
    /^[a-z0-9._-]{1,63}$/,
  );

  const root = path.resolve(__dirname, '../..');
  const jarvisSetupSource = fs.readFileSync(path.join(root, 'src/components/TestnetJarvisSetup.jsx'), 'utf8');
  assert.match(
    jarvisSetupSource,
    /const fundingReadyToBond = eligibility\?\.fundingReadyToBond === true\s+&& eligibility\?\.eligibilityStatus === ELIGIBILITY_STATUSES\.stakeReadyToBond/,
  );
  assert.match(jarvisSetupSource, /if \(!bondedEligibility && !fundingReadyToBond\)/);
  assert.match(jarvisSetupSource, /syncMode: syncMode === 'normal' \? 'normal' : 'snapshot'/);
  assert.match(jarvisSetupSource, /const requiredSyncGap = snapshotRestore \? HEAD_SYNC_GAP_BLOCKS : 0/);
  assert.match(jarvisSetupSource, /markValidatorSetupSyncComplete\(node, headSyncStatus, snapshotRestore \? 'snapshot' : 'normal'\)/);
  assert.match(jarvisSetupSource, /runActivationAfterStake\(node, snapshotSyncEnabled \? 'snapshot' : 'normal'\)/);
  const setupSource = fs.readFileSync(path.join(root, 'src/components/control-panel-v18/ControlPanelV18.jsx'), 'utf8');
  assert.match(setupSource, /const onboardingNodeId = setupConfig\.remoteNodeId \|\| selectedNodeId \|\| ''/);
  assert.match(setupSource, /const selectedValidatorAddress = setupConfig\.remoteNodeAddress \|\| context\.selectedNode\?\.node_address \|\| ''/);
  assert.match(setupSource, /remoteNodeId: createdNode\.id/);
  assert.match(setupSource, /remoteNodeAddress: createdNode\.node_address \|\| ''/);
  assert.match(setupSource, /testnet_mark_setup_sync_complete/);
  assert.match(setupSource, /syncMode,\s*\n\s*\}/);
  assert.match(setupSource, /waitForVerifiedSetupSync/);
  assert.match(setupSource, /const maximumGap = syncMode === 'normal' \? 0 : ACTIVE_SYNC_GAP_MAX/);
  assert.match(setupSource, /normalizeStoredActivationPending/);
  assert.match(setupSource, /Activation remains pending\. Resume the monitor/);
  assert.match(setupSource, /runAutonomousOnboarding\(input\)/);
  assert.match(setupSource, /activeConsensusEvidence/);
  assert.match(setupSource, /step === SETUP_STEP\.launchActivate && !activationConfirmed/);
  assert.match(setupSource, /Open Validator Overview/);

  const validatorLifecycleGuide = fs.readFileSync(
    path.join(root, 'docs/operator-manual/validator-lifecycle.md'),
    'utf8',
  );
  assert.match(validatorLifecycleGuide, /runtime automatically keeps the new validator in authenticated support-only mode/);
  assert.match(validatorLifecycleGuide, /Canonical activation automatically removes that restriction and starts consensus participation/);
  assert.match(validatorLifecycleGuide, /Operators do not need a separate peer-unblock command, firewall change, validator allowlist edit, or manual service restart after activation/);

  const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const packageLock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
  const cargoToml = fs.readFileSync(path.join(root, 'control-service/Cargo.toml'), 'utf8');
  const innernetCoordinator = fs.readFileSync(path.join(root, 'control-service/src/innernet.rs'), 'utf8');
  const testnetControlService = fs.readFileSync(path.join(root, 'control-service/src/testnet.rs'), 'utf8');
  const workflow = fs.readFileSync(path.join(root, '.github/workflows/release.yml'), 'utf8');
  assert.match(cargoToml, new RegExp(`^version = "${packageJson.version}"$`, 'm'));
  assert.equal(packageLock.version, packageJson.version);
  assert.equal(packageLock.packages[''].version, packageJson.version);
  assert.doesNotMatch(workflow, /TESTNET_RUNTIME_REF:.*['"]v\d+\.\d+\.\d+['"]/);
  assert.match(workflow, /TESTNET_RUNTIME_REF:.*format\('v\{0\}', needs\.verify-release-identity\.outputs\.version\)/);
  assert.match(workflow, /node scripts\/qa\/runtime-version-alignment-test\.mjs/);
  assert.match(testnetControlService, /async fn ensure_matching_validator_runtime\(/);
  assert.match(testnetControlService, /action: "restart"\.to_string\(\)/);
  assert.match(testnetControlService, /let restarted_version = query_local_validator_runtime_version/);
  assert.match(testnetControlService, /if restarted_version != required_version/);
  assert.match(testnetControlService, /ensure_matching_validator_runtime\(app_context, &node\)\.await\?/);
  assert.doesNotMatch(innernetCoordinator, /Innernet invitation has expired\./);
  assert.match(innernetCoordinator, /verify_server_handshake\(&peer_name, &interface_name, &assigned_ip\)\?/);

  console.log('Deterministic onboarding contract QA passed.');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const read = (relativePath) => fs.readFileSync(path.join(root, relativePath), 'utf8');

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function assertIncludes(source, value, label) {
  assert(source.includes(value), `${label} missing: ${value}`);
}

function assertNotIncludes(source, value, label) {
  assert(!source.includes(value), `${label} must not include: ${value}`);
}

const appSource = read('src/App.jsx');
assertIncludes(appSource, '<ControlPanelV18 />', 'App v18 shell mount');
assertNotIncludes(appSource, 'TestnetJarvisSetup', 'App setup routing');

const v18Source = read('src/components/control-panel-v18/ControlPanelV18.jsx');
for (const label of ['Overview', 'Setup Node', 'Operations', 'Performance', 'Monitoring', 'Logs', 'Settings']) {
  assertIncludes(v18Source, `label: '${label}'`, 'Primary navigation');
}
for (const route of ['path="/setup"', 'path="/operations"', 'path="/validator"', 'path="/performance"', 'path="/monitoring"', 'path="/logs"', 'path="/settings"']) {
  assertIncludes(v18Source, route, 'V18 routes');
}
for (const label of ['Choose Node Role', 'Validator Identity', 'Wallet & Stake', 'Device, Network & Sync', 'Launch & Activate']) {
  assertIncludes(v18Source, `'${label}'`, 'Re-architected onboarding order');
}
assertIncludes(v18Source, 'Connect Wallet & Fund Validator', 'Wallet and stake screen title');
assertIncludes(v18Source, 'REQUIRED_VALIDATOR_STAKE_SNRG', 'Stake requirement');
assertIncludes(v18Source, 'Verify Bond', 'Stake verification action');
assertIncludes(v18Source, 'Complete Validator Self-Bond', 'Explicit local validator self-bond action');
assertIncludes(v18Source, 'onClick={completeValidatorSelfBond}', 'Self-bond action wiring');
assertIncludes(v18Source, 'disabled={!fundingReadyToBond || !selectedValidatorAddress || !connectedWalletAddress || checking || bondSubmissionPending}', 'Funded-only self-bond replay guard');
assertIncludes(v18Source, 'canContinueEligibility', 'Eligibility continuation gate');
assertIncludes(v18Source, '&& (eligible || fundingReadyToBond)', 'Confirmed validator funding continuation gate');
assertIncludes(v18Source, 'walletCanFundValidator', 'New validator wallet funding gate');
assertIncludes(v18Source, 'disabled={!selectedValidatorAddress || !connectedWalletAddress || checking || unresolvedFunding || typeof wallet?.requestWalletAction', 'Stake action waits for generated validator address and mobile wallet approval');
assertIncludes(v18Source, 'validatorAddress: validatorAddress || context.selectedNode?.nodeAddress || null', 'VPN enrollment uses the validator address defined inside SetupStepContent');
assertIncludes(v18Source, 'const unresolvedFunding = Boolean(', 'Duplicate validator funding replay guard');
assertIncludes(v18Source, 'bondSubmissionPending', 'Duplicate validator self-bond replay guard');
assertIncludes(v18Source, "onboardingNextAction(result) === 'complete_validator_self_bond'", 'Runtime-ready automatic validator self-bond');
assertIncludes(v18Source, 'Validator self-bond is confirmed on-chain. Continuing guarded onboarding.', 'Canonical self-bond confirmation gate');
assertIncludes(v18Source, "syncStatusIsVerified(context.selectedNodeLive, 'normal')", 'Live zero-gap sync can reconcile stale setup state');
assertIncludes(v18Source, 'continueToLaunchAndActivate', 'Launch continuation records verified sync evidence before advancing');
assertIncludes(v18Source, 'Normal peer sync started. Continue to Launch & Activate', 'Normal sync hands ongoing catch-up to guarded onboarding');
assertIncludes(v18Source, 'Normal Sync Running', 'Normal sync running state');
assertIncludes(v18Source, 'Switch to Fast Snapshot Sync', 'Normal sync snapshot recovery action');
assertIncludes(v18Source, 'readinessChecksAreVerified(checks)', 'Live readiness evidence can recover stale device-check state');
assertIncludes(v18Source, 'Committee Node', 'Future node type');
assertIncludes(v18Source, 'disabled={!enabled}', 'Future node type disabled gate');
assertIncludes(v18Source, 'Coordinator + handshake confirmed', 'Coordinator and handshake gate');
assertIncludes(v18Source, 'One-time onboarding token', 'Coordinator invite token input');
assertIncludes(v18Source, 'SETUP_WIZARD_STORAGE_PREFIX', 'Setup wizard persistence');
assertIncludes(v18Source, 'restoreStoredProvisioningState', 'Provisioning state restore');
assertIncludes(v18Source, 'Start Validator Onboarding', 'Autonomous onboarding monitor');
assertIncludes(v18Source, 'Submit Activation Transaction', 'Operator activation action');
assertIncludes(v18Source, 'requestWalletAction', 'Mobile wallet staking approval');
assertIncludes(v18Source, 'Launch is waiting for bonded stake from the connected Synergy Wallet', 'Wallet-owned stake block');

const provisioningSource = read('src/services/validatorProvisioningService.js');
assertIncludes(provisioningSource, 'requireBootstrapEligibility(input?.eligibility)', 'Funded validator bootstrap gate');
assertIncludes(provisioningSource, "eligibility?.fundingReadyToBond === true && eligibility?.eligibilityStatus === 'stake_ready_to_bond'", 'Confirmed funding bootstrap status');

const coordinatorSource = read('control-service/src/control_service.rs');
assertIncludes(coordinatorSource, 'eligibility.eligible || eligibility.funding_ready_to_bond', 'Coordinator funded-validator Innernet bootstrap gate');

const testnetSource = read('control-service/src/testnet.rs');
assertIncludes(testnetSource, '"complete_validator_self_bond"', 'Machine-readable self-bond onboarding action');
assertIncludes(testnetSource, 'result.message = blocked_message.to_string();', 'Onboarding message and action separation');
assertNotIncludes(v18Source, 'Activation remains blocked until the validator VPN enrollment backend returns a valid enrollment result.', 'Old static VPN activation block');
assertNotIncludes(v18Source, 'action-error:${entry.id}', 'Log-derived notification source');
assertIncludes(v18Source, 'useUpdateMonitor', 'V18 updater monitor');
assertIncludes(v18Source, 'updateNotificationForState', 'Updater notification source');
assertIncludes(v18Source, 'footerUpdateLabel(updateState)', 'Footer dynamic updater status');
assertIncludes(v18Source, '© 2026 Synergy Network. All rights reserved.', 'Footer copyright text');
assertIncludes(v18Source, '<span>Version {version}</span><span className="v18-dot is-purple" /> <span>{footerUpdateLabel(updateState)}</span>', 'Footer version and update status');
assertIncludes(v18Source, 'className="v18-footer-action"', 'Footer validator eligibility action');
assertIncludes(v18Source, 'ConfirmationModal', 'Dangerous action confirmation');
assertIncludes(v18Source, 'settingsService.updateSettings', 'Settings persistence through service adapter');
assertIncludes(v18Source, '<section className="v18-overview-status-strip"', 'Overview status strip');
assertIncludes(v18Source, 'v18-overview-trend-grid', 'Overview live metric trends');
assertIncludes(v18Source, 'alt="Node Operator Control Panel"', 'Node Operator sidebar banner label');
assertNotIncludes(v18Source, 'v18-window-dots', 'Mock macOS window controls');
assertNotIncludes(v18Source, 'v18-brand-icon', 'Redundant sidebar icon above banner');

const v18Css = read('src/styles/controlPanelV18.css');
assertNotIncludes(v18Css, '.v18-window-dots', 'Mock macOS window control styles');
assertNotIncludes(v18Css, '.v18-brand-icon', 'Redundant sidebar icon styles');

const nodeOperatorBanner = fs.readFileSync(path.join(root, 'public/branding/assets/control-panel-banner.png'));
assert(nodeOperatorBanner.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])), 'Control panel banner must be a PNG.');
assert(nodeOperatorBanner.readUInt32BE(16) === 445 && nodeOperatorBanner.readUInt32BE(20) === 150, 'Control panel banner must use the supplied Node Operator artwork dimensions.');

const walletConfig = read('src/components/wallet/synergyOnlyWalletConnectionConfig.js');
assertIncludes(walletConfig, 'bannerSrc: controlPanelBannerSrc', 'Control panel wallet banner override');
assertIncludes(walletConfig, 'synergy: true', 'Synergy wallet lane');
assertIncludes(walletConfig, 'evm: false', 'EVM lane disabled');
assertIncludes(walletConfig, 'nonEvm: false', 'Non-EVM lane disabled');
assertIncludes(walletConfig, 'browserProviderEnabled: false', 'Browser Synergy wallet disabled');
assertIncludes(walletConfig, 'mobilePairingEnabled: true', 'Mobile Synergy wallet pairing enabled');

const walletCard = read('src/components/wallet/SynergyWalletConnection.jsx');
assertIncludes(walletCard, 'data-wallet-policy="synergy-only"', 'Synergy-only wallet policy marker');
assertIncludes(walletCard, '<WalletModal wallet={modalWallet}', 'Shared wallet modal integration');
assertIncludes(walletCard, 'startMobilePairing', 'Synergy Wallet mobile pairing path');
assertIncludes(walletCard, "source: 'mobile-pairing'", 'Synergy Wallet mobile pairing source');
assertNotIncludes(walletCard, 'connectEvm', 'Control panel wallet component');
assertNotIncludes(walletCard, 'connectSolana', 'Control panel wallet component');

const masterModal = read('src/wallet-connection/components/wallet/WalletModal.jsx');
assertIncludes(masterModal, 'snrg-btn.png', 'Copied master wallet SNRG icon');
assertIncludes(masterModal, 'eth-btn.png', 'Copied master wallet EVM icon');
assertIncludes(masterModal, 'net-btn.png', 'Copied master wallet non-EVM icon');
assertIncludes(masterModal, 'wallet-modal__brand--banner', 'Wallet banner support');

const masterCss = read('src/wallet-connection/components/wallet/wallet-connection.css');
assertIncludes(masterCss, '@keyframes wallet-family-spin', 'Rotating SNRG icon animation');
assertIncludes(masterCss, '.wallet-modal__family--synergy:hover', 'Synergy hover glow');
assertIncludes(masterCss, '.wallet-modal__family--evm:hover', 'EVM hover glow');
assertIncludes(masterCss, '.wallet-modal__family--non-evm:hover', 'Non-EVM hover glow');

const packageJson = JSON.parse(read('package.json'));
assert(/^19\.\d+\.\d+$/.test(packageJson.version), `package.json must remain on the v19 release line, got ${packageJson.version}`);
assertIncludes(v18Source, "useState('unknown')", 'Panel version fallback');
assert(!v18Source.includes(`useState('${packageJson.version}')`), 'Panel version fallback must not hardcode the package version');

const cargoToml = read('control-service/Cargo.toml');
assertIncludes(cargoToml, `version = "${packageJson.version}"`, 'control-service version');

const workflow = read('.github/workflows/release.yml');
assertIncludes(workflow, '# Windows installer builds are intentionally disabled', 'Windows workflow pause');
assertIncludes(workflow, '# - os: windows-latest', 'Windows matrix commented');
assertIncludes(workflow, '#     electron-dist/*.exe', 'Windows release upload commented');

const electronBuilder = read('electron-builder.yml');
assertIncludes(electronBuilder, '# Windows installers are intentionally disabled', 'Electron-builder Windows pause');
assertIncludes(electronBuilder, '# win:', 'Electron-builder Windows block commented');

const verifier = read('scripts/testnet/verify-node-installers.sh');
assertIncludes(verifier, '# "bin/synergy-testnet-windows-amd64.exe"', 'Windows verifier binary commented');
assertIncludes(verifier, '# "install_and_start.ps1"', 'Windows verifier install script commented');

const docs = read('docs/control-panel/v18-ui-architecture-and-validator-onboarding.md');
assertIncludes(docs, '50,000 SNRG', 'V18 docs stake requirement');
assertIncludes(docs, 'Validator VPN', 'V18 docs VPN onboarding');
assertIncludes(docs, 'Synergy-only wallet policy', 'V18 docs wallet policy');

console.log('Control panel v18 UI/UX overhaul acceptance checks passed.');

import { cloneElement, useEffect, useId, useMemo, useRef, useState } from 'react';
import { NavLink, Navigate, Route, Routes, useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Archive,
  ArchiveRestore,
  BadgeCheck,
  BarChart3,
  Bell,
  Blocks,
  BookOpen,
  Braces,
  CalendarClock,
  CalendarDays,
  Camera,
  CheckCircle2,
  ChevronRight,
  ClipboardCheck,
  Coins,
  Clock,
  Copy,
  Cpu,
  Database,
  Download,
  Eye,
  FileArchive,
  FileCheck2,
  FileDown,
  FileInput,
  FileText,
  FlagTriangleRight,
  FolderOpen,
  Gauge,
  Gift,
  GitCompare,
  GitFork,
  GitPullRequestArrow,
  Globe2,
  HardDrive,
  Home,
  KeyRound,
  List,
  LogIn,
  Lock,
  Mail,
  Monitor,
  MonitorDown,
  Network,
  OctagonAlert,
  PackageOpen,
  Pause,
  Play,
  PlugZap,
  Power,
  RadioTower,
  RefreshCcw,
  RefreshCw,
  RotateCcw,
  RotateCw,
  Route as RouteIcon,
  Search,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Square,
  Stethoscope,
  Terminal,
  Trash2,
  Trophy,
  TerminalSquare,
  Upload,
  Users,
  Wallet,
  Wifi,
  XCircle,
  Zap,
} from 'lucide-react';
import {
  formatPeerLastSeen,
  normalizePeerInfoPayload,
  peerMeshStatus,
} from '../../lib/testnetPeerInfo';
import {
  getVersion,
  invoke,
  invokeOnboarding,
  listenOnboardingMeshProgress,
  appendTerminalOutput,
  openTerminalSession,
  showOpenDialog,
  writeAllowlistedOperation,
} from '../../lib/desktopClient';
import {
  checkForUpdate,
  downloadAndInstallUpdate,
  installDownloadedUpdate,
  onUpdaterEvent,
} from '../../lib/appUpdater';
import { controlPanelBannerSrc, controlPanelIconSrc } from '../../lib/runtimeAssets';
import { epochWindowForBlockHeight } from '../../lib/protocolPolicy';
import { useControlPanel } from '../control-panel/ControlPanelProvider';
import {
  formatNumber,
  formatPercent,
  formatRuntimeDuration,
  localRpcEndpointForNode,
  nodeRuntimeLabel,
  nodeSyncPercent,
  queryLocalRpc,
  truncateMiddle,
} from '../control-panel/controlPanelModel';
import SynergyWalletConnection from '../wallet/SynergyWalletConnection';
import { nodeService } from '../../services/nodeService';
import { sessionTimeoutMs, settingsService } from '../../services/settingsService';
import {
  ELIGIBILITY_STATUSES,
  VALIDATOR_FEE_RESERVE_SNRG,
  VALIDATOR_FUNDING_SENDER_MINIMUM_SNRG,
  VALIDATOR_FUNDING_TARGET_SNRG,
  REQUIRED_VALIDATOR_STAKE_SNRG,
  emptyEligibility,
  validatorEligibilityService,
} from '../../services/validatorEligibilityService';
import { validatorProvisioningService } from '../../services/validatorProvisioningService';
import { OPERATION_CATEGORIES as OPERATION_CATALOG } from '../../features/operations/operationCatalog';
import {
  createOperationHandlers,
} from '../../features/operations/operationBindings';
import { getOperationActionBinding } from '../../features/operations/operationActionMap';
import { executeOperationThroughPty } from '../../features/operations/operationExecution';
import DeveloperTerminalDock, { operationTerminalSessionName } from './DeveloperTerminalDock';

const ACTIVE_SYNC_GAP_MAX = 2;
const UPDATE_POLL_MS = 30 * 60 * 1000;
const NOTIFICATION_DISMISSED_STORAGE_KEY = 'synergy:node-control-panel:v18:dismissed-notifications';

function navItemsForSetupState(setupVisible) {
  return [
    ...(setupVisible ? [{ label: 'Setup Node', path: '/setup', icon: Server }] : []),
    { label: 'Overview', path: setupVisible ? '/overview' : '/', icon: Home },
    { label: 'Operations', path: '/operations', icon: TerminalSquare },
    { label: 'Performance', path: '/performance', icon: BarChart3 },
    { label: 'Monitoring', path: '/monitoring', icon: Activity },
    { label: 'Logs', path: '/logs', icon: FileText },
    { label: 'Settings', path: '/settings', icon: Settings },
  ];
}

const SETUP_STEP = Object.freeze({
  welcome: 0,
  nodeRole: 1,
  validatorIdentity: 2,
  walletStake: 3,
  deviceNetworkSync: 4,
  launchActivate: 5,
});

const setupSteps = [
  'Welcome',
  'Choose Node Role',
  'Validator Identity',
  'Wallet & Stake',
  'Device, Network & Sync',
  'Launch & Activate',
];

const healthCheckStages = [
  { id: 'workspace', label: 'Inspecting validator workspace' },
  { id: 'runtime', label: 'Checking control service and runtime state' },
  { id: 'network', label: 'Testing local RPC, ports, and peer reachability' },
  { id: 'readiness', label: 'Loading live readiness checks' },
];

const launchStages = [
  { id: 'profile-registered', statusKey: 'onboarding', label: 'Register validator profile if needed' },
  { id: 'service-started', statusKey: 'service', label: 'Start validator service' },
  { id: 'secure-network-confirmed', statusKey: 'vpn', label: 'Confirm secure network connection' },
  { id: 'validator-synchronized', statusKey: 'sync', label: 'Sync to current chain head' },
  { id: 'observation-mode', statusKey: 'shadow', label: 'Enter observation mode' },
  { id: 'source-proof', statusKey: 'source', label: 'Verify source-majority head match' },
  { id: 'duty-proof', statusKey: 'duties', label: 'Keep consensus duty gates closed' },
  { id: 'shadow-epoch', statusKey: 'shadow', label: 'Complete the required shadow window' },
  { id: 'activation-submitted', statusKey: 'activation-submitted', label: 'Submit activation transaction when eligible' },
  { id: 'activation-ready', statusKey: 'activation-ready', label: 'Await activation epoch' },
  { id: 'active', statusKey: 'active', label: 'Validator active' },
];

const OPERATION_CATEGORY_ICONS = Object.freeze({
  lifecycle: Power,
  'network-vpn': Network,
  'sync-chain-state': RefreshCw,
  'snapshots-recovery': Archive,
  'wallet-keys': Shield,
  consensus: Activity,
  'logs-diagnostics': TerminalSquare,
  'staking-rewards': Wallet,
  'updates-maintenance': Settings,
});

const OPERATION_ACTION_ICONS = Object.freeze({
  Activity,
  Archive,
  ArchiveRestore,
  BadgeCheck,
  BarChart3,
  Blocks,
  BookOpen,
  Braces,
  CalendarClock,
  CalendarDays,
  Camera,
  ClipboardCheck,
  Coins,
  Download,
  Eye,
  FileArchive,
  FileCheck2,
  FileDown,
  FileInput,
  FlagTriangleRight,
  Gauge,
  Gift,
  GitCompare,
  GitFork,
  GitPullRequestArrow,
  HardDrive,
  KeyRound,
  List,
  ListClock: Clock,
  LogIn,
  MonitorDown,
  Network,
  OctagonAlert,
  PackageOpen,
  Play,
  PlugZap,
  RadioTower,
  RefreshCcw,
  RefreshCw,
  RotateCcw,
  RotateCw,
  Route: RouteIcon,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Square,
  Stethoscope,
  Terminal,
  Trash2,
  Users,
});

const OPERATION_CATEGORY_TONES = Object.freeze({
  lifecycle: 'green',
  'network-vpn': 'blue',
  'sync-chain-state': 'cyan',
  'snapshots-recovery': 'purple',
  'wallet-keys': 'lime',
  consensus: 'yellow',
  'logs-diagnostics': 'orange',
  'staking-rewards': 'red',
  'updates-maintenance': 'indigo',
});

function availableOperationTooltip(value) {
  return String(value || '')
    .replace(/^Planned:\s*/i, '')
    .replace(/^Planned tools\b/i, 'Tools');
}

function operationTerminalTooltip(operation, fallback = '') {
  const base = availableOperationTooltip(operation?.tooltip || operation?.detail || operation?.description || fallback);
  const command = String(operation?.displayCommand || '').trim();
  const terminalCopy = command
    ? `Runs in the in-app Node shell as "${command}".`
    : 'Runs in the in-app Node shell.';
  return base ? `${base} ${terminalCopy}` : terminalCopy;
}

const OPERATION_CATEGORIES = OPERATION_CATALOG.map((category) => ({
  ...category,
  detail: category.description,
  tooltip: availableOperationTooltip(category.tooltip || category.description),
  icon: OPERATION_CATEGORY_ICONS[category.id] || TerminalSquare,
  tone: OPERATION_CATEGORY_TONES[category.id] || 'blue',
  actions: category.actions
    .filter((action) => Boolean(getOperationActionBinding(action.actionId)))
    .map((action) => ({
      ...action,
      id: action.actionId,
      detail: action.description,
      tooltip: availableOperationTooltip(action.tooltip || action.description),
      icon: OPERATION_ACTION_ICONS[action.icon] || OPERATION_CATEGORY_ICONS[category.id] || TerminalSquare,
      binding: getOperationActionBinding(action.actionId),
      handler: getOperationActionBinding(action.actionId).handler,
      dangerous: Boolean(action.requiresConfirmation),
      requiresOwnerWallet: Boolean(action.requiresOwnerWallet)
        || getOperationActionBinding(action.actionId).handler === 'eligibility',
      roleIds: action.validatorOnly ? ['validator'] : undefined,
    })),
})).filter((category) => category.actions.length > 0);

const SHADOW_EPOCH_POLL_MS = 30_000;
const SETUP_SYNC_POLL_MS = 10_000;
const SETUP_SYNC_MAX_ATTEMPTS = 720;
const ACTIVATION_MONITOR_POLL_MS = 12_000;
const OPERATION_TOOLTIP_DELAY_MS = 450;
const SETUP_WIZARD_STORAGE_PREFIX = 'synergy:node-control-panel:v18:setup-wizard-v2';
const CONTINUABLE_ONBOARDING_ACTIONS = new Set([
  'wait_for_live_head_match',
  'wait_for_epoch_boundary',
  'wait_for_registry_activation_confirmation',
  'sync_catch_up',
  'run_full_shadow_epoch',
  'continue_full_shadow_epoch',
  'regenerate_shadow_epoch_proof',
  'restore_archive_validator_pruned_snapshot',
  'prove_source_majority_head_match',
  'regenerate_source_majority_proof',
  'prove_source_majority_with_validator_relayers_or_archive',
  'prove_activation_evidence',
  'prove_onboarding_duty_gates_closed',
  'regenerate_duty_gate_proof',
  'monitor_active_validator',
]);

function cls(...values) {
  return values.filter(Boolean).join(' ');
}

function sleep(ms) {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

function extractWalletActionTxHash(result) {
  const candidates = [
    result?.txHash,
    result?.tx_hash,
    result?.transactionHash,
    result?.transaction_hash,
    result?.transactionId,
    result?.transaction_id,
    result?.txid,
    result?.hash,
    result?.data?.txHash,
    result?.data?.transactionHash,
    result?.payload?.txHash,
    result?.payload?.transactionHash,
    result?.transaction?.hash,
    result?.receipt?.transactionHash,
    result?.result?.txHash,
    result?.result?.tx_hash,
    result?.result?.transactionHash,
    result?.result?.transaction_hash,
    result?.result?.hash,
    result?.response?.txHash,
    result?.response?.tx_hash,
    result?.response?.transactionHash,
    result?.response?.transaction_hash,
    result?.response?.hash,
  ];
  return candidates.find((candidate) => typeof candidate === 'string' && candidate.trim())?.trim() || '';
}

function onboardingPolicy(result) {
  return result?.policy || result?.preflight?.onboardingPolicy || result?.preflight?.onboarding_policy || {};
}

function activationReadyFromOnboarding(result) {
  const policy = onboardingPolicy(result);
  const preflight = result?.preflight || {};
  return Boolean((policy.activationAllowed || policy.activation_allowed) && (preflight.canActivate || preflight.can_activate));
}

function shadowProgressFromOnboarding(result) {
  const policy = onboardingPolicy(result);
  const gate = policy.shadowEpoch || policy.shadow_epoch || {};
  const detail = gate.detail || 'Waiting for full shadow epoch evidence.';
  const match = detail.match(/observed=(\d+).*required=(\d+)/i);
  if (match) {
    const observed = Number(match[1]);
    const required = Number(match[2]);
    if (Number.isFinite(observed) && Number.isFinite(required) && required > 0) {
      return {
        observed,
        required,
        percent: Math.min(100, Math.round((observed / required) * 100)),
      };
    }
  }
  return { observed: 0, required: 1000, percent: 0 };
}

function finiteNumberFrom(...values) {
  for (const value of values) {
    const number = Number(value);
    if (Number.isFinite(number)) return number;
  }
  return Number.NaN;
}

function extractSyncMetrics(liveStatus) {
  const syncSnapshot = liveStatus?.sync_snapshot || liveStatus?.syncSnapshot || {};
  const targetHeight = finiteNumberFrom(
    syncSnapshot.target_finalized_height,
    syncSnapshot.targetFinalizedHeight,
    liveStatus?.sync_target_height,
    liveStatus?.syncTargetHeight,
    liveStatus?.best_network_height,
    liveStatus?.bestNetworkHeight,
  );
  const localHeight = finiteNumberFrom(
    liveStatus?.local_chain_height,
    liveStatus?.localChainHeight,
    liveStatus?.latest_finalized_height,
    liveStatus?.latestFinalizedHeight,
  );
  const reportedGap = finiteNumberFrom(
    syncSnapshot.blocks_remaining,
    syncSnapshot.blocksRemaining,
    liveStatus?.sync_gap,
    liveStatus?.syncGap,
  );
  const liveGap = Number.isFinite(reportedGap)
    ? reportedGap
    : Number.isFinite(targetHeight) && Number.isFinite(localHeight)
      ? Math.max(0, targetHeight - localHeight)
      : Number.NaN;
  return { liveGap, targetHeight, localHeight };
}

function syncStatusIsVerified(liveStatus, syncMode = 'snapshot') {
  const { liveGap, targetHeight, localHeight } = extractSyncMetrics(liveStatus);
  const maximumGap = syncMode === 'normal' ? 0 : ACTIVE_SYNC_GAP_MAX;
  if (!Number.isFinite(localHeight) || localHeight <= 0 || !Number.isFinite(liveGap) || liveGap > maximumGap) {
    return false;
  }
  return !Number.isFinite(targetHeight) || localHeight + maximumGap >= targetHeight;
}

function setupSyncModeFromState(snapshotState, liveStatus) {
  if (snapshotState?.status === 'normal-sync') return 'normal';
  if (snapshotState?.status === 'success') return 'snapshot';
  if (syncStatusIsVerified(liveStatus, 'normal')) return 'normal';
  return '';
}

function setupSyncIsSelected(snapshotState, liveStatus) {
  return Boolean(setupSyncModeFromState(snapshotState, liveStatus));
}

function readinessChecksAreVerified(checks) {
  return Array.isArray(checks)
    && checks.length > 0
    && checks.every((check) => {
      const status = String(check?.status || '').toLowerCase();
      return !['fail', 'failed', 'error'].includes(status);
    });
}

function activationConfirmedFromOnboarding(result) {
  const status = String(result?.status || '').toLowerCase();
  const state = String(result?.state || '').toUpperCase();
  const confirmationStatus = String(
    result?.policy?.activationConfirmation?.status
      || result?.policy?.activation_confirmation?.status
      || '',
  ).toLowerCase();
  return status === 'complete'
    || state === 'ACTIVE'
    || state === 'ACTIVE_CONFIRMED'
    || confirmationStatus === 'pass';
}

function activeConsensusEvidence(value) {
  return Boolean(value?.is_consensus_active || value?.consensus_active);
}

function normalizeStoredActivationPending(value) {
  if (!value || typeof value !== 'object' || value.status !== 'pending' || !value.nodeId) return null;
  return {
    status: 'pending',
    nodeId: value.nodeId,
    txHash: value.txHash || '',
    syncMode: value.syncMode === 'normal' ? 'normal' : 'snapshot',
    targetId: value.targetId || 'local',
    walletAddress: value.walletAddress || '',
    submittedAt: value.submittedAt || '',
    lastCheckedAt: value.lastCheckedAt || '',
  };
}

function setupWizardStorageKey(nodeId) {
  return `${SETUP_WIZARD_STORAGE_PREFIX}:${nodeId || 'pending-node'}`;
}

function readSetupWizardState(nodeId) {
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.localStorage.getItem(setupWizardStorageKey(nodeId));
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function writeSetupWizardState(nodeId, patch) {
  if (typeof window === 'undefined') return;
  try {
    const previous = readSetupWizardState(nodeId) || {};
    window.localStorage.setItem(
      setupWizardStorageKey(nodeId),
      JSON.stringify({
        ...previous,
        ...patch,
        nodeId: nodeId || previous.nodeId || '',
        updatedAt: new Date().toISOString(),
      }),
    );
  } catch {
    // Setup persistence should never block validator operations.
  }
}

function clearSetupWizardState(nodeId) {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.removeItem(setupWizardStorageKey(nodeId));
  } catch {
    // Setup persistence should never block validator operations.
  }
}

function normalizeSetupStep(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  return Math.max(0, Math.min(setupSteps.length - 1, Math.trunc(numeric)));
}

function normalizeStoredEligibility(value, fallbackWalletAddress = '') {
  const stored = value && typeof value === 'object' ? value : {};
  const requiredStake = REQUIRED_VALIDATOR_STAKE_SNRG;
  const activeStakeAmount = Number(stored.activeStakeAmount);
  const activeStakeIsCurrent = Number.isFinite(activeStakeAmount) && activeStakeAmount >= requiredStake;
  const validatorFundingAmount = Number(stored.validatorFundingAmount);
  const fundingReadyToBond = !activeStakeIsCurrent
    && Number.isFinite(validatorFundingAmount)
    && validatorFundingAmount >= VALIDATOR_FUNDING_TARGET_SNRG;
  return {
    ...emptyEligibility(fallbackWalletAddress),
    ...stored,
    activeStakeAmount: Number.isFinite(activeStakeAmount) ? activeStakeAmount : 0,
    requiredStake,
    validatorFundingAmount: Number.isFinite(validatorFundingAmount) ? validatorFundingAmount : 0,
    fundingReadyToBond,
    eligible: stored.eligibilityStatus === ELIGIBILITY_STATUSES.eligible && activeStakeIsCurrent,
    walletAddress: stored.walletAddress || fallbackWalletAddress || '',
  };
}

function mergePendingEligibility(current, next) {
  const bonded = next?.eligible === true && next?.eligibilityStatus === ELIGIBILITY_STATUSES.eligible;
  return {
    ...next,
    stakeTxHash: next?.stakeTxHash || current?.stakeTxHash || '',
    bondTxHash: bonded ? '' : current?.bondTxHash || '',
    bondTxStatus: bonded ? 'confirmed' : current?.bondTxStatus || 'not_provided',
  };
}

function restoreStoredProvisioningState(value) {
  const restored = value && typeof value === 'object' ? value : {};
  const wasRunning = restored.running === true;
  return {
    running: false,
    stageId: restored.stageId || '',
    steps: restored.steps && typeof restored.steps === 'object' ? restored.steps : {},
    result: restored.result || null,
    message: wasRunning
      ? 'Onboarding monitor paused while you were away. Resume to continue shadow epoch observation.'
      : restored.message || '',
    error: restored.error || '',
  };
}

function onboardingNextAction(result) {
  return String(result?.nextAction || result?.next_action || '').trim();
}

function onboardingCanContinue(result) {
  if (!result || String(result.status || '').toLowerCase() !== 'blocked') return true;
  return CONTINUABLE_ONBOARDING_ACTIONS.has(onboardingNextAction(result));
}

function onboardingStepStatuses(result) {
  const status = String(result?.status || '').toLowerCase();
  const blockedContinuable = status === 'blocked' && onboardingCanContinue(result);
  return {
    onboarding: status === 'failed' || (status === 'blocked' && !blockedContinuable)
      ? 'error'
      : ['complete', 'ready'].includes(status)
        ? 'success'
        : 'running',
    shadow: blockedContinuable ? 'running' : null,
  };
}

function onboardingMonitorMessage(result) {
  const status = String(result?.status || '').toLowerCase();
  const nextAction = onboardingNextAction(result);
  if (status === 'blocked' && onboardingCanContinue(result)) {
    if (['run_full_shadow_epoch', 'continue_full_shadow_epoch'].includes(nextAction)) {
      const progress = shadowProgressFromOnboarding(result);
      return `Shadow epoch observation in progress: ${progress.observed}/${progress.required} blocks observed. Monitoring will continue automatically.`;
    }
    if (nextAction === 'wait_for_epoch_boundary') {
      return 'Full shadow epoch observed. Waiting for the next eligible epoch boundary; monitoring will continue automatically.';
    }
  }
  return result?.message || 'Autonomous onboarding is running.';
}

function provisioningStageForNextAction(nextAction) {
  if (nextAction.includes('vpn')) return 'vpn';
  if (nextAction.includes('stake')) return 'stake';
  if (nextAction.includes('source')) return 'source';
  if (nextAction.includes('duty')) return 'duties';
  if (nextAction.includes('shadow') || nextAction.includes('epoch_boundary')) return 'shadow';
  if (nextAction.includes('fork') || nextAction.includes('recover')) return 'sync';
  if (nextAction.includes('sync') || nextAction.includes('snapshot') || nextAction.includes('head_match')) return 'sync';
  if (nextAction.includes('activate')) return 'activation-ready';
  return 'onboarding';
}

function onboardingBlockedMessage(result) {
  const nextAction = onboardingNextAction(result);
  if (nextAction === 'stake_validator') {
    return 'Launch is waiting for bonded stake from the connected Synergy Wallet. Return to Wallet & Stake and complete the wallet-approved bond transaction.';
  }
  if (nextAction === 'restore_archive_validator_pruned_snapshot') {
    return result?.message || 'Snapshot restore is pending or unavailable. Onboarding will keep monitoring while the validator speed syncs from the best available state.';
  }
  if (nextAction === 'repair_monitoring_registration') {
    return result?.message || 'Launch cannot continue until onboarding monitoring registration is repaired.';
  }
  if (nextAction === 'recover_local_fork') {
    return result?.message || 'This validator is stuck on local chain data that does not match the network. Run Recover Local Fork to preserve validator keys, wallet, stake, and VPN enrollment while rebuilding chain data from peers.';
  }
  return result?.message || `Launch is blocked by backend action: ${nextAction || 'unknown'}.`;
}

function statusLabel(context) {
  const runtime = nodeRuntimeLabel(context.selectedNodeLive);
  return runtime === 'Healthy' ? 'Healthy' : runtime;
}

function statusToneClass(nodeLive, error = '') {
  if (!nodeLive?.is_running || nodeLive?.is_offline) return 'gray';
  if (error) return 'red';
  if (nodeLive?.is_quarantined || nodeLive?.is_failed_closed) return 'red';
  if (nodeLive.local_rpc_ready === false || (Number(nodeLive.sync_gap) || 0) > 0 || nodeLive.is_syncing) return 'blue';
  const failedChecks = Array.isArray(nodeLive.readiness?.checks)
    ? nodeLive.readiness.checks.filter((check) => check.status !== 'pass')
    : [];
  if (failedChecks.length) return 'yellow';
  return 'green';
}

function readDismissedNotificationKeys() {
  if (typeof window === 'undefined') return new Set();
  try {
    return new Set(JSON.parse(window.localStorage.getItem(NOTIFICATION_DISMISSED_STORAGE_KEY) || '[]'));
  } catch {
    return new Set();
  }
}

function writeDismissedNotificationKeys(keys) {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(NOTIFICATION_DISMISSED_STORAGE_KEY, JSON.stringify(Array.from(keys).slice(-200)));
  } catch {
    // Dismissed notifications are helpful persistence, not required app state.
  }
}

function notificationTimestamp() {
  return Date.now();
}

function buildStateNotifications(context) {
  const node = context.selectedNode || {};
  const live = context.selectedNodeLive || {};
  const notifications = [];
  const nodeId = node.id || 'selected-node';

  if (context.error) {
    notifications.push({
      key: `service-error:${context.error}`,
      title: 'Control service needs attention',
      detail: context.error,
      tone: 'red',
      at: notificationTimestamp(),
    });
  }

  const syncGap = Number(live.sync_gap);
  if (Number.isFinite(syncGap) && syncGap > ACTIVE_SYNC_GAP_MAX) {
    notifications.push({
      key: `sync-gap:${nodeId}:${Math.floor(syncGap / 25)}`,
      title: 'Validator is syncing',
      detail: `${formatNumber(syncGap)} block(s) behind the live chain head.`,
      tone: 'blue',
      at: notificationTimestamp(),
    });
  }

  if (live.is_quarantined || live.is_failed_closed) {
    notifications.push({
      key: `validator-safety:${nodeId}:${live.is_quarantined ? 'quarantine' : 'failed-closed'}`,
      title: live.is_quarantined ? 'Validator quarantined' : 'Validator failed closed',
      detail: 'The live validator status reported a safety state that requires operator attention.',
      tone: 'red',
      at: notificationTimestamp(),
    });
  }

  (live.readiness?.checks || [])
    .filter((check) => check.status !== 'pass')
    .forEach((check) => {
      notifications.push({
        key: `readiness:${nodeId}:${check.id || check.label}:${check.status}:${check.detail || ''}`,
        title: check.label || 'Readiness check failed',
        detail: check.detail || `Readiness status: ${check.status}`,
        tone: check.status === 'fail' ? 'red' : 'yellow',
        at: notificationTimestamp(),
      });
    });

  return notifications;
}

function usePanelNotifications(context) {
  const [dismissedKeys, setDismissedKeys] = useState(() => readDismissedNotificationKeys());
  const previousRuntimeRef = useRef('');
  const [runtimeNotifications, setRuntimeNotifications] = useState([]);

  useEffect(() => {
    const runtime = nodeRuntimeLabel(context.selectedNodeLive);
    const nodeId = context.selectedNode?.id || 'selected-node';
    const previousRuntime = previousRuntimeRef.current;
    previousRuntimeRef.current = runtime;
    if (!previousRuntime || previousRuntime === runtime) return;
    const notification = {
      key: `runtime-transition:${nodeId}:${previousRuntime}->${runtime}:${Date.now()}`,
      title: 'Node status changed',
      detail: `${previousRuntime} -> ${runtime}`,
      tone: statusToneClass(context.selectedNodeLive, context.error),
      at: Date.now(),
    };
    setRuntimeNotifications((current) => [notification, ...current].slice(0, 20));
  }, [context.error, context.selectedNode?.id, context.selectedNodeLive]);

  const notifications = useMemo(() => {
    const dismissed = dismissedKeys;
    return [...runtimeNotifications, ...buildStateNotifications(context)]
      .filter((item) => !dismissed.has(item.key))
      .sort((left, right) => (right.at || 0) - (left.at || 0))
      .slice(0, 20);
  }, [context, dismissedKeys, runtimeNotifications]);

  const dismiss = (key) => {
    setDismissedKeys((current) => {
      const next = new Set(current);
      next.add(key);
      writeDismissedNotificationKeys(next);
      return next;
    });
  };

  const clearAll = () => {
    setDismissedKeys((current) => {
      const next = new Set(current);
      notifications.forEach((item) => next.add(item.key));
      writeDismissedNotificationKeys(next);
      return next;
    });
  };

  return { notifications, dismiss, clearAll };
}

function readObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function stringValue(...values) {
  for (const value of values) {
    if (typeof value === 'string' && value.trim()) return value.trim();
    if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  }
  return '';
}

function snapshotCopyValues(result) {
  const root = readObject(result);
  const restore = readObject(root.restore || root);
  const evidence = readObject(restore.evidence || root.evidence);
  const manifest = readObject(restore.manifest || root.manifest || evidence.manifest);
  return {
    manifest: stringValue(
      restore.manifestPath,
      restore.manifest_path,
      restore.snapshotManifestPath,
      restore.snapshot_manifest_path,
      restore.manifestUrl,
      restore.manifest_url,
      root.manifestPath,
      root.manifest_path,
      evidence.distributionManifestPath,
      evidence.distribution_manifest_path,
      evidence.snapshotManifestPath,
      evidence.snapshot_manifest_path,
      manifest.path,
      manifest.url,
    ),
    snapshotHash: stringValue(
      restore.snapshotHash,
      restore.snapshot_hash,
      restore.hash,
      root.snapshotHash,
      root.snapshot_hash,
      evidence.snapshotHash,
      evidence.snapshot_hash,
      evidence.hash,
    ),
    manifestHash: stringValue(
      restore.manifestSha256,
      restore.manifest_sha256,
      restore.manifestHash,
      restore.manifest_hash,
      restore.sourceManifestSha256,
      restore.source_manifest_sha256,
      root.manifestSha256,
      root.manifest_sha256,
      root.manifestHash,
      root.manifest_hash,
      evidence.manifestSha256,
      evidence.manifest_sha256,
      evidence.sourceManifestSha256,
      evidence.source_manifest_sha256,
      manifest.sha256,
      manifest.hash,
    ),
    archiveHash: stringValue(
      restore.archiveSha256,
      restore.archive_sha256,
      root.archiveSha256,
      root.archive_sha256,
      evidence.archiveSha256,
      evidence.archive_sha256,
    ),
  };
}

const DEFAULT_VALIDATOR_STORAGE_PATH = '~/.synergy-node-control-panel/validator';

function validatorStoragePath(node) {
  return node?.workspace_directory || node?.workspaceDirectory || node?.data_directory || DEFAULT_VALIDATOR_STORAGE_PATH;
}

function setupConfigForNode(node, stored = {}) {
  return {
    nodeType: stored.nodeType || 'validator',
    nodeNickname: stored.nodeNickname || node?.display_label || 'My Validator Node',
    network: stored.network || 'Synergy Testnet',
    storageLocation: stored.storageLocation || validatorStoragePath(node),
    snapshotSync: stored.snapshotSync !== false,
    targetMode: stored.targetMode || 'local',
    targetLabel: stored.targetLabel || '',
    targetId: stored.targetId || (stored.targetMode === 'remote' ? '' : 'local'),
    targetHost: stored.targetHost || '',
    targetPort: stored.targetPort || 22,
    targetUsername: stored.targetUsername || '',
    targetAuthMethod: stored.targetAuthMethod || 'ncp_managed_key',
    remoteNodeId: stored.remoteNodeId || '',
    remoteNodeAddress: stored.remoteNodeAddress || '',
    remoteWorkspaceDirectory: stored.remoteWorkspaceDirectory || '',
    backupLocation: stored.backupLocation || '',
  };
}

function targetConnectionState(target) {
  const value = String(
    target?.connectionStatus
      || target?.connection_status
      || target?.status
      || '',
  ).toLowerCase();
  if (target?.connected === true || ['connected', 'ready', 'online', 'verified'].includes(value)) return 'connected';
  if (target?.reachable === false || ['failed', 'unreachable', 'auth_failed'].includes(value)) return 'error';
  return 'unknown';
}

function secureNetworkTruth(result, live) {
  const root = readObject(result);
  const detail = readObject(root.detail);
  const coordinator = readObject(root.coordinator || root.coordinatorStatus || root.coordinator_status);
  const mesh = readObject(root.mesh || root.network || root.secureNetwork || root.secure_network);
  const localInterfaceEvidence = readObject(
    root.localInterfaceEvidence
      || root.local_interface_evidence
      || detail.localInterfaceEvidence
      || detail.local_interface_evidence,
  );
  const coordinatorStatus = String(
    coordinator.status
      || coordinator.state
      || root.coordinatorStatus
      || root.coordinator_status
      || root.applyStatus
      || root.apply_status
      || root.status
      || detail.applyStatus
      || detail.apply_status
      || detail.status
      || '',
  ).toLowerCase();
  const handshakeConfirmed = Boolean(
    root.handshakeConfirmed
      ?? root.handshake_confirmed
      ?? root.connected
      ?? mesh.handshakeConfirmed
      ?? mesh.handshake_confirmed
      ?? localInterfaceEvidence.handshakeConfirmed
      ?? localInterfaceEvidence.handshake_confirmed,
  );
  const assignedIp = stringValue(
    root.assignedIp,
    root.assigned_ip,
    root.vpnIp,
    root.vpn_ip,
    mesh.assignedIp,
    mesh.assigned_ip,
    localInterfaceEvidence.assignedIp,
    localInterfaceEvidence.assigned_ip,
    live?.validator_vpn_ip,
    live?.validator_vpn_address,
  );
  const peersConnected = Number(
    root.peersConnected
      ?? root.peers_connected
      ?? mesh.peersConnected
      ?? mesh.peers_connected
      ?? detail.peersConnected
      ?? detail.peers_connected,
  );
  const vpnRouteCheck = (live?.readiness?.checks || []).find((check) => check?.id === 'validator-vpn-route');
  const vpnRouteConfirmed = String(vpnRouteCheck?.status || '').toLowerCase() === 'pass';
  const livePeerCount = Number(live?.local_peer_count ?? live?.localPeerCount);
  const livePeerTransportConfirmed = Boolean(
    live?.is_running
      && live?.local_rpc_ready
      && Number.isFinite(livePeerCount)
      && livePeerCount > 0,
  );
  const coordinatorConfirmed = ['applied', 'connected', 'active', 'ready', 'confirmed', 'enrolled', 'coordinator_managed'].includes(coordinatorStatus)
    || Boolean(root.coordinatorConfirmed || root.coordinator_confirmed)
    || vpnRouteConfirmed
    || livePeerTransportConfirmed;
  const liveConfirmed = live?.secure_network_status === 'connected'
    || live?.secure_network_connected === true
    || live?.validator_vpn_connected === true
    || vpnRouteConfirmed
    || livePeerTransportConfirmed;
  const handshakeEvidence = handshakeConfirmed
    || (Number.isFinite(peersConnected) && peersConnected > 0)
    || livePeerTransportConfirmed;
  return {
    confirmed: Boolean((coordinatorConfirmed || liveConfirmed) && handshakeEvidence),
    coordinatorConfirmed,
    handshakeConfirmed: Boolean(handshakeEvidence),
    assignedIp,
    peersConnected: Number.isFinite(peersConnected) ? peersConnected : null,
  };
}

function logLevelKey(level) {
  const normalized = String(level || '').trim().toLowerCase();
  if (normalized.includes('warn')) return 'warning';
  if (normalized.includes('err') || normalized.includes('fail') || normalized.includes('critical')) return 'error';
  if (normalized.includes('service')) return 'service';
  if (normalized.includes('network') || normalized.includes('p2p') || normalized.includes('peer')) return 'network';
  return normalized || 'info';
}

function formatBytes(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const exponent = Math.min(units.length - 1, Math.floor(Math.log(numeric) / Math.log(1024)));
  return `${(numeric / (1024 ** exponent)).toLocaleString(undefined, { maximumFractionDigits: exponent === 0 ? 0 : 1 })} ${units[exponent]}`;
}

function firstFiniteValue(source, keys) {
  for (const key of keys) {
    const value = source?.[key];
    if (value == null || value === '') continue;
    const numeric = Number(value);
    if (Number.isFinite(numeric)) return numeric;
  }
  return null;
}

function operationsRoleLabel(context) {
  const role = context.selectedRole || {};
  return stringValue(
    role.label,
    role.display_label,
    role.displayLabel,
    role.name,
    context.selectedNode?.role_label,
  ) || titleizeMetric(context.selectedNode?.role_id || 'node');
}

function operationAvailability(operation, node, roleId, roleLabel) {
  if (!node?.id) return { available: false, message: 'Select a provisioned node before running this control.' };
  if (operation.roleIds?.length && !operation.roleIds.includes(roleId)) {
    return {
      available: false,
      message: `${operation.label} is not mapped for the selected ${roleLabel} role.`,
    };
  }
  if (operation.requiresOwnerWallet && !stringValue(node.owner_wallet_address, node.ownerWalletAddress)) {
    return { available: false, message: 'Connect and assign the node owner wallet before running this check.' };
  }
  return { available: true, message: '' };
}

function OperationTooltip({ message, label, disabled = false, children }) {
  const tooltipId = `operation-tooltip-${useId().replace(/:/g, '')}`;
  const timeoutRef = useRef(null);
  const [visible, setVisible] = useState(false);

  const showTooltip = () => {
    window.clearTimeout(timeoutRef.current);
    timeoutRef.current = window.setTimeout(() => setVisible(true), OPERATION_TOOLTIP_DELAY_MS);
  };

  const hideTooltip = () => {
    window.clearTimeout(timeoutRef.current);
    timeoutRef.current = null;
    setVisible(false);
  };

  useEffect(() => () => window.clearTimeout(timeoutRef.current), []);

  return (
    <span
      className="v18-operation-tooltip-trigger"
      tabIndex={disabled ? 0 : undefined}
      aria-label={disabled ? label : undefined}
      aria-describedby={visible ? tooltipId : undefined}
      onMouseEnter={showTooltip}
      onMouseLeave={hideTooltip}
      onFocus={showTooltip}
      onBlur={hideTooltip}
    >
      {cloneElement(children, { 'aria-describedby': visible ? tooltipId : undefined })}
      {visible ? <span id={tooltipId} className="v18-operation-tooltip" role="tooltip">{message}</span> : null}
    </span>
  );
}

function terminalTime(value) {
  const date = value ? new Date(value) : null;
  return date && !Number.isNaN(date.valueOf()) ? date.toLocaleTimeString() : 'Unknown time';
}

function operationResultMessage(result, fallback, operationId = '') {
  if (typeof result === 'string' && result.trim()) return result.trim();

  if (operationId === 'operations.network-vpn.view-connected-peers') {
    const probes = Array.isArray(result?.rpc?.probes) ? result.rpc.probes : [];
    const peerProbe = probes.find((probe) => probe?.method === 'synergy_getPeerInfo');
    const peers = Array.isArray(peerProbe?.result?.peers) ? peerProbe.result.peers : [];
    if (!peerProbe || peerProbe.status !== 'pass') {
      return 'Connected peer details are unavailable because the local node RPC did not answer the peer query.';
    }
    if (!peers.length) return 'The local node RPC reports no connected peers.';
    const identities = peers
      .map((peer) => stringValue(peer?.validator_address, peer?.node_id, peer?.public_address, peer?.address))
      .filter(Boolean)
      .slice(0, 4)
      .map((identity) => truncateMiddle(identity, 9, 6));
    return `${formatNumber(peers.length)} connected peer(s): ${identities.join(', ')}${peers.length > identities.length ? ', and more' : ''}.`;
  }

  if (operationId === 'operations.sync-chain-state.inspect-recent-blocks') {
    const blocks = Array.isArray(result)
      ? result
      : Array.isArray(result?.chain?.blocks) ? result.chain.blocks : [];
    const latest = blocks[0] || {};
    const latestHeight = firstFiniteValue(latest, ['number', 'block_index', 'blockNumber', 'height']);
    return blocks.length
      ? `Loaded ${formatNumber(blocks.length)} recent local block(s)${latestHeight == null ? '' : ` through block ${formatNumber(latestHeight)}`}.`
      : 'No recent local blocks were returned. Check whether the node runtime and local RPC are running.';
  }

  const exportPath = stringValue(result?.file_path, result?.filePath);
  if (operationId === 'operations.logs-diagnostics.export-support-bundle' && exportPath) {
    const bytes = firstFiniteValue(result, ['bytes']);
    return `Support bundle saved to ${exportPath}${bytes == null ? '' : ` (${formatBytes(bytes)})`}.`;
  }

  const explicit = stringValue(result?.message, result?.detail);
  if (explicit) return explicit;

  const featureScreen = stringValue(result?.screenKey, result?.screen_key).toLowerCase();
  const featureLive = readObject(result?.live);
  if (featureScreen === 'consensus') {
    const connectedPeers = firstFiniteValue(featureLive, ['connected_validator_count', 'local_peer_count']);
    const knownPeers = firstFiniteValue(featureLive, ['status_ready_validator_count']);
    const localHeight = firstFiniteValue(featureLive, ['local_chain_height']);
    const syncGap = firstFiniteValue(featureLive, ['sync_gap']);
    const parts = [connectedPeers == null ? 'Connected peer count is unavailable' : `${formatNumber(connectedPeers)} connected validator peer(s)`];
    if (knownPeers != null) parts.push(`${formatNumber(knownPeers)} status-ready peer(s)`);
    if (localHeight != null) parts.push(`local block ${formatNumber(localHeight)}`);
    if (syncGap != null) parts.push(`${formatNumber(syncGap)} block sync gap`);
    return `${parts.join('; ')}.`;
  }

  if (featureScreen === 'storage') {
    const storage = readObject(result?.storage);
    const disk = readObject(storage.disk);
    const workspaceBytes = firstFiniteValue(storage, ['workspaceBytes', 'workspace_bytes']);
    const availableBytes = firstFiniteValue(disk, ['availableBytes', 'available_bytes']);
    const fileCount = firstFiniteValue(storage, ['workspaceFiles', 'workspace_files']);
    return [
      workspaceBytes == null ? 'Workspace size is unavailable' : `Workspace uses ${formatBytes(workspaceBytes)}`,
      availableBytes == null ? 'free disk space is unavailable' : `${formatBytes(availableBytes)} free on this disk`,
      fileCount == null ? '' : `${formatNumber(fileCount)} workspace file(s)`,
    ].filter(Boolean).join('; ');
  }

  if (featureScreen === 'config') {
    const files = Array.isArray(result?.config?.files) ? result.config.files : [];
    const present = files.filter((file) => file?.exists).length;
    return `Configuration check found ${formatNumber(present)} of ${formatNumber(files.length)} expected file(s).`;
  }

  if (featureScreen === 'diagnostics') {
    const diagnostics = readObject(result?.diagnostics);
    const processes = Array.isArray(diagnostics.processes) ? diagnostics.processes.length : 0;
    const listenersReady = Number(diagnostics?.listeners?.status) === 0;
    const diskReady = Number(diagnostics?.disk?.status) === 0;
    return `${formatNumber(processes)} matching runtime process(es); port inspection ${listenersReady ? 'completed' : 'needs attention'}; disk inspection ${diskReady ? 'completed' : 'needs attention'}.`;
  }

  if (featureScreen === 'api') {
    const probes = Array.isArray(result?.rpc?.probes) ? result.rpc.probes : [];
    const passing = probes.filter((probe) => probe?.status === 'pass').length;
    return `Local RPC diagnostics: ${formatNumber(passing)} of ${formatNumber(probes.length)} read-only request(s) passed.`;
  }

  if (featureScreen === 'dag') {
    const dag = readObject(result?.dag);
    const vertices = Array.isArray(dag.vertices) ? dag.vertices.length : 0;
    const certificates = Array.isArray(dag.certificates) ? dag.certificates.length : 0;
    return dag.available === false
      ? `DAG data is unavailable: ${stringValue(dag.detail, 'the local RPC did not return ordering data')}.`
      : `DAG data is available with ${formatNumber(vertices)} vertex record(s) and ${formatNumber(certificates)} certificate(s).`;
  }

  if (featureScreen === 'transactions') {
    const mempool = readObject(result?.mempool);
    const pending = firstFiniteValue(mempool?.stats, ['pendingCount']);
    return mempool.available === false
      ? `The pending transaction queue is unavailable: ${stringValue(mempool.detail, 'the local RPC did not respond')}.`
      : `The local transaction queue is responding with ${formatNumber(pending ?? 0)} pending transaction(s).`;
  }

  if (featureScreen === 'security') {
    const probes = Array.isArray(result?.rpc?.probes) ? result.rpc.probes : [];
    const passingProbes = probes.filter((probe) => probe?.status === 'pass').length;
    const checks = reportCheckCounts(result);
    return `Security inspection: ${formatNumber(checks.passed)} of ${formatNumber(checks.total)} readiness checks passed; ${formatNumber(passingProbes)} of ${formatNumber(probes.length)} protected RPC probe(s) passed.`;
  }

  if (typeof result?.can_activate === 'boolean' || typeof result?.canActivate === 'boolean') {
    const policy = readObject(result?.onboarding_policy || result?.onboardingPolicy);
    const validatorSet = readObject(policy.validator_set_snapshot || policy.validatorSetSnapshot);
    const activeValidators = Array.isArray(validatorSet.active_validators)
      ? validatorSet.active_validators.length
      : Array.isArray(validatorSet.activeValidators) ? validatorSet.activeValidators.length : null;
    const quorum = firstFiniteValue(validatorSet, ['quorum_threshold', 'quorumThreshold']);
    const checks = reportCheckCounts(result);
    return [
      `Activation checks: ${formatNumber(checks.passed)} of ${formatNumber(checks.total)} passed`,
      activeValidators == null ? '' : `${formatNumber(activeValidators)} active validator(s) in the recorded set`,
      quorum == null ? '' : `quorum ${formatNumber(quorum)}`,
      (result.can_activate ?? result.canActivate) ? 'activation is allowed' : 'activation remains blocked',
    ].filter(Boolean).join('; ');
  }

  const finalizedHeight = firstFiniteValue(result, ['latest_finalized_height', 'local_chain_height']);
  const syncGap = firstFiniteValue(result, ['sync_gap'])
    ?? firstFiniteValue(result?.sync_snapshot, ['blocks_remaining']);
  if (finalizedHeight != null || syncGap != null || result?.current_status) {
    const parts = [stringValue(result?.status_headline, result?.current_status, 'Node status collected.')];
    if (finalizedHeight != null) parts.push(`finalized block ${formatNumber(finalizedHeight)}`);
    if (syncGap != null) parts.push(`${formatNumber(syncGap)} block sync gap`);
    if (typeof result?.is_consensus_active === 'boolean') {
      parts.push(result.is_consensus_active ? 'consensus active' : 'consensus not active');
    }
    if (result?.current_epoch != null) parts.push(`epoch ${formatNumber(result.current_epoch)}`);
    return parts.join('; ');
  }

  const rewards = result?.live;
  if (rewards && typeof rewards === 'object') {
    return [
      `Stake ${formatSnrg(rewards.staked_balance_snrg)} SNRG`,
      `pending rewards ${formatSnrg(rewards.pending_rewards_snrg)} SNRG`,
      `validator ${stringValue(rewards.validator_status, 'status unavailable')}`,
    ].join('; ');
  }

  if (typeof result?.eligible === 'boolean') {
    const missing = firstFiniteValue(result, ['missing_stake_amount', 'missingStakeAmount']);
    return `${result.eligible ? 'Validator eligibility passed' : 'Validator is not yet eligible'}${missing ? `; ${formatNumber(missing)} SNRG still required` : ''}.`;
  }

  const snapshotId = stringValue(result?.snapshotId, result?.snapshot_id, result?.snapshot?.snapshotId, result?.snapshot?.snapshot_id);
  if (snapshotId) {
    const height = firstFiniteValue(result, ['height']) ?? firstFiniteValue(result?.snapshot, ['height']);
    return `Snapshot ${snapshotId}${height == null ? '' : ` at block ${formatNumber(height)}`} is ready.`;
  }

  const checks = reportCheckCounts(result);
  if (checks.total > 0) {
    return `Readiness checks: ${checks.passed} passed, ${checks.warnings} warning(s), ${checks.failed} failed.`;
  }

  const entries = Array.isArray(result?.entries) ? result.entries.length : null;
  if (entries != null) return `Loaded ${formatNumber(entries)} recent log entries.`;

  if (typeof result?.available === 'boolean') {
    return result.available
      ? `Control Panel update ${result.version || ''} is available.`.replace(/\s+is/, ' is')
      : 'This Control Panel is up to date.';
  }

  return stringValue(result?.status && `Status: ${result.status}`) || fallback;
}

function trendPoints(history, key) {
  return (Array.isArray(history) ? history : [])
    .map((point) => ({ at: point?.at, value: firstFiniteValue(point, [key]) }))
    .filter((point) => point.at != null || point.value != null);
}

function finiteChartValue(value) {
  if (value == null || value === '') return null;
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}

function chartTime(value) {
  const numeric = Number(value);
  if (Number.isFinite(numeric) && numeric > 0 && numeric < 1e12) {
    return terminalTime(numeric * 1000);
  }
  return terminalTime(value);
}

function chartDomain(values, fixedDomain) {
  if (fixedDomain) return fixedDomain;
  const minimum = Math.min(...values);
  const maximum = Math.max(...values);
  const range = maximum - minimum;
  const padding = range > 0 ? range * 0.12 : Math.max(1, Math.abs(maximum) * 0.08);
  return [Math.max(0, minimum - padding), maximum + padding || 1];
}

function OperationalLineChart({
  title,
  points = [],
  current,
  tone = 'green',
  formatValue = formatNumber,
  unit = '',
  fixedDomain,
  sampleLabel = 'samples',
  emptyText = 'No history returned for this metric.',
  className = '',
}) {
  const samples = points
    .map((point) => ({ ...point, value: finiteChartValue(point?.value) }))
    .filter((point) => point.at != null || point.value != null)
    .slice(-48);
  const values = samples.map((point) => point.value).filter((value) => value != null);
  const latest = [...samples].reverse().find((point) => point.value != null);
  const currentValue = finiteChartValue(current);
  const displayValue = currentValue ?? latest?.value ?? null;
  const width = 420;
  const height = 170;
  const plot = { left: 54, right: 16, top: 14, bottom: 32 };
  const domain = values.length ? chartDomain(values, fixedDomain) : [0, 1];
  const range = domain[1] - domain[0] || 1;
  const coordinates = samples.map((point, index) => point.value == null ? null : ({
    x: plot.left + (index / Math.max(1, samples.length - 1)) * (width - plot.left - plot.right),
    y: plot.top + (1 - ((point.value - domain[0]) / range)) * (height - plot.top - plot.bottom),
  }));
  const segments = [];
  let segment = [];
  coordinates.forEach((coordinate) => {
    if (coordinate) {
      segment.push(coordinate);
    } else if (segment.length) {
      segments.push(segment);
      segment = [];
    }
  });
  if (segment.length) segments.push(segment);
  const lastCoordinate = coordinates.at(samples.length - 1) || [...coordinates].reverse().find(Boolean);
  const directLabelY = lastCoordinate ? Math.max(plot.top + 12, Math.min(height - plot.bottom - 4, lastCoordinate.y - 9)) : 0;
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((position) => ({
    position,
    value: domain[1] - position * range,
  }));
  const valueLabel = displayValue == null ? 'Unavailable' : `${formatValue(displayValue)}${unit ? ` ${unit}` : ''}`;
  const statusLabel = currentValue != null ? 'Current sample' : latest ? 'Latest history' : 'No sample';

  return (
    <section className={cls('v18-operational-chart', `is-${tone}`, className)} aria-label={`${title} chart`}>
      <header className="v18-operational-chart__header">
        <div>
          <span>{title}</span>
          <strong>{valueLabel}</strong>
        </div>
        <small>{samples.length ? `${samples.length} ${sampleLabel}` : statusLabel}</small>
      </header>
      {values.length ? (
        <div className="v18-operational-chart__plot">
          <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`${title} over time`} preserveAspectRatio="none">
            <g className="v18-operational-chart__grid" aria-hidden="true">
              {ticks.map((tick) => {
                const y = plot.top + tick.position * (height - plot.top - plot.bottom);
                return <line key={tick.position} x1={plot.left} x2={width - plot.right} y1={y} y2={y} />;
              })}
            </g>
            <line className="v18-operational-chart__axis" x1={plot.left} x2={plot.left} y1={plot.top} y2={height - plot.bottom} />
            <g className="v18-operational-chart__axis-labels" aria-hidden="true">
              {ticks.map((tick) => {
                const y = plot.top + tick.position * (height - plot.top - plot.bottom);
                return <text key={tick.position} x={plot.left - 8} y={y + 3} textAnchor="end">{formatValue(tick.value)}</text>;
              })}
            </g>
            {segments.map((pointsSegment, index) => pointsSegment.length > 1 ? <polyline key={index} className="v18-operational-chart__line" points={pointsSegment.map((point) => `${point.x.toFixed(2)},${point.y.toFixed(2)}`).join(' ')} fill="none" /> : null)}
            {lastCoordinate ? <circle className="v18-operational-chart__point" cx={lastCoordinate.x} cy={lastCoordinate.y} r="4" /> : null}
            {latest && lastCoordinate ? <text className="v18-operational-chart__direct-label" x={width - plot.right} y={directLabelY} textAnchor="end">{formatValue(latest.value)}{unit ? ` ${unit}` : ''}</text> : null}
            <g className="v18-operational-chart__time-labels" aria-hidden="true">
              <text x={plot.left} y={height - 8}>{samples[0]?.label || chartTime(samples[0]?.at)}</text>
              <text x={width - plot.right} y={height - 8} textAnchor="end">{latest?.label || chartTime(latest?.at)}</text>
            </g>
          </svg>
        </div>
      ) : (
        <div className="v18-operational-chart__empty">
          <strong>{statusLabel}</strong>
          <span>{emptyText}</span>
        </div>
      )}
    </section>
  );
}

function UsageGauge({ value, detail }) {
  const numericValue = finiteChartValue(value);
  const numeric = numericValue == null ? null : Math.max(0, Math.min(100, numericValue));
  return (
    <div className="v18-usage-gauge" aria-label="Disk usage">
      <div className="v18-usage-gauge__readout">
        <strong>{numeric == null ? 'Unavailable' : `${formatPercent(numeric, 0)}`}</strong>
        <span>{numeric == null ? 'No disk metric returned' : detail}</span>
      </div>
      {numeric == null ? <div className="v18-usage-gauge__empty">Disk utilization will appear after a live process sample.</div> : (
        <>
          <div className="v18-usage-gauge__track"><span style={{ '--usage': `${numeric}%` }} /></div>
          <div className="v18-usage-gauge__scale"><span>0%</span><span>50%</span><span>100%</span></div>
        </>
      )}
    </div>
  );
}

function PerformanceScoreDonut({ score, available, loading }) {
  const numeric = available ? clampPercent(score) : 0;
  const radius = 50;
  const circumference = 2 * Math.PI * radius;
  const dash = (numeric / 100) * circumference;
  return (
    <div className={cls('v18-score-donut', !available && 'is-unavailable')}>
      <svg viewBox="0 0 120 120" role="img" aria-label={available ? `Participation score ${formatPercent(numeric, 1)}` : 'Participation score unavailable'}>
        <circle className="v18-score-donut__track" cx="60" cy="60" r={radius} />
        {available ? <circle className="v18-score-donut__value" cx="60" cy="60" r={radius} strokeDasharray={`${dash} ${circumference - dash}`} /> : null}
      </svg>
      <div className="v18-score-donut__label">
        <span>Participation</span>
        <strong>{available ? formatPercent(numeric, 1) : '—'}</strong>
        <small>{available ? 'out of 100' : loading ? 'Loading score' : 'Not reported'}</small>
      </div>
    </div>
  );
}

function reportCheckCounts(report) {
  const checks = Array.isArray(report?.checks) ? report.checks : Array.isArray(report?.readiness?.checks) ? report.readiness.checks : [];
  const passed = Number(report?.ready_count ?? report?.readyCount ?? checks.filter((check) => check.status === 'pass').length);
  const total = Number(report?.total_count ?? report?.totalCount ?? checks.length);
  const failed = checks.filter((check) => check.status === 'fail' || check.status === 'error').length;
  const warnings = Math.max(0, total - passed - failed);
  return {
    passed: Number.isFinite(passed) ? passed : 0,
    failed: Number.isFinite(failed) ? failed : 0,
    warnings: Number.isFinite(warnings) ? warnings : 0,
    total: Number.isFinite(total) ? total : checks.length,
  };
}

function formatSnrg(value, digits = 3) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return '—';
  return numeric.toLocaleString(undefined, {
    minimumFractionDigits: numeric > 0 && numeric < 10 ? Math.min(2, digits) : 0,
    maximumFractionDigits: digits,
  });
}

function passphraseStrength(passphrase) {
  const value = String(passphrase || '');
  let score = 0;
  if (value.length >= 12) score += 1;
  if (/[a-z]/.test(value) && /[A-Z]/.test(value)) score += 1;
  if (/\d/.test(value)) score += 1;
  if (/[^A-Za-z0-9]/.test(value)) score += 1;
  if (value.length >= 18) score += 1;
  if (score >= 4) return { label: 'Strong', tone: 'green', detail: 'Good passphrase strength for encrypted validator files.' };
  if (score >= 2) return { label: 'Moderate', tone: 'yellow', detail: 'Use 12+ characters with mixed letters, numbers, and symbols.' };
  return { label: 'Needs work', tone: 'red', detail: 'Use at least 12 characters. Longer passphrases protect validator recovery better.' };
}

function friendlySetupError(error, fallback = 'This step could not be completed.') {
  const detail = String(error?.message || error || '').trim();
  const lower = detail.toLowerCase();
  if (!detail) return fallback;
  if (lower.includes('genesis_validator') || lower.includes('stale') && lower.includes('provenance')) {
    return 'Snapshot provenance is stale. The archive snapshot needs to be regenerated.';
  }
  if (lower.includes('checksum') || lower.includes('sha256')) {
    return 'Snapshot download did not pass integrity verification. The file was not applied.';
  }
  if (lower.includes('no compatible snapshot')) {
    return 'No compatible snapshot is available for this app/node version.';
  }
  if (lower.includes('snapshot') && (lower.includes('unavailable') || lower.includes('catalog') || lower.includes('latest'))) {
    return 'Snapshot service is temporarily unavailable. You can retry or continue with normal sync.';
  }
  if (lower.includes('no handshake') || lower.includes('handshake')) {
    return 'Secure network setup could not confirm a peer handshake.';
  }
  if (lower.includes('auth') || lower.includes('token') || lower.includes('401')) {
    return 'The onboarding token was invalid, expired, or already used.';
  }
  if (lower.includes('disk') || lower.includes('storage')) {
    return 'Not enough storage is available, or the selected storage location is not writable.';
  }
  if (lower.startsWith('{') || lower.startsWith('[') || detail.length > 180) {
    return fallback;
  }
  return detail;
}

function SetupErrorNotice({ error, fallback }) {
  if (!error) return null;
  const detail = String(error?.message || error || '').trim();
  const message = friendlySetupError(detail, fallback);
  return (
    <div className="v18-alert is-error">
      <strong>{message}</strong>
      {detail && detail !== message ? (
        <details>
          <summary>Show technical details</summary>
          <pre>{detail}</pre>
        </details>
      ) : null}
    </div>
  );
}

function clampPercent(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  return Math.max(0, Math.min(100, numeric));
}

function titleizeMetric(value) {
  return String(value || '')
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function normalizeRewardsPayload(payload) {
  const root = readObject(payload);
  const live = readObject(root.live || root);
  return {
    loaded: root.loaded !== false,
    root,
    live,
    telemetry: readObject(root.telemetry),
    rewardHistory: Array.isArray(live.reward_history) ? live.reward_history : [],
    pendingRewardsSnrg: live.pending_rewards_snrg ?? live.pending_rewards,
    totalEarnedSnrg: live.historical_earned_snrg ?? live.total_earned,
    totalReleasedSnrg: live.total_released_snrg ?? live.total_released,
    totalPendingSnrg: live.total_pending_snrg ?? live.total_pending ?? live.pending_rewards_snrg ?? live.pending_rewards,
    totalWithdrawnSnrg: live.total_withdrawn_snrg ?? live.total_withdrawn,
    slashedSnrg: live.slashed_snrg ?? live.total_slashed_snrg ?? live.slashed,
    treasuryRecoverySnrg: live.treasury_recovery_snrg ?? live.total_treasury_recovery_snrg,
    stakedBalanceSnrg: live.staked_balance_snrg ?? live.staked_amount,
    walletBalanceSnrg: live.wallet_balance_snrg,
    synergyBreakdown: readObject(live.synergy_breakdown),
    synergyComponents: readObject(live.synergy_components),
    validatorStatus: live.validator_status || '',
    tokenSymbol: root.token_symbol || 'SNRG',
  };
}

function validatorIsActivelyParticipating(context) {
  const node = context.selectedNode || {};
  const live = context.selectedNodeLive || {};
  if (!node.id) return false;
  if ((node.setup_sync_required ?? node.setupSyncRequired) === true) return false;

  const syncGap = Number(live.sync_gap ?? 0);
  const synced = !Number.isFinite(syncGap) || syncGap <= ACTIVE_SYNC_GAP_MAX;
  const consensusActivity = Boolean(
    live.is_consensus_active
      || live.is_voting
      || live.is_proposing
      || live.consensus_activity?.has_voted
      || live.consensus_activity?.vote_phase
      || live.consensus_activity?.current_leader
  );
  const canParticipate = live.jailing?.can_vote !== false && live.jailing?.can_propose !== false;

  return Boolean(
    live.is_running === true
      && live.local_rpc_ready !== false
      && synced
      && canParticipate
      && consensusActivity
  );
}

function setupVisibleForContext(context) {
  if (!Array.isArray(context.nodes) || context.nodes.length === 0) return true;
  return !validatorIsActivelyParticipating(context);
}

function useRewardsData(nodeId) {
  const [state, setState] = useState({ loading: false, payload: null, error: '' });
  useEffect(() => {
    if (!nodeId) {
      setState({ loading: false, payload: null, error: '' });
      return undefined;
    }
    let cancelled = false;
    setState((current) => ({ ...current, loading: true, error: '' }));
    nodeService.getRewardsData(nodeId)
      .then((payload) => {
        if (!cancelled) setState({ loading: false, payload, error: '' });
      })
      .catch((error) => {
        if (!cancelled) setState({ loading: false, payload: null, error: String(error?.message || error) });
      });
    return () => {
      cancelled = true;
    };
  }, [nodeId]);
  return state;
}

function useLocalPeerInfo(context) {
  const selectedNode = context.selectedNode;
  const selectedNodeLive = context.selectedNodeLive;
  const knownValidatorAddressesByHost = context.knownValidatorAddressesByHost;
  const [state, setState] = useState({ loading: false, peerInfo: null, error: '' });

  useEffect(() => {
    if (!selectedNode || !selectedNodeLive?.is_running || selectedNodeLive?.local_rpc_ready !== true) {
      setState({ loading: false, peerInfo: null, error: '' });
      return undefined;
    }

    let cancelled = false;
    const endpoint = localRpcEndpointForNode(selectedNode, selectedNodeLive);

    const fetchPeerInfo = async (showSpinner = false) => {
      if (showSpinner && !cancelled) setState((current) => ({ ...current, loading: true }));
      try {
        const peerInfo = await queryLocalRpc(endpoint, 'synergy_getPeerInfo', []);
        if (!cancelled) {
          setState({
            loading: false,
            peerInfo: normalizePeerInfoPayload(peerInfo, knownValidatorAddressesByHost),
            error: '',
          });
        }
      } catch (error) {
        if (!cancelled) setState({ loading: false, peerInfo: null, error: String(error?.message || error) });
      }
    };

    void fetchPeerInfo(true);
    const intervalId = window.setInterval(() => {
      void fetchPeerInfo(false);
    }, 8000);
    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [knownValidatorAddressesByHost, selectedNode, selectedNodeLive]);

  return state;
}

function scoreComponentFromValue(key, value) {
  const objectValue = readObject(value);
  const score = Number(
    objectValue.score
      ?? objectValue.value
      ?? objectValue.percent
      ?? objectValue.points
      ?? value,
  );
  const weight = Number(objectValue.weight ?? objectValue.weight_percent ?? objectValue.max ?? 0);
  return {
    id: key,
    label: titleizeMetric(objectValue.label || key),
    score: Number.isFinite(score) ? clampPercent(score) : 0,
    weight: Number.isFinite(weight) && weight > 0 ? weight : null,
    detail: objectValue.detail || objectValue.reason || 'Reported by Synergy score RPC.',
  };
}

function buildDerivedScoreBreakdown(context, peerInfo) {
  const live = context.selectedNodeLive || {};
  const readinessChecks = live.readiness?.checks || [];
  const passedChecks = readinessChecks.filter((check) => check.status === 'pass').length;
  const readinessScore = readinessChecks.length ? (passedChecks / readinessChecks.length) * 100 : (live.local_rpc_ready !== false ? 100 : 0);
  const peerCount = Number(peerInfo?.peerCount ?? live.local_peer_count ?? 0);
  const sync = nodeSyncPercent(live, context.liveStatus);
  const uptimeHours = Number(live.process_uptime_secs || 0) / 3600;
  const consensusScore = live.is_consensus_active ? 100 : (live.is_voting || live.is_proposing ? 85 : (Number(live.connected_validator_count || 0) > 0 ? 65 : 0));

  return [
    { id: 'consensus', label: 'Consensus Participation', score: consensusScore, weight: 35, detail: live.is_consensus_active ? 'Consensus activity is currently active.' : 'Derived from voting, proposing, and validator mesh status.' },
    { id: 'sync', label: 'Sync Health', score: sync, weight: 20, detail: `Current sync gap: ${formatNumber(live.sync_gap ?? 0)} block(s).` },
    { id: 'readiness', label: 'Validation Accuracy', score: readinessScore, weight: 20, detail: readinessChecks.length ? `${passedChecks} of ${readinessChecks.length} readiness checks passing.` : 'Derived from local RPC readiness.' },
    { id: 'peers', label: 'Peer Connectivity', score: Math.min(100, (peerCount / 4) * 100), weight: 15, detail: `${formatNumber(peerCount)} validator peer(s) visible.` },
    { id: 'uptime', label: 'Uptime', score: Math.min(100, (uptimeHours / 24) * 100), weight: 10, detail: `Runtime uptime ${formatRuntimeDuration(live.process_uptime_secs)}.` },
  ];
}

function scoreBreakdownForContext(context, rewardsPayload, peerInfo) {
  const normalizedRewards = normalizeRewardsPayload(rewardsPayload);
  const rpcComponents = Object.entries(normalizedRewards.synergyComponents);
  const items = rpcComponents.length
    ? rpcComponents.map(([key, value]) => scoreComponentFromValue(key, value))
    : buildDerivedScoreBreakdown(context, peerInfo);
  const derivedTotal = items.reduce((sum, item) => {
    const weight = Number(item.weight ?? 0);
    return sum + (weight > 0 ? (item.score * weight) / 100 : 0);
  }, 0);
  const totalScore = Number(
    normalizedRewards.synergyBreakdown.total_score
      ?? normalizedRewards.synergyBreakdown.totalScore
      ?? context.selectedNodeLive?.synergy_score
      ?? derivedTotal,
  );
  return {
    source: rpcComponents.length ? 'RPC synergy score breakdown' : 'Live telemetry derived breakdown',
    total: Number.isFinite(totalScore) ? totalScore : derivedTotal,
    items,
  };
}

function PageHeader({ title, subtitle, children }) {
  return (
    <header className="v18-page-header">
      <div>
        <h1>{title}</h1>
        <p>{subtitle}</p>
      </div>
      {children ? <div className="v18-page-header__actions">{children}</div> : null}
    </header>
  );
}

function Card({ title, icon: Icon, children, className = '', action }) {
  return (
    <section className={cls('v18-card', className)}>
      {(title || Icon || action) ? (
        <div className="v18-card__head">
          <div>
            {Icon ? <span className="v18-icon-bubble"><Icon size={18} /></span> : null}
            {title ? <h2>{title}</h2> : null}
          </div>
          {action}
        </div>
      ) : null}
      {children}
    </section>
  );
}

function MetricCard({ icon: Icon, label, value, detail, tone = 'neutral', progress }) {
  return (
    <section className={cls('v18-metric-card', `tone-${tone}`)}>
      <Icon size={28} />
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{detail}</small>
      </div>
      {progress != null ? (
        <div className="v18-meter" style={{ '--meter': `${Math.max(0, Math.min(100, Number(progress) || 0))}%` }}>
          <span />
        </div>
      ) : null}
    </section>
  );
}

function StatusPill({ tone = 'green', children }) {
  return <span className={cls('v18-status-pill', `is-${tone}`)}>{children}</span>;
}

function CopyButton({ value, label = 'Copy' }) {
  const [copied, setCopied] = useState(false);
  const copyValue = stringValue(value);
  return (
    <button
      type="button"
      className={cls('v18-icon-button', copied && 'is-copied')}
      aria-label={copied ? `${label} copied` : label}
      title={copied ? 'Copied' : label}
      disabled={!copyValue}
      onClick={async () => {
        if (!navigator?.clipboard || !copyValue) return;
        await navigator.clipboard.writeText(copyValue);
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1300);
      }}
    >
      {copied ? <CheckCircle2 size={16} /> : <Copy size={16} />}
    </button>
  );
}

function CopyValue({ label, value, displayValue, copyLabel = `Copy ${label.toLowerCase()}` }) {
  const copyValue = stringValue(value);
  if (!copyValue) return null;
  return (
    <div className="v18-copy-value">
      <div>
        <span>{label}</span>
        <strong title={copyValue}>{displayValue || copyValue}</strong>
      </div>
      <CopyButton value={copyValue} label={copyLabel} />
    </div>
  );
}

function ConfirmationModal({ request, onCancel, onConfirm }) {
  if (!request) return null;
  return (
    <div className="v18-modal-backdrop" role="presentation">
      <section className="v18-confirm-modal" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
        <span className="v18-icon-bubble is-red"><AlertTriangle size={22} /></span>
        <h2 id="confirm-title">{request.title}</h2>
        <p>{request.body}</p>
        <div className="v18-modal-actions">
          <button type="button" className="v18-ghost-button" onClick={onCancel}>Cancel</button>
          <button type="button" className="v18-danger-button" onClick={() => onConfirm(request)}>Confirm</button>
        </div>
      </section>
    </div>
  );
}

function Toast({ toast, onClose }) {
  if (!toast) return null;
  return (
    <div className={cls('v18-toast', toast.tone === 'error' && 'is-error')} role="status">
      <span>{toast.message}</span>
      <button type="button" onClick={onClose} aria-label="Dismiss notification">x</button>
    </div>
  );
}

function NotificationsDropdown({ notifications, open, onToggle, onDismiss, onClearAll, onClose }) {
  const wrapRef = useRef(null);
  const [mounted, setMounted] = useState(open);

  useEffect(() => {
    if (open) {
      setMounted(true);
      return undefined;
    }
    const timeoutId = window.setTimeout(() => setMounted(false), 180);
    return () => window.clearTimeout(timeoutId);
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;
    const closeOnOutsidePointer = (event) => {
      if (wrapRef.current?.contains(event.target)) return;
      onClose?.();
    };
    const closeOnEscape = (event) => {
      if (event.key === 'Escape') onClose?.();
    };
    document.addEventListener('pointerdown', closeOnOutsidePointer);
    document.addEventListener('keydown', closeOnEscape);
    return () => {
      document.removeEventListener('pointerdown', closeOnOutsidePointer);
      document.removeEventListener('keydown', closeOnEscape);
    };
  }, [onClose, open]);

  const clearAllAndClose = () => {
    onClearAll();
    onClose?.();
  };

  return (
    <div className="v18-notification-wrap" ref={wrapRef}>
      <button type="button" className="v18-icon-button v18-notification-button" aria-label="Notifications" onClick={onToggle}>
        <Bell size={18} />
        {notifications.length ? <span>{Math.min(9, notifications.length)}</span> : null}
      </button>
      {mounted ? (
        <section className={cls('v18-notification-menu', open ? 'is-open' : 'is-closing')} aria-label="Notifications menu">
          <div className="v18-notification-menu__head">
            <strong>Notifications</strong>
            <button type="button" className="v18-link-button" disabled={!notifications.length} onClick={clearAllAndClose}>Clear all</button>
          </div>
          <div className="v18-notification-list">
            {notifications.length ? notifications.map((item) => (
              <article key={item.key} className={cls('v18-notification-item', `is-${item.tone || 'blue'}`)}>
                <span className={cls('v18-dot', `is-${item.tone || 'blue'}`)} />
                <div>
                  <strong>{item.title}</strong>
                  <p>{item.detail}</p>
                  <small>{item.at ? new Date(item.at).toLocaleString() : 'Just now'}</small>
                  {item.actionLabel && typeof item.onAction === 'function' ? (
                    <button type="button" className="v18-notification-action" onClick={item.onAction}>{item.actionLabel}</button>
                  ) : null}
                </div>
                {item.dismissible === false ? <span aria-hidden="true" /> : (
                  <button type="button" className="v18-icon-button" aria-label={`Dismiss ${item.title}`} onClick={() => onDismiss(item.key)}><XCircle size={14} /></button>
                )}
              </article>
            )) : <p className="v18-muted">No notifications. New items appear when node status, readiness, sync, or safety state changes.</p>}
          </div>
        </section>
      ) : null}
    </div>
  );
}

function usePanelVersion() {
  const [version, setVersion] = useState('unknown');
  useEffect(() => {
    getVersion().then((value) => {
      if (value && value !== 'unknown') setVersion(value);
    }).catch(() => {});
  }, []);
  return version;
}

function useUpdateMonitor(settings) {
  const autoCheckEnabled = settings?.checkUpdatesAutomatically !== false;
  const [updateState, setUpdateState] = useState({
    status: 'idle',
    message: 'No update check has been run yet.',
    version: '',
    currentVersion: '',
    percent: 0,
    at: Date.now(),
  });

  useEffect(() => {
    let disposed = false;

    const runCheck = async (silent = false) => {
      if (!disposed && !silent) {
        setUpdateState((previous) => ({
          ...previous,
          status: 'checking',
          message: 'Checking for updates...',
          at: Date.now(),
        }));
      }

      const result = await checkForUpdate();
      if (disposed) return;

      if (result?.error) {
        if (!silent) {
          setUpdateState((previous) => ({
            ...previous,
            status: 'error',
            message: result.error,
            version: '',
            currentVersion: result.currentVersion || previous.currentVersion,
            percent: 0,
            at: Date.now(),
          }));
        }
        return;
      }

      if (result?.available) {
        setUpdateState({
          status: 'available',
          message: `Update ${result.version} is available.`,
          version: result.version || '',
          currentVersion: result.currentVersion || '',
          percent: 0,
          at: Date.now(),
        });
        return;
      }

      setUpdateState((previous) => ({
        ...previous,
        status: 'up_to_date',
        message: 'You are running the latest published version.',
        version: '',
        currentVersion: result?.currentVersion || previous.currentVersion,
        percent: 0,
        at: Date.now(),
      }));
    };

    const unsubAvailable = onUpdaterEvent('update-available', (data) => {
      if (disposed) return;
      setUpdateState((previous) => ({
        ...previous,
        status: 'available',
        message: `Update ${data?.version || previous.version || ''} is available.`,
        version: data?.version || previous.version || '',
        at: Date.now(),
      }));
    });

    const unsubProgress = onUpdaterEvent('download-progress', (data) => {
      if (disposed) return;
      setUpdateState((previous) => ({
        ...previous,
        status: 'downloading',
        message: 'Downloading update...',
        percent: Number(data?.percent) || 0,
        at: Date.now(),
      }));
    });

    const unsubDownloaded = onUpdaterEvent('update-downloaded', (data) => {
      if (disposed) return;
      setUpdateState((previous) => ({
        ...previous,
        status: 'ready',
        message: `Update ${data?.version || previous.version || ''} is ready to install.`,
        version: data?.version || previous.version || '',
        percent: 100,
        at: Date.now(),
      }));
    });

    const unsubError = onUpdaterEvent('error', (data) => {
      if (disposed) return;
      setUpdateState((previous) => ({
        ...previous,
        status: 'error',
        message: data?.message || 'Update failed.',
        at: Date.now(),
      }));
    });

    if (autoCheckEnabled) {
      void runCheck(true);
    }

    const intervalId = autoCheckEnabled
      ? window.setInterval(() => {
        void runCheck(true);
      }, UPDATE_POLL_MS)
      : null;

    return () => {
      disposed = true;
      if (intervalId) window.clearInterval(intervalId);
      unsubAvailable();
      unsubProgress();
      unsubDownloaded();
      unsubError();
    };
  }, [autoCheckEnabled]);

  const handleUpdateAction = async () => {
    if (['checking', 'downloading', 'installing'].includes(updateState.status)) return;
    if (updateState.status === 'ready') {
      setUpdateState((previous) => ({
        ...previous,
        status: 'installing',
        message: 'Restarting to install the update...',
        at: Date.now(),
      }));
      await installDownloadedUpdate(updateState.version);
      return;
    }

    if (!['available', 'error'].includes(updateState.status)) {
      setUpdateState((previous) => ({
        ...previous,
        status: 'checking',
        message: 'Checking for updates...',
        at: Date.now(),
      }));
      const result = await checkForUpdate();
      if (!result?.available) {
        setUpdateState((previous) => ({
          ...previous,
          status: result?.error ? 'error' : 'up_to_date',
          message: result?.error || 'You are running the latest published version.',
          version: '',
          currentVersion: result?.currentVersion || previous.currentVersion,
          percent: 0,
          at: Date.now(),
        }));
        return;
      }
      setUpdateState((previous) => ({
        ...previous,
        status: 'available',
        message: `Update ${result.version} is available.`,
        version: result.version || '',
        currentVersion: result.currentVersion || previous.currentVersion,
        percent: 0,
        at: Date.now(),
      }));
    }

    setUpdateState((previous) => ({
      ...previous,
      status: 'downloading',
      message: 'Downloading update...',
      percent: 0,
      at: Date.now(),
    }));
    const result = await downloadAndInstallUpdate(updateState.version);
    if (result?.status === 'error') {
      setUpdateState((previous) => ({
        ...previous,
        status: 'error',
        message: result.message,
        percent: 0,
        at: Date.now(),
      }));
      return;
    }
    if (result?.status === 'manual-install') {
      setUpdateState((previous) => ({
        ...previous,
        status: 'manual-install',
        message: result.message,
        version: result.version || previous.version,
        percent: 0,
        at: Date.now(),
      }));
      return;
    }
    if (result?.status === 'up-to-date') {
      setUpdateState((previous) => ({
        ...previous,
        status: 'up_to_date',
        message: result.message,
        version: '',
        percent: 0,
        at: Date.now(),
      }));
    }
  };

  return { updateState, handleUpdateAction };
}

function updateNotificationForState(updateState, onAction) {
  if (!['available', 'downloading', 'ready', 'manual-install', 'error'].includes(updateState.status)) return null;
  const tone = updateState.status === 'error'
    ? 'red'
    : updateState.status === 'ready'
      ? 'green'
      : updateState.status === 'downloading'
        ? 'blue'
        : 'purple';
  const actionLabel = updateState.status === 'ready'
    ? 'Restart'
    : updateState.status === 'manual-install'
      ? 'Open installer'
    : updateState.status === 'downloading'
      ? ''
      : updateState.status === 'error'
        ? 'Retry'
        : 'Download';
  return {
    key: `control-panel-update:${updateState.status}:${updateState.version || updateState.message}`,
    title: updateState.status === 'ready'
      ? 'Control panel update ready'
      : updateState.status === 'manual-install'
        ? 'macOS installer opened'
        : updateState.status === 'error'
          ? 'Update check failed'
          : 'Control panel update available',
    detail: updateState.status === 'downloading'
      ? `${updateState.message} ${Math.round(updateState.percent || 0)}%`
      : updateState.message,
    tone,
    at: updateState.at,
    actionLabel,
    onAction,
    dismissible: false,
  };
}

function footerUpdateLabel(updateState) {
  if (updateState.status === 'available') return `Update ${updateState.version || ''} available`.trim();
  if (updateState.status === 'downloading') return `Downloading ${Math.round(updateState.percent || 0)}%`;
  if (updateState.status === 'ready') return 'Restart to update';
  if (updateState.status === 'manual-install') return 'Install from DMG';
  if (updateState.status === 'installing') return 'Installing update';
  if (updateState.status === 'checking') return 'Checking for updates';
  if (updateState.status === 'error') return 'Update check failed';
  return 'Up to date';
}

function AppShell({ children }) {
  const context = useControlPanel();
  const version = usePanelVersion();
  const [settings, setSettings] = useState(null);
  const [locked, setLocked] = useState(false);
  const [unlockPassword, setUnlockPassword] = useState('');
  const [unlockError, setUnlockError] = useState('');
  const [autoStartAttempted, setAutoStartAttempted] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const runtime = statusLabel(context);
  const runtimeTone = statusToneClass(context.selectedNodeLive, context.error);
  const setupVisible = setupVisibleForContext(context);
  const navItems = useMemo(() => navItemsForSetupState(setupVisible), [setupVisible]);
  const notificationState = usePanelNotifications(context);
  const { updateState, handleUpdateAction } = useUpdateMonitor(settings);
  const updateNotification = useMemo(
    () => updateNotificationForState(updateState, handleUpdateAction),
    [handleUpdateAction, updateState],
  );
  const notifications = useMemo(
    () => [updateNotification, ...notificationState.notifications].filter(Boolean),
    [notificationState.notifications, updateNotification],
  );

  useEffect(() => {
    settingsService.getSettings().then(setSettings).catch(() => {});
  }, []);

  useEffect(() => {
    if (!settings) return;
    document.documentElement.dataset.theme = settings.darkTheme ? 'dark' : 'light';
    document.documentElement.lang = settings.language === 'English' ? 'en' : 'en';
  }, [settings]);

  useEffect(() => {
    if (!settings?.autoStartNode || autoStartAttempted || !context.selectedNode?.id) return;
    setAutoStartAttempted(true);
    if (context.selectedNodeLive?.is_running) return;
    nodeService.start(context.selectedNode.id)
      .then(() => context.refresh({ silent: true }))
      .catch((error) => context.recordAction({
        title: 'Auto start failed',
        detail: String(error?.message || error),
        status: 'error',
      }));
  }, [autoStartAttempted, context, settings?.autoStartNode]);

  useEffect(() => {
    if (!settings?.passwordLock || !settings.lockPasswordHash) return undefined;
    let timeoutId = null;
    const reset = () => {
      if (locked) return;
      window.clearTimeout(timeoutId);
      timeoutId = window.setTimeout(() => setLocked(true), sessionTimeoutMs(settings));
    };
    const events = ['click', 'keydown', 'mousemove', 'scroll', 'touchstart'];
    events.forEach((eventName) => window.addEventListener(eventName, reset, { passive: true }));
    reset();
    return () => {
      window.clearTimeout(timeoutId);
      events.forEach((eventName) => window.removeEventListener(eventName, reset));
    };
  }, [locked, settings]);

  const refreshStatus = async () => {
    await context.refresh({ silent: false });
  };

  const unlock = async (event) => {
    event.preventDefault();
    const ok = await settingsService.verifyLockPassword(settings, unlockPassword);
    if (!ok) {
      setUnlockError('Invalid password.');
      return;
    }
    setUnlockPassword('');
    setUnlockError('');
    setLocked(false);
  };

  return (
    <div className="v18-shell">
      <aside className="v18-sidebar">
        <div className="v18-sidebar-brand">
          <img className="v18-brand-banner" src={controlPanelBannerSrc} alt="Node Operator Control Panel" />
        </div>
        <nav className="v18-nav" aria-label="Primary">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink key={item.path} to={item.path} end={item.path === '/'} className={({ isActive }) => cls('v18-nav-link', isActive && 'is-active')}>
                <Icon size={22} />
                <span>{item.label}</span>
              </NavLink>
            );
          })}
        </nav>
      </aside>
      <main className="v18-main">
        <div className="v18-top-controls">
          <button type="button" className={cls('v18-health-select', `is-${runtimeTone}`)} onClick={refreshStatus}>
            <span className="v18-dot" />
            {runtime}
          </button>
          <NotificationsDropdown
            notifications={notifications}
            open={notificationsOpen}
            onToggle={() => setNotificationsOpen((value) => !value)}
            onDismiss={notificationState.dismiss}
            onClearAll={notificationState.clearAll}
            onClose={() => setNotificationsOpen(false)}
          />
        </div>
        <div className="v18-content">
          {children}
        </div>
        <footer className="v18-bottom-bar">
          <span className="v18-footer-copy">© 2026 Synergy Network. All rights reserved.</span>
          <span className="v18-footer-status"><span>Version {version}</span><span className="v18-dot is-purple" /> <span>{footerUpdateLabel(updateState)}</span></span>
          {setupVisible ? (
            <NavLink to="/setup" className="v18-footer-action">
              <Wallet size={14} />
              Wallet & Stake
            </NavLink>
          ) : <span className="v18-footer-spacer" aria-hidden="true" />}
        </footer>
        {locked ? (
          <div className="v18-lock-backdrop" role="presentation">
            <form className="v18-lock-panel" onSubmit={unlock}>
              <Lock size={30} />
              <h2>Control Panel Locked</h2>
              <p>Enter your control panel password to continue.</p>
              <input
                type="password"
                value={unlockPassword}
                onChange={(event) => setUnlockPassword(event.target.value)}
                autoFocus
              />
              {unlockError ? <small className="v18-error-text">{unlockError}</small> : null}
              <button type="submit" className="v18-primary-button">Unlock</button>
            </form>
          </div>
        ) : null}
      </main>
    </div>
  );
}

function LiveTrendChart({ title, value, points, tone = 'green', formatValue = formatNumber }) {
  return (
    <OperationalLineChart
      title={title}
      current={value}
      points={points}
      tone={tone}
      formatValue={formatValue}
      sampleLabel="live samples"
      emptyText="No current metric or polling history was returned."
      className="v18-live-trend"
    />
  );
}

function OverviewPage() {
  const context = useControlPanel();
  const navigate = useNavigate();
  const node = context.selectedNode || {};
  const live = context.selectedNodeLive || {};
  const nodeAddress = stringValue(node.node_address, node.nodeAddress);
  const roleLabel = operationsRoleLabel(context);
  const history = context.telemetryHistory?.byNodeId?.[node.id] || [];
  const blockHeight = firstFiniteValue(live, ['local_chain_height', 'sync_target_height', 'best_network_height']);
  const peerCount = firstFiniteValue(live, ['local_peer_count']);
  const syncGap = firstFiniteValue(live, ['sync_gap']);
  const rpcLatency = firstFiniteValue(live, ['rpc_latency_ms']);
  const uptime = firstFiniteValue(live, ['process_uptime_secs']);
  const readinessChecks = Array.isArray(live.readiness?.checks) ? live.readiness.checks : [];
  const failedChecks = readinessChecks.filter((check) => check.status === 'fail' || check.status === 'error');
  const syncPercent = nodeSyncPercent(live, context.liveStatus);

  return (
    <>
      <PageHeader title="Operations Overview" subtitle="Compact live state and short-horizon telemetry for the selected node." />
      <section className="v18-overview-status-strip" aria-label="Selected node status">
        <div className="v18-overview-status-strip__address">
          <span>Node Address</span>
          <strong title={nodeAddress}>{nodeAddress || 'Unavailable'}</strong>
          {nodeAddress ? <CopyButton value={nodeAddress} label="Copy node address" /> : null}
        </div>
        <div><span>Role</span><strong>{roleLabel}</strong></div>
        <div><span>Runtime</span><strong>{context.selectedNodeLive ? nodeRuntimeLabel(live) : 'Unavailable'}</strong></div>
        <div><span>Last poll</span><strong>{context.lastUpdatedAt ? terminalTime(context.lastUpdatedAt) : 'Unavailable'}</strong></div>
        <button type="button" className="v18-icon-button" onClick={() => context.refresh({ silent: true })} title="Refresh live status" aria-label="Refresh live status"><RefreshCw size={16} /></button>
      </section>
      <div className="v18-overview-metric-grid">
        <MetricCard icon={Activity} label="Runtime" value={context.selectedNodeLive ? nodeRuntimeLabel(live) : 'Unavailable'} detail={live.local_rpc_status || 'No runtime status returned'} tone={live.is_running ? 'green' : 'gray'} />
        <MetricCard icon={Archive} label="Block Height" value={blockHeight == null ? 'Unavailable' : formatNumber(blockHeight)} detail={blockHeight == null ? 'No live chain height returned' : 'Latest reported height'} tone="blue" />
        <MetricCard icon={RefreshCw} label="Sync Gap" value={syncGap == null ? 'Unavailable' : formatNumber(syncGap)} detail={syncGap == null ? 'No live sync gap returned' : `${formatPercent(syncPercent, 1)} sync progress`} tone={syncGap != null && syncGap <= ACTIVE_SYNC_GAP_MAX ? 'green' : 'yellow'} progress={syncGap == null ? null : Math.max(0, 100 - Math.min(100, syncGap))} />
        <MetricCard icon={Users} label="Peers" value={peerCount == null ? 'Unavailable' : formatNumber(peerCount)} detail={peerCount == null ? 'No peer count returned' : 'Connected peers'} tone="purple" />
      </div>
      <section className="v18-overview-trend-grid" aria-label="Live metric trends">
        <LiveTrendChart title="Block height" value={blockHeight} points={trendPoints(history, 'blockHeight')} tone="blue" />
        <LiveTrendChart title="Peer count" value={peerCount} points={trendPoints(history, 'localPeerCount')} tone="purple" />
        <LiveTrendChart title="Sync gap" value={syncGap} points={trendPoints(history, 'syncGap')} tone="yellow" />
        <LiveTrendChart title="RPC latency" value={rpcLatency} points={trendPoints(history, 'rpcLatencyMs')} tone="cyan" formatValue={(value) => `${formatNumber(value)} ms`} />
      </section>
      <section className="v18-overview-operations-row">
        <div>
          <span>Node health</span>
          <strong>{failedChecks.length ? `${failedChecks.length} readiness issue${failedChecks.length === 1 ? '' : 's'}` : readinessChecks.length ? 'Readiness checks passing' : 'Readiness unavailable'}</strong>
          <small>{uptime == null ? 'Runtime uptime unavailable' : `Runtime uptime ${formatRuntimeDuration(uptime)}`}</small>
        </div>
        <button type="button" className="v18-primary-button" onClick={() => navigate('/operations')}><TerminalSquare size={16} /> Open Node Controls</button>
      </section>
    </>
  );
}

function SetupNodePage() {
  const context = useControlPanel();
  const selectedNodeId = context.selectedNode?.id;
  const refreshPanel = context.refresh;
  const storedWizard = readSetupWizardState(selectedNodeId);
  const [wallet, setWallet] = useState(null);
  const [eligibility, setEligibility] = useState(() => normalizeStoredEligibility(storedWizard?.eligibility, storedWizard?.walletAddress));
  const [checking, setChecking] = useState(false);
  const [currentStep, setCurrentStep] = useState(() => normalizeSetupStep(storedWizard?.currentStep));
  const [setupConfig, setSetupConfig] = useState(() => setupConfigForNode(context.selectedNode, storedWizard?.setupConfig));
  const onboardingNodeId = setupConfig.remoteNodeId || selectedNodeId || '';
  const selectedValidatorAddress = setupConfig.remoteNodeAddress || context.selectedNode?.node_address || '';
  const onboardingTargetId = setupConfig.targetMode === 'remote' ? setupConfig.targetId : 'local';
  const connectedWalletAddress = wallet?.address || eligibility.walletAddress || '';
  const eligible = eligibility.eligible === true && eligibility.eligibilityStatus === ELIGIBILITY_STATUSES.eligible;
  const fundingReadyToBond = eligibility.fundingReadyToBond === true;
  const unresolvedFunding = Boolean(
    eligibility.stakeTxHash
      && !eligible
      && eligibility.eligibilityStatus !== ELIGIBILITY_STATUSES.stakeInvalid,
  );
  const bondSubmissionPending = ['submitting', 'submitted', 'stake-pending', 'submission-unknown']
    .includes(String(eligibility.bondTxStatus || '').toLowerCase());
  const bondAttempted = Boolean(eligibility.bondTxHash)
    || String(eligibility.bondTxStatus || '').toLowerCase() !== 'not_provided';
  const bondFailureMessage = String(eligibility.errorMessage || '').trim();
  const fundingSenderRequiredSnrg = Number(eligibility.fundingSenderRequiredSnrg)
    || VALIDATOR_FUNDING_SENDER_MINIMUM_SNRG;
  const fundingNetworkFeeSnrg = Number(eligibility.fundingNetworkFeeSnrg)
    || Math.max(0, fundingSenderRequiredSnrg - VALIDATOR_FUNDING_TARGET_SNRG);
  const walletCanFundValidator = Number(eligibility.snrgBalance) >= fundingSenderRequiredSnrg;
  const canContinueEligibility = Boolean(
    connectedWalletAddress
      && selectedValidatorAddress
      && (eligible || fundingReadyToBond),
  );
  const canVerifyStake = Boolean(
    connectedWalletAddress
      && selectedValidatorAddress
      && (
        eligible
        || Number(eligibility.activeStakeAmount) > 0
        || Number(eligibility.pendingStakeAmount) > 0
        || eligibility.stakeTxHash
        || fundingReadyToBond
        || eligibility.eligibilityStatus === ELIGIBILITY_STATUSES.stakePending
      ),
  );

  useEffect(() => {
    const restored = readSetupWizardState(selectedNodeId);
    if (!restored) {
      setEligibility((current) => (current.walletAddress ? current : emptyEligibility()));
      setCurrentStep((current) => normalizeSetupStep(current));
      return;
    }
    setEligibility(normalizeStoredEligibility(restored.eligibility, restored.walletAddress));
    setCurrentStep(normalizeSetupStep(restored.currentStep));
    setSetupConfig(setupConfigForNode(context.selectedNode, restored.setupConfig));
  }, [context.selectedNode, selectedNodeId]);

  useEffect(() => {
    if (!wallet?.address) return;
    setEligibility((current) => (current.walletAddress === wallet.address ? current : emptyEligibility(wallet.address)));
    if (eligibility.walletAddress && eligibility.walletAddress !== wallet.address) {
      setCurrentStep(SETUP_STEP.walletStake);
    }
  }, [eligibility.walletAddress, wallet?.address]);

  useEffect(() => {
    writeSetupWizardState(selectedNodeId, {
      currentStep,
      eligibility,
      setupConfig,
      walletAddress: connectedWalletAddress,
    });
  }, [connectedWalletAddress, currentStep, eligibility, selectedNodeId, setupConfig]);

  useEffect(() => {
    if (context.loading || currentStep !== SETUP_STEP.welcome) return undefined;
    const timer = window.setTimeout(() => {
      setCurrentStep(SETUP_STEP.nodeRole);
    }, 18000);
    return () => window.clearTimeout(timer);
  }, [context.loading, currentStep]);

  useEffect(() => {
    if (!wallet?.address || !onboardingNodeId) return;
    validatorEligibilityService
      .setValidatorOwner(onboardingNodeId, wallet.address, { targetId: onboardingTargetId })
      .then(() => (setupConfig.targetMode === 'local' ? refreshPanel({ silent: true }) : null))
      .catch((error) => {
        setEligibility((current) => ({
          ...current,
          walletAddress: wallet.address,
          eligibilityStatus: ELIGIBILITY_STATUSES.error,
          errorMessage: String(error?.message || error),
          lastVerifiedAt: new Date().toISOString(),
        }));
      });
  }, [onboardingNodeId, onboardingTargetId, refreshPanel, setupConfig.targetMode, wallet?.address]);

  useEffect(() => {
    if (!wallet?.address || !selectedValidatorAddress) return undefined;
    let cancelled = false;
    const delays = [0, 1200, 3000];

    const refreshEligibility = async () => {
      for (const delay of delays) {
        if (delay > 0) {
          await sleep(delay);
        }
        if (cancelled) return;
        const next = await validatorEligibilityService.verifyValidatorEligibility(wallet.address, {
          nodeId: onboardingNodeId,
          validatorAddress: selectedValidatorAddress,
          targetId: onboardingTargetId,
          stakeTxHash: eligibility.stakeTxHash,
        });
        if (cancelled) return;
        setEligibility((current) => {
          if (current.walletAddress && current.walletAddress !== wallet.address) {
            return current;
          }
          if (
            current.stakeTxHash
            && !next.eligible
            && !next.fundingReadyToBond
            && !next.stakeTxHash
            && next.eligibilityStatus !== ELIGIBILITY_STATUSES.error
          ) {
            return {
              ...mergePendingEligibility(current, next),
              stakeTxHash: current.stakeTxHash,
              eligibilityStatus: ELIGIBILITY_STATUSES.stakePending,
              errorMessage: next.errorMessage || 'Funding transaction submitted. Waiting for Synergy Network confirmation.',
            };
          }
          return mergePendingEligibility(current, next);
        });
        if (next.eligible === true && next.eligibilityStatus === ELIGIBILITY_STATUSES.eligible) {
          return;
        }
      }
    };

    void refreshEligibility();
    return () => {
      cancelled = true;
    };
  }, [eligibility.stakeTxHash, onboardingNodeId, onboardingTargetId, selectedValidatorAddress, wallet?.address]);

  const verify = async () => {
    setChecking(true);
    setEligibility((current) => ({ ...current, eligibilityStatus: ELIGIBILITY_STATUSES.checking }));
    try {
      const next = await validatorEligibilityService.verifyValidatorEligibility(connectedWalletAddress, {
        nodeId: onboardingNodeId,
        validatorAddress: selectedValidatorAddress,
        targetId: onboardingTargetId,
        stakeTxHash: eligibility.stakeTxHash,
      });
      setEligibility((current) => mergePendingEligibility(current, next));
    } finally {
      setChecking(false);
    }
  };

  const stake = async () => {
    setChecking(true);
    try {
      const stakeResult = await validatorEligibilityService.stakeRequiredAmount({
        walletAddress: connectedWalletAddress,
        nodeId: onboardingNodeId,
        validatorAddress: selectedValidatorAddress,
        targetId: onboardingTargetId,
        requestWalletAction: wallet?.requestWalletAction,
        onTransactionSubmitted: ({ stakeTxHash, submittedAt }) => {
          setEligibility((current) => ({
            ...current,
            stakeTxHash,
            stakeTxStatus: 'submitted',
            eligibilityStatus: ELIGIBILITY_STATUSES.stakePending,
            errorMessage: 'Funding transaction submitted. The control panel will verify the validator balance automatically.',
            lastVerifiedAt: submittedAt,
          }));
        },
      });
      const stakeTxHash = extractWalletActionTxHash(stakeResult);
      const next = stakeResult?.eligibility || await validatorEligibilityService.verifyValidatorEligibility(connectedWalletAddress, {
        nodeId: onboardingNodeId,
        validatorAddress: selectedValidatorAddress,
        targetId: onboardingTargetId,
        stakeTxHash,
      });
      setEligibility((current) => {
        if (next.eligible === true && next.eligibilityStatus === ELIGIBILITY_STATUSES.eligible) {
          return next;
        }
        if (next.fundingReadyToBond) {
          return {
            ...next,
            stakeTxHash: next.stakeTxHash || stakeTxHash || current.stakeTxHash,
            errorMessage: next.errorMessage || stakeResult?.message || 'Funding is confirmed. Complete the local validator self-bond without sending another transfer.',
          };
        }
        return {
          ...next,
          stakeTxHash: next.stakeTxHash || stakeTxHash || current.stakeTxHash,
          eligibilityStatus: next.eligibilityStatus === ELIGIBILITY_STATUSES.error
            ? ELIGIBILITY_STATUSES.error
            : ELIGIBILITY_STATUSES.stakePending,
          errorMessage: next.errorMessage || stakeResult?.message || 'Funding transaction submitted. Use Verify Bond after it confirms on Synergy Network.',
        };
      });
    } catch (error) {
      setEligibility((current) => ({
        ...current,
        eligibilityStatus: ELIGIBILITY_STATUSES.error,
        errorMessage: String(error?.message || error),
        lastVerifiedAt: new Date().toISOString(),
      }));
    } finally {
      setChecking(false);
    }
  };

  const completeValidatorSelfBond = async () => {
    if (!fundingReadyToBond || !onboardingNodeId || !connectedWalletAddress) return;
    setChecking(true);
    setEligibility((current) => ({
      ...current,
      bondTxStatus: 'submitting',
      errorMessage: 'Submitting the validator\'s locally signed 50,000 SNRG self-bond. Do not close the control panel or submit another bond.',
    }));
    try {
      const bondResult = await validatorEligibilityService.finalizeValidatorBond({
        nodeId: onboardingNodeId,
        walletAddress: connectedWalletAddress,
        validatorAddress: selectedValidatorAddress,
        targetId: onboardingTargetId,
        stakeTxHash: eligibility.stakeTxHash,
      });
      const next = bondResult?.eligibility || await validatorEligibilityService.verifyValidatorEligibility(connectedWalletAddress, {
        nodeId: onboardingNodeId,
        validatorAddress: selectedValidatorAddress,
        targetId: onboardingTargetId,
        stakeTxHash: eligibility.stakeTxHash,
      });
      const confirmed = next.eligible === true && next.eligibilityStatus === ELIGIBILITY_STATUSES.eligible;
      const bondTxHash = bondResult?.txHash || bondResult?.tx_hash || next.bondTxHash || '';
      setEligibility((current) => ({
        ...mergePendingEligibility(current, next),
        bondTxHash,
        bondTxStatus: confirmed ? 'confirmed' : bondTxHash ? 'submitted' : String(bondResult?.status || 'stake-pending'),
        errorMessage: confirmed
          ? 'Validator self-bond is confirmed on-chain. Continue with device, network, and sync checks.'
          : bondResult?.message || 'Validator self-bond was submitted and is awaiting canonical confirmation. Use Verify Bond to refresh its status; do not submit another bond.',
      }));
    } catch (error) {
      const message = String(error?.message || error);
      const outcomeUnknown = /outcome is unknown|could not be verified|replay guard|submission lease/i.test(message);
      setEligibility((current) => ({
        ...current,
        bondTxStatus: outcomeUnknown ? 'submission-unknown' : 'failed',
        errorMessage: message,
        lastVerifiedAt: new Date().toISOString(),
      }));
    } finally {
      setChecking(false);
    }
  };

  const handleWalletChange = (nextWallet) => {
    setWallet(nextWallet);
    if (!nextWallet?.address) {
      setEligibility(emptyEligibility());
      return;
    }
    setEligibility((current) => (current.walletAddress === nextWallet.address ? current : emptyEligibility(nextWallet.address)));
  };

  return (
    <>
      <PageHeader title="Setup Node" subtitle={`Step ${currentStep + 1} of 6 - ${setupSteps[currentStep]}`} />
      <section className="v18-stepper">
        {setupSteps.map((step, index) => (
          <button
            key={step}
            type="button"
            className={cls(index === currentStep && 'is-active', index < currentStep && 'is-complete')}
            disabled={index > currentStep}
            onClick={() => setCurrentStep(index)}
          >
            <span>{index + 1}</span>
            {step}
          </button>
        ))}
      </section>
      {currentStep === SETUP_STEP.welcome ? (
        <SetupWelcome onContinue={() => setCurrentStep(SETUP_STEP.nodeRole)} />
      ) : currentStep === SETUP_STEP.walletStake ? (
        <div className="v18-setup-grid">
          <Card className="v18-eligibility-card">
            <div className="v18-step-title">
              <h2>Connect Wallet & Fund Validator</h2>
              <p>Fund the validator with {formatNumber(VALIDATOR_FUNDING_TARGET_SNRG)} SNRG from the owner wallet, then complete its local protocol self-bond.</p>
            </div>
            <p>
              Your validator identity represents this node. Your Synergy Wallet owns the validator,
              funds the validator, and receives rewards. The validator signs its own {formatNumber(REQUIRED_VALIDATOR_STAKE_SNRG)} SNRG
              self-bond after the funding transfer is confirmed. The additional {formatNumber(VALIDATOR_FEE_RESERVE_SNRG)} SNRG remains available for transaction fees.
            </p>
            <SynergyWalletConnection onWalletChange={handleWalletChange} />
            <CopyValue
              label="Operator wallet address"
              value={connectedWalletAddress}
              displayValue={truncateMiddle(connectedWalletAddress, 10, 8)}
              copyLabel="Copy operator wallet address"
            />
            <div className="v18-eligibility-metrics">
              <MetricCard icon={Wallet} label="Available SNRG" value={formatNumber(eligibility.snrgBalance)} detail={`Owner wallet needs up to ${formatNumber(fundingSenderRequiredSnrg)} SNRG, including the funding transaction fee`} />
              <MetricCard icon={Server} label="Validator Funding" value={`${formatNumber(eligibility.validatorFundingAmount)} SNRG`} detail={fundingReadyToBond ? `Confirmed: ${formatNumber(REQUIRED_VALIDATOR_STAKE_SNRG)} SNRG bond + ${formatNumber(VALIDATOR_FEE_RESERVE_SNRG)} SNRG fee reserve` : `Target: ${formatNumber(VALIDATOR_FUNDING_TARGET_SNRG)} SNRG`} tone={eligible ? 'green' : 'yellow'} />
              <MetricCard icon={Shield} label="Bonded Stake" value={`${formatNumber(eligibility.activeStakeAmount)} SNRG`} detail={`Pending: ${formatNumber(eligibility.pendingStakeAmount)} SNRG`} tone={eligible ? 'green' : 'yellow'} />
              <MetricCard icon={AlertTriangle} label="Missing Stake" value={`${formatNumber(eligibility.missingStakeAmount)} SNRG`} detail={eligibility.eligibilityStatus} tone={eligible ? 'green' : 'red'} />
            </div>
            <div className={cls('v18-status-panel', eligible ? 'is-eligible' : fundingReadyToBond ? 'is-pending' : 'is-blocked')}>
              {eligible ? <CheckCircle2 size={30} /> : fundingReadyToBond && !(bondAttempted && bondFailureMessage) ? <Clock size={30} /> : <AlertTriangle size={30} />}
              <div>
                <strong>{eligible ? 'Bonded Stake Verified' : fundingReadyToBond && bondAttempted && bondFailureMessage ? 'Self-Bond Requires Attention' : fundingReadyToBond ? 'Funding Confirmed' : canContinueEligibility ? 'Wallet Ready' : 'Not Ready'}</strong>
                <p>
                  {eligible
                    ? 'Your wallet meets the 50,000 SNRG validator staking requirement.'
                    : bondSubmissionPending
                      ? `Validator self-bond ${truncateMiddle(eligibility.bondTxHash, 10, 8) || 'submission'} is awaiting canonical confirmation. Do not submit another self-bond.`
                    : fundingReadyToBond
                      ? bondAttempted && bondFailureMessage
                        ? bondFailureMessage
                        : `The confirmed ${formatNumber(VALIDATOR_FUNDING_TARGET_SNRG)} SNRG is in the validator balance. Guarded sync and exact local/public account-state parity must finish before the control panel submits the ${formatNumber(REQUIRED_VALIDATOR_STAKE_SNRG)} SNRG self-bond. Do not send another transfer.`
                    : eligibility.eligibilityStatus === ELIGIBILITY_STATUSES.stakePending
                      ? `Funding transaction ${truncateMiddle(eligibility.stakeTxHash, 10, 8) || 'submitted by Synergy Wallet'} is awaiting canonical confirmation. Do not submit another transfer while it is pending.`
                      : eligibility.eligibilityStatus === ELIGIBILITY_STATUSES.stakeInvalid
                        ? eligibility.errorMessage || 'The submitted transaction is not a canonical validator bond. It was not counted as stake.'
                    : walletCanFundValidator && connectedWalletAddress
                      ? `Use Synergy Wallet approval to send ${formatNumber(VALIDATOR_FUNDING_TARGET_SNRG)} SNRG to the validator: ${formatNumber(REQUIRED_VALIDATOR_STAKE_SNRG)} SNRG bonded stake plus a ${formatNumber(VALIDATOR_FEE_RESERVE_SNRG)} SNRG validator fee reserve. The owner wallet may also pay up to ${formatNumber(fundingNetworkFeeSnrg)} SNRG in network fees.`
                      : eligibility.errorMessage || `Fund the validator with an additional ${formatNumber(eligibility.missingStakeAmount)} SNRG before continuing.`}
                </p>
              </div>
            </div>
            {eligibility.stakeTxHash ? (
              <CopyValue
                label="Funding transaction"
                value={eligibility.stakeTxHash}
                displayValue={truncateMiddle(eligibility.stakeTxHash, 12, 10)}
                copyLabel="Copy funding transaction hash"
              />
            ) : null}
            <div className="v18-button-row">
              <button type="button" className="v18-primary-button" disabled={!selectedValidatorAddress || !connectedWalletAddress || checking || unresolvedFunding || typeof wallet?.requestWalletAction !== 'function' || Number(eligibility.snrgBalance) < fundingSenderRequiredSnrg} onClick={stake}>
                Fund {formatNumber(VALIDATOR_FUNDING_TARGET_SNRG)} SNRG
              </button>
              <button
                type="button"
                className="v18-primary-button"
                disabled={!fundingReadyToBond || !selectedValidatorAddress || !connectedWalletAddress || checking || bondSubmissionPending}
                onClick={completeValidatorSelfBond}
                title="Creates the validator's protocol-locked 50,000 SNRG self-bond from funds already confirmed in the validator account. This does not send another funding transfer."
              >
                <Lock size={16} />
                Complete Validator Self-Bond
              </button>
              <button type="button" className="v18-ghost-button" disabled={!canVerifyStake || checking} onClick={verify}>
                {checking ? <RefreshCw size={16} className="v18-spin" /> : <ClipboardCheck size={16} />}
                Verify Bond
              </button>
              <button type="button" className="v18-ghost-button" disabled={!connectedWalletAddress || checking} onClick={verify}>Refresh Status</button>
              <button type="button" className="v18-primary-button" disabled={!canContinueEligibility} onClick={() => setCurrentStep(SETUP_STEP.deviceNetworkSync)}>Continue to Device & Network</button>
            </div>
          </Card>
          <SetupSummary eligibility={eligibility} setupConfig={setupConfig} />
        </div>
      ) : (
        <SetupStepContent
          step={currentStep}
          eligibility={eligibility}
          setupConfig={setupConfig}
          setSetupConfig={setSetupConfig}
          setCurrentStep={setCurrentStep}
          setEligibility={setEligibility}
        />
      )}
    </>
  );
}

function SetupWelcome({ onContinue }) {
  return (
    <section className="v18-setup-welcome" aria-label="Welcome to Synergy Network">
      <div className="v18-setup-welcome__orb">
        <img src={controlPanelIconSrc} alt="" />
      </div>
      <div className="v18-setup-welcome__copy">
        <h2>Welcome to Synergy Network!</h2>
        <p style={{ '--line-delay': '0.35s' }}>We are glad you decided to setup and operate a node for the Synergy Network!</p>
        <p style={{ '--line-delay': '0.7s' }}>So now let's get started!</p>
        <p style={{ '--line-delay': '1.05s' }}>The first thing we have to do is decide what type of node you want to run.</p>
        <p style={{ '--line-delay': '1.4s' }}>Then we will create and back up your validator identity before any wallet or stake step.</p>
      </div>
      <button type="button" className="v18-primary-button" onClick={onContinue}>
        Choose Node Role
        <ChevronRight size={16} />
      </button>
    </section>
  );
}

function SetupSummary({
  eligibility,
  setupConfig = setupConfigForNode(null),
  backupConfirmed = false,
  secureNetworkStatus = '',
  syncStatus = '',
  currentStatus = '',
}) {
  const context = useControlPanel();
  const validatorAddress = setupConfig.remoteNodeAddress || context.selectedNode?.node_address || '';
  const ownerWallet = eligibility.walletAddress || context.selectedNode?.owner_wallet_address || '';
  const stakeReady = eligibility.eligible === true && eligibility.eligibilityStatus === ELIGIBILITY_STATUSES.eligible;
  const targetLabel = setupConfig.targetMode === 'remote'
    ? (setupConfig.targetLabel || 'Remote server over SSH')
    : 'This computer';
  return (
    <aside className="v18-setup-summary">
      <Card title="Setup Summary">
        <div className="v18-time-card">
          <span>Estimated setup time</span>
          <strong>20-30 min</strong>
          <Clock size={34} />
        </div>
        <div className="v18-summary-list">
          <div><Server size={18} /><span>Selected Role</span><strong>{setupConfig.nodeType === 'validator' ? 'Validator Node' : setupConfig.nodeType}</strong></div>
          <div><Monitor size={18} /><span>Target</span><strong>{targetLabel}</strong></div>
          <div><Globe2 size={18} /><span>Network</span><strong>{setupConfig.network}</strong></div>
          <div><Shield size={18} /><span>Validator Nickname</span><strong>{setupConfig.nodeNickname || 'Not set'}</strong></div>
          <div><Shield size={18} /><span>Validator Address</span><strong>{validatorAddress ? truncateMiddle(validatorAddress, 8, 6) : 'Create identity first'}</strong></div>
          <div><Wallet size={18} /><span>Owner Wallet</span><strong>{ownerWallet ? truncateMiddle(ownerWallet, 6, 5) : 'Not connected'}</strong></div>
          <div><Lock size={18} /><span>Bonded Stake</span><strong>{stakeReady ? `${formatNumber(eligibility.activeStakeAmount)} SNRG` : 'Not bonded'}</strong></div>
          <div><KeyRound size={18} /><span>Backup Status</span><strong>{backupConfirmed ? 'Confirmed' : 'Not confirmed'}</strong></div>
          <div><Wifi size={18} /><span>Secure Network</span><strong>{secureNetworkStatus || 'Not connected'}</strong></div>
          <div><Archive size={18} /><span>Sync Method</span><strong>{syncStatus || (setupConfig.snapshotSync ? 'Fast Snapshot Sync' : 'Normal Sync')}</strong></div>
          <div><FolderOpen size={18} /><span>Storage</span><strong>{setupConfig.storageLocation}</strong></div>
          <div><ClipboardCheck size={18} /><span>Current Status</span><strong>{currentStatus || setupSteps[0]}</strong></div>
        </div>
      </Card>
    </aside>
  );
}

function SetupStepContent({ step, eligibility, setupConfig, setSetupConfig, setCurrentStep, setEligibility }) {
  const context = useControlPanel();
  const navigate = useNavigate();
  const nodeId = setupConfig.remoteNodeId || context.selectedNode?.id || '';
  const storedStepContent = readSetupWizardState(nodeId)?.stepContent || {};
  const [identityGenerated, setIdentityGenerated] = useState(() => Boolean(storedStepContent.identityGenerated));
  const [consensusKeysGenerated, setConsensusKeysGenerated] = useState(() => Boolean(storedStepContent.consensusKeysGenerated));
  const [keysEncrypted, setKeysEncrypted] = useState(() => Boolean(storedStepContent.keysEncrypted));
  const [backupExported, setBackupExported] = useState(() => Boolean(storedStepContent.backupExported));
  const [backupConfirmed, setBackupConfirmed] = useState(() => Boolean(storedStepContent.backupConfirmed));
  const [stepError, setStepError] = useState('');
  const [stepBusy, setStepBusy] = useState('');
  const [healthCheckProgress, setHealthCheckProgress] = useState(() => storedStepContent.healthCheckProgress || { state: 'idle', activeIndex: -1, percent: 0, message: '' });
  const [preProvisionChecks, setPreProvisionChecks] = useState(() => storedStepContent.preProvisionChecks || []);
  const [setupConfigStatus, setSetupConfigStatus] = useState('');
  const [setupPassphraseDialogOpen, setSetupPassphraseDialogOpen] = useState(false);
  const [setupPassphrase, setSetupPassphrase] = useState('');
  const [setupPassphraseConfirm, setSetupPassphraseConfirm] = useState('');
  const [setupPassphraseError, setSetupPassphraseError] = useState('');
  const [encryptionDialogOpen, setEncryptionDialogOpen] = useState(false);
  const [encryptionPassphrase, setEncryptionPassphrase] = useState('');
  const [encryptionConfirm, setEncryptionConfirm] = useState('');
  const [encryptionInputError, setEncryptionInputError] = useState('');
  const [provisioningState, setProvisioningState] = useState(() => restoreStoredProvisioningState(storedStepContent.provisioningState));
  const [activationPending, setActivationPending] = useState(() => normalizeStoredActivationPending(storedStepContent.activationPending));
  const [vpnSetupState, setVpnSetupState] = useState(() => storedStepContent.vpnSetupState || { status: 'idle', message: '' });
  const [snapshotState, setSnapshotState] = useState(() => storedStepContent.snapshotState || { status: 'idle', message: '' });
  const [targetsState, setTargetsState] = useState({ loading: false, targets: [], error: '' });
  const [targetDraft, setTargetDraft] = useState({
    label: '',
    host: '',
    port: 22,
    username: '',
    authMethod: 'ncp_managed_key',
    identityFile: '',
    temporaryPassword: '',
    keyStoragePassphrase: '',
  });
  const [targetInstall, setTargetInstall] = useState('');
  const [secureNetworkToken, setSecureNetworkToken] = useState('');
  const provisioningCancelRef = useRef(false);
  const activationMonitorStartedRef = useRef(false);
  const encryptedKeyPath = context.selectedNode?.encrypted_private_key_path || context.selectedNode?.encryptedPrivateKeyPath || '';
  const validatorAddress = setupConfig.remoteNodeAddress || context.selectedNode?.node_address || '';
  const identityReady = identityGenerated || Boolean(validatorAddress);
  const consensusReady = consensusKeysGenerated || identityReady;
  const encryptedReady = keysEncrypted || Boolean(encryptedKeyPath);
  const keysReady = identityReady && consensusReady && encryptedReady;
  const selectedTarget = targetsState.targets.find((target) => target.id === setupConfig.targetId);
  const targetState = setupConfig.targetMode === 'local' ? 'connected' : targetConnectionState(selectedTarget);

  const reloadTargets = async () => {
    const response = await invokeOnboarding('listTargets');
    const remoteTargets = Array.isArray(response?.targets)
      ? response.targets.filter((target) => target.mode === 'remote')
      : [];
    setTargetsState({ loading: false, targets: remoteTargets, error: '' });
    return remoteTargets;
  };

  const runStepAction = async (label, action, onSuccess, onError) => {
    setStepBusy(label);
    setStepError('');
    try {
      const result = await action();
      await onSuccess(result);
      return true;
    } catch (error) {
      setStepError(String(error?.message || error));
      onError?.(error);
      return false;
    } finally {
      setStepBusy('');
    }
  };

  useEffect(() => {
    const restored = readSetupWizardState(nodeId)?.stepContent || {};
    setIdentityGenerated(Boolean(restored.identityGenerated));
    setConsensusKeysGenerated(Boolean(restored.consensusKeysGenerated));
    setKeysEncrypted(Boolean(restored.keysEncrypted));
    setBackupExported(Boolean(restored.backupExported));
    setBackupConfirmed(Boolean(restored.backupConfirmed));
    setHealthCheckProgress(restored.healthCheckProgress || { state: 'idle', activeIndex: -1, percent: 0, message: '' });
    setPreProvisionChecks(restored.preProvisionChecks || []);
    setProvisioningState(restoreStoredProvisioningState(restored.provisioningState));
    setActivationPending(normalizeStoredActivationPending(restored.activationPending));
    setVpnSetupState(restored.vpnSetupState || { status: 'idle', message: '' });
    setSnapshotState(restored.snapshotState || { status: 'idle', message: '' });
  }, [nodeId]);

  useEffect(() => listenOnboardingMeshProgress((progress = {}) => {
    const messageByStep = {
      requesting_elevation: 'Requesting permission to configure the secure validator network.',
      redeeming_invite: 'Redeeming the coordinator-issued secure-network invite.',
      interface_up: 'Secure-network interface is online. Verifying peer connectivity.',
      handshake_probe_started: 'Secure-network peers are configured. Establishing encrypted peer handshakes.',
      handshake_waiting: 'Waiting for the secure peer mesh to finish converging.',
      enrolling_validator: 'Submitting this validator to the coordinator-managed network configuration.',
      confirming_propagation: 'Waiting for every active validator to acknowledge the new network configuration.',
      handshake_confirmed: 'A secure-network peer handshake has been confirmed.',
    };
    const message = messageByStep[progress.step];
    if (message) {
      setVpnSetupState((current) => current.status === 'running' ? { ...current, message } : current);
    }
  }), []);

  useEffect(() => {
    if (step !== SETUP_STEP.deviceNetworkSync || !nodeId) return undefined;
    let cancelled = false;

    const refreshExistingVpnStatus = async () => {
      try {
        const result = await nodeService.getValidatorVpnStatus(nodeId);
        if (cancelled) return;
        const secureNetwork = secureNetworkTruth(result, context.selectedNodeLive);
        if (!secureNetwork.confirmed) return;
        setSecureNetworkToken('');
        setVpnSetupState((current) => {
          if (current.status === 'running') return current;
          return {
            status: 'success',
            message: result?.message || 'Secure validator network confirmed from the existing enrollment and live peer evidence.',
            result,
          };
        });
      } catch {
        // A passive status refresh must not hide the explicit setup error.
      }
    };

    void refreshExistingVpnStatus();
    const interval = window.setInterval(refreshExistingVpnStatus, 15_000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [
    context.selectedNodeLive?.is_running,
    context.selectedNodeLive?.local_peer_count,
    context.selectedNodeLive?.local_rpc_ready,
    context.selectedNodeLive?.secure_network_connected,
    context.selectedNodeLive?.validator_vpn_connected,
    nodeId,
    step,
  ]);

  useEffect(() => {
    if (step !== SETUP_STEP.validatorIdentity || setupConfig.targetMode !== 'remote') return undefined;
    let cancelled = false;
    setTargetsState((current) => ({ ...current, loading: true, error: '' }));
    invokeOnboarding('listTargets')
      .then((response) => {
        if (cancelled) return;
        const remoteTargets = Array.isArray(response?.targets)
          ? response.targets.filter((target) => target.mode === 'remote')
          : [];
        setTargetsState({ loading: false, targets: remoteTargets, error: '' });
      })
      .catch((error) => {
        if (!cancelled) setTargetsState({ loading: false, targets: [], error: String(error?.message || error) });
      });
    return () => { cancelled = true; };
  }, [setupConfig.targetMode, step]);

  useEffect(() => {
    writeSetupWizardState(nodeId, {
      stepContent: {
        identityGenerated,
        consensusKeysGenerated,
        keysEncrypted,
        backupExported,
        backupConfirmed,
        healthCheckProgress,
        preProvisionChecks,
        activationPending,
        vpnSetupState,
        snapshotState,
        provisioningState: {
          ...provisioningState,
          running: false,
          message: provisioningState.running
            ? provisioningState.message || 'Onboarding monitor is active.'
            : provisioningState.message,
        },
      },
    });
  }, [
    backupConfirmed,
    backupExported,
    consensusKeysGenerated,
    healthCheckProgress,
    identityGenerated,
    keysEncrypted,
    nodeId,
    preProvisionChecks,
    provisioningState,
    activationPending,
    snapshotState,
    vpnSetupState,
  ]);

  useEffect(() => () => {
    provisioningCancelRef.current = true;
  }, []);

  useEffect(() => {
    setStepError('');
    setEncryptionInputError('');
  }, [step]);

  useEffect(() => {
    if (stepBusy !== 'requirements') return undefined;
    let index = 0;
    setHealthCheckProgress({
      state: 'running',
      activeIndex: 0,
      percent: 12,
      message: healthCheckStages[0].label,
    });
    const timer = window.setInterval(() => {
      index = Math.min(index + 1, healthCheckStages.length - 1);
      setHealthCheckProgress({
        state: 'running',
        activeIndex: index,
        percent: Math.min(88, 18 + index * 24),
        message: healthCheckStages[index].label,
      });
    }, 650);
    return () => window.clearInterval(timer);
  }, [stepBusy]);

  const runPreProvisionRequirementsCheck = async () => {
    const targetId = setupConfig.targetMode === 'remote' ? setupConfig.targetId : 'local';
    const [device, pathValidation, rpcEligibility] = await Promise.all([
      invokeOnboarding('deviceCheck', { targetId }),
      setupConfig.targetMode === 'remote'
        ? Promise.resolve({ message: setupConfig.storageLocation, writable: true, is_file: false })
        : nodeService.validatePath(setupConfig.storageLocation),
      validatorEligibilityService.verifyValidatorEligibility(eligibility.walletAddress, { targetId }),
    ]);
    const rows = [
      {
        id: 'cpu',
        label: 'CPU',
        value: `${formatNumber(device?.cpu_cores || device?.cpuCores || 0)} cores`,
        status: Number(device?.cpu_cores || device?.cpuCores || 0) >= 8 ? 'pass' : 'fail',
      },
      {
        id: 'memory',
        label: 'RAM',
        value: `${formatNumber(device?.total_memory_gb || device?.totalMemoryGb || 0)} GB`,
        status: Number(device?.total_memory_gb || device?.totalMemoryGb || 0) >= 16 ? 'pass' : 'fail',
      },
      {
        id: 'storage',
        label: 'Storage',
        value: pathValidation?.message || setupConfig.storageLocation,
        status: pathValidation?.is_file || pathValidation?.writable === false ? 'fail' : 'pass',
      },
      {
        id: 'disk',
        label: 'Free Disk',
        value: `${formatNumber(device?.available_disk_gb || device?.availableDiskGb || 0)} GB available`,
        status: Number(device?.available_disk_gb || device?.availableDiskGb || 0) >= 200 ? 'pass' : 'fail',
      },
      {
        id: 'network',
        label: 'Synergy RPC',
        value: rpcEligibility?.lastVerifiedAt ? 'Reachable' : 'Unavailable',
        status: rpcEligibility?.eligibilityStatus === ELIGIBILITY_STATUSES.error ? 'fail' : 'pass',
      },
      {
        id: 'wallet',
        label: 'Operator Wallet',
        value: rpcEligibility?.eligible
          ? 'Bonded stake verified'
          : `${formatNumber(rpcEligibility?.snrgBalance || 0)} SNRG available`,
        status: rpcEligibility?.eligible || Number(rpcEligibility?.snrgBalance || 0) >= VALIDATOR_FUNDING_TARGET_SNRG ? 'pass' : 'fail',
      },
    ];
    setPreProvisionChecks(rows);
    const failed = rows.filter((row) => row.status === 'fail');
    if (failed.length) {
      throw new Error(`Requirement check failed: ${failed.map((row) => row.label).join(', ')}.`);
    }
    return rows;
  };

  const runRequirementsCheck = async () => {
    const ok = await runStepAction(
      'requirements',
      () => (nodeId ? nodeService.runHealthCheck(nodeId) : runPreProvisionRequirementsCheck()),
      async () => {
        await context.refresh({ silent: true });
        setHealthCheckProgress({
          state: 'success',
          activeIndex: healthCheckStages.length,
          percent: 100,
          message: 'Requirements check completed successfully.',
        });
      },
    );
    if (!ok) {
      setHealthCheckProgress({
        state: 'error',
        activeIndex: -1,
        percent: 100,
        message: 'Requirements check failed.',
      });
    }
  };

  const setupValidatorVpn = async () => {
    if (!nodeId) {
      setStepError('Generate the validator identity before connecting the secure validator network.');
      return;
    }
    setVpnSetupState({ status: 'running', message: 'Preparing local secure-network keys and enrolling with the coordinator.' });
    const ok = await runStepAction(
      'vpn-setup',
      () => validatorProvisioningService.enrollValidatorVpn({
        nodeId,
        walletAddress: eligibility.walletAddress,
        operatorAddress: eligibility.walletAddress,
        validatorAddress: validatorAddress || context.selectedNode?.nodeAddress || null,
        stakeTxHash: eligibility.stakeTxHash || eligibility.stake_tx_hash || null,
        eligibility,
        onboardingToken: secureNetworkToken,
        peerName: setupConfig.nodeNickname || context.selectedNode?.node_address || nodeId,
        targetId: setupConfig.targetId || (setupConfig.targetMode === 'remote' ? '' : 'local'),
        target: {
          id: setupConfig.targetId || undefined,
          mode: setupConfig.targetMode || 'local',
        },
      }),
      async (result) => {
        await context.refresh({ silent: true });
        setSecureNetworkToken('');
        setVpnSetupState({
          status: 'success',
          message: result?.message || 'Coordinator-managed Innernet enrollment and signed membership receipt were confirmed.',
          result,
        });
      },
    );
    if (!ok) {
      setVpnSetupState({ status: 'error', message: 'Secure validator network setup failed.' });
    }
  };

  const refreshTargetConnection = async () => {
    if (setupConfig.targetMode !== 'remote' || !setupConfig.targetId) {
      setStepError('Select a configured SSH target before testing the validator connection.');
      return;
    }
    await runStepAction('target-test', async () => {
      const response = await invokeOnboarding('testConnection', { targetId: setupConfig.targetId });
      if (response?.connected !== true) {
        throw new Error('The SSH target could not be reached.');
      }
      setTargetsState((current) => ({
        ...current,
        targets: current.targets.map((target) => target.id === setupConfig.targetId ? { ...target, connected: true, connectionStatus: 'connected' } : target),
      }));
      return response;
    }, () => setSetupConfigStatus('SSH connection confirmed for this target.'));
  };

  const addRemoteTarget = async () => {
    await runStepAction('target-add', async () => {
      const result = await invokeOnboarding('addTarget', {
        mode: 'remote',
        label: targetDraft.label,
        host: targetDraft.host,
        port: Number(targetDraft.port) || 22,
        username: targetDraft.username,
        authMethod: targetDraft.authMethod,
        identityFile: targetDraft.identityFile || undefined,
        temporaryPassword: targetDraft.temporaryPassword || undefined,
        keyStoragePassphrase: targetDraft.keyStoragePassphrase || undefined,
      });
      const remoteTargets = await reloadTargets();
      const target = remoteTargets.find((item) => item.id === result.targetId);
      updateSetupConfig({
        targetId: result.targetId,
        targetLabel: target?.label || targetDraft.label || targetDraft.host,
        targetHost: target?.host || targetDraft.host,
        targetPort: target?.port || Number(targetDraft.port) || 22,
        targetUsername: target?.username || targetDraft.username,
        targetAuthMethod: target?.authMethod || targetDraft.authMethod,
      });
      setTargetInstall(result.pubkeyToInstall || '');
      setTargetDraft((current) => ({
        ...current,
        temporaryPassword: '',
        keyStoragePassphrase: '',
      }));
      return result;
    }, () => setSetupConfigStatus('SSH target saved. Test the connection before creating the validator identity.'));
  };

  const waitForVerifiedSetupSync = async (syncMode, syncInput) => {
    let liveStatus = null;
    for (let attempt = 1; attempt <= SETUP_SYNC_MAX_ATTEMPTS; attempt += 1) {
      liveStatus = await invoke('testnet_get_validator_live_status', { nodeId });
      const { liveGap, targetHeight, localHeight } = extractSyncMetrics(liveStatus);
      if (syncStatusIsVerified(liveStatus, syncMode)) {
        setSnapshotState((current) => ({
          ...current,
          stage: 'verified',
          message: `Verified ${syncMode} catch-up at local height ${Math.trunc(localHeight)} with ${Math.trunc(liveGap)} block(s) remaining.`,
        }));

        if (syncMode === 'normal') {
          try {
            await invoke('testnet_mark_setup_sync_complete', {
              input: {
                nodeId,
                localChainHeight: Math.trunc(localHeight),
                syncTargetHeight: Number.isFinite(targetHeight) ? Math.trunc(targetHeight) : undefined,
                syncGap: Math.trunc(liveGap),
                syncMode,
              },
            });
          } catch (error) {
            if (!String(error?.message || error).toLowerCase().includes('normal peer sync cannot complete setup sync')) {
              throw error;
            }
            await invoke('testnet_run_validator_onboarding', {
              input: {
                nodeId,
                dryRun: false,
                autoResyncTime: true,
                autoStart: true,
                autoStake: false,
                autoActivate: false,
                syncMode,
                ...(syncInput?.targetId ? { targetId: syncInput.targetId } : {}),
              },
            });
            liveStatus = await invoke('testnet_get_validator_live_status', { nodeId });
            if (!syncStatusIsVerified(liveStatus, syncMode)) {
              throw new Error('Normal sync verification changed before setup sync evidence could be recorded.');
            }
            const verified = extractSyncMetrics(liveStatus);
            await invoke('testnet_mark_setup_sync_complete', {
              input: {
                nodeId,
                localChainHeight: Math.trunc(verified.localHeight),
                syncTargetHeight: Number.isFinite(verified.targetHeight) ? Math.trunc(verified.targetHeight) : undefined,
                syncGap: Math.trunc(verified.liveGap),
                syncMode,
              },
            });
          }
        } else {
          await invoke('testnet_mark_setup_sync_complete', {
            input: {
              nodeId,
              localChainHeight: Math.trunc(localHeight),
              syncTargetHeight: Number.isFinite(targetHeight) ? Math.trunc(targetHeight) : undefined,
              syncGap: Math.trunc(liveGap),
              syncMode,
            },
          });
        }
        return liveStatus;
      }

      setSnapshotState((current) => ({
        ...current,
        stage: 'sync',
        message: Number.isFinite(liveGap)
          ? `Waiting for verified ${syncMode} catch-up: ${Math.max(0, Math.trunc(liveGap))} block(s) remaining.`
          : 'Waiting for verified validator catch-up telemetry from the local RPC.',
      }));
      if (attempt < SETUP_SYNC_MAX_ATTEMPTS) await sleep(SETUP_SYNC_POLL_MS);
    }
    throw new Error(`Validator did not reach the verified setup sync gate within ${SETUP_SYNC_MAX_ATTEMPTS} checks.`);
  };

  const downloadApplySnapshot = async () => {
    if (!nodeId) {
      setStepError('Generate the validator identity before downloading a validator snapshot.');
      return;
    }
    const targetId = setupConfig.targetMode === 'remote' ? setupConfig.targetId : 'local';
    setSnapshotState({ status: 'running', stage: 'discover', message: 'Discovering a compatible archive-validator snapshot.' });
    const ok = await runStepAction(
      'snapshot',
      async () => {
        const discovered = await invokeOnboarding('discoverSnapshots', { targetId });
        const snapshotId = discovered?.snapshot?.snapshotId || discovered?.snapshot?.snapshot_id;
        if (!snapshotId) {
          throw new Error('The archive catalog did not return a compatible snapshot ID.');
        }
        setSnapshotState({ status: 'running', stage: 'download', message: `Downloading verified snapshot ${snapshotId}.`, result: { discovered } });
        const downloaded = await invokeOnboarding('downloadSnapshot', { targetId, nodeId, snapshotId });
        setSnapshotState({ status: 'running', stage: 'verify', message: `Verifying snapshot ${snapshotId} before any node state is changed.`, result: { discovered, downloaded } });
        const verified = await invokeOnboarding('verifySnapshot', { targetId, nodeId, snapshotId });
        setSnapshotState({ status: 'running', stage: 'apply', message: `Applying verified snapshot ${snapshotId} to a clean validator state directory.`, result: { discovered, downloaded, verified } });
        const restore = await invokeOnboarding('applyVerifiedSnapshot', { targetId, nodeId, snapshotId });
        setSnapshotState({ status: 'running', stage: 'sync', message: `Starting guarded catch-up from snapshot ${snapshotId}.`, result: { discovered, downloaded, verified, restore } });
        const sync = await invokeOnboarding('syncAfterSnapshot', { targetId, nodeId });
        return { discovered, downloaded, verified, restore, sync, snapshotId, message: `${restore?.detail || restore?.message || 'Validator snapshot applied.'} ${sync?.message || 'Live speed sync requested.'}` };
      },
      async (result) => {
        const verifiedLiveStatus = await waitForVerifiedSetupSync('snapshot', { targetId, nodeId });
        await context.refresh({ silent: true });
        setSnapshotState({
          status: 'success',
          stage: 'complete',
          message: result?.message || 'Validator snapshot applied and verified catch-up completed.',
          result: { ...result, verifiedLiveStatus, setupSyncMode: 'snapshot' },
        });
      },
    );
    if (!ok) {
      setSnapshotState({
        status: 'error',
        message: 'Snapshot workflow failed before completion. Review the failed stage before selecting normal sync.',
      });
    }
  };

  const updateSetupConfig = (patch) => {
    setSetupConfig((current) => ({
      ...setupConfigForNode(context.selectedNode, current),
      ...patch,
    }));
  };

  const chooseStorageLocation = async () => {
    setSetupConfigStatus('');
    setStepError('');
    if (setupConfig.targetMode === 'remote') {
      setStepError('Enter an absolute directory on the remote server. Local folder browsing is not used for remote validator storage.');
      return;
    }
    try {
      const selectedPath = await showOpenDialog({
        title: 'Select validator storage location',
        properties: ['openDirectory', 'createDirectory'],
      });
      if (!selectedPath) return;
      updateSetupConfig({ storageLocation: selectedPath });
      const validation = await nodeService.validatePath(selectedPath);
      setSetupConfigStatus(validation?.message || 'Storage location validated.');
    } catch (error) {
      setStepError(String(error?.message || error));
    }
  };

  const createValidatorNodeFromSetup = async (identityPassphrase) => {
    const nickname = String(setupConfig.nodeNickname || '').trim();
    const isRemote = setupConfig.targetMode === 'remote';
    const result = await nodeService.setupValidatorNode({
      targetId: setupConfig.targetId || (setupConfig.targetMode === 'remote' ? '' : 'local'),
      target: {
        mode: setupConfig.targetMode || 'local',
        label: setupConfig.targetLabel || '',
        host: setupConfig.targetHost || undefined,
        port: Number(setupConfig.targetPort) || 22,
        username: setupConfig.targetUsername || undefined,
        authMethod: setupConfig.targetAuthMethod || 'ncp_managed_key',
      },
      displayLabel: nickname,
      intendedDirectory: setupConfig.storageLocation,
      identityPassphrase,
    });
    const createdNode = result?.node;
    if (!createdNode?.id) {
      throw new Error('Validator setup did not return a validator node record.');
    }
    if (!isRemote) {
      await invoke('testnet_apply_atlas_validator_profile', {
        input: {
          nodeId: createdNode.id,
          validatorAddress: createdNode.node_address,
          nickname,
          ownerWalletAddress: eligibility.walletAddress || undefined,
          publicTags: ['validator-node', 'synergy-testnet'],
          privateTags: ['node-control-panel'],
        },
      });
    }
    const nextSetupConfig = {
      ...setupConfig,
      nodeNickname: nickname,
      storageLocation: createdNode.workspace_directory || setupConfig.storageLocation,
      remoteNodeId: createdNode.id,
      remoteNodeAddress: createdNode.node_address || '',
      remoteWorkspaceDirectory: isRemote ? createdNode.workspace_directory || '' : '',
    };
    setSetupConfig(nextSetupConfig);
    setIdentityGenerated(true);
    setConsensusKeysGenerated(true);
    setKeysEncrypted(Boolean(createdNode.encrypted_private_key_path || createdNode.encryptedPrivateKeyPath));
    writeSetupWizardState(createdNode.id, {
      currentStep: SETUP_STEP.validatorIdentity,
      eligibility,
      setupConfig: nextSetupConfig,
      walletAddress: eligibility.walletAddress,
      stepContent: {
        identityGenerated: true,
        consensusKeysGenerated: true,
        keysEncrypted: Boolean(createdNode.encrypted_private_key_path || createdNode.encryptedPrivateKeyPath),
        backupExported,
        backupConfirmed,
        healthCheckProgress,
        preProvisionChecks,
        provisioningState,
      },
    });
    clearSetupWizardState(null);
    if (isRemote) {
      setSetupConfigStatus('Remote validator workspace created and identity encrypted on the target. Continue with the owner wallet and bonded stake.');
      return result;
    }
    context.setSelectedNodeId?.(createdNode.id);
    await context.refresh({ silent: true });
    try {
      const publish = await invoke('testnet_publish_validator_profile_to_atlas', {
        input: { nodeId: createdNode.id },
      });
      setSetupConfigStatus(publish?.published
        ? 'Validator workspace created, keys encrypted, and profile published to Atlas.'
        : `Validator workspace created, keys encrypted, and nickname saved locally. Atlas sync is pending: ${publish?.message || publish?.status || 'unknown Atlas response'}`);
    } catch (error) {
      setSetupConfigStatus(`Validator workspace created and nickname saved locally. Atlas sync is pending: ${String(error?.message || error)}`);
    }
    return result;
  };

  const applyNodeTypeConfiguration = async () => {
    const nickname = String(setupConfig.nodeNickname || '').trim();
    if (!nickname) {
      setStepError('Node nickname is required.');
      return;
    }
    setStepBusy('node-config');
    setStepError('');
    setSetupConfigStatus('');
    try {
      if (setupConfig.storageLocation) {
        const validation = await nodeService.validatePath(setupConfig.storageLocation);
        if (validation?.is_file) {
          throw new Error('Storage location must be a directory, not a file.');
        }
        setSetupConfigStatus(validation?.message || 'Storage location validated.');
      }
      if (nodeId) {
        await invoke('testnet_apply_atlas_validator_profile', {
          input: {
            nodeId,
            validatorAddress: context.selectedNode?.node_address || undefined,
            nickname,
            ownerWalletAddress: eligibility.walletAddress || undefined,
            publicTags: ['validator-node', 'synergy-testnet'],
            privateTags: ['node-control-panel'],
          },
        });
        try {
          const publish = await invoke('testnet_publish_validator_profile_to_atlas', {
            input: { nodeId },
          });
          setSetupConfigStatus(publish?.published
            ? 'Node nickname saved and published to Atlas.'
            : `Node nickname saved locally. Atlas sync is pending: ${publish?.message || publish?.status || 'unknown Atlas response'}`);
        } catch (error) {
          setSetupConfigStatus(`Node nickname saved locally. Atlas sync is pending: ${String(error?.message || error)}`);
        }
        await context.refresh({ silent: true });
      } else {
        setSetupPassphraseDialogOpen(true);
        return;
      }
      setCurrentStep(SETUP_STEP.walletStake);
    } catch (error) {
      setStepError(String(error?.message || error));
    } finally {
      setStepBusy('');
    }
  };

  const cancelEncryptionDialog = () => {
    if (stepBusy === 'encrypt') return;
    setEncryptionDialogOpen(false);
    setEncryptionPassphrase('');
    setEncryptionConfirm('');
    setEncryptionInputError('');
  };

  const cancelSetupPassphraseDialog = () => {
    if (stepBusy === 'node-config') return;
    setSetupPassphraseDialogOpen(false);
    setSetupPassphrase('');
    setSetupPassphraseConfirm('');
    setSetupPassphraseError('');
  };

  const submitSetupPassphrase = async (event) => {
    event.preventDefault();
    const passphrase = setupPassphrase;
    if (passphrase.length < 8) {
      setSetupPassphraseError('Use at least 8 characters.');
      return;
    }
    if (passphrase !== setupPassphraseConfirm) {
      setSetupPassphraseError('Passphrases do not match.');
      return;
    }
    setSetupPassphraseError('');
    setStepBusy('node-config');
    setStepError('');
    setSetupPassphraseDialogOpen(false);
    try {
      await createValidatorNodeFromSetup(passphrase);
      setSetupPassphrase('');
      setSetupPassphraseConfirm('');
      setSetupPassphraseError('');
      setCurrentStep(SETUP_STEP.validatorIdentity);
    } catch (error) {
      const message = String(error?.message || error);
      setStepError(message);
      setSetupPassphraseError(message);
      setSetupPassphraseDialogOpen(true);
    } finally {
      setStepBusy('');
    }
  };

  const submitEncryption = async (event) => {
    event.preventDefault();
    const passphrase = encryptionPassphrase;
    if (passphrase.length < 8) {
      setEncryptionInputError('Use at least 8 characters.');
      return;
    }
    if (passphrase !== encryptionConfirm) {
      setEncryptionInputError('Passphrases do not match.');
      return;
    }
    setEncryptionInputError('');
    const ok = await runStepAction(
      'encrypt',
      () => nodeService.encryptKeys(nodeId, passphrase),
      () => setKeysEncrypted(true),
    );
    if (ok) {
      setEncryptionDialogOpen(false);
      setEncryptionPassphrase('');
      setEncryptionConfirm('');
      setEncryptionInputError('');
    }
  };

  const updateProvisioningStep = (id, status, detail = '') => {
    setProvisioningState((current) => ({
      ...current,
      stageId: id,
      steps: {
        ...current.steps,
        [id]: { status, detail },
      },
      message: detail || current.message,
    }));
  };

  const applyOnboardingResultToSteps = (result) => {
    const policy = onboardingPolicy(result);
    const source = policy.sourceMajority || policy.source_majority;
    const shadow = policy.shadowEpoch || policy.shadow_epoch;
    const duties = policy.dutyGates || policy.duty_gates;
    const shadowProgress = shadowProgressFromOnboarding(result);
    const stepStatuses = onboardingStepStatuses(result);
    const monitorMessage = onboardingMonitorMessage(result);
    const resultComplete = result?.status === 'complete';
    const backendSteps = new Map(
      (Array.isArray(result?.steps) ? result.steps : [])
        .filter((stepResult) => stepResult?.id)
        .map((stepResult) => [stepResult.id, stepResult]),
    );
    const backendStepState = (id, fallback) => {
      const stepResult = backendSteps.get(id);
      if (!stepResult) return fallback;
      const status = String(stepResult.status || '').toLowerCase();
      const detail = stepResult.detail || fallback?.detail || '';
      if (status === 'pass' || status === 'ok' || status === 'complete') {
        return { status: 'success', detail };
      }
      if (status === 'fail' || status === 'failed' || status === 'error' || status === 'blocked') {
        return { status: 'error', detail };
      }
      if (status === 'warn' || status === 'warning') {
        return { status: 'error', detail };
      }
      if (status === 'running' || status === 'in_progress') {
        return { status: 'running', detail };
      }
      return { status: fallback?.status || 'pending', detail };
    };
    const activeProof = backendStepState('active-proof', { status: 'pending', detail: result?.message || 'Waiting for activation proof.' });
    const ready = resultComplete || activeProof.status === 'success' || activationReadyFromOnboarding(result);
    const gateStatus = (gate, runningStatus = 'running') => {
      if (resultComplete) return { status: 'success', detail: result?.message || 'Validator onboarding is complete.' };
      if (!gate) return { status: 'pending', detail: 'Waiting for evidence.' };
      if (gate.status === 'pass') return { status: 'success', detail: gate.detail };
      if (gate.status === 'failed') return { status: 'error', detail: gate.detail };
      return { status: runningStatus, detail: gate.detail };
    };
    const syncState = resultComplete
      ? { status: 'success', detail: result?.message || 'Snapshot-backed catch-up and activation evidence are complete.' }
      : backendStepState('sync-catch-up', {
        status: result?.catchUp?.status === 'failed' ? 'error' : result?.catchUp ? 'success' : 'pending',
        detail: result?.catchUp?.message || 'Waiting for snapshot restore and live sync evidence.',
      });
    setProvisioningState((current) => ({
      ...current,
      result,
      steps: {
        ...current.steps,
        onboarding: {
          status: stepStatuses.onboarding,
          detail: monitorMessage,
        },
        sync: syncState,
        stake: {
          status: resultComplete || result?.stake?.status ? 'success' : result?.preflight?.stakedBalanceNwei ? 'success' : 'running',
          detail: result?.stake?.message || 'Waiting for bonded validator stake proof.',
        },
        source: gateStatus(source).status === 'running' ? gateStatus(source, 'pending') : gateStatus(source),
        duties: gateStatus(duties).status === 'running' ? gateStatus(duties, 'pending') : gateStatus(duties),
        shadow: {
          ...gateStatus(shadow),
          status: stepStatuses.shadow || gateStatus(shadow).status,
          detail: stepStatuses.shadow
            ? monitorMessage
            : `${shadow?.detail || 'Observing shadow epoch.'} ${shadowProgress.observed}/${shadowProgress.required} blocks observed.`,
        },
        'activation-ready': {
          status: ready ? 'success' : 'pending',
          detail: ready
            ? 'Shadow epoch, source-majority, duty gates, stake, and preflight are passing. Operator activation is available.'
            : result?.message || 'Activation remains locked until all onboarding evidence passes.',
        },
      },
    }));
  };

  const buildActivationMonitorInput = (pending = activationPending) => ({
    nodeId: pending?.nodeId || nodeId,
    walletAddress: pending?.walletAddress || eligibility.walletAddress,
    eligibility,
    targetId: pending?.targetId || (setupConfig.targetMode === 'remote' ? setupConfig.targetId : 'local'),
    syncMode: pending?.syncMode || (snapshotState.status === 'normal-sync' ? 'normal' : 'snapshot'),
  });

  const runActivationMonitor = async (input) => {
    let lastResult = provisioningState.result || null;
    while (!provisioningCancelRef.current) {
      try {
        const result = await validatorProvisioningService.runAutonomousOnboarding(input);
        lastResult = result;
        applyOnboardingResultToSteps(result);
        const liveStatus = await invoke('testnet_get_validator_live_status', { nodeId: input.nodeId }).catch(() => null);
        const canonicalConfirmed = activationConfirmedFromOnboarding(result);
        const activeProof = (Array.isArray(result?.steps) ? result.steps : [])
          .find((stepResult) => stepResult?.id === 'active-proof');
        const activeEvidence = activeConsensusEvidence(liveStatus)
          || (canonicalConfirmed && String(activeProof?.status || '').toLowerCase() === 'pass');

        if (canonicalConfirmed && activeEvidence) {
          setActivationPending(null);
          setProvisioningState((current) => ({
            ...current,
            running: false,
            stageId: 'active',
            result: { ...result, activeConsensusEvidence: liveStatus || { source: 'canonical-onboarding-result' } },
            message: result?.message || 'Canonical activation and active-consensus evidence are confirmed.',
            error: '',
            steps: {
              ...current.steps,
              'activation-submitted': { status: 'success', detail: 'Activation transaction is confirmed in the canonical validator registry.' },
              'activation-ready': { status: 'success', detail: 'Canonical activation confirmation is recorded.' },
              active: { status: 'success', detail: 'Active-consensus evidence is visible for this validator.' },
            },
          }));
          await context.refresh({ silent: true }).catch(() => null);
          return result;
        }

        if (String(result?.status || '').toLowerCase() === 'failed') {
          const message = result?.message || 'Validator activation monitoring reported a terminal failure.';
          setProvisioningState((current) => ({
            ...current,
            running: false,
            stageId: 'activation-submitted',
            error: message,
            message,
            result,
            steps: {
              ...current.steps,
              'activation-submitted': { status: 'error', detail: message },
            },
          }));
          return result;
        }

        setActivationPending((current) => current ? ({
          ...current,
          lastCheckedAt: new Date().toISOString(),
        }) : current);
        const nextAction = onboardingNextAction(result);
        setProvisioningState((current) => ({
          ...current,
          running: true,
          stageId: 'activation-submitted',
          result,
          message: nextAction === 'sync_catch_up'
            ? 'Activation is pending while the validator catches up to the canonical head.'
            : result?.message || 'Activation is pending canonical registry and active-consensus confirmation.',
          error: '',
          steps: {
            ...current.steps,
            'activation-submitted': {
              status: 'running',
              detail: result?.message || 'Activation transaction submitted; monitoring propagation without resubmitting.',
            },
          },
        }));
      } catch (error) {
        const message = String(error?.message || error);
        setActivationPending((current) => current ? ({
          ...current,
          lastCheckedAt: new Date().toISOString(),
        }) : current);
        setProvisioningState((current) => ({
          ...current,
          running: true,
          stageId: 'activation-submitted',
          message: `Activation monitor will retry after this check failed: ${message}`,
          error: '',
        }));
      }
      if (!provisioningCancelRef.current) await sleep(ACTIVATION_MONITOR_POLL_MS);
    }

    setProvisioningState((current) => ({
      ...current,
      running: false,
      result: lastResult,
      stageId: 'activation-submitted',
      message: 'Activation remains pending. Resume the monitor to continue checking without resubmitting the transaction.',
    }));
    return lastResult;
  };

  const startActivationMonitor = async (input) => {
    if (activationMonitorStartedRef.current || !input?.nodeId) return null;
    activationMonitorStartedRef.current = true;
    provisioningCancelRef.current = false;
    setProvisioningState((current) => ({
      ...current,
      running: true,
      stageId: 'activation-submitted',
      message: 'Activation is pending. Monitoring canonical activation and active-consensus evidence without resubmitting.',
      error: '',
    }));
    try {
      return await runActivationMonitor(input);
    } finally {
      activationMonitorStartedRef.current = false;
    }
  };

  useEffect(() => {
    if (step !== SETUP_STEP.launchActivate || activationPending?.status !== 'pending' || provisioningState.running || stepBusy || activationMonitorStartedRef.current) {
      return undefined;
    }
    const timer = window.setTimeout(() => {
      void startActivationMonitor(buildActivationMonitorInput(activationPending));
    }, 3000);
    return () => window.clearTimeout(timer);
  }, [activationPending?.nodeId, step]);

  const runProvisioningWorkflow = async () => {
    if (!nodeId || provisioningState.running) return;
    if (activationPending?.status === 'pending') {
      await startActivationMonitor(buildActivationMonitorInput());
      return;
    }
    provisioningCancelRef.current = false;
    const selectedSyncMode = setupSyncModeFromState(snapshotState, context.selectedNodeLive);
    const selectedSyncLabel = selectedSyncMode === 'normal'
      ? 'Normal sync was verified before launch.'
      : selectedSyncMode === 'snapshot'
        ? 'Fast snapshot sync was selected before launch.'
        : 'Choose snapshot sync or normal sync before launch.';
    const secureNetwork = secureNetworkTruth(vpnSetupState.result, context.selectedNodeLive);
    const vpnReady = secureNetwork.confirmed;
    setStepError('');
    setProvisioningState({
      running: true,
      stageId: 'onboarding',
      steps: {
        vpn: {
          status: vpnReady ? 'success' : 'pending',
          detail: vpnReady ? 'Secure validator network was verified before launch.' : 'Secure validator network must be connected before launch.',
        },
        sync: {
          status: selectedSyncMode ? 'success' : 'pending',
          detail: selectedSyncLabel,
        },
      },
      result: null,
      message: 'Starting validator launch and observation.',
      error: '',
    });
    try {
      updateProvisioningStep('eligibility', 'running', 'Verifying connected wallet stake and owner permissions.');
      const verifiedEligibility = await validatorEligibilityService.verifyValidatorEligibility(eligibility.walletAddress, {
        nodeId,
        validatorAddress,
        targetId: setupConfig.targetMode === 'remote' ? setupConfig.targetId : 'local',
      });
      let currentEligibility = verifiedEligibility;
      setEligibility?.(currentEligibility);
      const bootstrapEligible = currentEligibility.eligible === true
        || (currentEligibility.fundingReadyToBond === true
          && currentEligibility.eligibilityStatus === ELIGIBILITY_STATUSES.stakeReadyToBond);
      if (!bootstrapEligible) {
        setCurrentStep(SETUP_STEP.walletStake);
        throw new Error(
          currentEligibility.errorMessage
            || `Fund the validator with ${formatNumber(VALIDATOR_FUNDING_TARGET_SNRG)} SNRG (${formatNumber(REQUIRED_VALIDATOR_STAKE_SNRG)} bond plus ${formatNumber(VALIDATOR_FEE_RESERVE_SNRG)} fee reserve) from Wallet & Stake, then verify the confirmed validator balance before starting launch.`,
        );
      }
      updateProvisioningStep(
        'eligibility',
        'success',
        currentEligibility.eligible
          ? 'Connected wallet stake and owner permissions verified.'
          : 'Validator funding and owner permissions verified. Self-bond will complete after runtime startup.',
      );
      const input = {
        nodeId,
        walletAddress: currentEligibility.walletAddress,
        eligibility: currentEligibility,
        targetId: setupConfig.targetMode === 'remote' ? setupConfig.targetId : 'local',
        syncMode: selectedSyncMode || (snapshotState.status === 'normal-sync' ? 'normal' : 'snapshot'),
      };

      if (!vpnReady) {
        setCurrentStep(SETUP_STEP.deviceNetworkSync);
        throw new Error('Secure Validator Network must be connected before launch.');
      }
      if (!selectedSyncMode) {
        setCurrentStep(SETUP_STEP.deviceNetworkSync);
        throw new Error('Choose Fast Snapshot Sync or Normal Sync before launch.');
      }
      updateProvisioningStep('vpn', 'success', vpnSetupState.message || 'Secure validator network is connected.');
      updateProvisioningStep('sync', 'success', snapshotState.message || (selectedSyncMode === 'normal' ? 'Normal sync verified.' : 'Snapshot sync selected.'));

      updateProvisioningStep('onboarding', 'running', 'Starting validator service and observation mode without submitting activation.');
      let lastResult = null;
      while (!provisioningCancelRef.current) {
        const result = await validatorProvisioningService.runAutonomousOnboarding(input);
        lastResult = result;
        applyOnboardingResultToSteps(result);
        if (setupConfig.targetMode === 'local') await context.refresh({ silent: true });
        if (
          currentEligibility.fundingReadyToBond === true
          && currentEligibility.eligible !== true
          && onboardingNextAction(result) === 'complete_validator_self_bond'
        ) {
          updateProvisioningStep('stake', 'running', 'Runtime wallet is ready. Submitting the validator self-bond once and waiting for canonical confirmation.');
          const bondResult = await validatorEligibilityService.finalizeValidatorBond({
            nodeId,
            walletAddress: currentEligibility.walletAddress,
            validatorAddress,
            targetId: input.targetId,
            stakeTxHash: currentEligibility.stakeTxHash,
          });
          currentEligibility = bondResult?.eligibility || currentEligibility;
          setEligibility?.(currentEligibility);
          input.eligibility = currentEligibility;
          if (currentEligibility.eligible !== true || currentEligibility.eligibilityStatus !== ELIGIBILITY_STATUSES.eligible) {
            const pendingMessage = bondResult?.message || 'Validator self-bond is awaiting canonical confirmation. Resume onboarding to continue without submitting a duplicate bond.';
            updateProvisioningStep('stake', 'pending', pendingMessage);
            setProvisioningState((current) => ({
              ...current,
              running: false,
              stageId: 'stake',
              result,
              message: pendingMessage,
            }));
            return;
          }
          updateProvisioningStep('stake', 'success', 'Validator self-bond is confirmed on-chain. Continuing guarded onboarding.');
          continue;
        }
        if (activationReadyFromOnboarding(result)) {
          setProvisioningState((current) => ({
            ...current,
            running: false,
            stageId: 'activation-ready',
            message: 'Validator completed shadow onboarding and is ready for operator activation.',
          }));
          return;
        }
        if (['failed'].includes(result?.status)) {
          throw new Error(result?.message || 'Validator onboarding failed.');
        }
        if (!onboardingCanContinue(result)) {
          const nextAction = onboardingNextAction(result);
          const blockedStage = provisioningStageForNextAction(nextAction);
          const message = onboardingBlockedMessage(result);
          setProvisioningState((current) => ({
            ...current,
            running: false,
            stageId: blockedStage,
            error: message,
            message,
            steps: {
              ...current.steps,
              [blockedStage]: {
                status: 'error',
                detail: message,
              },
            },
          }));
          setStepError(message);
          return;
        }
        const nextAction = onboardingNextAction(result);
        setProvisioningState((current) => ({
          ...current,
          stageId: provisioningStageForNextAction(nextAction),
          message: onboardingMonitorMessage(result),
        }));
        await sleep(SHADOW_EPOCH_POLL_MS);
      }
      setProvisioningState((current) => ({
        ...current,
        running: false,
        result: lastResult,
        message: 'Validator onboarding monitor stopped. Resume to continue shadow epoch observation.',
      }));
    } catch (error) {
      const message = String(error?.message || error);
      setProvisioningState((current) => ({
        ...current,
        running: false,
        error: message,
        message,
        steps: {
          ...current.steps,
          [current.stageId || 'onboarding']: {
            status: 'error',
            detail: message,
          },
        },
      }));
      setStepError(message);
    }
  };

  const stopProvisioningWorkflow = () => {
    provisioningCancelRef.current = true;
    setProvisioningState((current) => ({
      ...current,
      running: false,
      message: 'Stopping validator onboarding monitor after the current backend check completes.',
    }));
  };

  const activateWhenReady = async (input) => {
    if (activationPending?.status === 'pending') {
      return startActivationMonitor(buildActivationMonitorInput());
    }
    const result = await validatorProvisioningService.activateValidator(input);
    const pending = {
      status: 'pending',
      nodeId: input.nodeId,
      txHash: extractWalletActionTxHash(result),
      syncMode: input.syncMode || (snapshotState.status === 'normal-sync' ? 'normal' : 'snapshot'),
      targetId: input.targetId || 'local',
      walletAddress: input.walletAddress || eligibility.walletAddress || '',
      submittedAt: new Date().toISOString(),
      lastCheckedAt: '',
    };
    setActivationPending(pending);
    setProvisioningState((current) => ({
      ...current,
      running: true,
      stageId: 'activation-submitted',
      result: {
        ...(current.result || {}),
        activation: result,
      },
      steps: {
        ...current.steps,
        'activation-ready': {
          status: 'success',
          detail: result?.message || 'Activation transaction submitted.',
        },
        'activation-submitted': {
          status: 'running',
          detail: result?.message || 'Activation transaction submitted; monitoring without resubmitting.',
        },
      },
      message: result?.message || 'Activation transaction submitted.',
    }));
    setCurrentStep(SETUP_STEP.launchActivate);
    return startActivationMonitor(buildActivationMonitorInput(pending));
  };

  const createValidatorIdentityFromScreen = async (event) => {
    event?.preventDefault?.();
    const nickname = String(setupConfig.nodeNickname || '').trim();
    if (!nickname) {
      setSetupPassphraseError('');
      setStepError('Validator nickname is required.');
      return;
    }
    if (setupConfig.targetMode === 'remote' && !setupConfig.targetId) {
      setStepError('Select an SSH target before creating the validator identity.');
      return;
    }
    if (setupConfig.targetMode === 'remote' && targetState !== 'connected') {
      setStepError('Test the SSH connection successfully before creating keys on the remote target.');
      return;
    }
    if (setupPassphrase.length < 8) {
      setSetupPassphraseError('Use at least 8 characters.');
      return;
    }
    if (setupPassphrase !== setupPassphraseConfirm) {
      setSetupPassphraseError('Passphrases do not match.');
      return;
    }
    setSetupPassphraseError('');
    setStepBusy('node-config');
    setStepError('');
    try {
      await createValidatorNodeFromSetup(setupPassphrase);
      setSetupPassphrase('');
      setSetupPassphraseConfirm('');
    } catch (error) {
      const message = String(error?.message || error);
      setStepError(message);
      setSetupPassphraseError(message);
    } finally {
      setStepBusy('');
    }
  };

  const exportEncryptedBackup = async () => {
    const ok = await runStepAction(
      'backup',
      () => (setupConfig.targetMode === 'remote'
        ? invokeOnboarding('exportEncryptedBackup', {
          targetId: setupConfig.targetId,
          nodeId,
          target: setupConfig.backupLocation || undefined,
        })
        : nodeService.backupKeys(nodeId)),
      (result) => {
        setBackupExported(true);
        if (result?.path) setSetupConfigStatus(`Encrypted backup created at ${result.path}.`);
      },
    );
    return ok;
  };

  const selectNormalSync = async () => {
    if (!nodeId) {
      setStepError('Generate the validator identity before starting normal sync.');
      return;
    }
    setSnapshotState({ status: 'running', message: 'Starting validator normal sync from peer state.' });
    const ok = await runStepAction(
      'normal-sync',
      () => invokeOnboarding('startNormalSync', {
        targetId: setupConfig.targetMode === 'remote' ? setupConfig.targetId : 'local',
        nodeId,
      }),
      (result) => {
        setSnapshotState({
          status: 'normal-sync',
          stage: 'running',
          message: result?.message || 'Normal peer sync started. Continue to Launch & Activate so guarded onboarding can monitor catch-up. Self-bond remains locked until exact local/public state parity is verified.',
          result: { ...result, setupSyncMode: 'normal', startedAt: new Date().toISOString() },
        });
      },
      (error) => setSnapshotState({
        status: 'error',
        message: friendlySetupError(error, 'Normal sync could not be started. Review the technical details and retry.'),
      }),
    );
    if (!ok) return;
  };

  const continueToLaunchAndActivate = async () => {
    if (snapshotState.status === 'success') {
      setCurrentStep(SETUP_STEP.launchActivate);
      return;
    }
    if (!syncStatusIsVerified(context.selectedNodeLive, 'normal')) {
      setStepError('The validator must have a verified zero-block sync gap before launch. Select snapshot sync or normal sync and wait for verification.');
      return;
    }

    setStepBusy('sync-reconcile');
    setStepError('');
    try {
      const targetId = setupConfig.targetMode === 'remote' ? setupConfig.targetId : 'local';
      const verifiedLiveStatus = await waitForVerifiedSetupSync('normal', { targetId, nodeId });
      setSnapshotState({
        status: 'normal-sync',
        stage: 'complete',
        message: 'Existing validator state is fully synced and its canonical head match has been verified.',
        result: { verifiedLiveStatus, setupSyncMode: 'normal', reconciledFromLiveStatus: true },
      });
      setCurrentStep(SETUP_STEP.launchActivate);
    } catch (error) {
      setStepError(friendlySetupError(error, 'The fully synced validator could not be reconciled with setup evidence. Run Device Check and retry.'));
    } finally {
      setStepBusy('');
    }
  };

  if (step === SETUP_STEP.nodeRole) {
    return (
      <div className="v18-setup-grid">
        <Card title="Choose Node Role" icon={Server}>
          <p>A validator helps secure Synergy Network by verifying blocks and participating in consensus.</p>
          <div className="v18-node-type-grid">
            {[
              ['validator', 'Validator Node', 'A validator helps secure Synergy Network by verifying blocks and participating in consensus.', true, controlPanelIconSrc, Shield],
              ['committee', 'Committee Node', 'Participates in governance and decision making. Coming later.', false, null, Users],
              ['archive', 'Archive Validator', 'Stores and serves historical network data for light clients. Coming later.', false, null, Database],
              ['relayer', 'Relayer', 'Relays messages between chains and networks securely. Coming later.', false, null, Network],
              ['oracle', 'Oracle', 'Provides external data to smart contracts. Coming later.', false, null, Globe2],
            ].map(([id, name, detail, enabled, image, Icon]) => (
              <button
                key={name}
                type="button"
                className={cls('v18-node-type', setupConfig.nodeType === id && 'is-selected')}
                disabled={!enabled}
                onClick={() => updateSetupConfig({ nodeType: id })}
              >
                <span>{image ? <img src={image} alt="" /> : <Icon size={28} />}</span>
                <strong>{name}</strong>
                <small>{detail}</small>
                {!enabled ? <em>Coming later</em> : <CheckCircle2 size={18} className="v18-node-selected-mark" />}
              </button>
            ))}
          </div>
          <div className="v18-button-row">
            <button type="button" className="v18-primary-button" disabled={setupConfig.nodeType !== 'validator'} onClick={() => setCurrentStep(SETUP_STEP.validatorIdentity)}>
              Continue to Validator Identity
              <ChevronRight size={16} />
            </button>
          </div>
        </Card>
        <SetupSummary eligibility={eligibility} setupConfig={setupConfig} currentStatus="Role selected" />
      </div>
    );
  }

  if (step === SETUP_STEP.validatorIdentity) {
    const validatorGenerated = Boolean(nodeId && validatorAddress);
    const selectedAddress = validatorAddress;
    const passphraseStatus = passphraseStrength(setupPassphrase);
    const keyProtection = setupConfig.targetMode === 'remote' ? 'Encrypted on target' : 'Encrypted backup required';
    const backupReadyForStake = validatorGenerated && backupConfirmed;
    const remoteTargetReady = setupConfig.targetMode === 'local' || Boolean(setupConfig.targetId && targetState === 'connected');
    return (
      <div className="v18-setup-config-grid">
        <div className="v18-setup-config-main">
          <Card title="Create Validator Identity & Backup" icon={KeyRound}>
            <p>Create the validator address and encrypted identity before connecting a wallet or bonding stake.</p>
            <div className="v18-setup-config-columns">
              <div>
                <label className="v18-field">
                  <span>Where will this validator run?</span>
                  <select value={setupConfig.targetMode} onChange={(event) => updateSetupConfig({ targetMode: event.target.value })} disabled={validatorGenerated}>
                    <option value="local">This computer</option>
                    <option value="remote">Remote server over SSH</option>
                  </select>
                </label>
                {setupConfig.targetMode === 'remote' ? (
                  <div className="v18-target-panel">
                    <div className="v18-target-panel__head"><strong>SSH target</strong><StatusPill tone={targetState === 'connected' ? 'green' : targetState === 'error' ? 'red' : 'yellow'}>{targetState === 'connected' ? 'Connected' : targetState === 'error' ? 'Connection failed' : 'Needs connection test'}</StatusPill></div>
                    <label className="v18-field"><span>Configured target</span><select value={setupConfig.targetId} onChange={(event) => { const target = targetsState.targets.find((item) => item.id === event.target.value); updateSetupConfig({ targetId: event.target.value, targetLabel: target?.label || '', targetHost: target?.host || '', targetPort: target?.port || 22, targetUsername: target?.username || '' }); }} disabled={validatorGenerated || targetsState.loading}><option value="">Select an SSH target</option>{targetsState.targets.map((target) => <option key={target.id} value={target.id}>{target.label} ({target.host})</option>)}</select></label>
                    <div className="v18-target-fields">
                      <label className="v18-field"><span>Host</span><input value={setupConfig.targetHost} onChange={(event) => updateSetupConfig({ targetHost: event.target.value })} placeholder="validator.example.com" disabled={validatorGenerated} /></label>
                      <label className="v18-field"><span>Port</span><input type="number" min="1" max="65535" value={setupConfig.targetPort} onChange={(event) => updateSetupConfig({ targetPort: event.target.value })} disabled={validatorGenerated} /></label>
                    </div>
                    <label className="v18-field"><span>SSH username</span><input value={setupConfig.targetUsername} onChange={(event) => updateSetupConfig({ targetUsername: event.target.value })} placeholder="ubuntu" disabled={validatorGenerated} /></label>
                    <button type="button" className="v18-ghost-button" onClick={refreshTargetConnection} disabled={stepBusy || !setupConfig.targetId}><Wifi size={16} /> Test SSH Connection</button>
                    {!validatorGenerated ? (
                      <div className="v18-target-panel__add">
                        <strong>Add SSH target</strong>
                        <div className="v18-target-fields">
                          <label className="v18-field"><span>Label</span><input value={targetDraft.label} onChange={(event) => setTargetDraft((current) => ({ ...current, label: event.target.value }))} placeholder="Validator VPS" /></label>
                          <label className="v18-field"><span>Host</span><input value={targetDraft.host} onChange={(event) => setTargetDraft((current) => ({ ...current, host: event.target.value }))} placeholder="validator.example.com" /></label>
                          <label className="v18-field"><span>Port</span><input type="number" min="1" max="65535" value={targetDraft.port} onChange={(event) => setTargetDraft((current) => ({ ...current, port: event.target.value }))} /></label>
                          <label className="v18-field"><span>SSH username</span><input value={targetDraft.username} onChange={(event) => setTargetDraft((current) => ({ ...current, username: event.target.value }))} placeholder="ubuntu" /></label>
                        </div>
                        <label className="v18-field"><span>Connection method</span><select value={targetDraft.authMethod} onChange={(event) => setTargetDraft((current) => ({ ...current, authMethod: event.target.value }))}><option value="ncp_managed_key">NCP managed SSH key</option><option value="existing_key">Existing SSH key</option><option value="temporary_password">One-time password bootstrap</option></select></label>
                        {targetDraft.authMethod === 'existing_key' ? <label className="v18-field"><span>Existing private-key path</span><input value={targetDraft.identityFile} onChange={(event) => setTargetDraft((current) => ({ ...current, identityFile: event.target.value }))} placeholder="/Users/me/.ssh/id_ed25519" /></label> : null}
                        {targetDraft.authMethod === 'temporary_password' ? <label className="v18-field"><span>One-time SSH password</span><input type="password" autoComplete="one-time-code" value={targetDraft.temporaryPassword} onChange={(event) => setTargetDraft((current) => ({ ...current, temporaryPassword: event.target.value }))} /></label> : null}
                        {targetDraft.authMethod !== 'existing_key' ? <label className="v18-field"><span>Key-storage passphrase</span><input type="password" autoComplete="new-password" value={targetDraft.keyStoragePassphrase} onChange={(event) => setTargetDraft((current) => ({ ...current, keyStoragePassphrase: event.target.value }))} /></label> : null}
                        <button type="button" className="v18-ghost-button" onClick={addRemoteTarget} disabled={stepBusy || !targetDraft.host.trim() || !targetDraft.username.trim() || (targetDraft.authMethod === 'existing_key' && !targetDraft.identityFile.trim()) || (targetDraft.authMethod === 'temporary_password' && !targetDraft.temporaryPassword)}><Server size={16} /> {stepBusy === 'target-add' ? 'Saving target' : 'Add SSH Target'}</button>
                        {targetInstall ? <div className="v18-inline-success"><span>Install this public key on the target, then test the connection.</span><CopyButton value={targetInstall} /></div> : null}
                      </div>
                    ) : null}
                    {targetsState.error ? <small className="v18-error-text">{friendlySetupError(targetsState.error, 'Validator targets could not be loaded.')}</small> : null}
                  </div>
                ) : null}
                <label className="v18-field">
                  <span>Validator nickname</span>
                  <input
                    value={setupConfig.nodeNickname}
                    maxLength={80}
                    onChange={(event) => updateSetupConfig({ nodeNickname: event.target.value })}
                    placeholder="My Validator Node"
                    disabled={validatorGenerated}
                  />
                </label>
                <label className="v18-field">
                  <span>Network</span>
                  <select value={setupConfig.network} onChange={(event) => updateSetupConfig({ network: event.target.value })} disabled={validatorGenerated}>
                    <option>Synergy Testnet</option>
                  </select>
                </label>
                <label className="v18-field">
                  <span>Storage location</span>
                  <span className="v18-path-picker">
                    <input value={setupConfig.storageLocation} onChange={(event) => updateSetupConfig({ storageLocation: event.target.value })} disabled={validatorGenerated} />
                    <button type="button" className="v18-ghost-button" onClick={chooseStorageLocation} disabled={validatorGenerated}>Browse</button>
                  </span>
                </label>
                {setupConfigStatus ? <div className="v18-inline-success"><CheckCircle2 size={14} /> {setupConfigStatus}</div> : null}
              </div>
              <form onSubmit={createValidatorIdentityFromScreen}>
                <label className="v18-field">
                  <span>Encryption passphrase</span>
                  <input
                    type="password"
                    value={setupPassphrase}
                    onChange={(event) => setSetupPassphrase(event.target.value)}
                    minLength={8}
                    autoComplete="new-password"
                    disabled={validatorGenerated}
                  />
                </label>
                <label className="v18-field">
                  <span>Confirm encryption passphrase</span>
                  <input
                    type="password"
                    value={setupPassphraseConfirm}
                    onChange={(event) => setSetupPassphraseConfirm(event.target.value)}
                    minLength={8}
                    autoComplete="new-password"
                    disabled={validatorGenerated}
                  />
                </label>
                <StatusPill tone={passphraseStatus.tone}>{passphraseStatus.label}</StatusPill>
                <p className="v18-muted">{passphraseStatus.detail}</p>
                {setupPassphraseError ? <small className="v18-error-text">{friendlySetupError(setupPassphraseError)}</small> : null}
                <button type="submit" className="v18-primary-button" disabled={validatorGenerated || stepBusy === 'node-config' || !remoteTargetReady}>
                  {stepBusy === 'node-config' ? <RefreshCw size={16} className="v18-spin" /> : <KeyRound size={16} />}
                  Create Validator Identity
                </button>
              </form>
            </div>
          </Card>

          {validatorGenerated ? (
            <Card title="Validator identity created" icon={Shield} className="v18-generated-validator-card">
              <div className="v18-generated-validator-grid">
                <div><span>Validator Address / Node Address</span><strong>{selectedAddress}</strong><CopyButton value={selectedAddress} /></div>
                <div><span>Nickname</span><strong>{setupConfig.nodeNickname}</strong></div>
                <div><span>Storage Location</span><strong>{setupConfig.storageLocation}</strong></div>
                <div><span>Key Protection</span><strong>{keyProtection}</strong></div>
                <div><span>Network</span><strong>{setupConfig.network}</strong></div>
                <div><span>Created</span><strong>{context.selectedNode?.created_at_utc ? new Date(context.selectedNode.created_at_utc).toLocaleString() : 'Saved locally'}</strong></div>
              </div>
            </Card>
          ) : null}

          <Card title="Encrypted Backup" icon={Download}>
            <p>Export an encrypted backup before bonding stake. This backup protects your validator recovery path; the passphrase is never recoverable by Synergy Network.</p>
            {setupConfig.targetMode === 'remote' ? <label className="v18-field"><span>Remote backup file</span><input value={setupConfig.backupLocation} onChange={(event) => updateSetupConfig({ backupLocation: event.target.value })} placeholder={`${setupConfig.remoteWorkspaceDirectory || '~/.synergy/testnet'}/backups/validator-keys.tar.gz`} disabled={validatorGenerated && backupExported} /></label> : null}
            <div className="v18-button-row">
              <button type="button" className="v18-ghost-button" disabled={!validatorGenerated || !encryptedReady || stepBusy === 'backup'} onClick={exportEncryptedBackup}>
                {stepBusy === 'backup' ? <RefreshCw size={16} className="v18-spin" /> : <Download size={16} />}
                Export Encrypted Backup
              </button>
              <label className="v18-toggle-row">
                <span>I saved my encrypted backup and passphrase</span>
                <input type="checkbox" checked={backupConfirmed} disabled={!backupExported} onChange={(event) => setBackupConfirmed(event.target.checked)} />
              </label>
            </div>
            {!backupExported && validatorGenerated ? <div className="v18-alert is-warning">Backup confirmation is locked until an encrypted backup is exported.</div> : null}
          </Card>

          <SetupErrorNotice error={stepError} fallback="Validator identity could not be created." />

          <div className="v18-setup-config-actions">
            <button type="button" className="v18-primary-button" disabled={!backupReadyForStake} onClick={() => setCurrentStep(SETUP_STEP.walletStake)}>
              Continue to Wallet & Stake
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
        <SetupSummary eligibility={eligibility} setupConfig={setupConfig} backupConfirmed={backupConfirmed} currentStatus={validatorGenerated ? 'Identity created' : remoteTargetReady ? 'Create identity' : 'Connect target'} />
      </div>
    );
  }

  if (step === SETUP_STEP.deviceNetworkSync) {
    const checks = context.selectedNodeLive?.readiness?.checks || [];
    const readinessRows = checks.length ? checks : preProvisionChecks;
    const hasHealthProgress = healthCheckProgress.state !== 'idle';
    const healthReady = healthCheckProgress.state === 'success' || readinessChecksAreVerified(checks);
    const secureNetwork = secureNetworkTruth(vpnSetupState.result, context.selectedNodeLive);
    const vpnReady = secureNetwork.confirmed;
    const syncSelected = setupSyncIsSelected(snapshotState, context.selectedNodeLive);
    const snapshotValues = snapshotCopyValues(snapshotState.result);
    return (
      <div className="v18-setup-config-grid">
        <div className="v18-setup-config-main">
          <Card title="Check Device, Secure Connection & Sync" icon={ClipboardCheck}>
            <p>We will check the selected machine, connect it to the secure validator network, then choose how it catches up to the chain.</p>

            <h3>Device Readiness</h3>
            <div className="v18-check-grid">
              {readinessRows.length ? readinessRows.map((check) => (
                <div key={check.id || check.label} className={cls(check.status === 'pass' && 'is-pass', check.status === 'fail' && 'is-fail')}>
                  <span>{check.label}</span>
                  <strong>{check.value || check.detail || check.status}</strong>
                  {check.status === 'fail' ? <XCircle size={18} /> : <CheckCircle2 size={18} />}
                </div>
              )) : <p className="v18-muted">Run Device Check to load storage, memory, runtime, command access, port, internet, and write-permission checks.</p>}
            </div>
            {hasHealthProgress ? (
              <div className={cls('v18-health-progress', healthCheckProgress.state === 'success' && 'is-success', healthCheckProgress.state === 'error' && 'is-error')} role="status">
                <div className="v18-health-progress__head">
                  <strong>{healthCheckProgress.message}</strong>
                  <span>{Math.round(healthCheckProgress.percent)}%</span>
                </div>
                <div className="v18-progress-bar" style={{ '--progress': `${healthCheckProgress.percent}%` }}><span /></div>
                <div className="v18-health-stage-grid">
                  {healthCheckStages.map((stage, index) => {
                    const complete = healthCheckProgress.state === 'success' || index < healthCheckProgress.activeIndex;
                    const active = healthCheckProgress.state === 'running' && index === healthCheckProgress.activeIndex;
                    return (
                      <div key={stage.id} className={cls(complete && 'is-complete', active && 'is-active')}>
                        <span>{complete ? <CheckCircle2 size={16} /> : active ? <RefreshCw size={16} className="v18-spin" /> : index + 1}</span>
                        <p>{stage.label}</p>
                      </div>
                    );
                  })}
                </div>
              </div>
            ) : null}
            <SetupErrorNotice error={stepError} fallback="Device, network, or sync setup could not be completed." />
            <div className="v18-button-row">
              <button type="button" className="v18-ghost-button" disabled={stepBusy} onClick={runRequirementsCheck}>{stepBusy === 'requirements' ? 'Checking' : healthCheckProgress.state === 'success' ? 'Run Check Again' : 'Run Device Check'}</button>
            </div>
          </Card>

          <Card title="Secure Validator Network" icon={Wifi}>
            <p>Use coordinator-managed secure networking so new validators can join without manually editing every existing validator config.</p>
            {!vpnReady ? (
              <label className="v18-input-row">
                <span>One-time onboarding token</span>
                <input type="password" autoComplete="off" value={secureNetworkToken} onChange={(event) => setSecureNetworkToken(event.target.value)} />
              </label>
            ) : null}
            <div className={cls('v18-vpn-setup-panel', vpnReady && 'is-success', vpnSetupState.status === 'error' && 'is-error')}>
              <div>
                <span className="v18-icon-bubble is-blue"><Wifi size={20} /></span>
                <div>
                  <strong>Secure Validator Network</strong>
                  <p>{vpnSetupState.message || 'The coordinator owns enrollment and peer propagation. This panel will only mark the network ready after coordinator and handshake evidence are returned.'}</p>
                  <small>{secureNetwork.confirmed ? `Confirmed${secureNetwork.assignedIp ? ` · ${secureNetwork.assignedIp}` : ''}${secureNetwork.peersConnected != null ? ` · ${secureNetwork.peersConnected} peer(s)` : ''}` : 'Coordinator confirmation and peer handshake evidence not yet confirmed.'}</small>
                </div>
              </div>
              <CopyValue label="Assigned VPN IP" value={secureNetwork.assignedIp} copyLabel="Copy assigned VPN IP" />
              <button type="button" className="v18-primary-button" disabled={!healthReady || stepBusy || vpnReady} onClick={setupValidatorVpn}>
                {stepBusy === 'vpn-setup' ? <RefreshCw size={16} className="v18-spin" /> : <Wifi size={16} />}
                {vpnReady ? 'Secure Network Confirmed' : vpnSetupState.status === 'success' ? 'Recheck Secure Network' : 'Connect Secure Network'}
              </button>
            </div>
          </Card>

          <Card title="Fast Chain Sync" icon={Archive}>
            <p>Use the latest compatible archive-validator snapshot when available, or continue with normal sync if snapshot service is unavailable.</p>
            <div className={cls('v18-snapshot-panel', snapshotState.status === 'success' && 'is-success', snapshotState.status === 'error' && 'is-warning', snapshotState.status === 'normal-sync' && 'is-success')}>
              <div>
                <span className="v18-icon-bubble is-purple"><Archive size={20} /></span>
                <div>
                  <strong>{snapshotState.status === 'normal-sync' ? 'Normal Sync Running' : 'Fast Snapshot Sync'}</strong>
                  <p>{snapshotState.message || 'Fetch snapshot metadata, verify compatibility and sha256, apply into a clean chain data directory, then catch up to the current head.'}</p>
                  {snapshotState.result?.restore?.snapshotId || snapshotState.result?.restore?.snapshot_id ? <small>Snapshot: {snapshotState.result.restore.snapshotId || snapshotState.result.restore.snapshot_id}</small> : null}
                </div>
              </div>
              <div className="v18-snapshot-metadata">
                <CopyValue label="Snapshot manifest" value={snapshotValues.manifest} copyLabel="Copy snapshot manifest" />
                <CopyValue label="Snapshot hash" value={snapshotValues.snapshotHash} copyLabel="Copy snapshot hash" />
                <CopyValue label="Manifest SHA-256" value={snapshotValues.manifestHash} copyLabel="Copy manifest SHA-256" />
                <CopyValue label="Archive SHA-256" value={snapshotValues.archiveHash} copyLabel="Copy archive SHA-256" />
              </div>
              <div className="v18-button-row">
                <button type="button" className="v18-primary-button" disabled={!vpnReady || stepBusy === 'snapshot'} onClick={downloadApplySnapshot}>
                  {stepBusy === 'snapshot' ? <RefreshCw size={16} className="v18-spin" /> : <Download size={16} />}
                  {snapshotState.status === 'normal-sync' ? 'Switch to Fast Snapshot Sync' : 'Retry Snapshot'}
                </button>
                <button type="button" className="v18-ghost-button" disabled={!vpnReady || stepBusy} onClick={selectNormalSync}>
                  Use Normal Sync
                </button>
              </div>
            </div>
            {snapshotState.status === 'error' ? (
              <div className="v18-alert is-warning">
                Snapshot sync could not be completed. Your validator can still continue with normal sync, but setup may take longer.
              </div>
            ) : null}
          </Card>

          <div className="v18-setup-config-actions">
            <button type="button" className="v18-primary-button" disabled={!healthReady || !vpnReady || !syncSelected || stepBusy === 'sync-reconcile'} onClick={continueToLaunchAndActivate}>
              {stepBusy === 'sync-reconcile' ? 'Verifying Synced State' : 'Continue to Launch & Activate'}
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
        <SetupSummary
          eligibility={eligibility}
          setupConfig={setupConfig}
          backupConfirmed={backupConfirmed}
          secureNetworkStatus={vpnReady ? 'Coordinator + handshake confirmed' : secureNetwork.coordinatorConfirmed ? 'Coordinator confirmed; handshake pending' : 'Not confirmed'}
          syncStatus={snapshotState.status === 'success' ? 'Snapshot applied' : snapshotState.status === 'normal-sync' ? 'Normal sync running under guarded onboarding' : ''}
          currentStatus="Device, network & sync"
        />
      </div>
    );
  }

  const activationConfirmed = activationConfirmedFromOnboarding(provisioningState.result);

  if (step === SETUP_STEP.launchActivate && !activationConfirmed) {
    const selectedSyncMode = setupSyncModeFromState(snapshotState, context.selectedNodeLive);
    const input = {
      nodeId,
      walletAddress: eligibility.walletAddress,
      eligibility,
      targetId: setupConfig.targetMode === 'remote' ? setupConfig.targetId : 'local',
      syncMode: selectedSyncMode || (snapshotState.status === 'normal-sync' ? 'normal' : 'snapshot'),
    };
    const activationReady = activationReadyFromOnboarding(provisioningState.result);
    const shadowProgress = shadowProgressFromOnboarding(provisioningState.result);
    const nextAction = onboardingNextAction(provisioningState.result);
    const canRecoverLocalFork = nextAction === 'recover_local_fork';
    const secureNetwork = secureNetworkTruth(vpnSetupState.result, context.selectedNodeLive);
    const vpnReady = secureNetwork.confirmed;
    const recoverLocalForkFromLaunch = () => runStepAction(
      'recover-local-fork',
      () => invokeOnboarding('recoverLocalFork', {
        targetId: setupConfig.targetMode === 'remote' ? setupConfig.targetId : 'local',
        nodeId,
      }),
      async (result) => {
        const message = result?.message || 'Local fork recovery started. The validator will rebuild chain data from peers.';
        setSnapshotState({
          status: 'normal-sync',
          stage: 'running',
          message,
          result: { ...result, setupSyncMode: 'normal', recoveredAt: new Date().toISOString() },
        });
        setProvisioningState((current) => ({
          ...current,
          running: false,
          stageId: 'sync',
          error: '',
          message,
          result: {
            ...(current.result || {}),
            recoverLocalFork: result,
            nextAction: 'wait_for_live_head_match',
          },
          steps: {
            ...current.steps,
            sync: {
              status: 'running',
              detail: message,
            },
          },
        }));
        await context.refresh({ silent: true }).catch(() => null);
      },
    );
    const completedSetup = [
      ['Identity created', identityReady],
      ['Backup confirmed', backupConfirmed],
      ['Wallet connected', Boolean(eligibility.walletAddress)],
      ['Stake bonded', eligibility.eligible === true && eligibility.eligibilityStatus === ELIGIBILITY_STATUSES.eligible],
      ['Secure network confirmed by coordinator', vpnReady],
      [selectedSyncMode === 'normal' ? 'Normal sync verified' : 'Snapshot applied', Boolean(selectedSyncMode)],
    ];
    return (
      <Card title="Launch & Activate" icon={Zap}>
        <p>Your validator is being prepared for activation. During observation mode, it watches the network and proves it matches the active validators before it is allowed to produce blocks.</p>
        <div className="v18-check-grid">
          {completedSetup.map(([label, done]) => (
            <div key={label} className={done ? 'is-pass' : 'is-fail'}>
              <span>{label}</span>
              <strong>{done ? 'Completed' : 'Missing'}</strong>
              {done ? <CheckCircle2 size={18} /> : <XCircle size={18} />}
            </div>
          ))}
        </div>
        <div className={cls('v18-health-progress', activationReady && 'is-success', provisioningState.error && 'is-error')}>
          <div className="v18-health-progress__head">
            <strong>{provisioningState.message || 'Start validator onboarding to run launch, sync, observation mode, and activation checks.'}</strong>
            <span>{activationConfirmed ? 'Active' : activationReady ? 'Ready' : provisioningState.running ? 'Running' : 'Idle'}</span>
          </div>
          <div className="v18-progress-bar" style={{ '--progress': `${activationReady ? 100 : Math.max(8, shadowProgress.percent)}%` }}><span /></div>
        </div>
        <div className="v18-provisioning-list">
          {launchStages.map((stage) => {
            const state = provisioningState.steps[stage.statusKey] || provisioningState.steps[stage.id] || { status: 'pending', detail: '' };
            const isRunning = state.status === 'running' || provisioningState.stageId === stage.statusKey && provisioningState.running;
            const isSuccess = state.status === 'success';
            const isError = state.status === 'error';
            const Icon = isSuccess ? CheckCircle2 : isError ? XCircle : isRunning ? RefreshCw : Clock;
            return (
              <div key={stage.id} className={cls(isSuccess && 'is-success', isRunning && 'is-running', isError && 'is-error')}>
                <Icon size={18} className={isRunning ? 'v18-spin' : undefined} />
                <span>{stage.label}<small>{state.detail}</small></span>
                <em>{isSuccess ? 'Done' : isError ? 'Error' : isRunning ? 'Running' : 'Pending'}</em>
              </div>
            );
          })}
        </div>
        <div className="v18-button-row">
          <button type="button" className="v18-primary-button" disabled={!nodeId || provisioningState.running || stepBusy} onClick={runProvisioningWorkflow}>
            {activationPending?.status === 'pending' ? 'Resume Activation Monitor' : provisioningState.result ? 'Resume Validator Onboarding' : 'Start Validator Onboarding'}
          </button>
          <button type="button" className="v18-ghost-button" onClick={() => window.location.assign('#/logs')}>View Logs</button>
          <button type="button" className="v18-ghost-button" disabled={!provisioningState.running} onClick={stopProvisioningWorkflow}>Stop Monitor</button>
          {canRecoverLocalFork ? (
            <button
              type="button"
              className="v18-primary-button"
              disabled={!nodeId || provisioningState.running || stepBusy}
              onClick={recoverLocalForkFromLaunch}
              title="Keeps validator keys, wallet, stake, and VPN enrollment, then rebuilds local chain data from peers."
            >
              {stepBusy === 'recover-local-fork' ? 'Recovering Local Fork' : 'Recover Local Fork'}
            </button>
          ) : null}
          <button
            type="button"
            className="v18-primary-button"
            disabled={!activationReady || activationPending?.status === 'pending' || activationConfirmed || provisioningState.running || stepBusy}
            onClick={() => runStepAction('Validator activated', () => activateWhenReady(input), () => context.refresh({ silent: true }))}
          >
            {activationPending?.status === 'pending' ? 'Activation Pending' : activationConfirmed ? 'Validator Active' : 'Submit Activation Transaction'}
          </button>
        </div>
        {provisioningState.result?.evidencePath ? (
          <div className="v18-alert">Onboarding evidence: {provisioningState.result.evidencePath}</div>
        ) : null}
        {provisioningState.result?.nextAction && !activationReady ? (
          <div className="v18-alert is-warning">Next backend action: {provisioningState.result.nextAction}</div>
        ) : null}
        {activationConfirmed ? (
          <div className="v18-alert is-success">Canonical activation and active-consensus evidence are confirmed. This validator is active.</div>
        ) : activationReady ? (
          <div className="v18-alert is-success">Full shadow epoch and activation evidence passed. Submit the activation transaction when ready.</div>
        ) : null}
        <SetupErrorNotice error={provisioningState.error || stepError} fallback="Validator launch could not be completed." />
      </Card>
    );
  }

  return (
    <Card title="Validator Activated" icon={CheckCircle2}>
      <div className="v18-activation-grid">
        {[
          ['Node Address', context.selectedNode?.node_address || 'Unavailable'],
          ['Validator Address', context.selectedNode?.node_address || 'Unavailable'],
          ['Wallet Address', truncateMiddle(eligibility.walletAddress, 8, 6)],
          ['Active Stake', `${formatNumber(eligibility.activeStakeAmount)} SNRG`],
          ['Connection IP', context.selectedNodeLive?.validator_vpn_address || context.selectedNodeLive?.validator_vpn_ip || 'Unavailable'],
          ['Network', 'Synergy Testnet'],
          ['Current Block Height', formatNumber(context.selectedNodeLive?.local_chain_height ?? context.networkStats?.publicChainHeight)],
          ['Connected Peers', formatNumber(context.selectedNodeLive?.local_peer_count)],
          ['Sync Status', formatPercent(nodeSyncPercent(context.selectedNodeLive, context.liveStatus), 1)],
          ['Consensus Status', context.selectedNodeLive?.local_rpc_ready ? 'RPC Ready' : 'Unavailable'],
          ['Health Score', formatNumber(context.selectedNodeLive?.synergy_score)],
        ].map(([label, value]) => <div key={label}><span>{label}</span><strong>{value}</strong></div>)}
      </div>
      <div className="v18-button-row">
        <button type="button" className="v18-primary-button" onClick={() => navigate('/')}>
          <Home size={16} /> Open Validator Overview
        </button>
        <button type="button" className="v18-ghost-button" onClick={() => navigate('/operations')}>
          <TerminalSquare size={16} /> Open Node Controls
        </button>
      </div>
    </Card>
  );
}

function SynergyScoreBreakdown({ breakdown, rewardsError }) {
  return (
    <Card title="Synergy Score Breakdown" icon={Gauge} className="v18-score-card">
      <div className="v18-score-summary">
        <div>
          <span>Current Score</span>
          <strong>{formatNumber(breakdown.total, { maximumFractionDigits: 1 })}/100</strong>
          <small>{breakdown.source}</small>
        </div>
        <div className="v18-score-ring" style={{ '--score': `${clampPercent(breakdown.total)}%` }}>
          <span>{formatPercent(breakdown.total, 0)}</span>
        </div>
      </div>
      <div className="v18-score-list">
        {breakdown.items.map((item) => (
          <div key={item.id} className="v18-score-row">
            <div>
              <strong>{item.label}</strong>
              <small>{item.detail}</small>
            </div>
            <span>{formatPercent(item.score, 0)}{item.weight ? ` / ${formatNumber(item.weight)}%` : ''}</span>
            <div className="v18-score-meter" style={{ '--score': `${clampPercent(item.score)}%` }}><i /></div>
          </div>
        ))}
      </div>
      {rewardsError ? <p className="v18-muted">RPC score breakdown unavailable: {rewardsError}</p> : null}
    </Card>
  );
}

function OperationsPage({ runAction }) {
  const context = useControlPanel();
  const navigate = useNavigate();
  const node = context.selectedNode || {};
  const live = context.selectedNodeLive || {};
  const nodeAddress = stringValue(node.node_address, node.nodeAddress);
  const roleLabel = operationsRoleLabel(context);
  const roleId = stringValue(node.role_id, context.selectedRole?.id).toLowerCase();
  const [activeCategoryId, setActiveCategoryId] = useState('');
  const [operationNotice, setOperationNotice] = useState('');
  const [runningOperationId, setRunningOperationId] = useState('');
  const operationLockRef = useRef('');
  const activeCategory = OPERATION_CATEGORIES.find((category) => category.id === activeCategoryId) || null;

  const handlers = createOperationHandlers({
    service: nodeService,
    node,
    nodeAddress,
    openLogs: () => navigate('/logs'),
  });

  const executeOperation = async (operation) => {
    const operationId = operation.actionId || operation.id;
    const handler = handlers[operation.handler];
    setOperationNotice('');
    try {
      if (typeof handler !== 'function') {
        throw new Error(`${operation.label} is unavailable because this build has no safe mapped action.`);
      }
      const execution = await executeOperationThroughPty({
        operation,
        terminalName: operationTerminalSessionName(node, 'Node shell'),
        cwd: node.workspace_directory || node.workspaceDirectory || node.data_directory || node.dataDirectory,
        openTerminalSession,
        writeAllowlistedOperation,
        appendTerminalOutput,
        handler,
        completionDetail: (value) => operationResultMessage(value, `${operation.label} completed without a status message.`, operation.id),
      });
      const { result } = execution;
      const message = operationResultMessage(result, `${operation.label} completed without a status message.`, operation.id);
      setOperationNotice(message);
      context.recordAction({ title: operation.label, detail: message, status: 'success', source: 'operations' });
      // Refresh is follow-up UI work; it must not overwrite the operation's final result.
      await context.refresh({ silent: true });
      return result;
    } catch (error) {
      const message = `${operation.label} failed: ${errorMessage(error)}`;
      setOperationNotice(message);
      context.recordAction({ title: operation.label, detail: message, status: 'error', source: 'operations' });
      throw error;
    } finally {
      if (operationLockRef.current === operationId) {
        operationLockRef.current = '';
        setRunningOperationId('');
      }
    }
  };

  const requestOperation = (operation) => {
    const operationId = operation.actionId || operation.id;
    if (operationLockRef.current) return;
    const availability = operationAvailability(operation, node, roleId, roleLabel);
    if (!availability.available) {
      setOperationNotice(availability.message);
      return;
    }
    operationLockRef.current = operationId;
    setRunningOperationId(operationId);
    runAction(
      operation.label,
      operation.dangerous
        ? `${operation.detail} This can affect the selected node. Continue?`
        : operation.detail,
      () => executeOperation(operation),
      Boolean(operation.dangerous),
      () => {
        if (operationLockRef.current === operationId) {
          operationLockRef.current = '';
          setRunningOperationId('');
        }
      },
    );
  };

  useEffect(() => {
    setActiveCategoryId('');
    setOperationNotice('');
  }, [node.id]);

  const runtimeStatus = context.selectedNodeLive
    ? nodeRuntimeLabel(live)
    : 'Unavailable';
  const syncGap = firstFiniteValue(live, ['sync_gap']);
  const refreshStatusOperation = {
    id: 'operations.lifecycle.view-status',
    actionId: 'operations.lifecycle.view-status',
    label: 'Refresh node status',
    detail: 'Query the node status through the control service.',
    tooltip: 'Check whether the selected node is running, syncing, or waiting for attention.',
    displayCommand: 'synergy node status',
    handler: 'getStatus',
  };
  const refreshStatusTooltip = operationTerminalTooltip(refreshStatusOperation);

  return (
    <>
      <PageHeader title="Operations" subtitle="Node Controls for the selected role, with safe mapped actions and live runtime output." />
      <section className="v18-operations-status-strip" aria-label="Operations status">
        <div className="v18-operations-status-strip__address">
          <span>Node Address</span>
          <strong title={nodeAddress}>{nodeAddress || 'Unavailable'}</strong>
          {nodeAddress ? <CopyButton value={nodeAddress} label="Copy node address" /> : null}
        </div>
        <div><span>Role</span><strong>{roleLabel}</strong></div>
        <div><span>Runtime</span><StatusPill tone={live.is_running ? 'green' : context.selectedNodeLive ? 'yellow' : 'gray'}>{runtimeStatus}</StatusPill></div>
        <div><span>Sync Gap</span><strong>{syncGap == null ? 'Unavailable' : formatNumber(syncGap)}</strong></div>
        <OperationTooltip message={refreshStatusTooltip} label={`Refresh node status. ${refreshStatusTooltip}`} disabled={Boolean(runningOperationId)}>
          <button type="button" className="v18-icon-button" onClick={() => requestOperation(refreshStatusOperation)} disabled={Boolean(runningOperationId)} aria-busy={runningOperationId === 'operations.lifecycle.view-status'} aria-label={`Refresh node status. ${refreshStatusTooltip}`}><RefreshCw size={16} /></button>
        </OperationTooltip>
      </section>
      <div className="v18-operations-workspace">
        <section className="v18-operations-menu" aria-label="Operations categories">
          <div className="v18-operations-menu__head">
            {activeCategory ? (
              <button type="button" className="v18-icon-button" onClick={() => setActiveCategoryId('')} title="Back to main menu" aria-label="Back to main menu"><ArrowLeft size={17} /></button>
            ) : <span className="v18-icon-bubble is-blue"><TerminalSquare size={20} /></span>}
            <div>
              <span>{activeCategory ? 'Main Menu' : 'Node Controls'}</span>
              <h2>{activeCategory ? activeCategory.label : 'Choose an operation category'}</h2>
            </div>
          </div>
          {operationNotice ? <div className="v18-operations-notice" role="status">{operationNotice}</div> : null}
          {activeCategory ? (
            <div className="v18-operation-list">
              {activeCategory.actions.map((operation) => {
                const availability = operationAvailability(operation, node, roleId, roleLabel);
                const Icon = operation.icon || activeCategory.icon;
                const tooltipMessage = availability.available
                  ? operationTerminalTooltip(operation)
                  : `Unavailable: ${availability.message}`;
                return (
                  <OperationTooltip
                    key={operation.id}
                    label={`${operation.label}. ${tooltipMessage}`}
                    message={tooltipMessage}
                    disabled={!availability.available}
                  >
                    <button
                      type="button"
                      className={cls('v18-operation-row', `is-${activeCategory.tone}`, !availability.available && 'is-unavailable')}
                      onClick={() => requestOperation(operation)}
                      disabled={!availability.available || Boolean(runningOperationId)}
                      aria-busy={runningOperationId === (operation.actionId || operation.id)}
                      aria-label={`${operation.label}. ${tooltipMessage}`}
                    >
                      <span className="v18-operation-row__icon"><Icon size={20} /></span>
                      <span><strong>{operation.label}</strong><small>{availability.available ? operation.detail : availability.message}</small></span>
                      <StatusPill tone={availability.available ? activeCategory.tone : 'gray'}>{availability.available ? 'Run' : 'Unavailable'}</StatusPill>
                    </button>
                  </OperationTooltip>
                );
              })}
            </div>
          ) : (
            <div className="v18-operation-category-grid">
              {OPERATION_CATEGORIES.map((category) => {
                const Icon = category.icon;
                const availableCount = category.actions.length;
                return (
                  <OperationTooltip key={category.id} message={category.tooltip || category.detail}>
                    <button type="button" className={cls('v18-operation-category', `is-${category.tone}`)} onClick={() => setActiveCategoryId(category.id)} aria-label={`${category.label}. ${category.tooltip || category.detail}`}>
                      <span className="v18-operation-category__icon"><Icon size={24} /></span>
                      <strong>{category.label}</strong>
                      <small>{category.detail}</small>
                      <em>{availableCount} available</em>
                    </button>
                  </OperationTooltip>
                );
              })}
            </div>
          )}
        </section>
        <DeveloperTerminalDock node={node} title="Node shell" />
      </div>
    </>
  );
}

function ValidatorPeers({ peerState }) {
  const peers = peerState.peerInfo?.peers || [];
  return (
    <Card title="Connected Peers" icon={Users} className="v18-peer-card">
      <div className="v18-peer-summary">
        <strong>{formatNumber(peerState.peerInfo?.peerCount ?? peers.length)}</strong>
        <span>validator peer(s)</span>
      </div>
      <div className="v18-peer-list">
        {peerState.loading && !peers.length ? <p className="v18-muted">Loading peer list...</p> : null}
        {peers.length ? peers.map((peer) => {
          const mesh = peerMeshStatus(peer);
          return (
            <div key={peer.id} className="v18-peer-row">
              <span className={cls('v18-dot', mesh.tone === 'warn' && 'is-purple', mesh.tone === 'bad' && 'is-red')} />
              <div>
                <strong>{truncateMiddle(peer.validatorAddress || peer.id, 9, 6)}</strong>
                <small>{peer.publicAddress || peer.address || 'No endpoint reported'}</small>
              </div>
              <div>
                <span>{mesh.label}</span>
                <small>Last seen {formatPeerLastSeen(peer.lastSeen)}</small>
              </div>
            </div>
          );
        }) : (!peerState.loading && <p className="v18-muted">{peerState.error || 'No validator peers reported by local RPC yet.'}</p>)}
      </div>
    </Card>
  );
}

function ValidatorPage({ runAction }) {
  const context = useControlPanel();
  const version = usePanelVersion();
  const node = context.selectedNode || {};
  const live = context.selectedNodeLive || {};
  const rewardsState = useRewardsData(node.id);
  const peerState = useLocalPeerInfo(context);
  const blockHeight = live.local_chain_height ?? context.networkStats?.publicChainHeight;
  const sync = nodeSyncPercent(live, context.liveStatus);
  const readinessChecks = live.readiness?.checks || [];
  const failedChecks = readinessChecks.filter((check) => check.status !== 'pass');
  const scoreBreakdown = useMemo(
    () => scoreBreakdownForContext(context, rewardsState.payload, peerState.peerInfo),
    [context, peerState.peerInfo, rewardsState.payload],
  );
  const serviceActions = [
    { label: 'Start', icon: Play, tone: 'green', action: () => nodeService.start(node.id) },
    { label: 'Stop', icon: Square, tone: 'slate', dangerous: true, action: () => nodeService.stop(node.id) },
    { label: 'Restart', icon: RefreshCw, tone: 'blue', dangerous: true, action: () => nodeService.restart(node.id) },
    { label: 'Update', icon: Download, tone: 'purple', action: () => nodeService.update() },
  ];
  const operatorActions = [
    {
      label: 'Download & Apply Validator Snapshot',
      detail: 'Replace chain data from the latest archive-validator snapshot, then speed sync to head.',
      icon: Database,
      tone: 'cyan',
      dangerous: true,
      action: () => nodeService.downloadApplyValidatorSnapshot(node.id),
    },
    {
      label: 'Speed Sync',
      detail: 'Pause consensus participation and catch up from the applied validator snapshot.',
      icon: Zap,
      tone: 'blue',
      dangerous: true,
      action: () => nodeService.speedSync(node.id),
    },
    {
      label: 'Backup Keys',
      detail: 'Export encrypted validator key material.',
      icon: Shield,
      tone: 'purple',
      action: () => nodeService.backupKeys(node.id),
    },
    {
      label: 'Export Config',
      detail: 'Export validator configuration.',
      icon: FileText,
      tone: 'green',
      action: () => nodeService.exportConfig(node.id),
    },
    {
      label: 'Verify Snapshot',
      detail: 'Run validator readiness and snapshot checks.',
      icon: CheckCircle2,
      tone: 'lime',
      action: () => nodeService.verifySnapshot(node.id),
    },
    {
      label: 'Restore Backup',
      detail: 'Restore validator files from an operator backup.',
      icon: Upload,
      tone: 'yellow',
      dangerous: true,
      action: () => nodeService.restoreBackup(node.id),
    },
    {
      label: 'Clear Cache',
      detail: 'Clear temporary validator cache files.',
      icon: Trash2,
      tone: 'orange',
      dangerous: true,
      action: () => nodeService.clearNodeCache(node.id),
    },
    {
      label: 'Emergency Stop',
      detail: 'Immediately stop validator runtime.',
      icon: AlertTriangle,
      tone: 'red',
      dangerous: true,
      action: () => nodeService.emergencyStop(node.id),
    },
  ];

  return (
    <>
      <PageHeader title="Validator Node" subtitle="Operate and monitor your validator with confidence." />
      <Card className="v18-validator-identity">
        <div><Users size={24} /><span>Validator Name</span><strong>{node.display_label || 'No validator selected'}</strong></div>
        <div><Shield size={24} /><span>Validator Address / Node Address</span><strong>{truncateMiddle(node.node_address, 8, 6)}</strong><CopyButton value={node.node_address} /></div>
        <div><Gauge size={24} /><span>Secure Network</span><strong>{live.validator_vpn_address || live.validator_vpn_ip ? 'Connected' : 'Not reported'}</strong><small>{live.validator_vpn_address || live.validator_vpn_ip || 'Connection IP unavailable'}</small></div>
        <div><Archive size={24} /><span>Software Version</span><strong>v{version}</strong><small>Installed app version</small></div>
        <div><Globe2 size={24} /><span>Network</span><strong>Synergy Testnet</strong></div>
        <div><CheckCircle2 size={24} /><span>Consensus Status</span><strong>{live.local_rpc_ready ? 'RPC Ready' : 'Unavailable'}</strong><small>{live.sync_target_source || 'Live status'}</small></div>
        <div><Wallet size={24} /><span>Wallet Ready</span><strong>{live.wallet_ready ? 'Ready' : 'Unavailable'}</strong></div>
        <div><Wallet size={24} /><span>Owner Wallet</span><strong>{truncateMiddle(node.owner_wallet_address, 8, 6)}</strong></div>
      </Card>
      <div className="v18-validator-layout">
        <div className="v18-validator-status-column">
          <Card title="Sync & Chain State" className="v18-validator-compact-card">
            <div className="v18-list">
              <div><span><Archive size={18} /> Block Height</span><strong>{formatNumber(blockHeight)}</strong></div>
              <div><span><CheckCircle2 size={18} /> Finalized</span><strong>{formatNumber(live.log_local_chain_height)}</strong></div>
              <div><span><RefreshCw size={18} /> Sync Progress</span><strong>{formatPercent(sync, 1)}</strong></div>
              <div><span><Users size={18} /> Peer Count</span><strong>{formatNumber(live.local_peer_count)}</strong></div>
              <div><span><Archive size={18} /> Snapshot</span><strong>{formatNumber(live.sync_target_height)}</strong></div>
            </div>
          </Card>
          <Card title="Validator Participation" className="v18-validator-compact-card">
            <div className="v18-list">
              <div><span><CheckCircle2 size={18} /> Signing</span><strong>{live.wallet_ready ? 'Ready' : 'Unavailable'}</strong></div>
              <div><span><Clock size={18} /> Uptime</span><strong>{formatRuntimeDuration(live.process_uptime_secs)}</strong></div>
              <div><span><ClipboardCheck size={18} /> Validators</span><strong>{formatNumber(live.connected_validator_count)}</strong></div>
              <div><span><AlertTriangle size={18} /> Issues</span><strong>{formatNumber(failedChecks.length)}</strong></div>
              <div><span><Shield size={18} /> Score</span><strong>{formatNumber(live.synergy_score)}</strong></div>
            </div>
          </Card>
        </div>
        <Card title="Operator Actions" className="v18-operator-actions-card">
          <div className="v18-service-control-row">
            {serviceActions.map(({ label, icon: Icon, tone, dangerous, action }) => (
              <button
                key={label}
                type="button"
                className={cls('v18-operator-pill', `is-${tone}`)}
                onClick={() => runAction(label, `${label} can affect validator operation. Continue?`, action, dangerous)}
              >
                <Icon size={16} />
                {label}
              </button>
            ))}
          </div>
          <p className="v18-muted">Status: <strong className="v18-green">{nodeRuntimeLabel(live)}</strong> - PID: {live.pid || 'Unavailable'} - Uptime: {formatRuntimeDuration(live.process_uptime_secs)}</p>
          <div className="v18-operator-action-grid">
            {operatorActions.map(({ label, detail, icon: Icon, tone, dangerous, action }) => (
              <button
                key={label}
                type="button"
                className={cls('v18-operator-action', `is-${tone}`)}
                onClick={() => runAction(label, `${label} can affect validator operation. Continue?`, action, dangerous)}
              >
                <span className="v18-operator-action-icon"><Icon size={20} /></span>
                <span><strong>{label}</strong><small>{detail}</small></span>
                <ChevronRight size={18} />
              </button>
            ))}
          </div>
        </Card>
      </div>
      <div className="v18-validator-bottom-grid">
        <SynergyScoreBreakdown breakdown={scoreBreakdown} rewardsError={rewardsState.error} />
        <ValidatorPeers peerState={peerState} />
      </div>
    </>
  );
}

function currentEpochInfo(context) {
  const live = context.selectedNodeLive || {};
  const height = Number(live.local_chain_height ?? context.networkStats?.publicChainHeight);
  const epochLength = Number(live.epoch_length ?? context.network?.epoch_length ?? context.network?.consensus?.epoch_length);
  if (!Number.isFinite(height) || !Number.isFinite(epochLength) || epochLength <= 0) {
    return { label: 'Epoch unavailable', height, epochLength: null, endHeight: null, progress: null, remaining: null };
  }
  const window = epochWindowForBlockHeight(height, epochLength);
  if (!window) {
    return { label: 'Epoch unavailable', height, epochLength: null, endHeight: null, progress: null, remaining: null };
  }
  return {
    label: `Epoch ${formatNumber(window.epoch)}`,
    height,
    epochLength,
    endHeight: window.endHeight,
    progress: window.progress,
    remaining: window.remaining,
  };
}

function PerformancePage() {
  const context = useControlPanel();
  const node = context.selectedNode || {};
  const live = context.selectedNodeLive || {};
  const [workflowStatus, setWorkflowStatus] = useState('');
  const [withdrawDialogOpen, setWithdrawDialogOpen] = useState(false);
  const [withdrawAmount, setWithdrawAmount] = useState('');
  const [withdrawDestination, setWithdrawDestination] = useState(node.owner_wallet_address || '');
  const [withdrawError, setWithdrawError] = useState('');
  const rewardsState = useRewardsData(node.id);
  const rewards = normalizeRewardsPayload(rewardsState.payload);
  const peerState = useLocalPeerInfo(context);
  const scoreBreakdown = useMemo(
    () => scoreBreakdownForContext(context, rewardsState.payload, peerState.peerInfo),
    [context, peerState.peerInfo, rewardsState.payload],
  );
  const epoch = currentEpochInfo(context);
  const rewardHistory = rewards.rewardHistory.slice(0, 5);
  const scoreItems = scoreBreakdown.items.slice(0, 5);
  const scoreAvailable = firstFiniteValue(rewards.live, ['synergy_score']) != null
    || Object.keys(rewards.synergyComponents).length > 0
    || Object.keys(rewards.synergyBreakdown).length > 0
    || (Array.isArray(live.readiness?.checks) && live.readiness.checks.length > 0)
    || live.is_consensus_active != null
    || live.is_voting != null
    || live.process_uptime_secs != null;
  const rewardHistoryPoints = rewardHistory
    .map((entry, index) => ({
      at: entry?.timestamp,
      label: entry?.epoch ?? entry?.epoch_label ?? entry?.reward_type ?? `Event ${index + 1}`,
      value: firstFiniteValue(entry, ['earned_snrg', 'amount_snrg', 'released_snrg']),
    }))
    .filter((point) => point.value != null);
  const pending = Number(rewards.pendingRewardsSnrg);
  const totalEarned = Number(rewards.totalEarnedSnrg);
  const totalReleased = Number(rewards.totalReleasedSnrg);
  const totalPending = Number(rewards.totalPendingSnrg);
  const totalWithdrawn = Number(rewards.totalWithdrawnSnrg);
  const slashed = Number(rewards.slashedSnrg);
  const treasuryRecovery = Number(rewards.treasuryRecoverySnrg);
  const walletBalance = Number(rewards.walletBalanceSnrg);
  const token = rewards.tokenSymbol || 'SNRG';
  useEffect(() => {
    setWithdrawDestination(node.owner_wallet_address || '');
  }, [node.owner_wallet_address]);
  const closeWithdrawDialog = () => {
    setWithdrawDialogOpen(false);
    setWithdrawAmount('');
    setWithdrawError('');
  };
  const submitWithdraw = async (event) => {
    event.preventDefault();
    const amount = Number.parseInt(withdrawAmount, 10);
    const destinationAddress = withdrawDestination.trim();
    if (!Number.isSafeInteger(amount) || amount <= 0) {
      setWithdrawError('Enter a whole SNRG amount greater than zero.');
      return;
    }
    if (!destinationAddress) {
      setWithdrawError('Enter a destination Synergy wallet address.');
      return;
    }
    setWithdrawError('');
    setWorkflowStatus('Submitting validator withdrawal...');
    try {
      const result = await nodeService.transferValidatorTokens(node.id, destinationAddress, amount);
      setWorkflowStatus(result?.message || 'Validator withdrawal submitted.');
      closeWithdrawDialog();
      await context.refresh({ silent: true });
    } catch (error) {
      setWorkflowStatus(String(error?.message || error));
      setWithdrawError(String(error?.message || error));
    }
  };

  return (
    <>
      <PageHeader title="Performance & Rewards" subtitle="Track validator performance, rewards, and penalties across epochs." />
      <div className="v18-performance-top-grid">
        <Card className="v18-performance-tile is-purple">
          <div className="v18-performance-tile__top"><span className="v18-icon-bubble is-purple"><Database size={22} /></span><span className="v18-eyebrow">Current Epoch</span></div>
          <strong>{epoch.label}</strong>
          <small>{epoch.remaining == null ? 'Epoch length not reported by control-service.' : `Ends in ${formatNumber(epoch.remaining)} block(s)`}</small>
          <p>{epoch.endHeight ? `Block ${formatNumber(epoch.height)} / ${formatNumber(epoch.endHeight)}` : `Block ${formatNumber(epoch.height)}`}</p>
          <div className="v18-meter" style={{ '--meter': `${clampPercent(epoch.progress)}%` }}><span /></div>
        </Card>
        <Card className="v18-performance-tile">
          <div className="v18-performance-tile__top"><span className="v18-icon-bubble is-green"><Wallet size={22} /></span><span className="v18-eyebrow is-green">Pending Reward (Epoch N)</span></div>
          <strong>{Number.isFinite(pending) ? `${formatSnrg(pending)} ${token}` : '—'}</strong>
          <small>{rewardsState.loading ? 'Refreshing reward RPC...' : rewardsState.error || 'Returned by staking RPC.'}</small>
          <StatusPill tone={Number.isFinite(pending) && pending > 0 ? 'purple' : 'green'}>{Number.isFinite(pending) && pending > 0 ? 'Pending' : 'No pending reward'}</StatusPill>
        </Card>
        <Card className="v18-performance-tile">
          <div className="v18-performance-tile__top"><span className="v18-icon-bubble is-green"><Gauge size={22} /></span><span className="v18-eyebrow is-green">Participation Score</span></div>
          <strong>{scoreAvailable ? formatPercent(scoreBreakdown.total, 2) : 'Unavailable'}</strong>
          <small>{scoreAvailable ? (scoreBreakdown.total >= 90 ? 'Excellent' : scoreBreakdown.total >= 70 ? 'Healthy' : 'Needs attention') : 'No score source returned.'}</small>
          <div className="v18-meter" style={{ '--meter': `${scoreAvailable ? clampPercent(scoreBreakdown.total) : 0}%` }}><span /></div>
          <p>{scoreAvailable ? scoreBreakdown.source : 'Participation inputs are not available.'}</p>
        </Card>
        <Card className="v18-performance-tile">
          <div className="v18-performance-tile__top"><span className="v18-icon-bubble is-blue"><Clock size={22} /></span><span className="v18-eyebrow is-green">Next Payout (Epoch N+1)</span></div>
          <strong>{Number.isFinite(pending) && pending > 0 ? `Est. ${formatSnrg(pending)} ${token}` : '—'}</strong>
          <small>{Number.isFinite(pending) && pending > 0 ? 'Pending reward currently reported.' : 'No payout estimate returned.'}</small>
          <p>{rewards.validatorStatus || 'Validator payout status unavailable'}</p>
        </Card>
      </div>

      <div className="v18-performance-wide-grid">
        <Card title="Reward Overview" className="v18-reward-overview">
          <div className="v18-reward-overview__body">
            <div className="v18-reward-stat-list">
              <div><span>Total Earned (This Epoch)</span><strong>{Number.isFinite(pending) ? `${formatSnrg(pending)} ${token}` : '—'}</strong></div>
              <div><span>Total Released (All Time)</span><strong>{Number.isFinite(totalReleased) ? `${formatSnrg(totalReleased)} ${token}` : '—'}</strong></div>
              <div><span>Total Pending</span><strong>{Number.isFinite(totalPending) ? `${formatSnrg(totalPending)} ${token}` : '—'}</strong></div>
              <div><span>Total Withdrawn</span><strong>{Number.isFinite(totalWithdrawn) ? `${formatSnrg(totalWithdrawn)} ${token}` : '—'}</strong></div>
            </div>
            <PerformanceScoreDonut score={scoreBreakdown.total} available={scoreAvailable} loading={rewardsState.loading} />
            <div className="v18-performance-breakdown-mini">
              <div className="v18-performance-breakdown-mini__heading"><span>Score composition</span><small>{scoreAvailable ? scoreBreakdown.source : 'No score source returned'}</small></div>
              {scoreAvailable ? scoreItems.map((item) => (
                <div key={item.id}><span><i /> {item.label}</span><strong>{item.weight ? `${formatNumber(item.weight)}%` : formatPercent(item.score, 0)}</strong></div>
              )) : <p className="v18-muted">Participation inputs will appear when the staking or live telemetry endpoint reports them.</p>}
            </div>
          </div>
          <div className="v18-reward-overview__chart">
            <OperationalLineChart
              title="Reward history"
              points={rewardHistoryPoints}
              tone="purple"
              formatValue={formatSnrg}
              unit={token}
              sampleLabel="recorded events"
              emptyText="No earned reward history was returned for this validator."
            />
          </div>
        </Card>
        <Card title="Reward Flow (Two-Phase Process)" className="v18-reward-flow-card">
          <div className="v18-reward-flow">
            <div><Trophy size={24} /><strong>Epoch N</strong><span>Phase 1 Earned</span><small>{Number.isFinite(pending) ? `${formatSnrg(pending)} ${token}` : 'No pending reward returned'}</small></div>
            <ChevronRight size={26} />
            <div><Shield size={24} /><strong>Epoch N+1</strong><span>Phase 2 Settlement</span><small>{rewards.validatorStatus || 'Awaiting validator status'}</small></div>
            <ChevronRight size={26} />
            <div><Wallet size={24} /><strong>Payout</strong><span>SYNV1 Wallet</span><small>{truncateMiddle(node.reward_payout_address || node.node_address, 8, 6)}</small></div>
          </div>
          <p className="v18-muted">Rewards are earned by protocol activity, reviewed in the next epoch, then paid to the validator wallet when available.</p>
        </Card>
      </div>

      <div className="v18-performance-mid-grid">
        <Card title="SYNV1 Wallet Balance" icon={Wallet}>
          <div className="v18-wallet-balance-line"><strong>{Number.isFinite(walletBalance) ? `${formatSnrg(walletBalance)} ${token}` : '—'}</strong><span>{truncateMiddle(node.reward_payout_address || node.node_address, 14, 8)}</span></div>
          <button type="button" className="v18-primary-button" disabled={!node.id} onClick={() => setWithdrawDialogOpen(true)}><Wallet size={16} /> Withdraw</button>
          <p className="v18-muted">{workflowStatus || 'Withdraw submits a validator wallet transfer through the control service.'}</p>
        </Card>
        <Card title="Reward History (Recent)">
          <div className="v18-reward-history v18-data-table">
            {rewardHistory.length ? <div className="v18-data-table__head"><span>Epoch</span><span>Status</span><span>Earned</span><span>Released</span><span>To Treasury</span></div> : null}
            {rewardHistory.length ? rewardHistory.map((entry, index) => (
              <div key={`${entry.timestamp || index}-${entry.amount_snrg || entry.amount}`}>
                <span>{entry.epoch ?? entry.epoch_label ?? entry.reward_type ?? `N-${index}`}</span>
                <StatusPill tone={String(entry.status || '').toLowerCase().includes('pending') ? 'purple' : 'green'}>{entry.status || (index === 0 ? 'Earning' : 'Released')}</StatusPill>
                <strong>{formatSnrg(entry.earned_snrg ?? entry.amount_snrg ?? entry.amount)} {token}</strong>
                <span>{entry.released_snrg == null ? '—' : `${formatSnrg(entry.released_snrg)} ${token}`}</span>
                <span>{entry.treasury_snrg == null ? '—' : `${formatSnrg(entry.treasury_snrg)} ${token}`}</span>
              </div>
            )) : <p className="v18-muted">No reward history was returned for this validator yet.</p>}
          </div>
        </Card>
        <Card title="Earnings Breakdown">
          <div className="v18-earnings-breakdown">
            {scoreAvailable && scoreItems.length ? scoreItems.map((item) => {
              const amount = Number.isFinite(totalEarned) && item.weight ? (totalEarned * item.weight) / 100 : null;
              return (
                <div key={item.id}>
                  <span>{item.label}</span>
                  <strong>{amount == null ? '—' : `${formatSnrg(amount)} ${token}`}</strong>
                  <small>{item.weight ? `${formatNumber(item.weight)}% weight` : formatPercent(item.score, 0)}</small>
                </div>
              );
            }) : <p className="v18-muted">No participation inputs were returned for an earnings breakdown.</p>}
          </div>
        </Card>
      </div>

      <Card title="Penalties & Sanctions" className="v18-penalties-card">
        <div className="v18-penalties-grid">
          <div className="v18-slashing-overview">
            <span className="v18-icon-bubble is-red"><Shield size={22} /></span>
            <div>
              <strong>Slashing Overview</strong>
              <span>Total slashed: {Number.isFinite(slashed) ? `${formatSnrg(slashed)} ${token}` : '—'}</span>
              <span>To treasury recovery: {Number.isFinite(treasuryRecovery) ? `${formatSnrg(treasuryRecovery)} ${token}` : '—'}</span>
            </div>
          </div>
          <div className="v18-sanction-status">
            <Shield size={30} />
            <div>
              <strong>{live.is_quarantined ? 'Quarantined' : 'Active & In Good Standing'}</strong>
              <span>{live.is_quarantined ? 'Control-service reports quarantine state.' : 'No active jail, quarantine, or expulsion state reported by live status.'}</span>
            </div>
          </div>
        </div>
      </Card>
      {withdrawDialogOpen ? (
        <div className="v18-modal-backdrop" role="presentation">
          <form className="v18-confirm-modal v18-passphrase-modal" role="dialog" aria-modal="true" aria-labelledby="withdraw-title" onSubmit={submitWithdraw}>
            <span className="v18-icon-bubble is-green"><Wallet size={22} /></span>
            <h2 id="withdraw-title">Withdraw Validator Rewards</h2>
            <p>Submit a validator wallet transfer through the control service.</p>
            <label className="v18-field">
              <span>Amount (whole SNRG)</span>
              <input inputMode="numeric" pattern="[0-9]*" value={withdrawAmount} onChange={(event) => setWithdrawAmount(event.target.value)} />
            </label>
            <label className="v18-field">
              <span>Destination Synergy wallet</span>
              <input value={withdrawDestination} onChange={(event) => setWithdrawDestination(event.target.value)} autoComplete="off" />
            </label>
            {withdrawError ? <small className="v18-error-text">{withdrawError}</small> : null}
            <div className="v18-modal-actions">
              <button type="button" className="v18-ghost-button" onClick={closeWithdrawDialog}>Cancel</button>
              <button type="submit" className="v18-primary-button">Submit Withdrawal</button>
            </div>
          </form>
        </div>
      ) : null}
    </>
  );
}

function MonitoringPage() {
  const context = useControlPanel();
  const navigate = useNavigate();
  const live = context.selectedNodeLive || {};
  const history = context.telemetryHistory?.byNodeId?.[context.selectedNode?.id] || [];
  const selectedNodeId = context.selectedNode?.id;
  const [readinessState, setReadinessState] = useState({ loading: false, report: null, error: '', updatedAt: null });
  const [settings, setSettings] = useState(null);
  const [status, setStatus] = useState('');
  useEffect(() => {
    if (!selectedNodeId) {
      setReadinessState({ loading: false, report: null, error: '', updatedAt: null });
      return undefined;
    }

    let cancelled = false;
    const loadReadiness = async () => {
      if (!cancelled) setReadinessState((current) => ({ ...current, loading: true, error: '' }));
      try {
        const report = await invoke('testnet_get_node_readiness', { nodeId: selectedNodeId });
        if (!cancelled) setReadinessState({ loading: false, report, error: '', updatedAt: Date.now() });
      } catch (error) {
        if (!cancelled) setReadinessState((current) => ({ ...current, loading: false, error: String(error?.message || error) }));
      }
    };

    void loadReadiness();
    const intervalId = window.setInterval(loadReadiness, 30_000);
    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [selectedNodeId]);

  useEffect(() => {
    settingsService.getSettings().then(setSettings).catch((error) => setStatus(String(error?.message || error)));
  }, []);
  const updateSetting = async (patch) => {
    const next = await settingsService.updateSettings(patch);
    setSettings(next);
  };
  const latestHeight = firstFiniteValue(history.at(-1), ['blockHeight']);
  const previousHeight = firstFiniteValue(history.at(-2), ['blockHeight']);
  const latestNetworkRate = latestHeight != null && previousHeight != null
    ? Math.max(0, latestHeight - previousHeight)
    : null;
  const cpuPercent = firstFiniteValue(live, ['cpu_percent']);
  const memoryPercent = firstFiniteValue(live, ['memory_percent']);
  const diskPercent = firstFiniteValue(live, ['disk_percent']);
  const peerCount = firstFiniteValue(live, ['local_peer_count']);
  const latencyMs = firstFiniteValue(live, ['rpc_latency_ms']);
  const metricCards = [
    [Cpu, 'CPU', formatPercent(cpuPercent, 0), 'Live process metric', cpuPercent, 'blue'],
    [Monitor, 'RAM', formatPercent(memoryPercent, 0), 'Live process metric', memoryPercent, 'purple'],
    [HardDrive, 'Disk', formatPercent(diskPercent, 0), 'Workspace disk usage', diskPercent, 'gray'],
    [Network, 'Network', latestNetworkRate == null ? 'Unavailable' : `${formatNumber(latestNetworkRate)} blocks/sample`, 'Derived from live history', latestNetworkRate, 'green'],
    [Users, 'Peers', formatNumber(peerCount), live.sync_trending || 'Peer count', peerCount, 'purple'],
    [Clock, 'Latency', latencyMs == null ? 'Unavailable' : `${formatNumber(latencyMs)} ms`, live.local_rpc_status || 'RPC latency', latencyMs, 'blue'],
  ];
  const readinessChecks = Array.isArray(readinessState.report?.checks)
    ? readinessState.report.checks
    : Array.isArray(readinessState.report?.readiness?.checks)
      ? readinessState.report.readiness.checks
      : [];
  const readinessStateLabel = readinessState.loading
    ? 'Refreshing readiness checks...'
    : readinessState.error
      ? 'Readiness request failed'
      : readinessState.updatedAt
        ? `Last checked ${terminalTime(readinessState.updatedAt)}`
        : 'Readiness has not been checked';
  const alerts = [
    ...readinessChecks.filter((check) => check.status !== 'pass').map((check) => ({
      title: check.label,
      detail: check.detail,
    })),
    ...(readinessState.error ? [{ title: 'Readiness check unavailable', detail: readinessState.error }] : []),
    ...(context.error ? [{ title: 'Control service error', detail: context.error }] : []),
  ];
  return (
    <>
      <PageHeader title="Synergy Node Control Panel" subtitle="Monitor your node performance, health, and activity in real time." />
      <div className="v18-monitor-metrics">
        {metricCards.map(([Icon, label, value, detail, progress, tone]) => <MetricCard key={label} icon={Icon} label={label} value={value} detail={detail} tone={tone} progress={progress} />)}
      </div>
      <div className="v18-monitor-layout">
        <div className="v18-monitor-main">
          <div className="v18-two-column">
            <ChartCard title="CPU Utilization" current={firstFiniteValue(live, ['cpu_percent'])} points={trendPoints(history, 'cpuPercent')} tone="green" formatValue={(value) => formatPercent(value, 0)} fixedDomain={[0, 100]} emptyText="No CPU history was returned for this node." />
            <ChartCard title="Memory Working Set" current={firstFiniteValue(live, ['memory_mb'])} points={trendPoints(history, 'memoryMb')} tone="purple" unit="MB" emptyText="No memory history was returned for this node." />
          </div>
          <div className="v18-two-column">
            <Card title="Disk Utilization"><UsageGauge value={firstFiniteValue(live, ['disk_percent'])} detail="Workspace storage used" /></Card>
            <ChartCard title="Block Height" current={firstFiniteValue(live, ['local_chain_height', 'sync_target_height', 'best_network_height'])} points={trendPoints(history, 'blockHeight')} tone="blue" unit="blocks" emptyText="No chain-height history was returned for this node." />
          </div>
          <Card title="Health Timeline" action={<span className={cls('v18-readiness-state', readinessState.error && 'is-error')}>{readinessStateLabel}</span>}>
            <div className="v18-health-timeline">
              {readinessChecks.length ? readinessChecks.map((item, index) => {
                const checkStatus = String(item.status || '').toLowerCase();
                const Icon = checkStatus === 'pass' ? CheckCircle2 : checkStatus === 'fail' || checkStatus === 'error' ? XCircle : AlertTriangle;
                return <div key={item.id || `${item.label || 'check'}-${index}`} className={cls(checkStatus === 'pass' ? 'is-pass' : checkStatus === 'fail' || checkStatus === 'error' ? 'is-fail' : 'is-warn')}><Icon size={26} /><span>{item.label || item.id || 'Readiness check'}<small>{item.detail || item.status || 'Status not reported'}</small></span></div>;
              }) : <p className="v18-muted">{readinessState.error || readinessState.loading ? readinessStateLabel : 'No readiness checks were returned for this node.'}</p>}
            </div>
          </Card>
        </div>
        <aside className="v18-monitor-side">
          <Card title="Alerts" action={<button type="button" className="v18-link-button" onClick={() => navigate('/logs')}>View all</button>}>
            <div className="v18-alert-list">
              {alerts.length ? alerts.map((item) => (
                <div key={item.title} className={String(item.detail || '').toLowerCase().includes('error') ? 'is-red' : 'is-yellow'}><AlertTriangle size={18} /><span>{item.title}<small>{item.detail}</small></span></div>
              )) : <p className="v18-muted">No live alerts from readiness or control-service status.</p>}
            </div>
          </Card>
          <Card title="Notification Channels">
            <label className="v18-toggle-row"><span><Monitor size={18} /> Desktop Notifications<small>Instant alerts on this device</small></span><input type="checkbox" checked={settings?.desktopNotifications === true} onChange={(event) => updateSetting({ desktopNotifications: event.target.checked })} /></label>
            <label className="v18-toggle-row"><span><Mail size={18} /> Email Notifications<small>{settings?.alertEmail || 'No email address set'}</small></span><input type="checkbox" checked={Boolean(settings?.alertEmail)} onChange={(event) => {
              if (!event.target.checked) {
                void updateSetting({ alertEmail: '' });
                return;
              }
              setStatus('Enter an alert email address below.');
            }} /></label>
            <label className="v18-input-row"><Mail size={16} /><span>Alert Email</span><input value={settings?.alertEmail || ''} onChange={(event) => updateSetting({ alertEmail: event.target.value })} /></label>
            <label className="v18-toggle-row"><span><Network size={18} /> Webhook<small>{settings?.webhookUrl || 'No webhook URL set'}</small></span><input type="checkbox" checked={Boolean(settings?.webhookUrl)} onChange={(event) => {
              if (!event.target.checked) {
                void updateSetting({ webhookUrl: '' });
                return;
              }
              setStatus('Enter a webhook URL below.');
            }} /></label>
            <label className="v18-input-row"><Network size={16} /><span>Webhook URL</span><input value={settings?.webhookUrl || ''} onChange={(event) => updateSetting({ webhookUrl: event.target.value })} /></label>
            <button type="button" className="v18-primary-button" onClick={async () => {
              await settingsService.sendTestNotifications(settings || await settingsService.getSettings());
              setStatus('Notification channels tested.');
            }}>Test All Channels</button>
            {status ? <p className="v18-muted">{status}</p> : null}
          </Card>
        </aside>
      </div>
    </>
  );
}

function ChartCard({ title, current, points = [], tone = 'green', formatValue = formatNumber, unit = '', fixedDomain, emptyText }) {
  return (
    <Card title={title}>
      <OperationalLineChart title={title} current={current} points={points} tone={tone} formatValue={formatValue} unit={unit} fixedDomain={fixedDomain} emptyText={emptyText} sampleLabel="polling samples" />
    </Card>
  );
}

function LogsPage({ runAction }) {
  const context = useControlPanel();
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('all');
  const [paused, setPaused] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [logBundle, setLogBundle] = useState(null);
  const [logLoading, setLogLoading] = useState(false);
  const [logError, setLogError] = useState('');
  const [diagnosticReport, setDiagnosticReport] = useState(null);
  const [diagnosticReportAt, setDiagnosticReportAt] = useState('');
  const logEndRef = useRef(null);
  const selectedNodeId = context.selectedNode?.id;

  const refreshLogs = async () => {
    if (!selectedNodeId) return;
    setLogLoading(true);
    setLogError('');
    try {
      const bundle = await nodeService.getLogs(selectedNodeId, 700);
      setLogBundle(bundle);
    } catch (error) {
      setLogError(String(error?.message || error));
    } finally {
      setLogLoading(false);
    }
  };

  useEffect(() => {
    if (!selectedNodeId || paused) return undefined;
    setLogLoading(true);
    setLogError('');
    const unsubscribe = nodeService.streamLogs(selectedNodeId, (bundle) => {
      if (bundle?.error) {
        setLogError(bundle.error);
        setLogBundle(bundle);
      } else {
        setLogError('');
        setLogBundle(bundle);
      }
      setLogLoading(false);
    }, { lines: 700, intervalMs: 3000 });
    return unsubscribe;
  }, [selectedNodeId, paused]);

  const entries = logBundle?.entries || [];
  const sources = logBundle?.sources || [];
  const logs = entries.filter((entry) => (
    (filter === 'all' || logLevelKey(`${entry.level} ${entry.kind} ${entry.source_label} ${entry.module} ${entry.message}`) === filter)
    && `${entry.message} ${entry.raw} ${entry.source_label} ${entry.module} ${JSON.stringify(entry.metadata || {})}`.toLowerCase().includes(query.toLowerCase())
  ));
  const summary = logBundle?.summary || {};
  const loadedLogBytes = Number(logBundle?.combined_text?.length || 0);
  const estimatedLogBytes = loadedLogBytes || sources.reduce((sum, source) => sum + Number(source.line_count || 0) * 140, 0);
  const reportCounts = reportCheckCounts(diagnosticReport);
  const live = context.selectedNodeLive || {};
  const lastRestart = live.last_restart_utc || live.lastRestartUtc;
  const diagnosticTools = [
    [Activity, 'Run Health Check', 'Check system health', () => nodeService.runHealthCheck(selectedNodeId).then((result) => {
      setDiagnosticReport(result);
      setDiagnosticReportAt(new Date().toISOString());
      return result;
    }), false],
    [Download, 'Export Support Bundle', 'Download diagnostics', () => nodeService.exportSupportBundle(selectedNodeId), false],
    [RefreshCw, 'Restart Service', 'Restart node service', () => nodeService.restart(selectedNodeId), true],
    [Trash2, 'Clear Cache', 'Clear temp & cache', () => nodeService.clearNodeCache(selectedNodeId), true],
    [Shield, 'Verify Ports', 'Check port connectivity', () => nodeService.verifyPorts(selectedNodeId), false],
    [Archive, 'Resync From Snapshot', 'Resync blockchain data', () => nodeService.resyncFromSnapshot(selectedNodeId), true],
  ];
  const commonFixes = [
    [Network, 'Fix Peer Connectivity', 'Run port and peer reachability checks', () => nodeService.verifyPorts(selectedNodeId)],
    [SlidersHorizontal, 'Clear Stuck Tasks', 'Restart queued validator control tasks', () => nodeService.restart(selectedNodeId)],
    [Database, 'Reindex Database', 'Rebuild local state from verified snapshot data', () => nodeService.resyncFromSnapshot(selectedNodeId)],
    [RefreshCw, 'Reset P2P Networking', 'Restart P2P service and routing', () => nodeService.restart(selectedNodeId)],
  ];
  const filterItems = [
    ['all', CheckCircle2, 'All'],
    ['info', Activity, 'Info'],
    ['warning', AlertTriangle, 'Warning'],
    ['error', XCircle, 'Error'],
    ['service', Shield, 'Service'],
    ['network', Network, 'Network'],
  ];

  useEffect(() => {
    if (!autoScroll) return;
    logEndRef.current?.scrollIntoView({ block: 'end' });
  }, [autoScroll, logs]);

  return (
    <>
      <PageHeader title="Synergy Node Control Panel" subtitle="Inspect service logs, diagnostics, and common fixes." />
      <div className="v18-metric-grid is-four">
        <MetricCard icon={CheckCircle2} label="Service Status" value={nodeRuntimeLabel(context.selectedNodeLive)} detail={context.selectedNodeLive?.local_rpc_status || 'Runtime status'} tone="green" />
        <MetricCard icon={Clock} label="Last Restart" value={lastRestart ? new Date(lastRestart).toLocaleString() : formatRuntimeDuration(context.selectedNodeLive?.process_uptime_secs)} detail={lastRestart ? 'Reported by runtime' : 'Runtime uptime'} tone="purple" />
        <MetricCard icon={AlertTriangle} label="Error Count (24h)" value={formatNumber(summary.error_count)} detail="View errors" tone="red" />
        <MetricCard icon={FileText} label="Log Size" value={formatBytes(estimatedLogBytes)} detail={`${formatNumber(summary.total_entries)} loaded entries`} tone="blue" />
      </div>
      <div className="v18-logs-layout">
        <Card title="Live Logs" icon={Activity}>
          <div className="v18-log-toolbar">
            <label><Search size={18} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search logs..." /></label>
            <button type="button" className="v18-icon-button" onClick={() => setPaused((value) => !value)}>{paused ? <Play size={16} /> : <Pause size={16} />}</button>
            <button type="button" className="v18-icon-button is-red" disabled={!entries.length} onClick={() => setLogBundle({ ...(logBundle || {}), entries: [] })} aria-label="Clear loaded log view"><Trash2 size={16} /></button>
            <button type="button" className={cls('v18-autoscroll-pill', autoScroll && 'is-active')} onClick={() => setAutoScroll((value) => !value)}>Auto-scroll <span className="v18-dot" /></button>
          </div>
          <div className="v18-filter-row">
            {filterItems.map(([item, Icon, label]) => (
              <button key={item} type="button" className={filter === item ? 'is-active' : ''} onClick={() => setFilter(item)}><Icon size={14} /> {label}</button>
            ))}
          </div>
          {logError ? <div className="v18-alert is-error">{logError}</div> : null}
          <div className="v18-log-viewer">
            {logs.length ? logs.map((entry) => (
              <div key={`${entry.source_id}-${entry.raw}`} className={`level-${logLevelKey(entry.level)}`}>
                <time>{entry.timestamp_utc || 'No timestamp'}</time>
                <span>{entry.level || 'info'}</span>
                <strong>{entry.message}</strong>
                <small>{[entry.module, entry.source_label, entry.metadata ? JSON.stringify(entry.metadata) : ''].filter(Boolean).join('  ')}</small>
              </div>
            )) : <p className="v18-muted">No log entries matched the current filter.</p>}
            <i ref={logEndRef} aria-hidden="true" />
          </div>
          <div className="v18-log-footer">
            <p className="v18-muted">{logLoading ? 'Refreshing logs...' : `Showing ${logs.length} of ${entries.length} log entries`}</p>
            <button type="button" className="v18-link-button" onClick={() => { setFilter('all'); setQuery(''); }}>Clear filters</button>
          </div>
        </Card>
        <aside className="v18-logs-side">
          <Card title="Diagnostic Tools">
            <div className="v18-diagnostic-grid">
              {diagnosticTools.map(([Icon, item, detail, action, destructive]) => (
                <button key={item} type="button" onClick={() => runAction(item, `${item} may affect validator operation. Continue?`, action, destructive)}>
                  <Icon size={22} /><span>{item}<small>{detail}</small></span>
                </button>
              ))}
            </div>
          </Card>
          <Card title="Common Fixes">
            {commonFixes.map(([Icon, item, detail, action]) => (
              <div key={item} className="v18-fix-row">
                <Icon size={20} />
                <span>{item}<small>{detail}</small></span>
                <button type="button" onClick={() => runAction(item, `${item} is a maintenance fix. Continue?`, action, true)}>Run</button>
              </div>
            ))}
          </Card>
          <Card title="Last Diagnostic Report" action={diagnosticReport ? <button type="button" className="v18-link-button">View full report</button> : null}>
            {diagnosticReport ? (
              <div className="v18-report-panel">
                <div className="v18-report-header">
                  <span>{diagnosticReportAt ? new Date(diagnosticReportAt).toLocaleString() : 'Latest run'}</span>
                  <StatusPill tone={reportCounts.failed ? 'red' : reportCounts.warnings ? 'yellow' : 'green'}>{diagnosticReport.overall_status || 'Completed'}</StatusPill>
                </div>
                <div className="v18-report-summary">
                  <span><CheckCircle2 size={18} /> <strong>{formatNumber(reportCounts.passed)}</strong> Passed</span>
                  <span><XCircle size={18} /> <strong>{formatNumber(reportCounts.failed)}</strong> Failed</span>
                  <span><AlertTriangle size={18} /> <strong>{formatNumber(reportCounts.warnings)}</strong> Warnings</span>
                </div>
              </div>
            ) : <p className="v18-muted">Run Health Check to create a diagnostic report.</p>}
          </Card>
        </aside>
      </div>
    </>
  );
}

function SettingsPage() {
  const context = useControlPanel();
  const [settings, setSettings] = useState(null);
  const [activeTab, setActiveTab] = useState('General');
  const [status, setStatus] = useState('');
  const [updateInfo, setUpdateInfo] = useState(null);
  const [passwordDialogOpen, setPasswordDialogOpen] = useState(false);
  const [lockPassword, setLockPassword] = useState('');
  const [lockPasswordConfirm, setLockPasswordConfirm] = useState('');
  const [lockPasswordError, setLockPasswordError] = useState('');
  useEffect(() => {
    settingsService.getSettings().then(setSettings).catch((error) => setStatus(String(error?.message || error)));
  }, []);
  const update = async (patch, afterUpdate = null) => {
    try {
      const next = await settingsService.updateSettings(patch);
      setSettings(next);
      if ('darkTheme' in patch) document.documentElement.dataset.theme = patch.darkTheme ? 'dark' : 'light';
      if ('language' in patch) document.documentElement.lang = 'en';
      if (afterUpdate) await afterUpdate(next);
      setStatus('Settings saved.');
    } catch (error) {
      setStatus(String(error?.message || error));
    }
  };
  const selectedNodeId = context.selectedNode?.id;
  const runSettingsAction = async (label, action) => {
    setStatus(`${label} running...`);
    try {
      const result = await action();
      setStatus(result?.message || `${label} completed.`);
      return result;
    } catch (error) {
      setStatus(String(error?.message || error));
      return null;
    }
  };
  const eraseAllNodeFiles = async () => {
    const confirmed = window.confirm('Erase all local Synergy Testnet node files on this machine? This cannot be undone.');
    if (!confirmed) return null;
    return runSettingsAction('Erase All Node Files', async () => {
      const result = await nodeService.eraseAllNodeFiles();
      await context.refresh({ silent: true });
      return result;
    });
  };
  const setPasswordLock = async (enabled) => {
    if (!enabled) {
      await update({ passwordLock: false });
      return;
    }
    if (settings.lockPasswordHash) {
      await update({ passwordLock: true });
      return;
    }
    setPasswordDialogOpen(true);
  };
  const closePasswordDialog = () => {
    setPasswordDialogOpen(false);
    setLockPassword('');
    setLockPasswordConfirm('');
    setLockPasswordError('');
  };
  const submitPasswordLock = async (event) => {
    event.preventDefault();
    if (lockPassword.length < 8) {
      setLockPasswordError('Use at least 8 characters.');
      return;
    }
    if (lockPassword !== lockPasswordConfirm) {
      setLockPasswordError('Passwords do not match.');
      return;
    }
    try {
      setSettings(await settingsService.setLockPassword(lockPassword));
      setStatus('Password lock enabled.');
      closePasswordDialog();
    } catch (error) {
      const message = String(error?.message || error);
      setStatus(message);
      setLockPasswordError(message);
    }
  };
  const scrollToSection = (label) => {
    setActiveTab(label);
    document.getElementById(`v18-settings-${label.toLowerCase().replace(/\s+/g, '-')}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  if (!settings) return null;
  return (
    <>
      <PageHeader title="Synergy Node Control Panel" subtitle="Configure your node settings, preferences, and maintenance." />
      <div className="v18-settings-tabs">
        {['General', 'Updates', 'Notifications', 'Backups', 'Security', 'Storage Paths', 'Danger Zone'].map((item) => <button key={item} type="button" className={activeTab === item ? 'is-active' : ''} onClick={() => scrollToSection(item)}>{item}</button>)}
      </div>
      <div className="v18-settings-grid">
        <Card title="General Preferences" icon={Settings} className="v18-settings-section" action={<span id="v18-settings-general" />}>
          <ToggleRow label="Auto Start Node on Launch" checked={settings.autoStartNode} onChange={(value) => update({ autoStartNode: value })} />
          <ToggleRow label="Check for Updates Automatically" checked={settings.checkUpdatesAutomatically} onChange={(value) => update({ checkUpdatesAutomatically: value })} />
          <ToggleRow label="Enable Desktop Notifications" checked={settings.desktopNotifications} onChange={(value) => update({ desktopNotifications: value })} />
          <ToggleRow label="Dark Theme" checked={settings.darkTheme} onChange={(value) => update({ darkTheme: value })} />
          <label className="v18-input-row"><span>Language</span><select value={settings.language} onChange={(event) => update({ language: event.target.value })}><option>English</option></select></label>
        </Card>
        <Card title="Software Update" icon={RefreshCw} action={<span id="v18-settings-updates" />}>
          <div className="v18-update-box"><span>Current Version</span><strong>{updateInfo?.currentVersion || 'Installed'}</strong><small>Read from packaged app metadata</small></div>
          <div className="v18-update-box"><span>Available Version</span><strong>{updateInfo?.version || 'None detected'}</strong><small>{updateInfo?.available ? 'Update available' : updateInfo?.error || 'No update available'}</small></div>
          <button type="button" className="v18-primary-button" onClick={() => runSettingsAction('Install Update', () => settingsService.installUpdate())}><Download size={16} /> Install Update</button>
          <button type="button" className="v18-ghost-button" onClick={() => runSettingsAction('Check Now', async () => {
            const result = await settingsService.checkForUpdates();
            setUpdateInfo(result);
            return { message: result?.available ? `Update ${result.version} is available.` : 'No update available.' };
          })}><RefreshCw size={16} /> Check Now</button>
        </Card>
        <Card title="Backup & Recovery" icon={Database} action={<span id="v18-settings-backups" />}>
          <div className="v18-action-grid is-two">
            {[
              ['Create Backup', () => nodeService.createSnapshot(selectedNodeId)],
              ['Verify Backup', () => nodeService.verifyBackup(selectedNodeId)],
              ['Import Config', () => nodeService.importConfigForNode(selectedNodeId)],
              ['Restore From Backup', () => nodeService.restoreBackup(selectedNodeId)],
            ].map(([item, action]) => <button key={item} type="button" className="v18-action-tile" onClick={() => runSettingsAction(item, action)}><Upload size={24} /><span>{item}</span></button>)}
          </div>
        </Card>
        <Card title="Notifications" icon={Bell} action={<span id="v18-settings-notifications" />}>
          <label className="v18-input-row"><Mail size={16} /><span>Alert Email</span><input value={settings.alertEmail} onChange={(event) => update({ alertEmail: event.target.value })} /></label>
          <label className="v18-input-row"><Network size={16} /><span>Webhook URL</span><input value={settings.webhookUrl} onChange={(event) => update({ webhookUrl: event.target.value })} /></label>
          <ToggleRow label="Critical Alerts" checked={settings.criticalAlerts} onChange={(value) => update({ criticalAlerts: value })} />
          <ToggleRow label="Daily Summary" checked={settings.dailySummary} onChange={(value) => update({ dailySummary: value })} />
          <button type="button" className="v18-primary-button" onClick={() => runSettingsAction('Test Notifications', () => settingsService.sendTestNotifications(settings))}><Bell size={16} /> Test Notification Channels</button>
        </Card>
        <Card title="Security" icon={Shield} action={<span id="v18-settings-security" />}>
          <div className="v18-list">
            <div><span>Key Backup Status</span><strong>{context.selectedNodeLive?.wallet_ready ? 'Runtime keys loaded' : 'Verify backup required'}</strong></div>
            <div><span>Backup Keys</span><button type="button" className="v18-ghost-button" onClick={() => runSettingsAction('Backup Keys', () => nodeService.backupKeys(selectedNodeId))}>Backup Keys</button></div>
          </div>
          <ToggleRow label="Encrypted Storage" checked={settings.encryptedStorage} onChange={(value) => update({ encryptedStorage: value })} />
          <ToggleRow label="Password Lock" checked={settings.passwordLock} onChange={setPasswordLock} />
          <label className="v18-input-row"><span>Session Timeout</span><select value={settings.sessionTimeout} onChange={(event) => update({ sessionTimeout: event.target.value })}><option>15 minutes</option><option>30 minutes</option></select></label>
        </Card>
        <Card title="Storage Paths" icon={FolderOpen} action={<span id="v18-settings-storage-paths" />}>
          {[
            ['Default Snapshot Location', 'snapshotLocation'],
            ['Log Directory', 'logDirectory'],
            ['Data Directory', 'dataDirectory'],
          ].map(([label, key]) => (
            <label key={key} className="v18-input-row"><span>{label}</span><input value={settings[key]} onChange={(event) => update({ [key]: event.target.value })} onBlur={(event) => runSettingsAction(`Validate ${label}`, () => nodeService.validatePath(event.target.value))} /></label>
          ))}
          <label className="v18-input-row"><span>Log Retention</span><select value={settings.logRetention} onChange={(event) => update({ logRetention: event.target.value }, () => nodeService.applyLogRetention(selectedNodeId, Number.parseInt(event.target.value, 10)))}><option>30 days</option><option>90 days</option></select></label>
        </Card>
        <Card title="Danger Zone" icon={AlertTriangle} className="v18-danger-zone" action={<span id="v18-settings-danger-zone" />}>
          <div className="v18-list">
            <div>
              <span>Erase all local node files</span>
              <strong>Control-service cleanup</strong>
            </div>
            <div>
              <span>Removes local testnet workspaces, stops node processes, and recreates an empty registry.</span>
              <button type="button" className="v18-danger-button" onClick={eraseAllNodeFiles}><AlertTriangle size={16} /> Erase All Node Files</button>
            </div>
          </div>
        </Card>
      </div>
      {passwordDialogOpen ? (
        <div className="v18-modal-backdrop" role="presentation">
          <form className="v18-confirm-modal v18-passphrase-modal" role="dialog" aria-modal="true" aria-labelledby="password-lock-title" onSubmit={submitPasswordLock}>
            <span className="v18-icon-bubble is-purple"><Lock size={22} /></span>
            <h2 id="password-lock-title">Set Control Panel Password</h2>
            <p>This password locks the local control panel session on this machine.</p>
            <label className="v18-field">
              <span>Password</span>
              <input type="password" value={lockPassword} onChange={(event) => setLockPassword(event.target.value)} minLength={8} autoComplete="new-password" autoFocus />
            </label>
            <label className="v18-field">
              <span>Confirm password</span>
              <input type="password" value={lockPasswordConfirm} onChange={(event) => setLockPasswordConfirm(event.target.value)} minLength={8} autoComplete="new-password" />
            </label>
            {lockPasswordError ? <small className="v18-error-text">{lockPasswordError}</small> : null}
            <div className="v18-modal-actions">
              <button type="button" className="v18-ghost-button" onClick={closePasswordDialog}>Cancel</button>
              <button type="submit" className="v18-primary-button">Enable Password Lock</button>
            </div>
          </form>
        </div>
      ) : null}
      {status ? <div className="v18-toast" role="status"><span>{status}</span><button type="button" onClick={() => setStatus('')}>x</button></div> : null}
    </>
  );
}

function ToggleRow({ label, checked, onChange }) {
  return (
    <label className="v18-toggle-row">
      <span>{label}</span>
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
    </label>
  );
}

function actionMessage(result, fallback) {
  return result?.message || result?.detail || fallback;
}

function errorMessage(error) {
  return String(error?.message || error || 'Operation failed.');
}

export default function ControlPanelV18() {
  const [confirmRequest, setConfirmRequest] = useState(null);
  const [toast, setToast] = useState(null);
  const context = useControlPanel();
  const setupVisible = setupVisibleForContext(context);
  const defaultRoute = setupVisible ? '/setup' : '/';

  const runAction = (title, body, action, dangerous = false, onCancel = () => {}) => {
    const request = { title, body, action, onCancel };
    if (dangerous) {
      setConfirmRequest(request);
      return;
    }
    Promise.resolve(action?.())
      .then((result) => setToast({ message: actionMessage(result, `${title} completed.`) }))
      .catch((error) => setToast({ tone: 'error', message: `${title} failed: ${errorMessage(error)}` }));
  };

  const confirm = async (request) => {
    setConfirmRequest(null);
    try {
      const result = await request.action?.();
      setToast({ message: actionMessage(result, `${request.title} completed.`) });
    } catch (error) {
      setToast({ tone: 'error', message: `${request.title} failed: ${errorMessage(error)}` });
    }
  };

  return (
    <AppShell>
      <Routes>
        <Route path="/" element={setupVisible ? <Navigate to="/setup" replace /> : <OverviewPage />} />
        <Route path="/overview" element={<OverviewPage />} />
        <Route path="/setup" element={setupVisible ? <SetupNodePage /> : <Navigate to="/" replace />} />
        <Route path="/operations" element={<OperationsPage runAction={runAction} />} />
        <Route path="/validator" element={<Navigate to="/operations" replace />} />
        <Route path="/performance" element={<PerformancePage />} />
        <Route path="/monitoring" element={<MonitoringPage />} />
        <Route path="/logs" element={<LogsPage runAction={runAction} />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/activity" element={<Navigate to="/logs" replace />} />
        <Route path="/node" element={<Navigate to="/operations" replace />} />
        <Route path="/node/:nodeId" element={<Navigate to="/operations" replace />} />
        <Route path="/validator/detail" element={<Navigate to="/operations" replace />} />
        <Route path="/validator/onboarding" element={<Navigate to={setupVisible ? '/setup' : '/'} replace />} />
        <Route path="/connectivity" element={<Navigate to="/monitoring" replace />} />
        <Route path="/rewards" element={<Navigate to="/performance" replace />} />
        <Route path="/help" element={<Navigate to="/settings" replace />} />
        <Route path="*" element={<Navigate to={defaultRoute} replace />} />
      </Routes>
      <ConfirmationModal
        request={confirmRequest}
        onCancel={() => {
          confirmRequest?.onCancel?.();
          setConfirmRequest(null);
        }}
        onConfirm={confirm}
      />
      <Toast toast={toast} onClose={() => setToast(null)} />
    </AppShell>
  );
}

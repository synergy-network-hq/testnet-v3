import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { invoke, listen } from '../lib/desktopClient';
import SynergyWalletConnection from './wallet/SynergyWalletConnection';
import {
  applyStoredTestnetPortSettings,
  buildPublicP2pEndpoint,
  checkValidatorPublicEndpoint,
  formatPortSettingsSummary,
  getValidatorNatModeOptions,
  heartbeatValidatorToSeedServers,
  normalizePublicP2pPort,
  registerValidatorWithSeedServers,
  refreshTestnetBootstrapConfig,
  resolveValidatorPublicEndpoint,
} from '../lib/testnetBootstrap';
import { clearTestnetDashboardCache } from './TestnetDashboard';
import {
  ELIGIBILITY_STATUSES,
  REQUIRED_VALIDATOR_STAKE_SNRG,
  VALIDATOR_FUNDING_TARGET_SNRG,
  emptyEligibility,
  validatorEligibilityService,
} from '../services/validatorEligibilityService';
import { SNRGButton } from '../styles/SNRGButton';

function createId(prefix = 'item') {
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function sleep(ms) {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

function formatClock(value = new Date()) {
  return value.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

function truncateAddress(value, visible = 8) {
  const text = String(value || '').trim();
  if (!text || text.length <= visible * 2) return text || 'Pending';
  return `${text.slice(0, visible)}...${text.slice(-visible)}`;
}

function normalizeOutputLines(value) {
  return String(value || '')
    .replace(/\r\n/g, '\n')
    .split('\n')
    .map((line) => line.trimEnd())
    .filter((line) => line.length > 0);
}

function formatSnapshotProgressBytes(transferredBytes, totalBytes) {
  const transferred = Number(transferredBytes);
  const total = Number(totalBytes);
  if (!Number.isFinite(transferred) || !Number.isFinite(total) || total <= 0) {
    return '';
  }

  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const formatValue = (value) => {
    let nextValue = Math.max(0, value);
    let unitIndex = 0;
    while (nextValue >= 1024 && unitIndex < units.length - 1) {
      nextValue /= 1024;
      unitIndex += 1;
    }
    const digits = nextValue >= 10 || unitIndex === 0 ? 0 : 1;
    return `${nextValue.toFixed(digits)} ${units[unitIndex]}`;
  };

  return `${formatValue(transferred)} / ${formatValue(total)}`;
}

function extractErrorText(error) {
  if (error == null) {
    return 'Unknown error';
  }

  if (typeof error === 'string') {
    const text = error.trim();
    return text.length ? text : 'Unknown error';
  }

  if (error instanceof Error) {
    return error.message || String(error);
  }

  if (typeof error === 'object') {
    const candidateMessage = [
      error.message,
      error.error,
      error.detail,
    ].find((value) => typeof value === 'string' && value.trim().length > 0);
    if (candidateMessage) return String(candidateMessage).trim();
  }

  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}

function compactErrorText(error, limit = 320) {
  const text = extractErrorText(error).trim();
  if (text.length <= limit) return text;
  return `${text.slice(0, Math.max(40, limit - 5))}...`;
}

function summarizeOnboardingResultForJarvis(result) {
  const status = String(result?.status || '').trim().toLowerCase();
  const message = String(result?.message || '').trim();
  const nextAction = String(result?.nextAction || result?.next_action || '').trim();
  const baseMessage = message || 'The onboarding workflow finished its current pass.';

  if (status === 'complete' || status === 'ready' || status === 'rejoined') {
    return `${baseMessage} The validator is ready for the next dashboard step.`;
  }

  if (status === 'blocked' || status === 'syncing') {
    return `${baseMessage} Onboarding is underway, and the dashboard will show the remaining gate${nextAction ? `: ${nextAction}` : ''}.`;
  }

  return `${baseMessage}${nextAction ? ` Next gate: ${nextAction}.` : ''}`;
}

function sanitizeSlug(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/-{2,}/g, '-');
}

function platformKind(operatingSystem) {
  const text = String(operatingSystem || '').toLowerCase();
  if (text.includes('linux')) return 'linux';
  if (text.includes('windows') || text.includes('win32')) return 'windows';
  if (text.includes('mac') || text.includes('darwin') || text.includes('os x')) return 'macos';
  return 'desktop';
}

function cleanupPlatformTarget(operatingSystem) {
  const detected = platformKind(operatingSystem);
  if (detected !== 'desktop') return detected;
  const browserText = `${navigator?.platform || ''} ${navigator?.userAgent || ''}`.toLowerCase();
  if (browserText.includes('mac')) return 'macos';
  if (browserText.includes('linux')) return 'linux';
  if (browserText.includes('win')) return 'windows';
  return 'macos';
}

function desktopValidatorApplianceRoot(homeDirectory) {
  const base = String(homeDirectory || '~').replace(/[\\/]+$/, '');
  return `${base}/.synergy-node-control-panel/validator`;
}

function validatorApplianceRoot(homeDirectory, operatingSystem) {
  if (platformKind(operatingSystem) === 'linux') {
    return '/var/lib/synergy/validator';
  }
  return desktopValidatorApplianceRoot(homeDirectory);
}

function suggestedDirectory(homeDirectory, roleId, operatingSystem) {
  if (roleId === 'validator') {
    return validatorApplianceRoot(homeDirectory, operatingSystem);
  }

  const base = String(homeDirectory || '~').replace(/[\\/]+$/, '');
  return `${base}/.synergy-node-control-panel/node-workspaces/${sanitizeSlug(roleId || 'node')}`;
}

function normalizeWorkspaceChoice(value, roleId = 'validator', homeDirectory = '~', operatingSystem = '') {
  const raw = String(value || '').trim();
  if (!raw) return suggestedDirectory(homeDirectory, roleId, operatingSystem);
  const cleaned = raw.replace(/[\\/]+$/, '');
  if (roleId === 'validator') {
    return cleaned;
  }
  return `${cleaned}/.synergy-node-control-panel/node-workspaces/${sanitizeSlug(roleId || 'node')}`;
}

function isContinueValue(value) {
  return /^(continue|yes|ok|proceed|use default|provision node|that works|that works\.)$/i.test(String(value || '').trim());
}

function validatorNodesFromState(state) {
  return (Array.isArray(state?.nodes) ? state.nodes : [])
    .filter((node) => String(node?.role_id || node?.roleId || '').trim() === 'validator');
}

function localValidatorSetupExists(setup) {
  return Boolean(setup?.exists || setup?.registered || setup?.orphaned);
}

function localValidatorSetupWorkspace(setup) {
  return String(setup?.workspace_directory || setup?.workspaceDirectory || '').trim();
}

function localValidatorSetupAddress(setup) {
  return String(setup?.node_address || setup?.nodeAddress || '').trim();
}

function validatorNodeMatchesLocalSetup(node, setup) {
  if (!node || !setup) return false;

  const setupNodeId = String(setup?.node_id || setup?.nodeId || '').trim();
  const setupWorkspace = localValidatorSetupWorkspace(setup);
  const setupAddress = localValidatorSetupAddress(setup);
  const nodeId = String(node?.id || '').trim();
  const nodeWorkspace = String(node?.workspace_directory || node?.workspaceDirectory || '').trim();
  const nodeAddress = String(node?.node_address || node?.nodeAddress || '').trim();

  return (setupNodeId && nodeId === setupNodeId)
    || (setupWorkspace && nodeWorkspace === setupWorkspace)
    || (setupAddress && nodeAddress === setupAddress);
}

function validatorNodeForExistingSetup(state, setup) {
  const validators = validatorNodesFromState(state)
    .sort((left, right) => {
      const leftTime = Date.parse(left?.created_at_utc || left?.createdAtUtc || '') || 0;
      const rightTime = Date.parse(right?.created_at_utc || right?.createdAtUtc || '') || 0;
      return rightTime - leftTime;
    });

  const matchingNode = validators.find((node) => validatorNodeMatchesLocalSetup(node, setup));
  if (localValidatorSetupExists(setup)) {
    return matchingNode || null;
  }

  return matchingNode
    || validators.find((node) => Boolean(node?.setup_sync_required ?? node?.setupSyncRequired))
    || validators[0]
    || null;
}

function existingWorkspaceErrorText(value) {
  return /already has a local Testnet node workspace/i.test(String(value || ''));
}

function isPublicIpv4Address(host) {
  const segments = String(host || '').split('.');
  if (segments.length !== 4) return false;
  const values = segments.map((segment) => {
    if (!/^\d+$/.test(segment)) return null;
    const value = Number.parseInt(segment, 10);
    return value >= 0 && value <= 255 ? value : null;
  });
  if (values.some((value) => value === null)) return false;

  const [first, second, third] = values;
  if (first === 0 || first === 10 || first === 127 || first >= 224) return false;
  if (first === 100 && second >= 64 && second <= 127) return false;
  if (first === 169 && second === 254) return false;
  if (first === 172 && second >= 16 && second <= 31) return false;
  if (first === 192 && second === 0 && third === 0) return false;
  if (first === 192 && second === 0 && third === 2) return false;
  if (first === 192 && second === 168) return false;
  if (first === 198 && (second === 18 || second === 19)) return false;
  if (first === 198 && second === 51 && third === 100) return false;
  if (first === 203 && second === 0 && third === 113) return false;
  return true;
}

function normalizePublicHostInput(value) {
  let candidate = String(value || '').trim();
  if (!candidate) return '';

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(candidate)) {
    try {
      candidate = new URL(candidate).hostname;
    } catch {
      return '';
    }
  }

  candidate = candidate
    .replace(/^\[/, '')
    .replace(/\]$/, '')
    .replace(/\.+$/, '')
    .trim()
    .toLowerCase();

  if (candidate.includes('/') || candidate.includes('@') || candidate.includes(' ')) {
    return '';
  }

  if (candidate.includes(':') && !/^[0-9a-f:]+$/i.test(candidate)) {
    const [hostPart, portPart] = candidate.split(':');
    if (!/^\d+$/.test(portPart || '')) return '';
    candidate = hostPart;
  }

  if (isPublicIpv4Address(candidate)) return candidate;
  if (/^[0-9a-f:]+$/i.test(candidate) && candidate.includes(':')) {
    const lowered = candidate.toLowerCase();
    if (
      lowered === '::1'
      || lowered === '::'
      || lowered.startsWith('fe80:')
      || lowered.startsWith('fc')
      || lowered.startsWith('fd')
    ) {
      return '';
    }
    return candidate;
  }

  if (
    candidate === 'localhost'
    || candidate.endsWith('.local')
    || !candidate.includes('.')
    || !/^[a-z0-9.-]+$/.test(candidate)
    || candidate.startsWith('.')
    || candidate.endsWith('.')
  ) {
    return '';
  }

  return candidate;
}

function formatStake(value) {
  const text = String(value ?? '').trim();
  if (!text) return '50,000 SNRG';
  const number = Number.parseFloat(text);
  if (!Number.isFinite(number)) return text;
  if (Number.isInteger(number)) return `${number.toLocaleString()} SNRG`;
  return `${number.toLocaleString(undefined, { maximumFractionDigits: 2 })} SNRG`;
}

const HEAD_SYNC_GAP_BLOCKS = 2;
const CATCH_UP_POLL_INTERVAL_MS = 10_000;
const FUNDING_POLL_INTERVAL_MS = 10_000;
const ACTIVATION_MONITOR_POLL_INTERVAL_MS = 12_000;
const ACTIVATION_RETRY_EVERY_ATTEMPTS = 6;
const DEFAULT_PUBLIC_P2P_PORT = 5622;

function finiteNumberFrom(...values) {
  for (const value of values) {
    const number = Number(value);
    if (Number.isFinite(number)) return number;
  }
  return Number.NaN;
}

function extractValidatorSyncMetrics(liveStatus) {
  const syncSnapshot = liveStatus?.sync_snapshot || liveStatus?.syncSnapshot || {};
  const liveGap = finiteNumberFrom(
    syncSnapshot.blocks_remaining,
    syncSnapshot.blocksRemaining,
    liveStatus?.sync_gap,
    liveStatus?.syncGap,
  );
  const targetHeight = finiteNumberFrom(
    syncSnapshot.target_finalized_height,
    syncSnapshot.targetFinalizedHeight,
    liveStatus?.sync_target_height,
    liveStatus?.syncTargetHeight,
    liveStatus?.best_network_height,
    liveStatus?.bestNetworkHeight,
  );
  const reportedLocalHeight = finiteNumberFrom(
    liveStatus?.local_chain_height,
    liveStatus?.localChainHeight,
    liveStatus?.latest_finalized_height,
    liveStatus?.latestFinalizedHeight,
  );
  const localHeight = Number.isFinite(reportedLocalHeight)
    ? reportedLocalHeight
    : Number.isFinite(targetHeight) && Number.isFinite(liveGap)
      ? Math.max(0, targetHeight - liveGap)
      : Number.NaN;

  return {
    liveGap,
    targetHeight,
    localHeight,
  };
}

function validatorAddressForNode(node) {
  return String(node?.node_address || node?.nodeAddress || '').trim();
}

function formatPublicEndpoint(host, port) {
  try {
    return buildPublicP2pEndpoint(host, port);
  } catch {
    return host ? `${host}:${normalizePublicP2pPort(port)}` : 'Pending';
  }
}

function natModeLabel(value) {
  return getValidatorNatModeOptions().find((option) => option.value === value)?.label || 'Router port-forward';
}

function statusHeight(liveStatus) {
  const { localHeight, targetHeight } = extractValidatorSyncMetrics(liveStatus);
  return {
    currentHeight: Number.isFinite(localHeight) ? Math.trunc(localHeight) : 0,
    highestKnownHeight: Number.isFinite(targetHeight) ? Math.trunc(targetHeight) : 0,
  };
}

function getPreflightCheck(preflight, id) {
  return (Array.isArray(preflight?.checks) ? preflight.checks : [])
    .find((check) => String(check?.id || '') === id) || null;
}

function preflightCheckPassed(preflight, id) {
  return String(getPreflightCheck(preflight, id)?.status || '').toLowerCase() === 'pass';
}

function preflightHasFunding(preflight) {
  const required = Number(preflight?.requiredStakeNwei ?? preflight?.required_stake_nwei ?? 0);
  const liquid = Number(preflight?.balanceNwei ?? preflight?.balance_nwei ?? 0);
  const staked = Number(preflight?.stakedBalanceNwei ?? preflight?.staked_balance_nwei ?? 0);
  if (required > 0 && (liquid >= required || staked >= required)) return true;
  return preflightCheckPassed(preflight, 'liquid-balance') || preflightCheckPassed(preflight, 'bonded-stake');
}

function preflightHasBondedStake(preflight) {
  const required = Number(preflight?.requiredStakeNwei ?? preflight?.required_stake_nwei ?? 0);
  const staked = Number(preflight?.stakedBalanceNwei ?? preflight?.staked_balance_nwei ?? 0);
  if (required > 0 && staked >= required) return true;
  return preflightCheckPassed(preflight, 'bonded-stake');
}

function preflightCanStake(preflight) {
  return Boolean(preflight?.canStake ?? preflight?.can_stake);
}

function preflightCanActivate(preflight) {
  return Boolean(preflight?.canActivate ?? preflight?.can_activate);
}

function failedPreflightLabels(preflight, ignoredIds = new Set()) {
  return (Array.isArray(preflight?.checks) ? preflight.checks : [])
    .filter((check) => String(check?.status || '').toLowerCase() === 'fail')
    .filter((check) => !ignoredIds.has(String(check?.id || '')))
    .map((check) => check.label || check.id)
    .filter(Boolean);
}

function onboardingPreflight(result) {
  return result?.preflight
    || result?.catchUp?.preflight
    || result?.catch_up?.preflight
    || result?.stake?.preflight
    || result?.activation?.preflight
    || null;
}

function onboardingIsActivationConfirmed(result) {
  const status = String(result?.status || '').toLowerCase();
  const state = String(result?.state || '').toUpperCase();
  const activationStatus = String(
    result?.policy?.activationConfirmation?.status
      || result?.policy?.activation_confirmation?.status
      || '',
  ).toLowerCase();
  return status === 'complete'
    || state === 'ACTIVE'
    || state === 'MONITOR_ACTIVE_VALIDATOR'
    || state === 'ACTIVE_CONFIRMED'
    || activationStatus === 'pass';
}

function onboardingSubmittedActivation(result) {
  const status = String(result?.status || '').toLowerCase();
  const state = String(result?.state || '').toUpperCase();
  return Boolean(result?.activation)
    || status === 'pending'
    || state === 'ACTIVATION_SUBMITTED'
    || state === 'MONITOR_ACTIVE_VALIDATOR'
    || state.startsWith('WAIT_FOR_');
}

function onboardingActivationPropagation(result) {
  return String(
    result?.activation?.propagation?.status
      || result?.activation?.propagation_status
      || '',
  ).toLowerCase();
}

function onboardingNextAction(result) {
  return String(result?.nextAction || result?.next_action || '').trim().toLowerCase();
}

function shouldRetryActivationSubmission(result, preflight) {
  const preflightCanActivateNow = preflightCanActivate(preflight);
  const policyAllowsActivation = onboardingPolicyAllowsActivation(result, preflight);
  const nextAction = onboardingNextAction(result);
  const propagation = onboardingActivationPropagation(result);

  if (!preflightCanActivateNow || !policyAllowsActivation) {
    return false;
  }

  if (nextAction !== 'monitor_active_validator' && nextAction !== 'sync_catch_up') {
    return false;
  }

  return propagation === 'not_found' || propagation === 'local_only_pending';
}

function onboardingPolicyAllowsActivation(result, preflight) {
  return Boolean(
    result?.policy?.activationAllowed
      ?? result?.policy?.activation_allowed
      ?? preflight?.onboardingPolicy?.activationAllowed
      ?? preflight?.onboarding_policy?.activation_allowed
      ?? false,
  );
}

function onboardingShadowEpochProgress(result) {
  const state = String(result?.state || '').toUpperCase();
  const shadowPolicy = result?.policy?.shadowEpoch || result?.policy?.shadow_epoch || null;
  const shadowStep = (Array.isArray(result?.steps) ? result.steps : [])
    .find((step) => String(step?.id || '') === 'shadow-epoch-proof');
  if (!shadowStep && ['CATCHING_UP', 'HEAD_MATCH_PENDING', 'PAUSED', 'FAILED_ONBOARDING'].includes(state)) {
    return null;
  }
  const detail = [
    shadowStep?.detail,
    shadowPolicy?.detail,
  ].find((value) => typeof value === 'string' && value.trim().length > 0) || '';
  if (!detail) return null;

  const observed = Number(detail.match(/observed=(\d+)/i)?.[1]);
  const required = Number(detail.match(/required=(\d+)/i)?.[1] || detail.match(/epoch(?:_| )length[=:](\d+)/i)?.[1]);
  const completed = /completed=true/i.test(detail) || String(shadowPolicy?.status || '').toLowerCase() === 'pass';
  const blocked = String(shadowPolicy?.status || '').toLowerCase() === 'blocked'
    || String(shadowStep?.status || '').toLowerCase() === 'blocked';

  if (completed) {
    return {
      completed: true,
      text: 'Shadow epoch proof is complete.',
    };
  }

  if (!blocked && !Number.isFinite(observed)) return null;

  const progressText = Number.isFinite(observed) && Number.isFinite(required) && required > 0
    ? `${Math.max(0, observed)} of ${required} shadow blocks observed`
    : 'Waiting for the full shadow epoch proof';
  return {
    completed: false,
    text: `Observing pre-activation shadow epoch: ${progressText}.`,
  };
}

function isActivationPendingErrorText(value) {
  return /activation/i.test(String(value || '')) && /(submitted|confirmation|confirmed|active)/i.test(String(value || ''));
}

function normalizeTxHash(value) {
  return String(value || '').trim();
}

function txHashLooksValid(value) {
  const text = normalizeTxHash(value);
  return text.length >= 16 && !/\s/.test(text);
}

function deriveSetupStatus(phase, running, hasProvisionedNode) {
  if (phase === 'error') {
    return { label: 'Needs Attention', tone: 'danger' };
  }

  if (running || phase === 'booting') {
    return { label: 'Getting Ready', tone: 'success' };
  }

  if (hasProvisionedNode || phase === 'ready_provision') {
    return { label: 'Ready', tone: 'success' };
  }

  return { label: 'In Progress', tone: 'success' };
}

const REMOTE_DEPLOYMENT_ROLES = new Set(['validator', 'rpc_gateway', 'indexer']);
const SETUP_ALLOWED_ROLE_IDS = new Set([
  'validator',
  'witness',
  'data_availability',
  'rpc_gateway',
  'indexer',
  'archive_validator',
  'audit_validator',
  'governance_auditor',
  'ai_inference',
  'observer',
]);

const FALLBACK_VALIDATOR_ROLE_PROFILE = {
  id: 'validator',
  display_name: 'Validator Node',
  class_name: 'Consensus',
  summary: 'Participates directly in PoSy propose-vote-commit finality.',
  responsibilities: [
    'Maintain deterministic consensus state and vote correctness.',
    'Join active committees only after state sync and policy validation.',
    'Quarantine instead of signing when integrity drift is detected.',
  ],
  service_surface: ['p2p', 'consensus', 'mempool', 'state', 'aegis-verifier', 'telemetry'],
};

const SETUP_PROGRESS_STORAGE_KEY = 'synergy:testnet:jarvis-setup-progress:v2';

function readStoredSetupProgress() {
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.localStorage.getItem(SETUP_PROGRESS_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

function writeStoredSetupProgress(progress) {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(SETUP_PROGRESS_STORAGE_KEY, JSON.stringify(progress));
  } catch {
    // Setup persistence is a convenience; backend state remains authoritative.
  }
}

function clearStoredSetupProgress() {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.removeItem(SETUP_PROGRESS_STORAGE_KEY);
  } catch {
    // Ignore storage cleanup failures.
  }
}

function TestnetJarvisSetup({ onComplete, onDefer }) {
  const restoredProgressRef = useRef(readStoredSetupProgress());
  const initializedRef = useRef(false);
  const messagesEndRef = useRef(null);
  const terminalScrollRef = useRef(null);
  const messageQueueRef = useRef(Promise.resolve());
  const conversationEpochRef = useRef(0);
  const snapshotProgressNodeRef = useRef('');
  const activationWatcherStartedRef = useRef(false);
  const navigate = useNavigate();

  const [messages, setMessages] = useState(() => (Array.isArray(restoredProgressRef.current?.messages)
    ? restoredProgressRef.current.messages
    : []));
  const [input, setInput] = useState('');
  const [phase, setPhase] = useState(() => restoredProgressRef.current?.phase || 'booting');
  const [running, setRunning] = useState(false);
  const [workingStatus, setWorkingStatus] = useState('');
  const [typing, setTyping] = useState(false);
  const [shellReady, setShellReady] = useState(false);
  const [selectValue, setSelectValue] = useState('');

  const [deviceProfile, setDeviceProfile] = useState(null);
  const [networkProfile, setNetworkProfile] = useState(null);
  const [nodeCatalog, setNodeCatalog] = useState([]);
  const [existingNodes, setExistingNodes] = useState([]);
  const [localValidatorSetup, setLocalValidatorSetup] = useState(null);

  const [selectedRoleId, setSelectedRoleId] = useState(() => restoredProgressRef.current?.selectedRoleId || '');
  const [validatorNickname, setValidatorNickname] = useState(() => restoredProgressRef.current?.validatorNickname || '');
  const [snapshotSyncEnabled, setSnapshotSyncEnabled] = useState(() => restoredProgressRef.current?.snapshotSyncEnabled !== false);
  const [publicHost, setPublicHost] = useState(() => restoredProgressRef.current?.publicHost || '');
  const [publicP2pPort, setPublicP2pPort] = useState(() => restoredProgressRef.current?.publicP2pPort || String(DEFAULT_PUBLIC_P2P_PORT));
  const [natMode, setNatMode] = useState(() => restoredProgressRef.current?.natMode || 'router_port_forward');
  const [networkOnboardingStatus, setNetworkOnboardingStatus] = useState(null);
  const [directoryChoice, setDirectoryChoice] = useState(() => restoredProgressRef.current?.directoryChoice || '');
  const [identityPassphrase, setIdentityPassphrase] = useState('');
  const [provisionResult, setProvisionResult] = useState(() => restoredProgressRef.current?.provisionResult || null);
  const [snapshotProgress, setSnapshotProgress] = useState(null);
  const [connectedWallet, setConnectedWallet] = useState(null);
  const [validatorEligibility, setValidatorEligibility] = useState(() => emptyEligibility());
  const [eligibilityBusy, setEligibilityBusy] = useState(false);
  const [eligibilityError, setEligibilityError] = useState('');

  const [terminalCwd, setTerminalCwd] = useState('');
  const [terminalBusy, setTerminalBusy] = useState(false);
  const [terminalInput, setTerminalInput] = useState('');
  const [terminalLines, setTerminalLines] = useState([]);
  const [terminalVisible, setTerminalVisible] = useState(false);
  const [showDeveloperPanel, setShowDeveloperPanel] = useState(false);

  const selectedRole = useMemo(
    () => nodeCatalog.find((entry) => entry.id === selectedRoleId)
      || (selectedRoleId === 'validator' ? FALLBACK_VALIDATOR_ROLE_PROFILE : null),
    [nodeCatalog, selectedRoleId],
  );
  const setupStatus = useMemo(
    () => deriveSetupStatus(phase, running, Boolean(provisionResult?.node)),
    [phase, provisionResult?.node, running],
  );
  const selectedRoleDisplayName = selectedRole?.display_name || 'Awaiting selection';
  const chatInputLocked = running || phase === 'booting';
  const defaultDirectoryChoice = useMemo(
    () => suggestedDirectory(
      deviceProfile?.home_directory || '~',
      selectedRoleId || 'validator',
      deviceProfile?.operating_system || '',
    ),
    [deviceProfile?.home_directory, deviceProfile?.operating_system, selectedRoleId],
  );

  const statusItems = useMemo(() => ([
    { label: 'Environment', value: networkProfile?.display_name || 'Synergy Testnet' },
    { label: 'Detected host', value: deviceProfile?.hostname || 'Detecting...' },
    { label: 'Setup mode', value: 'Standard onboarding' },
    { label: 'Public P2P', value: formatPublicEndpoint(publicHost, publicP2pPort) },
    { label: 'NAT mode', value: natModeLabel(natMode) },
    { label: 'Seed dial-back', value: networkOnboardingStatus?.label || 'Pending runtime start' },
    { label: 'Consensus state', value: networkOnboardingStatus?.consensus || 'Reachable only until activation approval' },
    { label: 'Provisioned nodes', value: existingNodes.length ? String(existingNodes.length) : '0' },
    { label: 'Selected node type', value: selectedRoleDisplayName },
  ]), [deviceProfile?.hostname, existingNodes.length, natMode, networkOnboardingStatus, networkProfile?.display_name, publicHost, publicP2pPort, selectedRoleDisplayName]);

  const networkBootnodes = networkProfile?.bootnodes || [];
  const networkSeeds = networkProfile?.seed_servers || [];

  useEffect(() => {
    if (phase === 'booting') return;
    writeStoredSetupProgress({
      phase,
      messages: messages.slice(-40),
      selectedRoleId,
      validatorNickname,
      publicHost,
      publicP2pPort,
      natMode,
      directoryChoice,
      snapshotSyncEnabled,
      provisionResult,
      updatedAt: new Date().toISOString(),
    });
  }, [
    directoryChoice,
    messages,
    natMode,
    phase,
    provisionResult,
    publicHost,
    publicP2pPort,
    selectedRoleId,
    snapshotSyncEnabled,
    validatorNickname,
  ]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setShellReady(true);
    }, 100);

    return () => {
      window.clearTimeout(timer);
    };
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [messages, typing]);

  useEffect(() => {
    terminalScrollRef.current?.scrollTo({
      top: terminalScrollRef.current.scrollHeight,
      behavior: 'smooth',
    });
  }, [terminalLines]);

  useEffect(() => {
    let cleanup = null;
    let cancelled = false;

    listen('testnet.snapshot.restore.progress', (event) => {
      const payload = event?.payload || {};
      const activeNodeId = snapshotProgressNodeRef.current;
      if (activeNodeId && payload.nodeId && payload.nodeId !== activeNodeId) {
        return;
      }

      const rawPercent = Number(payload.percent);
      const percent = Number.isFinite(rawPercent) ? Math.max(0, Math.min(100, rawPercent)) : 0;
      const phase = String(payload.phase || 'download');

      setSnapshotProgress((current) => {
        const previousPhase = current?.phase || 'download';
        const eventPhase = phase === 'complete' ? 'apply' : phase;
        const isDownloadComplete = eventPhase === 'download' && percent >= 100 && previousPhase === 'download';
        const nextPhase = eventPhase === 'error' ? 'error' : isDownloadComplete ? 'apply' : eventPhase;
        const nextTitle = nextPhase === 'error'
          ? 'Snapshot Restore Failed'
          : nextPhase === 'apply'
            ? 'Applying Snapshot'
            : payload.title || 'Downloading Snapshot';
        const nextPercent = isDownloadComplete ? 0 : percent;

        return {
          visible: true,
          phase: nextPhase,
          title: nextTitle,
          percent: nextPercent,
          detail: payload.detail || current?.detail || '',
          snapshotId: payload.snapshotId || current?.snapshotId || '',
          transferredBytes: payload.transferredBytes ?? current?.transferredBytes ?? null,
          totalBytes: payload.totalBytes ?? current?.totalBytes ?? null,
        };
      });
    })
      .then((unsubscribe) => {
        if (cancelled) {
          unsubscribe();
          return;
        }
        cleanup = unsubscribe;
      })
      .catch(() => {
        // The Electron bridge retries service availability during invoke; missing
        // progress events should not block setup.
      });

    return () => {
      cancelled = true;
      if (cleanup) cleanup();
    };
  }, []);

  const resetMessageQueue = useCallback(() => {
    conversationEpochRef.current += 1;
    messageQueueRef.current = Promise.resolve();
    setTyping(false);
  }, []);

  const addMessage = useCallback((sender, text, type = 'text') => {
    setMessages((prev) => [
      ...prev,
      { id: createId('message'), sender, text, type },
    ]);
  }, []);

  const addTerminalLine = useCallback((kind, text) => {
    const lines = Array.isArray(text) ? text : [text];
    const nextLines = lines
      .map((line) => String(line || '').trimEnd())
      .filter(Boolean)
      .map((line) => ({
        id: createId('terminal'),
        kind,
        text: line,
        at: formatClock(),
      }));

    if (!nextLines.length) return;
    setTerminalLines((prev) => [...prev, ...nextLines]);
  }, []);

  const queueJarvisMessage = useCallback((text, type = 'text', options = {}) => {
    const messageText = String(text || '').trim();
    if (!messageText) return Promise.resolve();

    const epoch = conversationEpochRef.current;
    const typingMs = options.instant ? 0 : options.typingMs ?? Math.min(1450, 340 + messageText.length * 11);
    const pauseMs = options.pauseMs ?? 180;

    const job = async () => {
      if (epoch !== conversationEpochRef.current) return;

      if (typingMs > 0) {
        setTyping(true);
        await sleep(typingMs);
      }

      if (epoch !== conversationEpochRef.current) {
        setTyping(false);
        return;
      }

      setTyping(false);
      addMessage('jarvis', messageText, type);

      if (pauseMs > 0) {
        await sleep(pauseMs);
      }
    };

    messageQueueRef.current = messageQueueRef.current.then(job, job);
    return messageQueueRef.current;
  }, [addMessage]);

  const queueJarvisMessages = useCallback(async (items) => {
    for (const item of items) {
      await queueJarvisMessage(item.text, item.type || 'text', item);
    }
  }, [queueJarvisMessage]);

  const detectPublicHost = useCallback(async () => {
    const candidates = [
      'https://api.ipify.org?format=text',
      'https://api4.ipify.org?format=text',
      'https://ifconfig.me/ip',
    ];

    for (const endpoint of candidates) {
      try {
        const response = await fetch(endpoint, { cache: 'no-store' });
        if (!response.ok) continue;
        const value = normalizePublicHostInput(await response.text());
        if (value) return value;
      } catch {
        // Try the next endpoint.
      }
    }

    return '';
  }, []);

  const refreshPublicHost = useCallback(async ({ announce = false } = {}) => {
    const resolved = await detectPublicHost();
    setPublicHost(resolved);
    if (announce) {
      if (resolved) {
        addTerminalLine('info', `Detected public endpoint: ${resolved}`);
      } else {
        addTerminalLine('warning', 'Public endpoint auto-detection did not return a value.');
      }
    }
    return resolved;
  }, [addTerminalLine, detectPublicHost]);

  const executeCommandAndLog = useCallback(async (command, cwdOverride = null) => {
    const effectiveCwd = cwdOverride || terminalCwd || deviceProfile?.home_directory || null;
    const promptPrefix = effectiveCwd || '~';
    addTerminalLine('prompt', `${promptPrefix} $ ${command}`);

    const result = await invoke('monitor_run_terminal_command', {
      command,
      cwd: effectiveCwd,
    });

    if (result?.cwd) {
      setTerminalCwd(String(result.cwd));
    }

    normalizeOutputLines(result?.stdout).forEach((line) => addTerminalLine('output', line));
    normalizeOutputLines(result?.stderr).forEach((line) => addTerminalLine('error', line));
    return result;
  }, [addTerminalLine, deviceProfile?.home_directory, terminalCwd]);

  const runTerminalCommand = useCallback(async (rawCommand) => {
    const command = String(rawCommand || '').trim();
    if (!command || terminalBusy) return;

    setTerminalBusy(true);
    try {
      const result = await executeCommandAndLog(command);
      if (!result?.success && normalizeOutputLines(result?.stderr).length === 0) {
        addTerminalLine('error', `Command failed with exit code ${result?.exit_code ?? 'unknown'}`);
      }
    } catch (error) {
      addTerminalLine('error', String(error));
    } finally {
      setTerminalBusy(false);
    }
  }, [addTerminalLine, executeCommandAndLog, terminalBusy]);

  const submitTerminal = useCallback(async (event) => {
    event.preventDefault();
    const command = terminalInput.trim();
    if (!command) return;
    setTerminalInput('');
    await runTerminalCommand(command);
  }, [runTerminalCommand, terminalInput]);

  const refreshState = useCallback(async (announce = false) => {
    const data = await invoke('testnet_get_state');
    setDeviceProfile(data?.device_profile || null);
    setNetworkProfile(data?.network_profile || null);
    setNodeCatalog(
      (Array.isArray(data?.node_catalog) ? data.node_catalog : [])
        .filter((entry) => SETUP_ALLOWED_ROLE_IDS.has(String(entry?.id || '').trim())),
    );
    setExistingNodes(Array.isArray(data?.nodes) ? data.nodes : []);
    setLocalValidatorSetup(data?.local_validator_setup || data?.localValidatorSetup || null);
    setTerminalCwd(data?.device_profile?.home_directory || '');

    if (announce) {
      addTerminalLine('info', `Device profile refreshed for ${data?.device_profile?.hostname || 'unknown host'}`);
    }

    return data;
  }, [addTerminalLine]);

  const reconcileExistingValidatorRegistry = useCallback(async () => {
    addTerminalLine('info', 'Requesting backend reconciliation for the preserved validator workspace...');
    const data = await refreshState(false);
    addTerminalLine('info', 'Backend registry reconciliation returned. Rechecking the preserved validator identity.');
    return data;
  }, [addTerminalLine, refreshState]);

  const eraseLocalValidatorSetupState = useCallback(async ({
    resetSetupInputs = false,
    resetConversation = false,
  } = {}) => {
    const result = await invoke('testnet_erase_local_machine_data', {
      targetOs: cleanupPlatformTarget(deviceProfile?.operating_system || deviceProfile?.operatingSystem || ''),
    });

    clearTestnetDashboardCache();
    if (resetConversation) {
      resetMessageQueue();
    }

    setSelectedRoleId('validator');
    setProvisionResult(null);
    setSnapshotProgress(null);
    snapshotProgressNodeRef.current = '';
    if (resetSetupInputs) {
      setPublicHost('');
      setPublicP2pPort(String(DEFAULT_PUBLIC_P2P_PORT));
      setNatMode('router_port_forward');
      setNetworkOnboardingStatus(null);
      setDirectoryChoice('');
      setIdentityPassphrase('');
      setValidatorNickname('');
      setSnapshotSyncEnabled(true);
    }
    setPhase('select_node_type');
    await refreshState(false);
    return result;
  }, [
    deviceProfile?.operatingSystem,
    deviceProfile?.operating_system,
    refreshState,
    resetMessageQueue,
  ]);

  const getActiveValidatorNode = useCallback(async () => {
    if (provisionResult?.node?.id) return provisionResult.node;
    const state = await refreshState(false);
    const validators = validatorNodesFromState(state)
      .sort((left, right) => {
        const leftTime = Date.parse(left?.created_at_utc || left?.createdAtUtc || '') || 0;
        const rightTime = Date.parse(right?.created_at_utc || right?.createdAtUtc || '') || 0;
        return rightTime - leftTime;
      });
    return validators.find((node) => Boolean(node?.setup_sync_required ?? node?.setupSyncRequired))
      || validators[0]
      || null;
  }, [provisionResult?.node, refreshState]);

  const getValidatorPreflight = useCallback(async (node) => {
    if (!node?.id) return null;
    return invoke('testnet_get_validator_activation_preflight', { nodeId: node.id });
  }, []);

  const getValidatorLiveStatus = useCallback(async (node) => {
    if (!node?.id) return null;
    return invoke('testnet_get_validator_live_status', { nodeId: node.id });
  }, []);

  const runValidatorPublicNetworkOnboarding = useCallback(async (node, options = {}) => {
    if (!node?.id) {
      throw new Error('Validator public-network onboarding requires a provisioned validator node.');
    }
    const publicEndpoint = await resolveValidatorPublicEndpoint(node, {
      publicHost: publicHost || node?.public_host || node?.publicHost,
      publicP2pPort,
    });
    setNetworkOnboardingStatus({
      label: `Testing ${publicEndpoint}`,
      consensus: 'Reachable only until activation approval',
    });
    setWorkingStatus(`Testing public P2P reachability at ${publicEndpoint}...`);
    addTerminalLine('info', `Testing external validator P2P reachability: ${publicEndpoint}`);
    let reachability = null;
    for (let attempt = 1; attempt <= 8; attempt += 1) {
      reachability = await checkValidatorPublicEndpoint(node, { publicEndpoint });
      if (reachability?.reachable) {
        break;
      }
      if (attempt < 8) {
        addTerminalLine(
          'info',
          `Public P2P endpoint is not reachable yet (${reachability?.error || 'connection failed'}). Retrying ${attempt}/8...`,
        );
        await sleep(2500);
      }
    }
    if (!reachability?.reachable) {
      const detail = reachability?.error || 'connection failed';
      setNetworkOnboardingStatus({
        label: `Unreachable: ${publicEndpoint}`,
        consensus: 'Activation blocked',
      });
      throw new Error(`Public P2P endpoint ${publicEndpoint} is not externally reachable: ${detail}`);
    }
    addTerminalLine('success', `Public P2P endpoint reachable: ${publicEndpoint}`);

    const liveStatus = await getValidatorLiveStatus(node).catch((error) => {
      addTerminalLine('warning', `Live status was unavailable during seed registration: ${compactErrorText(error, 220)}`);
      return null;
    });
    const heights = statusHeight(liveStatus);
    setWorkingStatus('Registering validator public endpoint with seed servers...');
    setNetworkOnboardingStatus({
      label: 'Registering with seeds',
      consensus: 'Reachable only until activation approval',
    });
    const registration = await registerValidatorWithSeedServers(networkProfile, node, {
      publicEndpoint,
      ...heights,
      healthStatus: 'pending',
      appVersion: options.appVersion || 'node-control-panel',
    });
    if (registration.dialbackSuccessCount < 1) {
      const reason = registration.failures.join(' | ') || 'no seed returned dialback success';
      setNetworkOnboardingStatus({
        label: 'Seed dial-back failed',
        consensus: 'Activation blocked',
      });
      throw new Error(`Seed registration did not confirm public dial-back for ${publicEndpoint}: ${reason}`);
    }
    addTerminalLine(
      'success',
      `Seed registration accepted by ${registration.acceptedCount}/${registration.total} seed(s); ${registration.dialbackSuccessCount} confirmed dial-back.`,
    );

    setWorkingStatus('Sending initial validator heartbeat to seed servers...');
    const heartbeatLiveStatus = await getValidatorLiveStatus(node).catch(() => liveStatus);
    const heartbeatHeights = statusHeight(heartbeatLiveStatus);
    const heartbeat = await heartbeatValidatorToSeedServers(networkProfile, node, {
      publicEndpoint,
      ...heartbeatHeights,
      syncStatus: 'starting',
      peerCount: Number(heartbeatLiveStatus?.local_peer_count || heartbeatLiveStatus?.peer_count || 0),
      healthStatus: 'healthy',
      appVersion: options.appVersion || 'node-control-panel',
    });
    if (heartbeat.acceptedCount < 1) {
      const reason = heartbeat.failures.join(' | ') || 'no seed accepted heartbeat';
      setNetworkOnboardingStatus({
        label: 'Seed heartbeat failed',
        consensus: 'Activation blocked',
      });
      throw new Error(`Seed heartbeat did not succeed for ${publicEndpoint}: ${reason}`);
    }
    addTerminalLine(
      'success',
      `Seed heartbeat accepted by ${heartbeat.acceptedCount}/${heartbeat.total} seed(s); ${heartbeat.dialbackSuccessCount} confirmed dial-back.`,
    );
    setNetworkOnboardingStatus({
      label: `Reachable via ${heartbeat.dialbackSuccessCount} seed(s)`,
      consensus: 'Pending consensus approval',
      publicEndpoint,
      registration,
      heartbeat,
    });
    return { publicEndpoint, reachability, registration, heartbeat };
  }, [
    addTerminalLine,
    getValidatorLiveStatus,
    networkProfile,
    publicHost,
    publicP2pPort,
  ]);

  const verifyProvisionedValidator = useCallback(async (result) => {
    const node = result?.node;
    if (!node?.id) {
      throw new Error('Provisioning did not return a validator node record.');
    }

    const generatedPaths = [
      ...(Array.isArray(node.config_paths) ? node.config_paths : []),
      node.public_key_path,
      node.private_key_path,
    ].filter(Boolean);

    addTerminalLine('info', `Verifying validator workspace layout at ${node.workspace_directory}.`);
    generatedPaths.forEach((path) => addTerminalLine('output', `Provisioned file: ${path}`));

    const preflight = await getValidatorPreflight(node).catch((error) => {
      addTerminalLine('warning', `Provisioning preflight is not fully available yet: ${compactErrorText(error, 260)}`);
      return null;
    });

    if (preflight) {
      const requiredChecks = [
        'validator-role',
        'canonical-validator-address',
        'canonical-workspace-genesis',
        'canonical-chain-state',
        'post-fork-fndsa-metadata',
        'fndsa-consensus-key',
        'local-signing-key',
      ];
      const failed = requiredChecks.filter((id) => !preflightCheckPassed(preflight, id));
      if (failed.length > 0) {
        throw new Error(`Provisioning verification failed for ${failed.join(', ')}.`);
      }
      addTerminalLine('success', 'Provisioning verification passed for role, address, genesis, fork metadata, and validator keys.');
    }

    return preflight;
  }, [addTerminalLine, getValidatorPreflight]);

  const restoreSnapshotForValidator = useCallback(async (node) => {
    setWorkingStatus('Downloading the latest validator-pruned snapshot from the archive validator...');
    await queueJarvisMessage(
      'The validator workspace is provisioned. I am now going to grab the latest validator-pruned chain snapshot from the archive validator and apply it to this validator.',
      'text',
      { typingMs: 1100, pauseMs: 320 },
    );

    snapshotProgressNodeRef.current = node.id;
    setSnapshotProgress({
      visible: true,
      phase: 'download',
      title: 'Downloading Snapshot',
      percent: 0,
      detail: 'Preparing archive validator snapshot download.',
      snapshotId: '',
      transferredBytes: null,
      totalBytes: null,
    });

    try {
      const snapshotRestore = await invoke('testnet_restore_validator_snapshot', {
        input: { nodeId: node.id },
      });
      setWorkingStatus('Applying verified snapshot state to the validator appliance...');
      addTerminalLine('success', snapshotRestore?.detail || 'Snapshot applied to validator state.');
      setSnapshotProgress({
        visible: true,
        phase: 'apply',
        title: 'Applying Snapshot',
        percent: 100,
        detail: 'Snapshot applied to the validator.',
        snapshotId: snapshotRestore?.snapshotId || snapshotRestore?.snapshot_id || '',
        transferredBytes: null,
        totalBytes: null,
      });
      await sleep(450);
      setSnapshotProgress(null);
      snapshotProgressNodeRef.current = '';
      return snapshotRestore;
    } catch (snapshotError) {
      const restoreErrorText = compactErrorText(snapshotError, 520);
      setSnapshotProgress({
        visible: true,
        phase: 'error',
        title: 'Snapshot Restore Failed',
        percent: 0,
        detail: restoreErrorText,
        snapshotId: '',
        transferredBytes: null,
        totalBytes: null,
      });
      snapshotProgressNodeRef.current = '';
      addTerminalLine('error', `Validator snapshot restore failed: ${restoreErrorText}`);
      throw new Error(restoreErrorText);
    }
  }, [addTerminalLine, queueJarvisMessage]);

  const startValidatorRuntime = useCallback(async (node) => {
    setWorkingStatus('Starting the validator runtime from the restored snapshot...');
    await queueJarvisMessage(
      'The snapshot is applied. I am starting the validator runtime now so it can catch up from the restored state.',
      'text',
      { typingMs: 920, pauseMs: 240 },
    );
    const startResult = await invoke('testnet_node_control', {
      input: {
        nodeId: node.id,
        action: 'start',
      },
    });
    addTerminalLine('info', startResult?.message || 'Validator runtime start requested.');
    return startResult;
  }, [addTerminalLine, queueJarvisMessage]);

  const waitForValidatorSync = useCallback(async (node, snapshotRestore, targetGap, options = {}) => {
    const label = options.label || 'sync';
    const maxAttempts = options.maxAttempts || 60;
    const allowRestoredGap = options.allowRestoredGap !== false;
    const snapshotHeight = Number(snapshotRestore?.height || snapshotRestore?.snapshotHeight || 0);
    let latestLive = null;
    setWorkingStatus(`Watching validator ${label} progress...`);

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      latestLive = await getValidatorLiveStatus(node).catch((error) => {
        addTerminalLine('warning', `Validator live-status check failed during ${label}: ${compactErrorText(error, 220)}`);
        return null;
      });

      const { liveGap, targetHeight } = extractValidatorSyncMetrics(latestLive);
      const restoredGap = snapshotHeight > 0 && Number.isFinite(targetHeight)
        ? Math.max(0, targetHeight - snapshotHeight)
        : Number.NaN;
      const effectiveGap = Number.isFinite(liveGap)
        ? liveGap
        : allowRestoredGap
          ? restoredGap
          : Number.NaN;

      if (Number.isFinite(effectiveGap)) {
        setWorkingStatus(`Watching validator ${label}: ${effectiveGap.toLocaleString()} block(s) remaining...`);
        addTerminalLine('info', `Validator ${label}: ${effectiveGap.toLocaleString()} block(s) remaining.`);
        if (effectiveGap <= targetGap) {
          return latestLive;
        }
      } else {
        setWorkingStatus(`Waiting for validator ${label} telemetry from the local RPC...`);
        addTerminalLine(
          'info',
          allowRestoredGap
            ? `Validator ${label}: waiting for local RPC height and public target height.`
            : `Validator ${label}: waiting for the local validator RPC to report live catch-up progress.`,
        );
      }

      if (attempt === 1) {
        await queueJarvisMessage(
          targetGap <= HEAD_SYNC_GAP_BLOCKS
            ? snapshotRestore
              ? 'The validator is now catching up from the restored snapshot. I am going to wait here until it is synced to the chain head before asking for funding.'
              : 'The validator is catching up from its local chain state. I am going to wait here until it is synced to the chain head before asking for funding.'
            : 'I am checking that the restored snapshot is valid and that the validator is reporting catch-up telemetry.',
          'text',
          { typingMs: 880, pauseMs: 220 },
        );
      } else if (attempt % 6 === 0 && Number.isFinite(effectiveGap)) {
        await queueJarvisMessage(
          `Still catching up. The validator has ${effectiveGap.toLocaleString()} block(s) remaining.`,
          'text',
          { typingMs: 700, pauseMs: 180 },
        );
      }

      await sleep(options.intervalMs || CATCH_UP_POLL_INTERVAL_MS);
    }

    throw new Error(`Validator did not reach the required sync gap of ${targetGap} block(s) before the onboarding wait window ended.`);
  }, [addTerminalLine, getValidatorLiveStatus, queueJarvisMessage]);

  const markValidatorSetupSyncComplete = useCallback(async (node, liveStatus, syncMode) => {
    const { localHeight, targetHeight, liveGap } = extractValidatorSyncMetrics(liveStatus);
    if (!Number.isFinite(localHeight) || localHeight <= 0) {
      throw new Error('Validator reached the sync gate, but Jarvis could not verify a non-zero local chain height.');
    }

    const input = {
      nodeId: node.id,
      localChainHeight: Math.trunc(localHeight),
      syncMode: syncMode === 'normal' ? 'normal' : 'snapshot',
    };
    if (Number.isFinite(targetHeight)) {
      input.syncTargetHeight = Math.trunc(targetHeight);
    }
    if (Number.isFinite(liveGap)) {
      input.syncGap = Math.trunc(liveGap);
    }

    const result = await invoke('testnet_mark_setup_sync_complete', { input });
    addTerminalLine('success', result?.message || 'Validator setup sync gate recorded.');
    return result;
  }, [addTerminalLine]);

  const requestTeamFunding = useCallback(async (node) => {
    const address = validatorAddressForNode(node);
    await queueJarvisMessages([
      {
        text: 'The validator is synced to the chain head and ready for funding.',
        typingMs: 760,
        pauseMs: 220,
      },
      {
        text: `Your new validator address is ${address}. Please request ${VALIDATOR_FUNDING_TARGET_SNRG.toLocaleString()} SNRG for that synv1 validator address: 50,000 SNRG for the self-bond plus a 1 SNRG validator fee reserve.`,
        typingMs: 1100,
        pauseMs: 260,
      },
      {
        text: "I'll wait here while you do that. Just let me know once the team has sent it so we can continue with onboarding.",
        typingMs: 900,
      },
    ]);
    setPhase('await_funding');
  }, [queueJarvisMessages]);

  const runProvisionedValidatorOnboarding = useCallback(async (node, snapshotRestore) => {
    await startValidatorRuntime(node);
    await runValidatorPublicNetworkOnboarding(node);
    const requiredSyncGap = snapshotRestore ? HEAD_SYNC_GAP_BLOCKS : 0;
    const headSyncStatus = await waitForValidatorSync(node, snapshotRestore, requiredSyncGap, {
      label: snapshotRestore ? 'snapshot catch-up' : 'chain catch-up',
      maxAttempts: 90,
      allowRestoredGap: false,
    });
    await markValidatorSetupSyncComplete(node, headSyncStatus, snapshotRestore ? 'snapshot' : 'normal');
    const preflight = await getValidatorPreflight(node);
    if (preflightHasBondedStake(preflight)) {
      await queueJarvisMessage('This validator already has the required bonded stake, so I am continuing the activation checks now.');
      return 'continue-activation';
    }
    await requestTeamFunding(node);
    return 'await-funding';
  }, [getValidatorPreflight, markValidatorSetupSyncComplete, queueJarvisMessage, requestTeamFunding, runValidatorPublicNetworkOnboarding, startValidatorRuntime, waitForValidatorSync]);

  const runActivationAfterStake = useCallback(async (node, syncMode = 'snapshot') => {
    setWorkingStatus('Running onboarding evidence checks and activation policy gates...');
    await queueJarvisMessage('The required stake is bonded. I am running the remaining onboarding evidence checks now.');
    await runValidatorPublicNetworkOnboarding(node);
    let latestResult = null;
    let retriesSinceSubmission = 0;

    for (let attempt = 1; ; attempt += 1) {
      latestResult = await invoke('testnet_run_validator_onboarding', {
        input: {
          nodeId: node.id,
          dryRun: false,
          autoResyncTime: true,
          autoStart: true,
          autoStake: false,
          autoActivate: true,
          syncMode: syncMode === 'normal' ? 'normal' : 'snapshot',
        },
      });

      const onboardingStatusText = summarizeOnboardingResultForJarvis(latestResult);
      addTerminalLine('info', onboardingStatusText);
      const shadowProgress = onboardingShadowEpochProgress(latestResult);
      const nextAction = onboardingNextAction(latestResult);
      if (nextAction === 'monitor_active_validator' || nextAction === 'wait_for_activation_finality') {
        setWorkingStatus('Monitoring validator activation confirmation and registry registration...');
      } else if (nextAction === 'sync_catch_up') {
        setWorkingStatus('Catching up to chain head before activation confirmation...');
      } else {
        setWorkingStatus(shadowProgress && !shadowProgress.completed
          ? shadowProgress.text
          : onboardingStatusText);
      }

      if (onboardingIsActivationConfirmed(latestResult)) {
        await queueJarvisMessage(
          latestResult?.message || 'Validator activation is confirmed. Consensus activity is visible now.',
          'text',
          { typingMs: 920, pauseMs: 240 },
        );
        return latestResult;
      }

      const preflight = onboardingPreflight(latestResult);
      const isSubmitted = onboardingSubmittedActivation(latestResult);
      if (isSubmitted) {
        retriesSinceSubmission += 1;
        if (attempt === 1 || retriesSinceSubmission % 3 === 0) {
          await queueJarvisMessage(
            latestResult?.message || 'Activation is pending confirmation in the canonical validator registry. I am staying in setup and will keep checking.',
            'text',
            { typingMs: 760, pauseMs: 200 },
          );
        }
      } else {
        retriesSinceSubmission = 0;
      }

      if (shouldRetryActivationSubmission(latestResult, preflight)
        && retriesSinceSubmission > 0
        && retriesSinceSubmission % ACTIVATION_RETRY_EVERY_ATTEMPTS === 0
      ) {
        await queueJarvisMessage('Activation is still not visible to trusted peers. I am retrying activation submission now.');
        try {
          const activation = await invoke('testnet_activate_validator', {
            input: {
              nodeId: node.id,
              amountSnrg: REQUIRED_VALIDATOR_STAKE_SNRG,
              displayName: node.display_label || node.displayLabel || 'Validator',
            },
          });
          retriesSinceSubmission = 0;
          latestResult = {
            ...latestResult,
            activation,
            status: activation?.status || latestResult?.status || 'pending',
            state: activation?.state || latestResult?.state || 'ACTIVATION_SUBMITTED',
          };
          addTerminalLine('info', activation?.message || 'Activation retry submitted.');
          await queueJarvisMessage(
            activation?.message || 'Activation retry was accepted. I am continuing to monitor for registry confirmation.',
            'text',
            { typingMs: 820, pauseMs: 220 },
          );
        } catch (error) {
          addTerminalLine('warning', `Activation retry failed: ${compactErrorText(error, 260)}`);
        }
      }

      if (attempt === 1 || attempt % 3 === 0) {
        await queueJarvisMessage(
          shadowProgress?.text
            ? `${shadowProgress.text} I am keeping setup open until the remaining activation evidence passes.`
            : latestResult?.message || 'I am still waiting for the remaining source-majority, shadow, or duty-gate evidence to pass.',
          'text',
          { typingMs: 820, pauseMs: 220 },
        );
      }

      await sleep(nextAction === 'monitor_active_validator' || nextAction === 'wait_for_activation_finality'
        ? ACTIVATION_MONITOR_POLL_INTERVAL_MS
        : CATCH_UP_POLL_INTERVAL_MS);
    }
  }, [addTerminalLine, queueJarvisMessage, runValidatorPublicNetworkOnboarding]);

  const completeActivatedValidatorSetup = useCallback(async (node, activationResult, details = {}) => {
    if (!node?.id) {
      throw new Error('Jarvis cannot open the dashboard because the provisioned validator record is missing.');
    }
    if (!onboardingIsActivationConfirmed(activationResult)) {
      throw new Error('Jarvis cannot open the dashboard until canonical activation confirmation is visible.');
    }

    await refreshState(false);
    if (typeof onComplete === 'function') {
      onComplete({
        nodeId: node.id,
        snapshotRestored: true,
        activationConfirmed: true,
        ...details,
      });
    }
    clearStoredSetupProgress();
    clearTestnetDashboardCache();
    navigate('/');
  }, [navigate, onComplete, refreshState]);

  const continueAfterFundingHash = useCallback(async (txHashValue) => {
    const txHash = normalizeTxHash(txHashValue);
    if (!txHashLooksValid(txHash)) {
      await queueJarvisMessage('Please enter the transaction hash the project team provided. It should not contain spaces.');
      return;
    }

    const node = await getActiveValidatorNode();
    if (!node?.id) {
      await queueJarvisMessage('I do not see the provisioned validator node anymore. Please restart setup so I can recover the workspace context.');
      setPhase('error');
      return;
    }

    setRunning(true);
    setWorkingStatus('Checking validator funding and preparing staking...');
    addTerminalLine('info', `Recording Core team funding transaction hash: ${txHash}`);

    try {
      await invoke('testnet_record_validator_funding', {
        input: {
          nodeId: node.id,
          txHash,
          amountSnrg: VALIDATOR_FUNDING_TARGET_SNRG,
        },
      }).catch((error) => {
        addTerminalLine('warning', `Funding hash evidence could not be recorded locally: ${compactErrorText(error, 260)}`);
      });

      await queueJarvisMessage('Thank you. I am checking the validator funding and bonded stake now. Activation will only continue after the 50,001 SNRG funding is confirmed and the exact 50,000 SNRG self-bond is visible on-chain.');

      let preflight = null;
      for (let attempt = 1; attempt <= 36; attempt += 1) {
        preflight = await getValidatorPreflight(node).catch((error) => {
          addTerminalLine('warning', `Funding preflight check failed: ${compactErrorText(error, 220)}`);
          return null;
        });
        setWorkingStatus('Waiting for the 50,001 SNRG funding transaction to appear on-chain...');

        if (preflightHasFunding(preflight)) {
          break;
        }

        if (attempt === 1 || attempt % 6 === 0) {
          await queueJarvisMessage(
            'I do not see the required bonded stake from the operator wallet yet. I am still here and will keep checking.',
            'text',
            { typingMs: 780, pauseMs: 220 },
          );
        }
        await sleep(FUNDING_POLL_INTERVAL_MS);
      }

      if (!preflightHasFunding(preflight)) {
        await queueJarvisMessage('The transaction hash is recorded, but the operator-wallet bonded stake is not visible yet. I will wait here; refresh after the transaction is final.');
        setPhase('await_funding');
        return;
      }

      if (!preflightCanStake(preflight) && !preflightHasBondedStake(preflight)) {
        const failed = failedPreflightLabels(preflight, new Set(['bonded-stake'])).slice(0, 4).join(', ');
        await queueJarvisMessage(`Funding is visible, but staking is still blocked by: ${failed || 'preflight checks'}. I will keep this setup session open so we can retry.`);
        setPhase('await_funding');
        return;
      }

      let stakeResult = null;
      if (preflightHasBondedStake(preflight)) {
        await queueJarvisMessage('The validator already has the required bonded stake. I am continuing activation checks now.');
      } else {
        setWorkingStatus('Staking 50,000 SNRG to the validator...');
        await queueJarvisMessage('Funding is visible. I am staking 50,000 SNRG to the validator now.');
        stakeResult = await invoke('testnet_stake_validator', {
          input: {
            nodeId: node.id,
            amountSnrg: REQUIRED_VALIDATOR_STAKE_SNRG,
          },
        });
        addTerminalLine('success', stakeResult?.message || 'Validator stake submitted.');
        await queueJarvisMessage(stakeResult?.message || 'Validator stake submitted.');
      }

      const activationResult = await runActivationAfterStake(node, snapshotSyncEnabled ? 'snapshot' : 'normal');
      await queueJarvisMessages([
        {
          text: activationResult?.message || 'The validator activation workflow has been submitted.',
          typingMs: 820,
          pauseMs: 220,
        },
        {
          text: "That's it. I am sending you to the control panel dashboard now.",
          typingMs: 820,
        },
      ]);
      await completeActivatedValidatorSetup(node, activationResult, {
        fundingTxHash: txHash,
        stakeTxHash: stakeResult?.txHash || stakeResult?.tx_hash || '',
      });
    } catch (error) {
      const errorText = compactErrorText(error, 520);
      addTerminalLine('error', `Post-funding onboarding failed: ${errorText}`);
      if (isActivationPendingErrorText(errorText)) {
        await queueJarvisMessage(`${errorText} I am keeping you in setup and will keep checking activation automatically.`);
        setPhase('await_activation');
      } else {
        await queueJarvisMessage(`I hit a blocker after funding was reported: ${errorText}. I am keeping you in setup so we can retry from here.`);
        setPhase('await_funding');
      }
    } finally {
      setWorkingStatus('');
      setRunning(false);
    }
  }, [
    addTerminalLine,
    completeActivatedValidatorSetup,
    getActiveValidatorNode,
    getValidatorPreflight,
    queueJarvisMessage,
    queueJarvisMessages,
    runActivationAfterStake,
    snapshotSyncEnabled,
  ]);

  const resumeActivationUntilConfirmed = useCallback(async ({ announce = false } = {}) => {
    const node = await getActiveValidatorNode();
    if (!node?.id) {
      await queueJarvisMessage('I do not see the provisioned validator node anymore. Please restart setup so I can recover the workspace context.');
      setPhase('error');
      return;
    }

    setRunning(true);
    setPhase('await_activation');
    setWorkingStatus('Watching activation propagation and canonical validator registry confirmation...');

    try {
      if (announce) {
        await queueJarvisMessage('Activation is pending. I am staying here, checking propagation, and waiting for canonical activation confirmation before I open the dashboard.');
      }
      const activationResult = await runActivationAfterStake(node, snapshotSyncEnabled ? 'snapshot' : 'normal');
      await queueJarvisMessages([
        { text: activationResult?.message || 'The validator activation workflow is confirmed.', typingMs: 820, pauseMs: 220 },
        { text: 'Thank you for your patience. I am going to get you on over to your new dashboard now.', typingMs: 920 },
      ]);
      await completeActivatedValidatorSetup(node, activationResult);
    } catch (error) {
      const errorText = compactErrorText(error, 520);
      addTerminalLine('error', `Activation watcher failed: ${errorText}`);
      await queueJarvisMessage(`${errorText} I am keeping setup open and will retry activation confirmation automatically.`);
      setPhase('await_activation');
    } finally {
      setWorkingStatus('');
      setRunning(false);
    }
  }, [
    addTerminalLine,
    completeActivatedValidatorSetup,
    getActiveValidatorNode,
    queueJarvisMessage,
    queueJarvisMessages,
    runActivationAfterStake,
    snapshotSyncEnabled,
  ]);

  useEffect(() => {
    if (phase !== 'await_activation' || running) return undefined;

    const timer = window.setTimeout(() => {
      if (activationWatcherStartedRef.current) return;
      activationWatcherStartedRef.current = true;
      resumeActivationUntilConfirmed({ announce: true })
        .finally(() => {
          activationWatcherStartedRef.current = false;
        });
    }, 3000);

    return () => {
      window.clearTimeout(timer);
    };
  }, [phase, resumeActivationUntilConfirmed, running]);

  const continueExistingValidatorSetup = useCallback(async () => {
    setRunning(true);
    setWorkingStatus('Inspecting the existing validator setup...');

    try {
      let state = await refreshState(false);
      const localSetup = state?.local_validator_setup || state?.localValidatorSetup || null;
      let node = validatorNodeForExistingSetup(state, localSetup);

      if (!node?.id) {
        const workspace = localValidatorSetupWorkspace(localSetup) || 'the existing validator appliance root';
        addTerminalLine('warning', `No registry node matched the preserved validator workspace at ${workspace}.`);
        try {
          state = await reconcileExistingValidatorRegistry();
          node = validatorNodeForExistingSetup(state, state?.local_validator_setup || state?.localValidatorSetup || localSetup);
        } catch (error) {
          const errorText = compactErrorText(error, 360);
          addTerminalLine('error', `Preserved validator registry reconciliation failed: ${errorText}`);
          await queueJarvisMessages([
            {
              text: `I found validator files at ${workspace}, but the backend registry recovery request did not complete: ${errorText}`,
              typingMs: 820,
              pauseMs: 220,
            },
            {
              text: 'I have not erased or reset this workspace. Keep this setup open and choose Retry Registry Recovery so the backend can reconstruct the registry from the preserved identity and evidence.',
              typingMs: 960,
            },
          ]);
          setPhase('existing_validator_recovery');
          return;
        }

        if (!node?.id) {
          await queueJarvisMessages([
            {
              text: `The validator workspace at ${workspace} is preserved, but the registry still has no matching node after backend reconciliation.`,
              typingMs: 820,
              pauseMs: 220,
            },
            {
              text: 'I have not erased or reset any identity, keys, chain state, funding, VPN receipt, or evidence. Choose Retry Registry Recovery after the backend reconstructs the registry, then I will continue the existing validator onboarding flow.',
              typingMs: 980,
            },
          ]);
          setPhase('existing_validator_recovery');
          return;
        }
      }

      setProvisionResult({
        node,
        network_profile: state?.network_profile || networkProfile,
        device_profile: state?.device_profile || deviceProfile,
      });
      setTerminalCwd(node.workspace_directory || terminalCwd);
      addTerminalLine('info', `Continuing existing validator setup from ${node.workspace_directory}.`);
      await queueJarvisMessage(`I will continue setup with the existing validator ${validatorAddressForNode(node)}.`);

      if (!Boolean(node.setup_sync_required ?? node.setupSyncRequired)) {
        await queueJarvisMessage('This validator already has activation confirmation evidence. I am opening the dashboard now.');
        if (typeof onComplete === 'function') {
          onComplete({ nodeId: node.id, activationConfirmed: true });
        }
        clearTestnetDashboardCache();
        navigate('/');
        return;
      }

      const setupReason = String(node.setup_sync_reason || node.setupSyncReason || '').toLowerCase();
      const setupSyncMode = setupReason.includes('snapshot restore') || setupReason.includes('catch-up')
        ? 'snapshot'
        : snapshotSyncEnabled ? 'snapshot' : 'normal';
      if (setupReason.includes('snapshot restore') || setupReason.includes('catch-up')) {
        await verifyProvisionedValidator({ node });
        const snapshotRestore = await restoreSnapshotForValidator(node);
        const onboardingState = await runProvisionedValidatorOnboarding(node, snapshotRestore);
        if (onboardingState === 'await-funding') {
          await refreshState(false);
          return;
        }
      }

      const preflight = await getValidatorPreflight(node);
      if (preflightHasBondedStake(preflight)) {
        await queueJarvisMessage('The validator already has the required bonded stake. I am continuing activation checks now.');
      } else if (preflightHasFunding(preflight)) {
        if (!preflightCanStake(preflight)) {
          const failed = failedPreflightLabels(preflight, new Set(['bonded-stake'])).slice(0, 4).join(', ');
          await queueJarvisMessage(`Funding is visible, but staking is still blocked by: ${failed || 'preflight checks'}. I will keep this setup session open so we can retry.`);
          setPhase('await_funding');
          return;
        }

        setWorkingStatus('Staking 50,000 SNRG to the validator...');
        await queueJarvisMessage('Funding is visible. I am staking 50,000 SNRG to the validator now.');
        const stakeResult = await invoke('testnet_stake_validator', {
          input: {
            nodeId: node.id,
            amountSnrg: REQUIRED_VALIDATOR_STAKE_SNRG,
          },
        });
        addTerminalLine('success', stakeResult?.message || 'Validator stake submitted.');
        await queueJarvisMessage(stakeResult?.message || 'Validator stake submitted.');
      } else {
        await requestTeamFunding(node);
        return;
      }

      const activationResult = await runActivationAfterStake(node, setupSyncMode);
      await queueJarvisMessages([
        {
          text: activationResult?.message || 'The validator activation workflow is confirmed.',
          typingMs: 820,
          pauseMs: 220,
        },
        {
          text: 'Thank you for your patience. I am going to get you on over to your new dashboard now.',
          typingMs: 920,
        },
      ]);
      await completeActivatedValidatorSetup(node, activationResult);
    } catch (error) {
      const errorText = compactErrorText(error, 520);
      addTerminalLine('error', `Existing validator resume failed: ${errorText}`);
      if (isActivationPendingErrorText(errorText)) {
        await queueJarvisMessage(`${errorText} I am keeping this setup session open and will keep verifying activation before moving you to the dashboard.`);
        setPhase('await_activation');
      } else {
        await queueJarvisMessage(`I could not continue the existing validator setup yet: ${errorText}`);
        setPhase('await_funding');
      }
    } finally {
      setWorkingStatus('');
      setRunning(false);
    }
  }, [
    addTerminalLine,
    completeActivatedValidatorSetup,
    deviceProfile,
    getValidatorPreflight,
    navigate,
    networkProfile,
    onComplete,
    queueJarvisMessage,
    queueJarvisMessages,
    reconcileExistingValidatorRegistry,
    refreshState,
    requestTeamFunding,
    restoreSnapshotForValidator,
    runActivationAfterStake,
    runProvisionedValidatorOnboarding,
    snapshotSyncEnabled,
    terminalCwd,
    verifyProvisionedValidator,
  ]);

  const handoffToDashboard = useCallback(async () => {
    resetMessageQueue();
    await queueJarvisMessages([
      {
        text: 'No problem.',
        typingMs: 420,
        pauseMs: 220,
      },
      {
        text: 'I am returning you to the main control panel. You can come back to setup whenever you are ready.',
        typingMs: 820,
      },
    ]);

    if (typeof onDefer === 'function') {
      onDefer();
    } else if (typeof onComplete === 'function') {
      onComplete();
    }
    clearTestnetDashboardCache();
    navigate('/');
  }, [navigate, onComplete, onDefer, queueJarvisMessages, resetMessageQueue]);

  const bootstrap = useCallback(async () => {
    setRunning(true);
    setWorkingStatus('Checking this machine and loading Testnet setup state...');
    addTerminalLine('info', 'Loading the Testnet node catalog and local device profile...');
    try {
      const state = await refreshState(false);
      const restoredProgress = restoredProgressRef.current;
      if (restoredProgress?.phase && restoredProgress.phase !== 'booting') {
        setSelectedRoleId(restoredProgress.selectedRoleId || 'validator');
        setValidatorNickname(restoredProgress.validatorNickname || '');
        setSnapshotSyncEnabled(restoredProgress.snapshotSyncEnabled !== false);
        setPublicHost(restoredProgress.publicHost || '');
        setPublicP2pPort(restoredProgress.publicP2pPort || String(DEFAULT_PUBLIC_P2P_PORT));
        setNatMode(restoredProgress.natMode || 'router_port_forward');
        setDirectoryChoice(restoredProgress.directoryChoice || '');
        setProvisionResult(restoredProgress.provisionResult || null);
        if (!messages.length) {
          await queueJarvisMessage('I restored your validator setup progress from this device.', 'text', { typingMs: 560 });
        }
        setPhase(restoredProgress.phase);
        return;
      }
      const existingValidatorSetup = state?.local_validator_setup || state?.localValidatorSetup || null;
      setSelectedRoleId('validator');

      if (localValidatorSetupExists(existingValidatorSetup)) {
        const workspace = localValidatorSetupWorkspace(existingValidatorSetup) || 'the local validator appliance root';
        const address = localValidatorSetupAddress(existingValidatorSetup);
        await queueJarvisMessages([
          {
            text: address
              ? `I found validator setup files on this machine at ${workspace} for ${address}.`
              : `I found validator setup files on this machine at ${workspace}.`,
            typingMs: 760,
            pauseMs: 220,
          },
          {
            text: 'Do you want me to continue setting up that validator, or start over fresh with a new validator?',
            typingMs: 900,
            pauseMs: 220,
          },
        ]);
        setPhase('existing_validator_choice');
        return;
      }

      await queueJarvisMessages([
        {
          text: 'Hello, and welcome.',
          typingMs: 1000,
          pauseMs: 800,
        },
        {
          text: 'I am Jarvis, your setup assistant.',
          typingMs: 1200,
          pauseMs: 800,
        },
      ]);

      await queueJarvisMessages([
        { text: 'First, choose the type of Testnet node you want to set up.', typingMs: 900, pauseMs: 480 },
        { text: 'Validator onboarding is enabled here. The other node roles remain disabled until their setup contracts are production-ready.', typingMs: 1100, pauseMs: 520 },
      ]);

      setPhase('select_node_type');
    } catch (error) {
      addTerminalLine('error', `Failed to initialize Testnet setup: ${String(error)}`);
      await queueJarvisMessages([
        {
          text: 'Something interrupted setup on my end.',
          typingMs: 1000,
          pauseMs: 800,
        },
        {
          text: 'Please close and reopen the control panel to try again.',
          typingMs: 1100,
        },
      ]);
      setPhase('error');
    } finally {
      setWorkingStatus('');
      setRunning(false);
    }
  }, [addTerminalLine, messages.length, queueJarvisMessage, queueJarvisMessages, refreshState]);

  useEffect(() => {
    if (initializedRef.current) return;
    initializedRef.current = true;
    bootstrap();
  }, [bootstrap]);

  const runProvision = useCallback(async () => {
    if (!selectedRole) {
      await queueJarvisMessage('Select a node role before provisioning.');
      return;
    }

    setRunning(true);
    setWorkingStatus('Provisioning the validator appliance and writing runtime files...');
    addTerminalLine('info', `Provisioning ${selectedRole.display_name} in a Testnet appliance root...`);
    addTerminalLine('info', 'Provisioning started with role-validated runtime and bootstrap configuration.');

    try {
      if (selectedRole.id === 'validator') {
        const stateBeforeProvision = await refreshState(false);
        const existingValidators = validatorNodesFromState(stateBeforeProvision);
        if (existingValidators.length > 0) {
          const existingWorkspace = existingValidators[0]?.workspace_directory
            || existingValidators[0]?.workspaceDirectory
            || 'the existing local validator workspace';
          addTerminalLine('warning', `Existing local validator workspace detected: ${existingWorkspace}`);
          await queueJarvisMessage('I found an existing local validator setup on this machine. Do you want me to continue setup with that validator, or erase the local validator files and start over?');
          setPhase('existing_validator_choice');
          return;
        }
      }

      const setupInput = {
        input: {
          roleId: selectedRole.id,
          displayLabel: validatorNickname.trim() || selectedRole.display_name,
          intendedDirectory: normalizeWorkspaceChoice(
            directoryChoice || defaultDirectoryChoice,
            selectedRole.id,
            deviceProfile?.home_directory || '~',
            deviceProfile?.operating_system || '',
          ),
          publicHost: publicHost || null,
          publicP2pPort: normalizePublicP2pPort(publicP2pPort),
          natMode,
          identityPassphrase: selectedRole.id === 'validator' ? identityPassphrase || null : null,
        },
      };

      let result = null;
      for (let attempt = 0; attempt < 2; attempt += 1) {
        try {
          result = await invoke('testnet_setup_node', setupInput);
          break;
        } catch (setupError) {
          const setupErrorText = extractErrorText(setupError);
          if (selectedRole.id === 'validator' && attempt === 0 && existingWorkspaceErrorText(setupErrorText)) {
            addTerminalLine('warning', `Backend reported existing local validator setup: ${compactErrorText(setupError, 260)}`);
            await queueJarvisMessage('The local setup registry still has a previous validator workspace recorded. Do you want me to continue setup with that validator, or erase the local validator files and start over?');
            setPhase('existing_validator_choice');
            return;
          }
          throw setupError;
        }
      }

      if (!result?.node?.id) {
        throw new Error('Provisioning did not return a local node record.');
      }

      setProvisionResult(result);
      setTerminalCwd(result?.node?.workspace_directory || terminalCwd);
      addTerminalLine('success', `Appliance root created: ${result?.node?.workspace_directory || 'unknown path'}`);
      (result?.node?.config_paths || []).forEach((path) => addTerminalLine('output', `Generated: ${path}`));
      addTerminalLine('output', `Reward wallet: ${result?.node?.node_address || 'unknown address'}`);
      addTerminalLine('info', `Funding manifest: ${result?.node?.funding_manifest_id || 'pending'}`);
      try {
        const portConfig = await applyStoredTestnetPortSettings(result?.node, {
          publicHost,
          publicP2pPort,
        });
        addTerminalLine(
          'info',
          `Electron confirmed node.toml port profile (${portConfig.source}): ${formatPortSettingsSummary(portConfig.portSettings)}.`,
        );
      } catch (portError) {
        addTerminalLine('info', `Electron port profile update skipped: ${String(portError)}`);
      }
      try {
        const bootstrapConfig = await refreshTestnetBootstrapConfig(
          result?.node,
          result?.network_profile,
        );
      addTerminalLine(
        'info',
        `Electron refreshed peers.toml with ${bootstrapConfig.additionalDialTargets.length} seed-discovered dial target(s).`,
      );
        if (bootstrapConfig.failures.length > 0) {
          addTerminalLine(
            'info',
            `Seed preload warnings: ${bootstrapConfig.failures.join(' | ')}`,
          );
        }
      } catch (bootstrapError) {
        addTerminalLine(
          'info',
          `Electron bootstrap refresh skipped: ${String(bootstrapError)}`,
        );
      }
      addTerminalLine('info', 'Provisioning finished. The appliance root is configured for validator-pruned snapshot restore.');

      if (selectedRole.id === 'validator' && result?.node?.id) {
        setWorkingStatus('Verifying validator workspace layout and canonical files...');
        const preflight = await verifyProvisionedValidator(result);
        await refreshState(false);
        await queueJarvisMessages([
          {
            text: `Validator identity generated. The node address is ${validatorAddressForNode(result.node)}.`,
            typingMs: 920,
            pauseMs: 260,
          },
          {
            text: 'Review the validator details, connect a Synergy Wallet for stake eligibility, then continue onboarding when you are ready.',
            typingMs: 980,
            pauseMs: 260,
          },
        ]);
        setPhase('validator_identity_review');
        setValidatorEligibility((current) => ({
          ...current,
          requiredStake: Number(preflight?.requiredStakeSnrg || preflight?.required_stake_snrg || current.requiredStake || REQUIRED_VALIDATOR_STAKE_SNRG),
        }));
        return;
      } else {
        await queueJarvisMessages([
          { text: 'Alright I have everything set up, so I will get you on over to your new dashboard.', typingMs: 620, pauseMs: 220 },
        ]);
      }

      await refreshState(false);
      if (typeof onComplete === 'function') {
        onComplete({ nodeId: result?.node?.id || '', snapshotRestored: selectedRole.id === 'validator' });
      }
      clearTestnetDashboardCache();
      navigate('/');
    } catch (error) {
      setSnapshotProgress(null);
      snapshotProgressNodeRef.current = '';
      const errorText = compactErrorText(error, 460);
      addTerminalLine('error', `Validator setup failed: ${errorText}`);
      if (isActivationPendingErrorText(errorText)) {
        await queueJarvisMessage(`${errorText} I am keeping this setup session open and will keep verifying activation before moving you to the dashboard.`);
        setPhase('await_activation');
      } else if (existingWorkspaceErrorText(errorText)) {
        await queueJarvisMessages([
          {
            text: 'I found an existing local validator setup on this machine.',
            typingMs: 620,
            pauseMs: 220,
          },
          {
            text: 'I tried to erase it automatically, but the local setup registry still blocked provisioning. Use Restart Setup and I will clear it before trying again.',
            typingMs: 820,
          },
        ]);
        setPhase('error');
      } else {
        await queueJarvisMessages([
          {
            text: `I hit a problem before setup could finish: ${errorText}`,
            typingMs: 620,
            pauseMs: 220,
          },
          {
            text: 'You can restart setup once the issue is cleared.',
            typingMs: 820,
          },
        ]);
        setPhase('error');
      }
    } finally {
      setWorkingStatus('');
      setRunning(false);
    }
  }, [
    addTerminalLine,
    completeActivatedValidatorSetup,
    defaultDirectoryChoice,
    deviceProfile?.home_directory,
    deviceProfile?.operating_system,
    directoryChoice,
    identityPassphrase,
    navigate,
    onComplete,
    publicHost,
    publicP2pPort,
    natMode,
    eraseLocalValidatorSetupState,
    queueJarvisMessage,
    queueJarvisMessages,
    refreshState,
    selectedRole,
    terminalCwd,
    verifyProvisionedValidator,
    validatorNickname,
  ]);

  const refreshValidatorEligibility = useCallback(async (wallet = connectedWallet) => {
    const walletAddress = String(wallet?.address || '').trim();
    const node = provisionResult?.node || await getActiveValidatorNode();
    if (!walletAddress) {
      setValidatorEligibility(emptyEligibility());
      setEligibilityError('');
      return emptyEligibility();
    }

    setEligibilityBusy(true);
    setEligibilityError('');
    try {
      const eligibility = await validatorEligibilityService.verifyValidatorEligibility(walletAddress, {
        nodeId: node?.id,
        validatorAddress: validatorAddressForNode(node),
      });
      setValidatorEligibility(eligibility);
      if (eligibility.errorMessage) {
        setEligibilityError(eligibility.errorMessage);
      }
      return eligibility;
    } catch (error) {
      const message = compactErrorText(error, 360);
      const fallback = {
        ...emptyEligibility(walletAddress),
        eligibilityStatus: ELIGIBILITY_STATUSES.error,
        errorMessage: message,
      };
      setValidatorEligibility(fallback);
      setEligibilityError(message);
      return fallback;
    } finally {
      setEligibilityBusy(false);
    }
  }, [connectedWallet, getActiveValidatorNode, provisionResult?.node]);

  const handleWalletChange = useCallback((wallet) => {
    setConnectedWallet(wallet || null);
    if (!wallet?.address) {
      setValidatorEligibility(emptyEligibility());
      setEligibilityError('');
      return;
    }
    void refreshValidatorEligibility(wallet);
  }, [refreshValidatorEligibility]);

  const continueValidatorOnboarding = useCallback(async () => {
    const node = provisionResult?.node || await getActiveValidatorNode();
    if (!node?.id) {
      await queueJarvisMessage('I do not see the generated validator identity anymore. Restart setup so I can recover the workspace context.');
      setPhase('error');
      return;
    }

    const walletAddress = String(connectedWallet?.address || '').trim();
    if (!walletAddress) {
      setPhase('validator_wallet_eligibility');
      await queueJarvisMessage('Connect the operator Synergy Wallet before onboarding. The connected wallet must bond the 50,000 SNRG stake assigned to this validator.');
      return;
    }

    const eligibility = await refreshValidatorEligibility(connectedWallet);
    const requiredStake = Number(eligibility?.requiredStake || REQUIRED_VALIDATOR_STAKE_SNRG);
    const activeStake = Number(eligibility?.activeStakeAmount || 0);
    const bondedEligibility = eligibility?.eligible === true && activeStake >= requiredStake;
    const fundingReadyToBond = eligibility?.fundingReadyToBond === true
      && eligibility?.eligibilityStatus === ELIGIBILITY_STATUSES.stakeReadyToBond;
    if (!bondedEligibility && !fundingReadyToBond) {
      setPhase('validator_wallet_eligibility');
      await queueJarvisMessage('I cannot continue provisioning yet because validator funding or the self-bond is not confirmed on-chain. Approve the 50,001 SNRG funding transfer in the mobile wallet, then refresh eligibility; the validator will bond exactly 50,000 SNRG locally.');
      return;
    }

    setRunning(true);
    setWorkingStatus(snapshotSyncEnabled
      ? 'Preparing verified snapshot sync and validator onboarding...'
      : 'Preparing validator onboarding without snapshot restore...');
    addTerminalLine('info', snapshotSyncEnabled
      ? 'Continuing validator onboarding with verified archive snapshot sync enabled.'
      : 'Continuing validator onboarding with snapshot sync disabled by operator choice.');

    try {
      await verifyProvisionedValidator({ node });
      const snapshotRestore = snapshotSyncEnabled
        ? await restoreSnapshotForValidator(node)
        : null;
      if (!snapshotSyncEnabled) {
        await queueJarvisMessage('Snapshot sync is disabled. I will start from the current local chain state and wait for chain-head sync before staking checks.');
      }
      const onboardingState = await runProvisionedValidatorOnboarding(node, snapshotRestore);
      if (onboardingState === 'await-funding') {
        await refreshState(false);
        return;
      }

      const activationResult = await runActivationAfterStake(node, snapshotSyncEnabled ? 'snapshot' : 'normal');
      await queueJarvisMessages([
        {
          text: activationResult?.message || 'The validator onboarding flow has reached activation handoff.',
          typingMs: 820,
          pauseMs: 220,
        },
        {
          text: 'Thank you for your patience. I am going to get you on over to your new dashboard now.',
          typingMs: 920,
          pauseMs: 220,
        },
      ]);
      clearStoredSetupProgress();
      await completeActivatedValidatorSetup(node, activationResult);
    } catch (error) {
      setSnapshotProgress(null);
      snapshotProgressNodeRef.current = '';
      const errorText = compactErrorText(error, 520);
      addTerminalLine('error', `Validator onboarding failed: ${errorText}`);
      if (isActivationPendingErrorText(errorText)) {
        await queueJarvisMessage(`${errorText} I am keeping this setup session open and will keep verifying activation before moving you to the dashboard.`);
        setPhase('await_activation');
      } else {
        await queueJarvisMessage(`I hit a blocker while continuing onboarding: ${errorText}`);
        setPhase('validator_identity_review');
      }
    } finally {
      setWorkingStatus('');
      setRunning(false);
    }
  }, [
    addTerminalLine,
    completeActivatedValidatorSetup,
    connectedWallet,
    getActiveValidatorNode,
    provisionResult?.node,
    queueJarvisMessage,
    queueJarvisMessages,
    refreshValidatorEligibility,
    refreshState,
    restoreSnapshotForValidator,
    runActivationAfterStake,
    runProvisionedValidatorOnboarding,
    snapshotSyncEnabled,
    verifyProvisionedValidator,
  ]);

  const handleResponseValue = useCallback(async (value) => {
    if (!value || running) return;

    const trimmedValue = String(value).trim();

    if (/^developer data please$/i.test(trimmedValue)) {
      setShowDeveloperPanel((prev) => !prev);
      await queueJarvisMessage(
        showDeveloperPanel
          ? 'Developer panel hidden.'
          : 'Developer panel unlocked. Setup diagnostics are now visible on the right.',
      );
      return;
    }

    if (/^(i need a terminal|open terminal|show terminal)$/i.test(trimmedValue)) {
      setTerminalVisible(true);
      await queueJarvisMessage('Opening the local setup terminal at the bottom of the screen. You can inspect the appliance root or run commands there any time.');
      return;
    }

    if (/^(hide terminal|close terminal)$/i.test(trimmedValue)) {
      setTerminalVisible(false);
      await queueJarvisMessage('Terminal hidden.');
      return;
    }

    if (/^(dashboard|not now jarvis|not now|later)$/i.test(trimmedValue)) {
      await handoffToDashboard();
      return;
    }

    if (phase === 'existing_validator_choice') {
      if (/^(continue|continue setup|continue existing|continue existing setup|use existing|resume|resume setup)$/i.test(trimmedValue)) {
        await continueExistingValidatorSetup();
        return;
      }

      if (/^(start over|erase and start over|erase|new validator|fresh start|reset)$/i.test(trimmedValue)) {
        setRunning(true);
        setWorkingStatus('Erasing existing local validator setup state...');
        try {
          const eraseResult = await eraseLocalValidatorSetupState({
            resetSetupInputs: true,
            resetConversation: false,
          });
          addTerminalLine('info', eraseResult?.message || 'Local validator setup state erased.');
          await queueJarvisMessage('I erased the existing local validator files. I will continue with a fresh validator onboarding flow.');
          setPhase('select_node_type');
        } catch (error) {
          await queueJarvisMessage(`I could not erase the existing validator setup: ${extractErrorText(error)}`);
          setPhase('existing_validator_choice');
        } finally {
          setWorkingStatus('');
          setRunning(false);
        }
        return;
      }

      await queueJarvisMessage('Choose Continue Existing Setup or Start Over.');
      return;
    }

    if (phase === 'existing_validator_recovery') {
      if (/^(retry|retry registry recovery|continue|continue setup|continue existing|continue existing setup|resume|resume setup)$/i.test(trimmedValue)) {
        await continueExistingValidatorSetup();
        return;
      }

      await queueJarvisMessage('Choose Retry Registry Recovery. The preserved validator workspace will remain untouched.');
      return;
    }

    if (/^(restart|start over|reset)$/i.test(trimmedValue)) {
      setRunning(true);
      setWorkingStatus('Clearing failed local validator setup state...');
      try {
        const eraseResult = await eraseLocalValidatorSetupState({
          resetSetupInputs: true,
          resetConversation: true,
        });
        addTerminalLine('info', eraseResult?.message || 'Local validator setup state erased.');
        await queueJarvisMessage('I cleared the failed local validator setup state. I will continue with a fresh validator onboarding flow.');
      } catch (error) {
        await queueJarvisMessage(`I could not clear the failed setup state: ${extractErrorText(error)}`);
      } finally {
        setWorkingStatus('');
        setRunning(false);
      }
      return;
    }

    if (phase === 'select_node_type') {
      if (/validator/i.test(trimmedValue) || trimmedValue === 'validator') {
        setSelectedRoleId('validator');
        setRunning(true);
        try {
          await refreshPublicHost({ announce: true });
        } finally {
          setRunning(false);
        }
        await queueJarvisMessages([
          {
            text: 'Validator selected. I will generate a real validator identity through the local control service after the basic operator config is confirmed.',
            typingMs: 880,
            pauseMs: 220,
          },
          {
            text: 'Enter a short nickname for this validator. This is the display label in the control panel and setup manifests.',
            typingMs: 820,
          },
        ]);
        setPhase('validator_basic_config');
        return;
      }

      await queueJarvisMessage('Validator is the only enabled setup type right now.');
      return;
    }

    if (phase === 'validator_basic_config') {
      const nickname = trimmedValue || 'Validator Node';
      setValidatorNickname(nickname);
      await queueJarvisMessage(`I will label this validator "${nickname}". Next I will confirm the public P2P address for seed registration.`);
      setPhase('review_device');
      return;
    }

    if (phase === 'review_device') {
      if (/^refresh/i.test(trimmedValue)) {
        setRunning(true);
        try {
          await refreshState(true);
        } finally {
          setRunning(false);
        }
        return;
      }

      if (isContinueValue(trimmedValue)) {
        setRunning(true);
        let resolvedHost = publicHost;
        try {
          resolvedHost = await refreshPublicHost({ announce: false }) || publicHost;
        } finally {
          setRunning(false);
        }
        await queueJarvisMessage(`It looks like your current IPv4 address is ${resolvedHost || 'unknown'}. If this correct?`);
        setPhase('confirm_public_host');
        return;
      }

      await queueJarvisMessage('Choose Continue or Refresh Detection.');
      return;
    }

    if (phase === 'confirm_public_host') {
      if (/^yes|that is correct/i.test(trimmedValue)) {
        await queueJarvisMessage(`This validator will advertise ${formatPublicEndpoint(publicHost, publicP2pPort)} for public P2P. Which NAT mode matches this machine?`);
        setPhase('choose_nat_mode');
        return;
      }

      if (/^not quite/i.test(trimmedValue)) {
        await queueJarvisMessage('Enter the IPv4 address you want this node to advertise.');
        setPhase('enter_public_host');
        return;
      }

      if (trimmedValue) {
        const normalized = normalizePublicHostInput(trimmedValue);
        if (!normalized) {
          await queueJarvisMessage('Enter a valid public IPv4 address or DNS name.');
          return;
        }
        setPublicHost(normalized);
        await queueJarvisMessage(`It looks like your current IPv4 address is ${normalized}. If this correct?`);
        setPhase('confirm_public_host');
      }
      return;
    }

    if (phase === 'enter_public_host') {
      if (trimmedValue) {
        const normalized = normalizePublicHostInput(trimmedValue);
        if (!normalized) {
          await queueJarvisMessage('Enter a valid public IPv4 address or DNS name.');
          return;
        }
        setPublicHost(normalized);
        await queueJarvisMessage(`It looks like your current IPv4 address is ${normalized}. If this correct?`);
        setPhase('confirm_public_host');
      }
      return;
    }

    if (phase === 'choose_nat_mode') {
      const lowered = trimmedValue.toLowerCase();
      if (/custom/.test(lowered)) {
        setNatMode('custom_public_port');
        await queueJarvisMessage('Enter the public TCP port that your router forwards to this validator. The local validator listener will still default to 5622.');
        setPhase('enter_public_p2p_port');
        return;
      }
      if (/direct/.test(lowered)) {
        setNatMode('direct_public_ip');
      } else {
        setNatMode('router_port_forward');
      }
      setPublicP2pPort(String(DEFAULT_PUBLIC_P2P_PORT));
      const resolvedDirectory = normalizeWorkspaceChoice(
        directoryChoice || defaultDirectoryChoice,
        selectedRoleId || 'validator',
        deviceProfile?.home_directory || '~',
        deviceProfile?.operating_system || '',
      );
      await queueJarvisMessage(`I am going to create the validator appliance root at ${resolvedDirectory}. It will advertise ${formatPublicEndpoint(publicHost, DEFAULT_PUBLIC_P2P_PORT)} and use bootnodes plus seed discovery, while consensus activation stays separate. Is this alright or should it be created in a different location on your machine?`);
      setPhase('review_directory');
      return;
    }

    if (phase === 'enter_public_p2p_port') {
      const parsedPort = Number.parseInt(trimmedValue, 10);
      if (!/^\d+$/.test(trimmedValue) || !Number.isInteger(parsedPort) || parsedPort <= 0 || parsedPort > 65535) {
        await queueJarvisMessage('Enter a valid public TCP port between 1 and 65535.');
        return;
      }
      setPublicP2pPort(String(parsedPort));
      const resolvedDirectory = normalizeWorkspaceChoice(
        directoryChoice || defaultDirectoryChoice,
        selectedRoleId || 'validator',
        deviceProfile?.home_directory || '~',
        deviceProfile?.operating_system || '',
      );
      await queueJarvisMessage(`I am going to create the validator appliance root at ${resolvedDirectory}. It will advertise ${formatPublicEndpoint(publicHost, parsedPort)} and use bootnodes plus seed discovery, while consensus activation stays separate. Is this alright or should it be created in a different location on your machine?`);
      setPhase('review_directory');
      return;
    }

    if (phase === 'review_directory') {
      if (/^no/i.test(trimmedValue)) {
        await queueJarvisMessage('Enter the exact path where you want the validator appliance root created.');
        setPhase('enter_directory_choice');
        return;
      }

      const chosenDirectory = trimmedValue && !isContinueValue(trimmedValue)
        ? normalizeWorkspaceChoice(trimmedValue, selectedRoleId || 'validator', deviceProfile?.home_directory || '~', deviceProfile?.operating_system || '')
        : normalizeWorkspaceChoice(directoryChoice || defaultDirectoryChoice, selectedRoleId || 'validator', deviceProfile?.home_directory || '~', deviceProfile?.operating_system || '');
      setDirectoryChoice(chosenDirectory);
      await queueJarvisMessage(`Perfect. I am creating the validator appliance root at ${chosenDirectory}.`);
      await queueJarvisMessage("And now I need to generate your node's address and keys. This information is protected with quantum-safe encryption. Please create an encryption passphrase in case you need to decrypt this data for any reason.");
      setPhase('enter_passphrase');
      return;
    }

    if (phase === 'enter_directory_choice') {
      if (trimmedValue) {
        const chosenDirectory = normalizeWorkspaceChoice(trimmedValue, selectedRoleId || 'validator', deviceProfile?.home_directory || '~', deviceProfile?.operating_system || '');
        setDirectoryChoice(chosenDirectory);
        await queueJarvisMessage(`Perfect. I am creating the validator appliance root at ${chosenDirectory}.`);
        await queueJarvisMessage("And now I need to generate your node's address and keys. This information is protected with quantum-safe encryption. Please create an encryption passphrase in case you need to decrypt this data for any reason.");
        setPhase('enter_passphrase');
        return;
      }
    }

    if (phase === 'enter_passphrase') {
      if (trimmedValue) {
        setIdentityPassphrase(trimmedValue);
        await queueJarvisMessage('Enter the encryption passphrase again to confirm it.');
        setPhase('confirm_passphrase');
      }
      return;
    }

    if (phase === 'confirm_passphrase') {
      if (!trimmedValue) return;
      if (trimmedValue !== identityPassphrase) {
        await queueJarvisMessage('Those passphrases do not match. Please enter the encryption passphrase again.');
        return;
      }
      await queueJarvisMessage('Alright, I have everything that I need. I will now get your new node all set up and ready to begin the onboarding process. One moment, please.');
      setPhase('ready_provision');
      return;
    }

    if (phase === 'ready_provision') {
      if (isContinueValue(trimmedValue)) {
        await runProvision();
        return;
      }
      await queueJarvisMessage('Choose Provision Node when you are ready.');
      return;
    }

    if (phase === 'validator_identity_review') {
      if (/^refresh/i.test(trimmedValue)) {
        await refreshValidatorEligibility();
        await queueJarvisMessage('Wallet and stake eligibility refreshed.');
        return;
      }

      if (/^(continue|continue onboarding|wallet|stake|eligibility|check eligibility)$/i.test(trimmedValue)) {
        setPhase('validator_wallet_eligibility');
        if (connectedWallet?.address) {
          await refreshValidatorEligibility(connectedWallet);
        }
        await queueJarvisMessage('This is the wallet and stake eligibility checkpoint. Connect a Synergy Wallet or refresh eligibility, then continue onboarding.');
        return;
      }

      await queueJarvisMessage('Choose Continue to Wallet Eligibility when you are ready.');
      return;
    }

    if (phase === 'validator_wallet_eligibility') {
      if (/^refresh/i.test(trimmedValue) || /eligibility/i.test(trimmedValue)) {
        await refreshValidatorEligibility();
        await queueJarvisMessage('Wallet and stake eligibility refreshed.');
        return;
      }

      if (/^(continue|continue onboarding|proceed|start onboarding)$/i.test(trimmedValue)) {
        await continueValidatorOnboarding();
        return;
      }

      await queueJarvisMessage('Choose Continue Onboarding when you are ready.');
      return;
    }

    if (phase === 'await_funding') {
      if (/^(the team sent the snrg|team sent the snrg|funding sent|snrg sent|check funding status)$/i.test(trimmedValue)) {
        const node = await getActiveValidatorNode();
        if (node?.id) {
          const preflight = await getValidatorPreflight(node).catch(() => null);
          if (preflightHasBondedStake(preflight)) {
            await queueJarvisMessage('The required stake is already bonded. I am continuing activation checks now.');
            setRunning(true);
            setWorkingStatus('Running activation checks for the bonded validator stake...');
            try {
              const activationResult = await runActivationAfterStake(node, snapshotSyncEnabled ? 'snapshot' : 'normal');
              await queueJarvisMessages([
                { text: activationResult?.message || 'The validator activation workflow has been submitted.', typingMs: 820, pauseMs: 220 },
                { text: "That's it. I am sending you to the control panel dashboard now.", typingMs: 820 },
              ]);
              await completeActivatedValidatorSetup(node, activationResult);
            } finally {
              setWorkingStatus('');
              setRunning(false);
            }
            return;
          }
        }
        await queueJarvisMessage('Great. Please paste the transaction hash for the 50,001 SNRG validator funding transfer.');
        setPhase('enter_funding_tx_hash');
        return;
      }
      await queueJarvisMessage('I am waiting here. Click The team sent the SNRG once the project team has sent the validator funding.');
      return;
    }

    if (phase === 'enter_funding_tx_hash') {
      await continueAfterFundingHash(trimmedValue);
      return;
    }

    if (phase === 'await_activation') {
      await queueJarvisMessage('I am already watching activation propagation and canonical registry confirmation. I will open the dashboard only after activation is confirmed.');
      return;
    }

    if (phase === 'error') {
      await queueJarvisMessage('Something interrupted setup. Please close and reopen the control panel to try again.');
    }
  }, [
    addTerminalLine,
    completeActivatedValidatorSetup,
    continueExistingValidatorSetup,
    continueAfterFundingHash,
    continueValidatorOnboarding,
    connectedWallet,
    deviceProfile?.home_directory,
    deviceProfile?.operating_system,
    defaultDirectoryChoice,
    directoryChoice,
    deviceProfile?.operatingSystem,
    deviceProfile?.operating_system,
    eraseLocalValidatorSetupState,
    getActiveValidatorNode,
    getValidatorPreflight,
    handoffToDashboard,
    nodeCatalog,
    phase,
    provisionResult?.node?.id,
    publicHost,
    publicP2pPort,
    queueJarvisMessage,
    queueJarvisMessages,
    refreshPublicHost,
    refreshValidatorEligibility,
    refreshState,
    resetMessageQueue,
    runActivationAfterStake,
    runProvision,
    running,
    selectedRoleId,
    showDeveloperPanel,
  ]);

  const submitChat = useCallback(async (event) => {
    event.preventDefault();
    const value = input.trim();
    if (!value || running || phase === 'booting') return;

    addMessage('user', phase === 'enter_passphrase' || phase === 'confirm_passphrase' ? '********' : value);
    setInput('');
    await handleResponseValue(value);
  }, [addMessage, handleResponseValue, input, phase, running]);

  const submitChoice = useCallback(async (value, displayLabel = value) => {
    if (!value || running) return;
    addMessage('user', displayLabel);
    await handleResponseValue(value);
  }, [addMessage, handleResponseValue, running]);

  const submitSelect = useCallback(async (event) => {
    event.preventDefault();
    if (!selectValue || running) return;

    const label = nodeCatalog.find((entry) => entry.id === selectValue)?.display_name || selectValue;
    addMessage('user', label);
    await handleResponseValue(selectValue);
  }, [addMessage, handleResponseValue, nodeCatalog, running, selectValue]);

  const promptConfig = useMemo(() => {
    if (phase === 'existing_validator_choice') {
      return {
        kind: 'choices',
        hint: null,
        options: [
          { value: 'continue existing setup', label: 'Continue Existing Setup' },
          { value: 'start over', label: 'Start Over' },
        ],
        placeholder: 'Type your reply here',
      };
    }

    if (phase === 'existing_validator_recovery') {
      return {
        kind: 'choices',
        hint: 'The preserved validator workspace is waiting for backend registry recovery.',
        options: [
          { value: 'retry registry recovery', label: 'Retry Registry Recovery' },
        ],
        placeholder: 'Type your reply here',
      };
    }

    if (phase === 'review_device') {
      return {
        kind: 'choices',
        hint: null,
        options: [
          { value: 'continue', label: 'Continue' },
          { value: 'refresh detection', label: 'Refresh Detection' },
        ],
        placeholder: 'Type your reply here',
      };
    }

    if (phase === 'select_node_type') {
      return {
        kind: 'choices',
        hint: null,
        options: [
          { value: 'validator', label: 'Validator' },
        ],
        placeholder: 'Choose Validator to continue',
      };
    }

    if (phase === 'validator_basic_config') {
      return {
        kind: 'text',
        hint: null,
        placeholder: 'Validator nickname',
      };
    }

    if (phase === 'enter_public_host') {
      return { kind: 'text', hint: null, placeholder: 'Enter your IPv4 address' };
    }

    if (phase === 'confirm_public_host') {
      return {
        kind: 'choices',
        hint: null,
        options: [
          { value: 'yes, that is correct', label: 'Yes, that is correct.' },
          { value: 'not quite', label: 'Not quite.' },
        ],
        placeholder: 'Type your reply here',
      };
    }

    if (phase === 'choose_nat_mode') {
      return {
        kind: 'choices',
        hint: null,
        options: getValidatorNatModeOptions().map((option) => ({
          value: option.value,
          label: option.label,
        })),
        placeholder: 'Choose the NAT mode',
      };
    }

    if (phase === 'enter_public_p2p_port') {
      return { kind: 'text', hint: null, placeholder: 'Enter public P2P port, default 5622' };
    }

    if (phase === 'review_directory') {
      return {
        kind: 'choices',
        hint: null,
        options: [
          { value: 'that works', label: 'That works.' },
          { value: 'no, i want it somewhere else', label: 'No, I want it somewhere else.' },
        ],
        placeholder: 'Type your reply here',
      };
    }

    if (phase === 'enter_directory_choice') {
      return { kind: 'text', hint: null, placeholder: 'Enter the appliance root path' };
    }

    if (phase === 'enter_passphrase') {
      return { kind: 'text', inputType: 'password', hint: null, placeholder: 'Create an encryption passphrase' };
    }

    if (phase === 'confirm_passphrase') {
      return { kind: 'text', inputType: 'password', hint: null, placeholder: 'Re-enter the encryption passphrase' };
    }

    if (phase === 'ready_provision') {
      return {
        kind: 'choices',
        hint: null,
        options: [
          { value: 'provision node', label: 'Generate Validator Identity' },
        ],
        placeholder: 'Type your reply here',
      };
    }

    if (phase === 'validator_identity_review') {
      return {
        kind: 'choices',
        hint: null,
        options: [
          { value: 'continue onboarding', label: 'Continue to Wallet Eligibility' },
          { value: 'refresh eligibility', label: 'Refresh Eligibility' },
        ],
        placeholder: 'Type your reply here',
      };
    }

    if (phase === 'validator_wallet_eligibility') {
      return {
        kind: 'choices',
        hint: null,
        options: [
          { value: 'continue onboarding', label: 'Continue Onboarding' },
          { value: 'refresh eligibility', label: 'Refresh Eligibility' },
        ],
        placeholder: 'Type your reply here',
      };
    }

    if (phase === 'await_funding') {
      return {
        kind: 'choices',
        hint: null,
        options: [
          { value: 'the team sent the snrg', label: 'The team sent the SNRG' },
        ],
        placeholder: 'Type your reply here',
      };
    }

    if (phase === 'enter_funding_tx_hash') {
      return {
        kind: 'text',
        hint: null,
        placeholder: 'Paste the 50,001 SNRG transaction hash',
      };
    }

    if (phase === 'await_activation') {
      return {
        kind: 'none',
        hint: 'Jarvis is watching activation propagation and registry confirmation.',
        placeholder: 'Jarvis is watching activation...',
      };
    }

    if (phase === 'error') {
      return {
        kind: 'choices',
        hint: 'Setup needs attention. Restart the setup sequence to continue.',
        options: [
          { value: 'restart', label: 'Restart Setup' },
        ],
        placeholder: 'Type your reply here',
      };
    }

    return {
      kind: 'none',
      hint: 'Setup Assistant is getting things ready.',
      placeholder: 'Setup Assistant is warming up...',
    };
  }, [directoryChoice, nodeCatalog, phase, publicHost]);

  useEffect(() => {
    if (promptConfig.kind !== 'select') {
      setSelectValue('');
      return;
    }

    setSelectValue((current) => {
      if (promptConfig.options.some((option) => option.value === current)) {
        return current;
      }
      return promptConfig.options[0]?.value || '';
    });
  }, [promptConfig]);

  const selectedRoleHighlights = selectedRole ? (selectedRole.responsibilities || []).slice(0, 3) : [];
  const selectedRoleServices = selectedRole ? (selectedRole.service_surface || []) : [];
  const hidePromptHint = promptConfig.kind === 'select' || promptConfig.kind === 'choices';
  const setupNote = phase === 'error'
    ? 'Something interrupted setup. Resolve the issue and restart the setup flow.'
    : 'I will walk you through validator setup, generate identity through the control service, and keep stake activation separate from peer reachability.';
  const previewStatus = provisionResult?.node ? 'Created' : phase === 'ready_provision' ? 'Ready' : 'Pending';
  const previewNotes = [
    'Jarvis will append a unique suffix automatically if the requested appliance path is already in use.',
    snapshotSyncEnabled
      ? 'Snapshot sync is enabled and will use a verified archive-validator snapshot at any valid published height.'
      : 'Snapshot sync is disabled; onboarding will wait for normal chain catch-up from local state.',
  ];
  const snapshotProgressPercent = Math.round(Number(snapshotProgress?.percent || 0));
  const snapshotProgressBytes = snapshotProgress
    ? formatSnapshotProgressBytes(snapshotProgress.transferredBytes, snapshotProgress.totalBytes)
    : '';
  const activeWorkText = running
    ? (workingStatus || 'Jarvis is working in the background...')
    : '';
  const provisionedNode = provisionResult?.node || null;
  const provisionedAddress = validatorAddressForNode(provisionedNode);
  const eligibilityStatusLabel = eligibilityBusy
    ? 'Checking'
    : validatorEligibility?.eligible
      ? 'Eligible'
      : connectedWallet?.address
        ? validatorEligibility?.eligibilityStatus || 'Needs stake'
        : 'Wallet not connected';
  const missingStakeAmount = Number(validatorEligibility?.missingStakeAmount ?? REQUIRED_VALIDATOR_STAKE_SNRG);

  return (
    <section
      className={`jarvis-shell ${shellReady ? 'is-ready' : ''}`}
      data-developer={showDeveloperPanel ? 'true' : 'false'}
    >
      <div className="jarvis-layout">
        <article className="jarvis-chat-stage">
          <div className="jarvis-panel-header">
            <div>
              <h2 className="jarvis-panel-title">Welcome!</h2>
            </div>
          </div>

          <div className="jarvis-chat-window">
            <div className="jarvis-chat-log">
              {messages.map((message) => (
                <div key={message.id} className={`jarvis-chat-message jarvis-${message.sender}`}>
                  <span className="jarvis-chat-author">{message.sender === 'user' ? 'You' : 'Jarvis'}</span>
                  {message.type === 'code' ? <pre>{message.text}</pre> : <p>{message.text}</p>}
                </div>
              ))}

              {typing ? (
                <div className="jarvis-chat-message jarvis-jarvis jarvis-typing-message">
                  <div className="jarvis-typing-stack">
                    <span className="jarvis-chat-author">Jarvis</span>
                    <div className="jarvis-typing-indicator" aria-label="Jarvis is typing">
                      <span></span>
                      <span></span>
                      <span></span>
                    </div>
                  </div>
                </div>
              ) : null}

              {activeWorkText ? (
                <div className="jarvis-chat-message jarvis-jarvis jarvis-work-message" aria-live="polite">
                  <span className="jarvis-chat-author">Jarvis</span>
                  <div className="jarvis-work-card">
                    <div className="jarvis-work-orbit" aria-hidden="true">
                      <span></span>
                      <span></span>
                    </div>
                    <div className="jarvis-work-copy">
                      <strong>{activeWorkText}</strong>
                      <small>Setup is still running. Keep this window open.</small>
                    </div>
                  </div>
                </div>
              ) : null}

              <div ref={messagesEndRef} />
            </div>

            {phase === 'validator_basic_config' ? (
              <div className="jarvis-inline-panel">
                <div className="jarvis-inline-panel-header">
                  <span>Validator basic config</span>
                  <strong>Name this validator</strong>
                </div>
                <p>
                  The name is stored as the validator display label and is passed to the backend identity generation call.
                </p>
              </div>
            ) : null}

            {phase === 'validator_identity_review' || phase === 'validator_wallet_eligibility' ? (
              <div className="jarvis-validator-review">
                <section className="jarvis-inline-panel">
                  <div className="jarvis-inline-panel-header">
                    <span>Generated validator identity</span>
                    <strong>{provisionedAddress ? 'Ready' : 'Pending'}</strong>
                  </div>
                  <div className="jarvis-review-grid">
                    <div>
                      <span>Validator name</span>
                      <strong>{validatorNickname || provisionedNode?.display_label || provisionedNode?.displayLabel || 'Validator Node'}</strong>
                    </div>
                    <div>
                      <span>Node address</span>
                      <strong title={provisionedAddress}>{provisionedAddress || 'Pending backend identity generation'}</strong>
                    </div>
                    <div>
                      <span>Appliance root</span>
                      <strong>{provisionedNode?.workspace_directory || directoryChoice || defaultDirectoryChoice}</strong>
                    </div>
                    <div>
                      <span>Public P2P</span>
                      <strong>{formatPublicEndpoint(publicHost, publicP2pPort)}</strong>
                    </div>
                    <div>
                      <span>NAT mode</span>
                      <strong>{natModeLabel(natMode)}</strong>
                    </div>
                    <div>
                      <span>Required stake</span>
                      <strong>{formatStake(REQUIRED_VALIDATOR_STAKE_SNRG)}</strong>
                    </div>
                  </div>
                  <div className="jarvis-requirements-list">
                    <span>Minimum requirements</span>
                    <p>Stable public TCP reachability for P2P, enough disk for chain state, system clock sync, a generated synv1 validator identity, and 50,000 SNRG bonded stake before activation.</p>
                  </div>
                  <label className="jarvis-toggle-row">
                    <input
                      type="checkbox"
                      checked={snapshotSyncEnabled}
                      onChange={(event) => setSnapshotSyncEnabled(event.target.checked)}
                      disabled={running}
                    />
                    <span>
                      <strong>Use verified snapshot sync</strong>
                      <small>Start from the latest valid archive-validator snapshot, regardless of published snapshot height, then catch up to chain head.</small>
                    </span>
                  </label>
                </section>

                <section className="jarvis-inline-panel">
                  <div className="jarvis-inline-panel-header">
                    <span>Wallet and stake eligibility</span>
                    <strong>{eligibilityStatusLabel}</strong>
                  </div>
                  <SynergyWalletConnection onWalletChange={handleWalletChange} compact />
                  <div className="jarvis-review-grid is-compact">
                    <div>
                      <span>Connected wallet</span>
                      <strong title={connectedWallet?.address || ''}>{connectedWallet?.address ? truncateAddress(connectedWallet.address, 10) : 'Not connected'}</strong>
                    </div>
                    <div>
                      <span>Active stake</span>
                      <strong>{formatStake(validatorEligibility?.activeStakeAmount || 0)}</strong>
                    </div>
                    <div>
                      <span>Missing stake</span>
                      <strong>{formatStake(Number.isFinite(missingStakeAmount) ? missingStakeAmount : REQUIRED_VALIDATOR_STAKE_SNRG)}</strong>
                    </div>
                    <div>
                      <span>Last verified</span>
                      <strong>{validatorEligibility?.lastVerifiedAt ? new Date(validatorEligibility.lastVerifiedAt).toLocaleTimeString() : 'Not checked'}</strong>
                    </div>
                  </div>
                  {eligibilityError ? <p className="jarvis-inline-error">{eligibilityError}</p> : null}
                  <div className="jarvis-inline-actions">
                    <SNRGButton as="button" type="button" variant="purple" size="sm" disabled={eligibilityBusy || running} onClick={() => void refreshValidatorEligibility()}>
                      {eligibilityBusy ? 'Checking...' : 'Refresh Eligibility'}
                    </SNRGButton>
                  </div>
                </section>
              </div>
            ) : null}

            <div className="jarvis-chat-controls">
              {phase === 'select_node_type' ? (
                <div className="jarvis-node-type-grid" aria-label="Node type selection">
                  <button
                    type="button"
                    className="jarvis-node-type-card is-enabled"
                    disabled={running}
                    onClick={() => void submitChoice('validator', 'Validator')}
                  >
                    <span>Enabled</span>
                    <strong>Validator</strong>
                    <small>Generate a validator identity, configure public P2P, sync state, and proceed to stake eligibility.</small>
                  </button>
                  {[
                    ['RPC Gateway', 'Service-node setup is locked until the current validator onboarding contract is complete.'],
                    ['Relayer', 'Coming after validator onboarding.'],
                    ['Archive', 'Coming after validator onboarding.'],
                  ].map(([label, detail]) => (
                    <button key={label} type="button" className="jarvis-node-type-card is-disabled" disabled>
                      <span>Disabled</span>
                      <strong>{label}</strong>
                      <small>{detail}</small>
                    </button>
                  ))}
                </div>
              ) : null}

              {promptConfig.hint && !hidePromptHint ? (
                <div className="jarvis-choice-hint">
                  <p>{promptConfig.hint}</p>
                </div>
              ) : null}

              {promptConfig.kind === 'select' ? (
                <form className="jarvis-choice-select" onSubmit={submitSelect}>
                  <div className="jarvis-choice-header">
                    <strong>Choose an option</strong>
                    {promptConfig.hint ? <span>{promptConfig.hint}</span> : null}
                  </div>
                  <div className="jarvis-choice-select-row">
                    <select value={selectValue} onChange={(event) => setSelectValue(event.target.value)} disabled={running}>
                      {promptConfig.options.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                    <SNRGButton as="button" type="submit" variant="purple" size="sm" disabled={running || !selectValue}>
                      Choose
                    </SNRGButton>
                  </div>
                </form>
              ) : null}

              {promptConfig.kind === 'choices' ? (
                <div className="jarvis-choice-list jarvis-choice-list-utility">
                  {promptConfig.hint ? (
                    <div className="jarvis-choice-header">
                      <strong>Quick choices</strong>
                      <span>{promptConfig.hint}</span>
                    </div>
                  ) : null}
                  <div className="jarvis-choice-list-utility-row">
                    {promptConfig.options.map((option) => (
                      <button
                        key={option.value}
                        type="button"
                        className="jarvis-choice-pill"
                        disabled={running}
                        onClick={() => void submitChoice(option.value, option.label)}
                      >
                        {option.label}
                      </button>
                    ))}
                  </div>
                </div>
              ) : null}

              <form className="jarvis-chat-form" onSubmit={submitChat}>
                <input
                  type={promptConfig.inputType || 'text'}
                  value={input}
                  onChange={(event) => setInput(event.target.value)}
                  placeholder={promptConfig.placeholder || 'Type your reply here'}
                  disabled={chatInputLocked}
                />
                <SNRGButton as="button" type="submit" variant="blue" size="sm" disabled={chatInputLocked || !input.trim()}>
                  Send
                </SNRGButton>
              </form>
            </div>
          </div>
        </article>

        {showDeveloperPanel ? (
        <aside className="jarvis-side-stage">
          <section className="jarvis-detail-card">
            <div className="jarvis-detail-header">
              <h3>Setup status</h3>
              <span>{setupStatus.label}</span>
            </div>
            <p className="jarvis-detail-copy">{setupNote}</p>
            <div className="jarvis-status-list">
              {statusItems.map((item) => (
                <div key={item.label} className="jarvis-status-row">
                  <span>{item.label}</span>
                  <strong>{item.value}</strong>
                </div>
              ))}
            </div>
          </section>

          <section className="jarvis-detail-card">
            <div className="jarvis-detail-header">
              <h3>Selected node type</h3>
              <span>{selectedRole?.class_name || 'Choose a role'}</span>
            </div>
            <p className="jarvis-detail-copy">{selectedRole?.summary || 'Choose a validator role and its job details will appear here.'}</p>
            <div className="jarvis-plan-list">
              {selectedRoleHighlights.length ? selectedRoleHighlights.map((line) => <p key={line}>{line}</p>) : <p>Role responsibilities will appear here.</p>}
            </div>
            {selectedRoleServices.length ? (
              <div className="jarvis-choice-list jarvis-choice-list-static">
                {selectedRoleServices.slice(0, 6).map((entry) => (
                  <span key={entry} className="jarvis-choice-pill jarvis-choice-pill-static">{entry}</span>
                ))}
              </div>
            ) : null}
          </section>

          <section className="jarvis-detail-card">
            <div className="jarvis-detail-header">
              <h3>Network resources</h3>
              <span>Safe to continue</span>
            </div>
            <div className="jarvis-status-list">
              <div className="jarvis-status-row">
                <span>Treasury wallet</span>
                <strong>{truncateAddress(networkProfile?.treasury_wallet?.address)}</strong>
              </div>
              <div className="jarvis-status-row">
                <span>Faucet wallet</span>
                <strong>{truncateAddress(networkProfile?.faucet_wallet?.address)}</strong>
              </div>
              <div className="jarvis-status-row">
                <span>Stake vault</span>
                <strong>{truncateAddress(networkProfile?.stake_vault_wallet?.address)}</strong>
              </div>
              <div className="jarvis-status-row">
                <span>Minimum stake</span>
                <strong>{formatStake(networkProfile?.funding_manifests?.[0]?.amount_snrg || String(VALIDATOR_FUNDING_TARGET_SNRG))}</strong>
              </div>
            </div>
            <div className="jarvis-plan-list">
              <p>Network entry points: {networkBootnodes.map((entry) => entry.host).join(', ') || 'Pending'}</p>
              <p>Support servers: {networkSeeds.map((entry) => entry.host).join(', ') || 'Pending'}</p>
            </div>
          </section>

          <section className="jarvis-detail-card">
            <div className="jarvis-detail-header">
              <h3>Provision preview</h3>
              <span>{previewStatus}</span>
            </div>
            <div className="jarvis-status-list">
              <div className="jarvis-status-row">
                <span>Appliance root</span>
                <strong>{directoryChoice || defaultDirectoryChoice || 'Will be generated after role selection'}</strong>
              </div>
              {provisionResult?.node?.workspace_directory ? (
                <div className="jarvis-status-row">
                  <span>Created appliance</span>
                  <strong>{provisionResult.node.workspace_directory}</strong>
                </div>
              ) : null}
            </div>
            <div className="jarvis-plan-list">
              {previewNotes.map((line) => <p key={line}>{line}</p>)}
            </div>
          </section>
        </aside>
        ) : null}
      </div>

      {snapshotProgress?.visible ? (
        <div className="jarvis-snapshot-modal-backdrop">
          <div
            className="jarvis-snapshot-modal"
            role="dialog"
            aria-modal="true"
            aria-label={snapshotProgress.title}
          >
            <div className="jarvis-snapshot-modal-header">
              <span>Archive validator</span>
              <strong>{snapshotProgress.title}</strong>
            </div>
            <div className="jarvis-snapshot-progress-summary">
              <span>{snapshotProgressPercent}%</span>
              {snapshotProgressBytes ? <code>{snapshotProgressBytes}</code> : null}
            </div>
            <div className="jarvis-snapshot-progress-track" aria-hidden="true">
              <div
                className="jarvis-snapshot-progress-fill"
                style={{ width: `${Math.max(0, Math.min(100, snapshotProgressPercent))}%` }}
              />
            </div>
            <p aria-live="polite">{snapshotProgress.detail || 'Working on the validator snapshot.'}</p>
            {snapshotProgress.snapshotId ? <small>{snapshotProgress.snapshotId}</small> : null}
          </div>
        </div>
      ) : null}

      {terminalVisible ? (
        <div className="jarvis-terminal-stage wizard-terminal-panel">
          <div className="wizard-terminal-header">
            <span>Setup terminal</span>
            <code>{terminalCwd || '~'}</code>
            <SNRGButton
              as="button"
              variant="purple"
              size="sm"
              onClick={() => {
                setTerminalVisible(false);
              }}
            >
              Hide
            </SNRGButton>
          </div>
          <div className="wizard-terminal-scroll" ref={terminalScrollRef}>
            {terminalLines.map((line) => (
              <div key={line.id} className={`wizard-terminal-line terminal-${line.kind}`}>
                <span className="wizard-terminal-time">{line.at}</span>
                <span>{line.text}</span>
              </div>
            ))}
          </div>
          <form className="wizard-terminal-form" onSubmit={submitTerminal}>
            <input
              value={terminalInput}
              onChange={(event) => setTerminalInput(event.target.value)}
              placeholder="Run a setup command"
              disabled={terminalBusy}
            />
            <SNRGButton as="button" type="submit" variant="blue" size="sm" disabled={terminalBusy || !terminalInput.trim()}>
              Run
            </SNRGButton>
          </form>
        </div>
      ) : null}
    </section>
  );
}

export default TestnetJarvisSetup;

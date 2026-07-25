import { useEffect, useMemo, useRef, useState } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import {
  checkForUpdate,
  downloadAndInstallUpdate,
  installDownloadedUpdate,
  onUpdaterEvent,
} from '../../lib/appUpdater';
import { getVersion, invoke } from '../../lib/desktopClient';
import { controlPanelBannerSrc, jarvisIconSrc } from '../../lib/runtimeAssets';
import { useDeveloperMode } from '../../lib/developerMode';
import { useControlPanel } from './ControlPanelProvider';
import {
  formatNumber,
  formatPercent,
  formatTimestamp,
  nodeRuntimeLabel,
} from './controlPanelModel';
import DeveloperTerminalDock from './DeveloperTerminalDock';
import { ModeSwitcher } from './ControlPanelShared';
import {
  FEATURE_SCREEN_GROUPS,
  featureNavItemsForGroup,
  getFeatureScreenByPathname,
} from './controlPanelFeatureScreens';
import {
  isActivityPathname,
  isNodePathname,
  navGroupsForView,
} from './routeRegistry';

const UPDATE_POLL_MS = 30 * 60 * 1000;
const SETUP_UNAVAILABLE_MESSAGE = 'This machine already has a configured node. I can run validator onboarding for it now, including snapshot restore, runtime start, catch-up checks, and the next activation gates.';

function updateButtonLabel(updateState) {
  switch (updateState.status) {
    case 'checking':
      return 'Checking';
    case 'available':
      return `Update ${updateState.version}`;
    case 'downloading':
      return `Downloading ${Math.round(updateState.percent || 0)}%`;
    case 'ready':
      return 'Restart to update';
    case 'manual-install':
      return 'Open installer';
    case 'installing':
      return 'Restarting';
    default:
      return 'Check updates';
  }
}

function pageMetaFor(pathname, viewMode, selectedNode) {
  const featureScreen = getFeatureScreenByPathname(pathname);
  if (featureScreen) {
    return {
      title: featureScreen.title,
      description: featureScreen.modeCopy?.[viewMode] || featureScreen.description,
      jarvis: featureScreen.jarvis,
    };
  }

  if (pathname.startsWith('/connectivity')) {
    return {
      title: viewMode === 'basic' ? 'Connections' : viewMode === 'advanced' ? 'Connectivity' : 'P2P',
      description: viewMode === 'basic'
        ? 'See who your node is talking to and whether the network path looks healthy.'
        : 'Inspect mesh reachability, peer routing, and bootstrap health.',
      jarvis: viewMode === 'basic'
        ? 'This map turns peer traffic into something readable. Focus on whether the node is connected, catching up, or needs attention.'
        : 'This page is where I will eventually explain peer health, route traffic, and trigger reconnect actions for you.',
    };
  }

  if (isActivityPathname(pathname)) {
    return {
      title: viewMode === 'basic' ? 'Activity' : viewMode === 'advanced' ? 'Logs' : 'Runtime Logs',
      description: viewMode === 'basic'
        ? 'Jarvis distills the day into the moments that matter.'
        : 'Filter runtime events, source health, and raw developer traces.',
      jarvis: viewMode === 'basic'
        ? 'I am summarizing the important events so non-technical operators do not need to read raw terminal output.'
        : 'This is the live event stream. Expert and Developer views keep the underlying sources visible so you can trace what changed and when.',
    };
  }

  if (pathname.startsWith('/rewards')) {
    return {
      title: viewMode === 'basic' ? 'Rewards + Stake' : viewMode === 'advanced' ? 'Rewards + Stake' : 'Rewards + Ledger',
      description: viewMode === 'basic'
        ? 'Wallet, stake, rewards, and payout status for this node.'
        : 'Validator wallet, staking, payout history, and economics telemetry.',
      jarvis: viewMode === 'basic'
        ? 'This page explains wallet, stake, and rewards in plain language so operators can tell whether the node is funded, participating, and getting paid.'
        : 'This is the economics surface for validator income, staking state, pending rewards, and payout trends.',
    };
  }

  if (isNodePathname(pathname)) {
    return {
      title: selectedNode?.display_label || (viewMode === 'basic' ? 'My Node' : viewMode === 'advanced' ? 'Node Details' : 'Validator Detail'),
      description: viewMode === 'basic'
        ? 'Health, readiness, runtime controls, and plain-language status for this node.'
        : 'Identity, readiness, configuration, topology, and operator controls for the selected node.',
      jarvis: viewMode === 'basic'
        ? 'This page is tuned for simple operator decisions: is the node healthy, is it ready, and what should happen next. Wallet and staking controls live on Rewards.'
        : 'This is the node runtime surface. Wallet, stake, unstake, and withdraw controls are intentionally kept on Rewards.',
    };
  }

  if (pathname.startsWith('/settings')) {
    return {
      title: 'Settings',
      description: 'Machine-level controls, environment preferences, and controlled operations live here.',
      jarvis: viewMode === 'basic'
        ? 'This page keeps maintenance safe and guided.'
        : 'This is the local operations surface for workspace visibility, machine checks, and action history.',
    };
  }

  if (pathname.startsWith('/help')) {
    return {
      title: 'Documentation',
      description: 'Local help articles and operator documentation.',
      jarvis: 'Documentation stays close to the panel so new operators can learn without leaving the control surface.',
    };
  }

  return {
    title: 'Node Command Center',
    description: viewMode === 'basic'
      ? 'A friendlier view of your node, today’s activity, and the network around it.'
      : 'Synergy Network telemetry, node controls, topology, and operator insight in one workspace.',
    jarvis: viewMode === 'basic'
      ? 'I am keeping the overview approachable: simple language, clear health states, and the most important actions first.'
      : 'This is the new command center shell. Every page keeps Jarvis visible so future actions can move into guided chat instead of hidden menus.',
  };
}

function joinClasses(...values) {
  return values.filter(Boolean).join(' ');
}

function speedSyncPhaseLabel(phase) {
  switch (phase) {
    case 'starting':
      return 'Preparing catch-up';
    case 'complete':
      return 'Catch-up complete';
    case 'error':
      return 'Catch-up needs attention';
    default:
      return 'Catch-up running';
  }
}

function SpeedSyncProgressStrip({ progress }) {
  if (!progress) {
    return null;
  }

  const percentValue = Number(progress.percent);
  const hasPercent = Number.isFinite(percentValue);
  const currentHeight = Number(progress.currentHeight);
  const targetHeight = Number(progress.targetHeight);
  const gap = Number(progress.gap);
  const peerHeight = Number(progress.peerObservedHeight);
  const progressStyle = { '--speed-sync-progress': `${Math.max(0, Math.min(100, hasPercent ? percentValue : 0))}%` };
  const statusClass = progress.phase === 'error'
    ? 'is-error'
    : progress.phase === 'complete'
      ? 'is-complete'
      : 'is-running';

  return (
    <section className={joinClasses('cp-speed-sync-strip', statusClass)} aria-live="polite">
      <div className="cp-speed-sync-copy">
        <span className="cp-eyebrow">{speedSyncPhaseLabel(progress.phase)}</span>
        <strong>{progress.nodeLabel || 'Validator'}</strong>
        <p>{progress.detail || 'Validator catch-up is updating local chain state from peers.'}</p>
      </div>
      <div className="cp-speed-sync-meter" style={progressStyle}>
        <div className="cp-speed-sync-meter-head">
          <span>
            {Number.isFinite(currentHeight) ? `h${formatNumber(currentHeight)}` : 'height pending'}
            {Number.isFinite(targetHeight) ? ` / h${formatNumber(targetHeight)}` : ' / verified target pending'}
          </span>
          <strong>{hasPercent ? formatPercent(percentValue, 1) : 'Running'}</strong>
        </div>
        <div className={joinClasses('cp-speed-sync-track', !hasPercent && 'is-indeterminate')}>
          <div className="cp-speed-sync-fill"></div>
        </div>
        <div className="cp-speed-sync-meta">
          <span>{Number.isFinite(gap) ? `${formatNumber(gap)} blocks remaining` : 'Gap pending verified target'}</span>
          <span>{progress.targetSource ? `Target: ${progress.targetSource}` : 'Target source pending'}</span>
          {Number.isFinite(peerHeight) ? <span>Peer seen h{formatNumber(peerHeight)}</span> : null}
        </div>
      </div>
    </section>
  );
}

function buildJarvisResponse({ value, meta, selectedNode, selectedNodeLive, featureHit }) {
  const normalized = value.toLowerCase();
  const nodeLabel = selectedNode?.display_label || selectedNode?.role_display_name || 'the selected node';
  const roleId = String(selectedNode?.role_id || selectedNode?.role_type || '').trim().toLowerCase();
  const isValidator = roleId === 'validator';
  const runtime = selectedNode ? nodeRuntimeLabel(selectedNodeLive).toLowerCase() : 'no selected node';
  const syncGap = Number(selectedNodeLive?.sync_gap);
  const peers = Number(selectedNodeLive?.local_peer_count);

  if (/open setup|start setup|setup wizard/.test(normalized)) {
    if (selectedNode && isValidator) {
      return {
        text: SETUP_UNAVAILABLE_MESSAGE,
        path: '/validator',
        action: 'run-validator-onboarding',
      };
    }
    return { text: 'Opening setup so Jarvis can create a new node workspace on this machine.', action: 'launch-setup' };
  }
  if (selectedNode && isValidator && /shadow|onboard|onboarding|activation|gate|catch.?up|sync|restore snapshot|apply snapshot|start validator|start node|provisioned node/.test(normalized)) {
    return {
      text: 'I will run validator onboarding now. I will restore the newest verified archive snapshot if needed, start the validator runtime, check catch-up state, and report the next gate here before returning you to the dashboard.',
      path: '/validator',
      action: 'run-validator-onboarding',
    };
  }
  if (/withdraw|connect wallet|wallet|payout|reward|earning/.test(normalized)) {
    return {
      text: 'Opening Rewards so you can connect a Synergy wallet, review validator earnings, and withdraw claimable rewards from the validator to that wallet.',
      path: '/rewards',
    };
  }
  if (/peer|topology|map|connection|p2p/.test(normalized)) {
    return {
      text: `Opening P2P so you can inspect peer health and topology. Current summary: ${Number.isFinite(peers) ? `${peers} visible peer sessions` : 'peer count not reported'}.`,
      path: '/connectivity',
    };
  }
  if (/summarize|health|status|state/.test(normalized)) {
    const syncText = Number.isFinite(syncGap) ? `${syncGap} block sync gap` : 'sync gap not reported';
    const peerText = Number.isFinite(peers) ? `${peers} peers` : 'peer count not reported';
    return {
      text: `${nodeLabel} is currently ${runtime}. The latest local telemetry shows ${syncText} and ${peerText}. For validator lifecycle truth, use the Validator Lifecycle card rather than generic health badges.`,
    };
  }
  if (/diagnose|problem|broken|why/.test(normalized)) {
    return {
      text: 'Start with the page-specific evidence: Validator Lifecycle for shadow/stake/activation state, P2P for peers, Logs for runtime errors, and Rewards for wallet or withdrawal issues. I can route you to any of those screens.',
    };
  }
  if (/log|event|warning|error/.test(normalized)) {
    return {
      text: 'Opening Logs so you can inspect recent runtime warnings, errors, and control-service action receipts.',
      path: '/logs',
    };
  }
  if (featureHit) {
    return {
      text: `Opening ${featureHit.title}.`,
      path: featureHit.path,
    };
  }
  if (/node|details/.test(normalized) && selectedNode) {
    return {
      text: `Opening ${nodeLabel} so you can inspect runtime, readiness, validator state, and local artifacts.`,
      path: '/node',
    };
  }
  if (/restart|reboot|rejoin|stop|wipe|kill|pause signing|apply config/.test(normalized)) {
    return {
      text: 'That can affect uptime or local state. Use the visible page controls so the control panel records an action receipt and shows the relevant confirmation or gate.',
    };
  }
  if (/terminal/.test(normalized)) {
    return { text: 'Use the developer dock for a real terminal session; I keep risky command execution behind visible operator controls.' };
  }

  return { text: meta.jarvis };
}

function summarizeJarvisOnboardingResult(result) {
  const status = String(result?.status || '').trim().toLowerCase();
  const message = String(result?.message || '').trim();
  const nextAction = String(result?.nextAction || result?.next_action || '').trim();
  const baseMessage = message || 'Validator onboarding finished its current pass.';

  if (status === 'complete' || status === 'ready' || status === 'rejoined') {
    return `${baseMessage} The validator is ready for the next dashboard step.`;
  }

  if (status === 'blocked' || status === 'syncing') {
    return `${baseMessage} I started the validator onboarding flow and the dashboard will show the remaining gate${nextAction ? `: ${nextAction}` : ''}.`;
  }

  return `${baseMessage}${nextAction ? ` Next gate: ${nextAction}.` : ''}`;
}

function CurrentNodeCard({ node, nodeLive, onRename, onSetOwner }) {
  const [nicknameDraft, setNicknameDraft] = useState(node?.display_label || '');
  const [ownerDraft, setOwnerDraft] = useState(node?.owner_wallet_address || '');
  const [saveState, setSaveState] = useState('');
  const [ownerSaveState, setOwnerSaveState] = useState('');

  useEffect(() => {
    setNicknameDraft(node?.display_label || '');
    setOwnerDraft(node?.owner_wallet_address || '');
    setSaveState('');
    setOwnerSaveState('');
  }, [node?.display_label, node?.id, node?.owner_wallet_address]);

  if (!node) {
    return (
      <section className="cp-current-node-card is-empty" aria-label="Current node">
        <span className="cp-eyebrow">Current Node</span>
        <strong>No node configured</strong>
        <p>Complete initial setup to manage a local node on this machine.</p>
      </section>
    );
  }

  const commitNickname = async () => {
    const nextLabel = nicknameDraft.trim();
    if (!nextLabel || nextLabel === node.display_label) {
      setNicknameDraft(node.display_label || '');
      return;
    }

    setSaveState('saving');
    try {
      await onRename(node.id, nextLabel);
      setSaveState('saved');
      window.setTimeout(() => setSaveState(''), 1600);
    } catch (renameError) {
      setSaveState(String(renameError));
    }
  };

  const commitOwnerWallet = async () => {
    const nextOwner = ownerDraft.trim();
    if (nextOwner === (node.owner_wallet_address || '')) {
      setOwnerDraft(node.owner_wallet_address || '');
      return;
    }

    setOwnerSaveState('saving');
    try {
      await onSetOwner(node.id, nextOwner);
      setOwnerSaveState('saved');
      window.setTimeout(() => setOwnerSaveState(''), 1600);
    } catch (ownerError) {
      setOwnerSaveState(String(ownerError));
    }
  };

  return (
    <section className="cp-current-node-card" aria-label="Current node">
      <div className="cp-current-node-head">
        <span className="cp-eyebrow">Current Node</span>
        <span className={joinClasses('cp-node-health-dot', `tone-${nodeRuntimeLabel(nodeLive).toLowerCase().includes('offline') ? 'bad' : 'good'}`)} title={nodeRuntimeLabel(nodeLive)}></span>
      </div>
      <label className="cp-current-node-nickname">
        <span>Validator nickname</span>
        <input
          value={nicknameDraft}
          onChange={(event) => setNicknameDraft(event.target.value)}
          onBlur={() => void commitNickname()}
          onKeyDown={(event) => {
            if (event.key === 'Enter') {
              event.currentTarget.blur();
            }
            if (event.key === 'Escape') {
              setNicknameDraft(node.display_label || '');
              event.currentTarget.blur();
            }
          }}
          aria-label="Validator nickname"
          maxLength={80}
        />
      </label>
      <label className="cp-current-node-nickname">
        <span>Owner wallet</span>
        <input
          value={ownerDraft}
          onChange={(event) => setOwnerDraft(event.target.value)}
          onBlur={() => void commitOwnerWallet()}
          onKeyDown={(event) => {
            if (event.key === 'Enter') {
              event.currentTarget.blur();
            }
            if (event.key === 'Escape') {
              setOwnerDraft(node.owner_wallet_address || '');
              event.currentTarget.blur();
            }
          }}
          aria-label="Validator owner wallet"
          placeholder="syns..."
          maxLength={80}
        />
      </label>
      <p>{node.role_display_name || node.role_id || 'Validator'}</p>
      {saveState ? <small className={joinClasses('cp-current-node-save', saveState === 'saved' && 'is-saved')}>{saveState === 'saving' ? 'Saving nickname...' : saveState === 'saved' ? 'Nickname saved' : saveState}</small> : null}
      {ownerSaveState ? <small className={joinClasses('cp-current-node-save', ownerSaveState === 'saved' && 'is-saved')}>{ownerSaveState === 'saving' ? 'Saving owner...' : ownerSaveState === 'saved' ? 'Owner wallet saved' : ownerSaveState}</small> : null}
    </section>
  );
}

export default function ControlPanelShell({ children, onLaunchSetup }) {
  const location = useLocation();
  const navigate = useNavigate();
  const {
    error,
    lastUpdatedAt,
    nodes,
    refresh,
    selectedNode,
    selectedNodeLive,
    speedSyncProgress,
    setSelectedNodeId,
    setViewMode,
    viewMode,
  } = useControlPanel();

  const [developerModeEnabled] = useDeveloperMode();
  const [appVersion, setAppVersion] = useState('');
  const [jarvisOpen, setJarvisOpen] = useState(false);
  const [jarvisInput, setJarvisInput] = useState('');
  const [jarvisThread, setJarvisThread] = useState([]);
  const [jarvisTyping, setJarvisTyping] = useState(false);
  const [jarvisActionBusy, setJarvisActionBusy] = useState('');
  const jarvisThreadEndRef = useRef(null);
  const jarvisResponseTimerRef = useRef(null);
  const [updateState, setUpdateState] = useState({
    status: 'idle',
    message: 'No update check has been run yet.',
    version: '',
    percent: 0,
  });

  const meta = useMemo(
    () => pageMetaFor(location.pathname, viewMode, selectedNode),
    [location.pathname, selectedNode, viewMode],
  );
  const defaultNode = selectedNode || nodes[0] || null;

  useEffect(() => {
    document.querySelector('.cp-main-content')?.scrollTo({ top: 0, left: 0 });
    document.querySelector('.cp-sidebar')?.scrollTo({ top: 0, left: 0 });
  }, [location.pathname]);

  useEffect(() => {
    jarvisThreadEndRef.current?.scrollIntoView({ block: 'end', behavior: 'smooth' });
  }, [jarvisThread, jarvisTyping, jarvisOpen]);

  useEffect(() => () => {
    if (jarvisResponseTimerRef.current) {
      window.clearTimeout(jarvisResponseTimerRef.current);
    }
  }, []);

  useEffect(() => {
    if (!developerModeEnabled && viewMode === 'developer') {
      setViewMode('advanced');
      navigate('/', { replace: true });
    }
  }, [developerModeEnabled, navigate, setViewMode, viewMode]);

  useEffect(() => {
    let disposed = false;

    const loadVersion = async () => {
      try {
        const version = await getVersion();
        if (!disposed) {
          setAppVersion(version);
        }
      } catch {
        if (!disposed) {
          setAppVersion('unknown');
        }
      }
    };

    const runCheck = async (silent = false) => {
      if (!disposed && !silent) {
        setUpdateState((previous) => ({
          ...previous,
          status: 'checking',
          message: 'Checking for updates...',
        }));
      }

      const result = await checkForUpdate();
      if (disposed) {
        return;
      }

      if (result?.error) {
        if (!silent) {
          setUpdateState({
            status: 'error',
            message: result.error,
            version: '',
            percent: 0,
          });
        }
        return;
      }

      if (result?.available) {
        setUpdateState({
          status: 'available',
          message: `Update ${result.version} is ready to download.`,
          version: result.version || '',
          percent: 0,
        });
        return;
      }

      setUpdateState({
        status: 'up_to_date',
        message: 'You are running the latest published version.',
        version: '',
        percent: 0,
      });
    };

    const unsubAvailable = onUpdaterEvent('update-available', (data) => {
      if (!disposed) {
        setUpdateState((previous) => ({
          ...previous,
          status: 'available',
          message: `Update ${data?.version || previous.version} found.`,
          version: data?.version || previous.version || '',
        }));
      }
    });

    const unsubProgress = onUpdaterEvent('download-progress', (data) => {
      if (!disposed) {
        setUpdateState((previous) => ({
          ...previous,
          status: 'downloading',
          message: 'Downloading update...',
          percent: data?.percent || 0,
        }));
      }
    });

    const unsubDownloaded = onUpdaterEvent('update-downloaded', (data) => {
      if (!disposed) {
        setUpdateState((previous) => ({
          ...previous,
          status: 'ready',
          message: `Update ${data?.version || previous.version} is ready to apply.`,
          version: data?.version || previous.version || '',
        }));
      }
    });

    const unsubError = onUpdaterEvent('error', (data) => {
      if (!disposed) {
        setUpdateState((previous) => ({
          ...previous,
          status: 'error',
          message: data?.message || 'Update failed.',
        }));
      }
    });

    loadVersion();
    void runCheck(true);

    const intervalId = window.setInterval(() => {
      void runCheck(true);
    }, UPDATE_POLL_MS);

    return () => {
      disposed = true;
      window.clearInterval(intervalId);
      unsubAvailable();
      unsubProgress();
      unsubDownloaded();
      unsubError();
    };
  }, []);

  const handleUpdateAction = async () => {
    if (updateState.status === 'downloading' || updateState.status === 'installing' || updateState.status === 'checking') {
      return;
    }

    if (updateState.status === 'ready') {
      setUpdateState((previous) => ({
        ...previous,
        status: 'installing',
        message: 'Restarting to apply the update...',
      }));
      await installDownloadedUpdate(updateState.version);
      return;
    }

    setUpdateState((previous) => ({
      ...previous,
      status: 'downloading',
      message: 'Downloading update...',
      percent: 0,
    }));

    const result = await downloadAndInstallUpdate(updateState.version);
    if (result?.status === 'error') {
      setUpdateState({
        status: 'error',
        message: result.message,
        version: updateState.version,
        percent: 0,
      });
      return;
    }
    if (result?.status === 'manual-install') {
      setUpdateState({
        status: 'manual-install',
        message: result.message,
        version: result.version || updateState.version,
        percent: 0,
      });
      return;
    }
    if (result?.status === 'up-to-date') {
      setUpdateState({
        status: 'up_to_date',
        message: result.message,
        version: '',
        percent: 0,
      });
    }
  };

  const pushJarvisMessage = (sender, text) => {
    setJarvisThread((current) => [
      ...current,
      {
        id: `${sender}-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        sender,
        text,
      },
    ]);
  };

  const runJarvisResponseAction = async (response) => {
    if (!response?.action) {
      return;
    }

    if (response.action === 'launch-setup') {
      if (typeof onLaunchSetup === 'function') {
        onLaunchSetup();
      }
      return;
    }

    if (response.action !== 'run-validator-onboarding') {
      return;
    }

    if (!selectedNode?.id) {
      pushJarvisMessage('assistant', 'I do not see a selected validator node yet. Finish setup first, then I can run onboarding.');
      return;
    }

    setJarvisActionBusy(response.action);
    setJarvisTyping(true);
    try {
      const result = await invoke('testnet_run_validator_onboarding', {
        input: {
          nodeId: selectedNode.id,
          dryRun: false,
          autoResyncTime: true,
          autoStart: true,
          autoStake: false,
          autoActivate: true,
        },
      });
      setJarvisTyping(false);
      pushJarvisMessage('assistant', summarizeJarvisOnboardingResult(result));
      await refresh({ silent: true });
      if (response.path) {
        navigate(response.path);
      }
    } catch (error) {
      setJarvisTyping(false);
      pushJarvisMessage('assistant', `I could not finish validator onboarding: ${String(error)}`);
    } finally {
      setJarvisActionBusy('');
    }
  };

  const handleJarvisSubmit = (event, presetValue = '') => {
    event?.preventDefault?.();
    const value = jarvisInput.trim();
    const prompt = (presetValue || value).trim();
    if (!prompt || jarvisTyping || jarvisActionBusy) {
      return;
    }

    pushJarvisMessage('user', prompt);
    setJarvisInput('');
    setJarvisOpen(true);

    const normalized = prompt.toLowerCase();
    const featureHit = FEATURE_SCREEN_GROUPS
      .flatMap((group) => featureNavItemsForGroup(group.id))
      .find((screen) => (
        normalized.includes(screen.label.toLowerCase())
        || normalized.includes(screen.key.toLowerCase())
        || normalized.includes(screen.title.toLowerCase().split(' ')[0])
      ));
    const response = buildJarvisResponse({ value: prompt, meta, selectedNode, selectedNodeLive, featureHit });
    const typingDelay = Math.min(1800, Math.max(900, 520 + response.text.length * 9));
    const followUpDelay = response.path ? 280 : 180;

    setJarvisTyping(true);
    if (jarvisResponseTimerRef.current) {
      window.clearTimeout(jarvisResponseTimerRef.current);
    }
    jarvisResponseTimerRef.current = window.setTimeout(() => {
      setJarvisTyping(false);
      pushJarvisMessage('assistant', response.text);
      if (response.action) {
        void runJarvisResponseAction(response);
      } else if (response.path) {
        window.setTimeout(() => navigate(response.path), followUpDelay);
      }
    }, typingDelay);
  };

  const navigationGroups = navGroupsForView(viewMode, developerModeEnabled).map((group) => ({
    ...group,
    items: group.items.map((item) => ({
      ...item,
      disabled: item.key === 'details' && !defaultNode,
    })),
  }));

  const isNavigationItemActive = (item) => {
    if (item.key === 'dashboard') {
      return location.pathname === '/';
    }

    if (item.key === 'details') {
      return isNodePathname(location.pathname);
    }

    if (item.key === 'activity' || item.key === 'logs') {
      return isActivityPathname(location.pathname);
    }

    return item.to !== '/' && location.pathname.startsWith(item.to);
  };

  const hasFooterUpdateState = ['checking', 'available', 'downloading', 'ready', 'manual-install', 'installing', 'error'].includes(updateState.status);
  const footerMessage = hasFooterUpdateState ? updateState.message : error;
  const shellStatusMessage = footerMessage || `Last updated ${lastUpdatedAt ? formatTimestamp(lastUpdatedAt) : 'moments ago'}`;
  const currentYear = new Date().getFullYear();

  const renameNode = async (nodeId, displayLabel) => {
    await invoke('testnet_rename_node', {
      input: {
        nodeId,
        displayLabel,
      },
    });
    await invoke('testnet_publish_validator_profile_to_atlas', {
      input: { nodeId },
    }).catch(() => null);
    setSelectedNodeId(nodeId);
    await refresh({ silent: true });
  };

  const setValidatorOwner = async (nodeId, ownerWalletAddress) => {
    await invoke('testnet_set_validator_owner', {
      input: {
        nodeId,
        ownerWalletAddress,
      },
    });
    await invoke('testnet_publish_validator_profile_to_atlas', {
      input: { nodeId },
    }).catch(() => null);
    setSelectedNodeId(nodeId);
    await refresh({ silent: true });
  };

  return (
    <div className="cp-shell-frame" data-cp-mode={viewMode}>
      <div className="cp-shell" data-cp-mode={viewMode}>
        <aside className="cp-sidebar">
          <div className="cp-sidebar-brand">
            <img src={controlPanelBannerSrc} alt="Synergy Network Node Control Panel" className="cp-sidebar-brand-image" />
          </div>

          <CurrentNodeCard
            node={defaultNode}
            nodeLive={selectedNodeLive}
            onRename={renameNode}
            onSetOwner={setValidatorOwner}
          />

          <nav className="cp-sidebar-nav" aria-label="Primary">
            {navigationGroups.map((group) => (
              <div key={group.id} className="cp-nav-group" data-layout={group.layout}>
                <span className="cp-nav-group-label">{group.label}</span>
                {group.items.map((item) => (
                  item.disabled ? (
                    <button
                      key={item.key}
                      type="button"
                      className="cp-nav-link is-disabled"
                      disabled
                    >
                      <span className="material-icons" aria-hidden="true">{item.icon}</span>
                      <span>{item.label}</span>
                    </button>
                  ) : (
                    <NavLink
                      key={item.key}
                      to={item.to}
                      end={item.end}
                      onClick={() => {
                        if (item.key === 'details' && defaultNode) {
                          setSelectedNodeId(defaultNode.id);
                        }
                      }}
                      className={joinClasses('cp-nav-link', isNavigationItemActive(item) && 'is-active')}
                    >
                      <span className="material-icons" aria-hidden="true">{item.icon}</span>
                      <span>{item.label}</span>
                    </NavLink>
                  )
                ))}
              </div>
            ))}
          </nav>

          <div className="cp-sidebar-footer">
            <div className="cp-sidebar-mode-panel">
              <span className="cp-eyebrow cp-sidebar-footer-label">Views</span>
              <ModeSwitcher mode={viewMode} onChange={setViewMode} compact allowDeveloper={developerModeEnabled} />
            </div>
          </div>
        </aside>

        <div className="cp-main-shell">
          <header className="cp-topbar">
            <div className="cp-topbar-copy">
              <div className="cp-topbar-statusbar">
                <div className="cp-topbar-statuscopy">
                  <span className="cp-eyebrow">Environment</span>
                  <strong>Testnet</strong>
                </div>
                <div className="cp-topbar-statuscopy">
                  <span className="cp-eyebrow">Selected Node</span>
                  <strong>{selectedNode?.display_label || 'None selected'}</strong>
                </div>
              </div>
            </div>

            <div className="cp-topbar-actions">
              <button type="button" className="cp-icon-button" aria-label="Open Settings" onClick={() => navigate('/settings')}>
                <span className="material-icons" aria-hidden="true">settings</span>
              </button>
              <button type="button" className="cp-icon-button" aria-label="Open Help" onClick={() => navigate('/help')}>
                <span className="material-icons" aria-hidden="true">help</span>
              </button>
              <button
                type="button"
                className="cp-update-button"
                onClick={handleUpdateAction}
                disabled={updateState.status === 'checking' || updateState.status === 'downloading' || updateState.status === 'installing'}
                title={updateState.message}
              >
                {updateButtonLabel(updateState)}
              </button>
              <button type="button" className="cp-update-button cp-wallet-button" onClick={() => navigate('/rewards')}>
                Connect Wallet
              </button>
            </div>
          </header>

          <SpeedSyncProgressStrip progress={speedSyncProgress} />

          <main className="cp-main-content">
            <section className="cp-page-frame">
              {children}
            </section>
          </main>

          <DeveloperTerminalDock />
        </div>
      </div>

      <footer className="cp-app-footer">
        <span className="cp-app-footer-left">© {currentYear} Synergy Network. All rights reserved.</span>
        <span className="cp-app-footer-center">{shellStatusMessage}</span>
        <span className="cp-app-footer-right">{appVersion ? `Control Panel v${appVersion}` : 'Control Panel version not reported'}</span>
      </footer>

      <button
        type="button"
        className="cp-floating-jarvis-launcher"
        aria-expanded={jarvisOpen}
        aria-label="Open Jarvis node assistant"
        onClick={() => setJarvisOpen((current) => !current)}
      >
        <img src={jarvisIconSrc} alt="" aria-hidden="true" />
        <i aria-hidden="true"></i>
      </button>

      <aside className={`cp-jarvis-drawer ${jarvisOpen ? 'is-open' : ''}`}>
        <div className="cp-jarvis-drawer-head">
          <div className="cp-jarvis-title">
            <img src={jarvisIconSrc} alt="" aria-hidden="true" />
            <div className="cp-jarvis-title-copy">
              <span className="cp-eyebrow">Assistant</span>
              <h3>Jarvis</h3>
            </div>
          </div>
          <button type="button" className="cp-icon-button" onClick={() => setJarvisOpen(false)}>
            <span className="material-icons" aria-hidden="true">close</span>
          </button>
        </div>

        <div className="cp-jarvis-thread">
          <article className="cp-jarvis-message is-assistant cp-jarvis-message-intro">
            <span>Jarvis</span>
            <p>{meta.jarvis}</p>
          </article>

          {jarvisThread.map((message) => (
            <article key={message.id} className={`cp-jarvis-message ${message.sender === 'assistant' ? 'is-assistant' : 'is-user'}`}>
              <span>{message.sender === 'assistant' ? 'Jarvis' : 'You'}</span>
              <p>{message.text}</p>
            </article>
          ))}
          {jarvisTyping ? (
            <article className="cp-jarvis-message is-assistant is-typing" aria-live="polite">
              <span>Jarvis</span>
              <div className="cp-typing-dots" aria-label="Jarvis is typing">
                <i></i>
                <i></i>
                <i></i>
              </div>
            </article>
          ) : null}
          <div ref={jarvisThreadEndRef}></div>
        </div>

        <div className="cp-chip-row">
          <button type="button" className="cp-chip cp-chip-button" disabled={jarvisTyping || Boolean(jarvisActionBusy)} onClick={() => handleJarvisSubmit(null, 'Summarize node health')}
          >
            Summarize health
          </button>
          <button type="button" className="cp-chip cp-chip-button" disabled={jarvisTyping || Boolean(jarvisActionBusy)} onClick={() => handleJarvisSubmit(null, 'Run onboarding')}
          >
            Run onboarding
          </button>
          <button type="button" className="cp-chip cp-chip-button" disabled={jarvisTyping || Boolean(jarvisActionBusy)} onClick={() => handleJarvisSubmit(null, 'Diagnose peers')}
          >
            Diagnose peers
          </button>
          <button type="button" className="cp-chip cp-chip-button" disabled={jarvisTyping || Boolean(jarvisActionBusy)} onClick={() => handleJarvisSubmit(null, 'Explain this page')}
          >
            Explain this page
          </button>
        </div>

        <form className="cp-jarvis-form" onSubmit={handleJarvisSubmit}>
          <textarea
            value={jarvisInput}
            onChange={(event) => setJarvisInput(event.target.value)}
            rows={3}
            placeholder="Ask Jarvis to run onboarding, check health, or explain the current page."
            disabled={jarvisTyping || Boolean(jarvisActionBusy)}
          />
          <button type="submit" className="cp-jarvis-send" disabled={jarvisTyping || Boolean(jarvisActionBusy) || !jarvisInput.trim()}>
            {jarvisActionBusy ? 'Running' : jarvisTyping ? 'Thinking' : 'Send'}
          </button>
        </form>
      </aside>
    </div>
  );
}

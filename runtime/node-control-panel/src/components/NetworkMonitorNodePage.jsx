import { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { invoke } from '../lib/desktopClient';
import { validatorNetworkClusterQuorumThreshold } from '../lib/protocolPolicy';

const REFRESH_SECONDS_OPTIONS = [3, 5, 10, 15, 30];
const REQUIRES_NODE_ACTION_CONFIRMATION = {
  validator_wait_promote_vote_only:
    'You are about to execute a generic validator-recovery action: Promote Vote-only. This keeps fail-closed safety gates in place and should only be run after State Sync/Diagnostics evidence indicates the node is ready.',
  validator_mesh_reconnect:
    'You are about to execute a generic validator-recovery action: Mesh Reconnect. This restarts validator networking and writes mesh/qRPC evidence.',
  validator_chain_body_repair:
    'You are about to execute a generic validator-recovery action: Chain-Body Repair. This is a destructive mutation requiring explicit approval.',
};

function formatLocalTimestamp(value) {
  if (!value) return 'N/A';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function jsonPretty(value) {
  if (value === null || value === undefined) return 'N/A';
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function scalar(value) {
  if (value === null || value === undefined) return 'N/A';
  if (typeof value === 'object') return jsonPretty(value);
  return String(value);
}

function dynamicMaxValidators(value) {
  const parsed = Number(value);
  if (Number.isFinite(parsed) && parsed === 0) return 'Dynamic';
  return scalar(value);
}

function normalize(value) {
  return String(value || '').trim().toLowerCase();
}

function countByStatus(checks = [], status) {
  return checks.filter((check) => check.status === status).length;
}

function dedupeByKey(actions = []) {
  const map = new Map();
  actions.forEach((action) => {
    if (!action?.key || map.has(action.key)) return;
    map.set(action.key, action);
  });
  return Array.from(map.values());
}

function titleizeKey(value) {
  return String(value || '')
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (match) => match.toUpperCase());
}

function isRecord(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function findNestedValue(value, candidateKeys = []) {
  if (!candidateKeys.length) return undefined;
  const wanted = new Set(candidateKeys.map((entry) => normalize(entry)));
  const visited = new Set();

  const walk = (node) => {
    if (!node || typeof node !== 'object') return undefined;
    if (visited.has(node)) return undefined;
    visited.add(node);

    if (Array.isArray(node)) {
      for (const item of node) {
        const found = walk(item);
        if (found !== undefined) return found;
      }
      return undefined;
    }

    for (const [key, child] of Object.entries(node)) {
      if (wanted.has(normalize(key)) && child !== null && child !== undefined) {
        return child;
      }
    }

    for (const child of Object.values(node)) {
      const found = walk(child);
      if (found !== undefined) return found;
    }

    return undefined;
  };

  return walk(value);
}

function toNumber(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const normalized = value.replace(/,/g, '').trim();
    if (!normalized) return null;
    const numeric = Number(normalized);
    return Number.isFinite(numeric) ? numeric : null;
  }
  return null;
}

function toBooleanValue(value) {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (['true', 'yes', 'on', '1'].includes(normalized)) return true;
    if (['false', 'no', 'off', '0'].includes(normalized)) return false;
  }
  return null;
}

function formatNumberValue(value, options = {}) {
  const numeric = toNumber(value);
  if (numeric === null) return 'N/A';
  return new Intl.NumberFormat(undefined, options).format(numeric);
}

function formatStakeValue(value) {
  const numeric = toNumber(value);
  if (numeric === null) return 'N/A';
  const normalized = numeric > 1_000_000 ? numeric / 1_000_000_000 : numeric;
  return `${formatNumberValue(normalized, { maximumFractionDigits: 2 })} SNRG`;
}

function formatSnrgValue(value, maximumFractionDigits = 4) {
  const numeric = toNumber(value);
  if (numeric === null) return 'N/A';
  return `${formatNumberValue(numeric, { maximumFractionDigits })} SNRG`;
}

function formatSignedSnrgValue(value, maximumFractionDigits = 4) {
  const numeric = toNumber(value);
  if (numeric === null) return 'N/A';
  const sign = numeric > 0 ? '+' : '';
  return `${sign}${formatNumberValue(numeric, { maximumFractionDigits })} SNRG`;
}

function formatPercentValue(value) {
  const numeric = toNumber(value);
  if (numeric === null) return 'N/A';
  const normalized = numeric <= 1 ? numeric * 100 : numeric;
  return `${formatNumberValue(normalized, { maximumFractionDigits: 2 })}%`;
}

function formatUnixTimestamp(value) {
  const numeric = toNumber(value);
  if (numeric === null) return 'N/A';
  return formatLocalTimestamp(new Date(numeric * 1000).toISOString());
}

function formatBooleanPill(value) {
  const normalized = toBooleanValue(value);
  if (normalized === null) return 'N/A';
  return normalized ? 'Yes' : 'No';
}

function extractSignatureAlgorithms(latestBlock) {
  const transactions = Array.isArray(latestBlock?.transactions) ? latestBlock.transactions : [];
  const algorithms = [];
  transactions.forEach((tx) => {
    const algorithm = String(tx?.signature_algorithm || '').trim();
    if (!algorithm) return;
    if (!algorithms.includes(algorithm)) {
      algorithms.push(algorithm);
    }
  });
  return algorithms;
}

function compactLines(values = []) {
  return values.filter(Boolean).join(' | ') || 'N/A';
}

function isBootstrapConsensusValidator(node) {
  return normalize(node?.role_group) === 'consensus'
    && normalize(node?.node_type || node?.role) === 'validator';
}

function NetworkMonitorNodePage() {
  const { nodeSlotId } = useParams();
  const [nodeDetails, setNodeDetails] = useState(null);
  const [detailsLoading, setDetailsLoading] = useState(true);
  const [detailsError, setDetailsError] = useState('');

  const [snapshot, setSnapshot] = useState(null);
  const [agentSnapshot, setAgentSnapshot] = useState(null);
  const [localMachineIdentity, setLocalMachineIdentity] = useState(null);

  const [refreshSeconds, setRefreshSeconds] = useState(5);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const [controlResult, setControlResult] = useState(null);
  const [controlBusyAction, setControlBusyAction] = useState('');
  const [exportBusy, setExportBusy] = useState(false);
  const [exportResult, setExportResult] = useState(null);
  const [voteOnlyRejoinHeight, setVoteOnlyRejoinHeight] = useState('');

  const fetchSnapshot = async () => {
    try {
      const [data, agentData] = await Promise.all([
        invoke('get_monitor_snapshot'),
        invoke('get_monitor_agent_snapshot').catch(() => null),
      ]);
      setSnapshot(data);
      setAgentSnapshot(agentData);
    } catch (err) {
      console.error('Failed to fetch monitor snapshot for routing context:', err);
    }
  };

  const fetchLocalMachineIdentity = async () => {
    try {
      const identity = await invoke('monitor_detect_local_machine_identity');
      setLocalMachineIdentity(identity);
    } catch (err) {
      console.error('Failed to detect local machine identity:', err);
      setLocalMachineIdentity(null);
    }
  };

  const fetchNodeDetails = async (silent = false) => {
    if (!nodeSlotId) return;
    if (!silent) setDetailsLoading(true);

    try {
      const details = await invoke('get_monitor_node_details', { nodeSlotId });
      setNodeDetails(details);
      setDetailsError('');
    } catch (err) {
      console.error('Failed to fetch monitor node details:', err);
      setDetailsError(String(err));
    } finally {
      if (!silent) setDetailsLoading(false);
    }
  };

  useEffect(() => {
    fetchNodeDetails();
    fetchSnapshot();
    fetchLocalMachineIdentity();
  }, [nodeSlotId]);

  useEffect(() => {
    if (!autoRefresh) return undefined;
    const handle = setInterval(() => {
      fetchNodeDetails(true);
      fetchSnapshot();
    }, refreshSeconds * 1000);
    return () => clearInterval(handle);
  }, [autoRefresh, refreshSeconds, nodeSlotId]);

  const roleDiagnosticsEntries = useMemo(() => {
    const diag = nodeDetails?.role_diagnostics;
    if (!diag || typeof diag !== 'object') return [];
    return Object.entries(diag);
  }, [nodeDetails]);

  const sortedNodes = useMemo(() => {
    const nodes = snapshot?.nodes || [];
    return [...nodes].sort((a, b) =>
      (a?.node?.node_slot_id || '').localeCompare(b?.node?.node_slot_id || ''),
    );
  }, [snapshot]);

  const currentIndex = useMemo(() => {
    const target = normalize(nodeSlotId);
    return sortedNodes.findIndex(
      (entry) =>
        normalize(entry?.node?.node_slot_id) === target || normalize(entry?.node?.node_alias) === target,
    );
  }, [sortedNodes, nodeSlotId]);

  const previousNode = currentIndex > 0 ? sortedNodes[currentIndex - 1] : null;
  const nextNode = currentIndex >= 0 && currentIndex < sortedNodes.length - 1
    ? sortedNodes[currentIndex + 1]
    : null;

  const networkMaxHeight = snapshot?.highest_block ?? null;
  const localHeight = nodeDetails?.status?.block_height ?? null;
  const blockLag =
    networkMaxHeight !== null && localHeight !== null && networkMaxHeight >= localHeight
      ? networkMaxHeight - localHeight
      : null;
  const nodeStatus = nodeDetails?.status?.status || 'unknown';
  const syncing = nodeDetails?.status?.syncing;
  const installedBootstrapValidatorIds = useMemo(() => {
    const installedSet = new Set(
      (agentSnapshot?.agents || [])
        .filter((agent) => agent?.reachable)
        .flatMap((agent) => (Array.isArray(agent.node_slot_ids) ? agent.node_slot_ids : []))
        .map((value) => normalize(value))
        .filter(Boolean),
    );

    return (snapshot?.nodes || [])
      .filter((entry) => isBootstrapConsensusValidator(entry?.node))
      .map((entry) => normalize(entry?.node?.node_slot_id))
      .filter((value) => installedSet.has(value));
  }, [agentSnapshot, snapshot]);
  const bootstrapValidatorCount = useMemo(
    () => (snapshot?.nodes || []).filter((entry) => isBootstrapConsensusValidator(entry?.node)).length,
    [snapshot],
  );
  const bootstrapValidatorQuorum = validatorNetworkClusterQuorumThreshold(bootstrapValidatorCount);
  const validatorQuorumReady = installedBootstrapValidatorIds.length >= bootstrapValidatorQuorum;
  const isBootstrapNode = isBootstrapConsensusValidator(nodeDetails?.status?.node);
  const isStagedBootstrap = Boolean(
    nodeDetails?.status?.node
      && isBootstrapNode
      && installedBootstrapValidatorIds.includes(normalize(nodeDetails.status.node.node_slot_id))
      && !validatorQuorumReady
      && !nodeDetails?.status?.online,
  );
  const displayNodeStatus = isStagedBootstrap ? 'online' : nodeStatus;
  const heroTone =
    displayNodeStatus === 'online'
      ? 'healthy'
      : displayNodeStatus === 'syncing'
        ? 'degraded'
        : displayNodeStatus === 'offline'
          ? 'critical'
          : 'unknown';
  const statusSummary =
    isStagedBootstrap
      ? `Installed and waiting for validator quorum. ${installedBootstrapValidatorIds.length}/${bootstrapValidatorQuorum} bootstrap validators are installed.`
      : syncing === true
      ? 'Syncing toward chain head.'
      : syncing === false
        ? 'Tracking chain head normally.'
        : 'Sync state not reported yet.';

  const handleControlAction = async (action) => {
    if (!nodeSlotId) return;
    let requestedAction = action;
    if (action === 'validator_wait_promote_vote_only') {
      const normalizedHeight = voteOnlyRejoinHeight.trim();
      if (!/^\d+$/.test(normalizedHeight)) {
        setControlResult({
          success: false,
          action,
          exit_code: -1,
          stdout: '',
          stderr: 'Vote-only rejoin height must be a numeric finalized block height.',
          command: 'N/A',
          executed_at_utc: new Date().toISOString(),
        });
        return;
      }
      requestedAction = `${action}_${normalizedHeight}`;
    }

    if (action in REQUIRES_NODE_ACTION_CONFIRMATION) {
      const message = REQUIRES_NODE_ACTION_CONFIRMATION[action];
      const approved = window.confirm(message);
      if (!approved) return;
    }

    setControlBusyAction(action);
    setControlResult(null);

    try {
      if (isBootstrapNode && (action === 'start' || action === 'restart')) {
        const bulkResult = await invoke('monitor_bulk_node_control', {
          action,
          scope: installedBootstrapValidatorIds.join(','),
        });
        const failures = Array.isArray(bulkResult?.results)
          ? bulkResult.results.filter((entry) => !entry?.success)
          : [];
        setControlResult({
          success: Number(bulkResult?.failed || 0) === 0,
          action,
          exit_code: Number(bulkResult?.failed || 0) === 0 ? 0 : 1,
          stdout: `${bulkResult?.succeeded || 0} succeeded, ${bulkResult?.failed || 0} failed across ${bulkResult?.requested_nodes || 0} bootstrap validators.`,
          stderr: failures
            .map((entry) => `${entry.node_slot_id}: ${entry.stderr || 'unknown failure'}`)
            .join('\n'),
          command: `bulk:${action} ${installedBootstrapValidatorIds.join(',')}`,
          executed_at_utc: bulkResult?.executed_at_utc || new Date().toISOString(),
        });
      } else {
        const result = await invoke('monitor_node_control', {
          nodeSlotId,
          action: requestedAction,
        });
        setControlResult(result);
      }
      await fetchNodeDetails(true);
      await fetchSnapshot();
    } catch (err) {
      setControlResult({
        success: false,
        action,
        exit_code: -1,
        stdout: '',
        stderr: String(err),
        command: 'N/A',
        executed_at_utc: new Date().toISOString(),
      });
    } finally {
      setControlBusyAction('');
    }
  };

  const handleExportNodeData = async () => {
    if (!nodeSlotId) return;
    setExportBusy(true);
    setExportResult(null);
    try {
      const result = await invoke('monitor_export_node_data', { nodeSlotId });
      setExportResult({ ok: true, ...result });
    } catch (err) {
      setExportResult({
        ok: false,
        error: String(err),
        exported_at_utc: new Date().toISOString(),
      });
    } finally {
      setExportBusy(false);
    }
  };

  const handleLocalAgentUpdate = async () => {
    if (!nodeSlotId) return;
    setControlBusyAction('update_agent');
    setControlResult(null);

    try {
      const result = await invoke('monitor_update_local_agent', { nodeSlotId });
      setControlResult(result);
      await fetchNodeDetails(true);
      await fetchSnapshot();
    } catch (err) {
      setControlResult({
        success: false,
        action: 'update_agent',
        exit_code: -1,
        stdout: '',
        stderr: String(err),
        command: 'N/A',
        executed_at_utc: new Date().toISOString(),
      });
    } finally {
      setControlBusyAction('');
    }
  };

  const scrollToSection = (sectionId) => {
    const target = document.getElementById(sectionId);
    if (!target) return;
    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  if (detailsLoading) {
    return (
      <section className="monitor-shell">
        <div className="loading-container">
          <div className="spinner"></div>
          <p>Loading node diagnostics...</p>
        </div>
      </section>
    );
  }

  const control = nodeDetails?.control;
  const roleExecution = nodeDetails?.role_execution;
  const atlas = nodeDetails?.atlas;
  const roleOperations = dedupeByKey(
    (nodeDetails?.role_operations || []).filter((action) => action?.category !== 'custom'),
  );
  const customActions = dedupeByKey(control?.custom_actions || []);
  const resetChainAction = customActions.find((action) => action?.key === 'reset_chain');
  const customActionsVisible = customActions.filter((action) => action?.key !== 'reset_chain');
  const voteOnlyPromoteVisible = [...customActionsVisible, ...roleOperations]
    .some((action) => action?.key === 'validator_wait_promote_vote_only');
  const node = nodeDetails?.status?.node;
  const localMachineMatch =
    normalize(localMachineIdentity?.physical_machine_id) !== ''
    && normalize(localMachineIdentity?.physical_machine_id) === normalize(node?.physical_machine_id);
  const agentUpdateAvailable = localMachineMatch || control?.update_agent_configured;
  const agentUpdateTitle = localMachineMatch
    ? 'Reinstall the bundled local agent on this machine and restart the local service. No SSH keys are required.'
    : 'Push the latest local agent binary to the remote machine via SSH and restart it. Use when the remote agent is missing, outdated, or unresponsive.';
  const agentUpdateLabel = localMachineMatch ? 'Update Local Agent' : 'Update Agent';
  const protocolProfile = isRecord(nodeDetails?.protocol_profile) ? nodeDetails.protocol_profile : {};
  const economicsProfile = isRecord(nodeDetails?.economics_profile) ? nodeDetails.economics_profile : {};
  const economicsLive = isRecord(economicsProfile.live) ? economicsProfile.live : {};
  const economicsGenesis = isRecord(economicsProfile.genesis) ? economicsProfile.genesis : {};
  const economicsTelemetry = isRecord(economicsProfile.telemetry)
    ? economicsProfile.telemetry
    : {};
  const rewardHistory = Array.isArray(economicsLive.reward_history) ? economicsLive.reward_history : [];
  const recentRewardHistory = [...rewardHistory]
    .sort((a, b) => Number(b?.timestamp || 0) - Number(a?.timestamp || 0))
    .slice(0, 6);
  const synergyBreakdown = isRecord(economicsLive.synergy_breakdown)
    ? economicsLive.synergy_breakdown
    : {};
  const synergyComponents = isRecord(economicsLive.synergy_components)
    ? economicsLive.synergy_components
    : {};
  const localValidator = isRecord(nodeDetails?.role_diagnostics?.local_validator)
    ? nodeDetails.role_diagnostics.local_validator
    : null;
  const isAuthorityRole =
    ['consensus', 'governance'].includes(normalize(node?.role_group))
    || normalize(node?.role).includes('validator')
    || normalize(node?.node_type).includes('validator')
    || normalize(node?.node_type).includes('committee')
    || normalize(node?.role).includes('committee');
  const signatureAlgorithms = extractSignatureAlgorithms(nodeDetails?.rpc?.latest_block);
  const telemetryGaps = [];
  const economicsGaps = Array.isArray(economicsTelemetry.telemetry_gaps)
    ? economicsTelemetry.telemetry_gaps
    : [];
  const configuredChainId =
    toNumber(protocolProfile.chain_id) ?? toNumber(protocolProfile.network_id);
  const observedChainId =
    toNumber(findNestedValue(nodeDetails?.rpc?.node_status, ['chainId', 'chain_id']))
    ?? toNumber(findNestedValue(nodeDetails?.rpc?.node_info, ['chainId', 'chain_id']));
  const displayNodeAddress =
    node?.node_address
    || protocolProfile.validator_address
    || findNestedValue(nodeDetails?.rpc?.node_status, ['validator_address', 'node_address', 'address'])
    || findNestedValue(nodeDetails?.rpc?.node_info, ['validator_address', 'node_address', 'address'])
    || findNestedValue(localValidator, ['validator_address', 'node_address', 'address'])
    || 'N/A';
  const quickFacts = [
    { label: 'Configured Chain ID', value: configuredChainId != null ? String(configuredChainId) : 'N/A', code: true },
    { label: 'Node Slot', value: node?.node_slot_id || nodeSlotId },
    { label: 'Physical Machine', value: node?.physical_machine_id || 'N/A' },
    { label: 'Node Alias', value: node?.node_alias || 'N/A' },
    { label: 'Role Group', value: node?.role_group || 'N/A' },
    { label: 'Node Type', value: node?.node_type || 'N/A' },
    { label: 'Address', value: displayNodeAddress, code: true },
  ];
  const runtimeFacts = [
    { label: 'RPC Endpoint', value: node?.rpc_url || 'N/A', code: true },
    { label: 'Observed Chain ID', value: observedChainId != null ? String(observedChainId) : 'N/A', code: true },
    { label: 'Status', value: nodeDetails?.status?.status || 'unknown' },
    { label: 'Syncing', value: scalar(nodeDetails?.status?.syncing) },
    { label: 'Checked', value: formatLocalTimestamp(nodeDetails?.status?.last_checked_utc) },
    { label: 'Captured', value: formatLocalTimestamp(nodeDetails?.captured_at_utc) },
    { label: 'Role Summary', value: roleExecution?.summary || 'No execution assessment available.' },
  ];
  const healthStats = [
    { label: 'Network Head', value: scalar(networkMaxHeight) },
    { label: 'Local Height', value: scalar(localHeight) },
    { label: 'Block Lag', value: scalar(blockLag), tone: blockLag > 25 ? 'critical' : blockLag > 0 ? 'degraded' : 'healthy' },
    { label: 'Peers', value: scalar(nodeDetails?.status?.peer_count), tone: Number(nodeDetails?.status?.peer_count || 0) > 0 ? 'healthy' : 'critical' },
    { label: 'Latency', value: `${scalar(nodeDetails?.status?.response_ms)} ms`, tone: Number(nodeDetails?.status?.response_ms || 0) > 1000 ? 'degraded' : 'healthy' },
  ];
  const validatorActivity = nodeDetails?.rpc?.validator_activity;
  const syncStatus = nodeDetails?.rpc?.sync_status;
  const nodeStatusPayload = nodeDetails?.rpc?.node_status;
  const scoreValue = findNestedValue(localValidator, [
    'synergy_score',
    'current_synergy_score',
    'score',
    'total_score',
  ]) ?? findNestedValue(validatorActivity, ['average_synergy_score']);
  const stakeValue = findNestedValue(localValidator, ['stake_amount', 'stake', 'bond']);
  const blocksProducedValue = findNestedValue(localValidator, [
    'blocks_produced',
    'produced_blocks',
    'block_production_count',
  ]);
  const participationValue = findNestedValue(localValidator, [
    'participation_rate',
    'epoch_participation',
    'participation_score',
    'participation',
  ]);
  const uptimeValue = findNestedValue(localValidator, [
    'uptime_score',
    'availability_score',
    'uptime',
  ]);
  const collaborationValue = findNestedValue(localValidator, [
    'collaboration_score',
    'cooperation_score',
    'collaboration',
  ]);
  const governanceWeightValue = findNestedValue(localValidator, [
    'governance_weight',
    'governance_voting_weight',
    'voting_weight',
  ]);
  const currentEpochValue = findNestedValue(syncStatus, [
    'current_epoch',
    'epoch_number',
    'epoch',
  ]) ?? findNestedValue(nodeStatusPayload, ['current_epoch', 'epoch_number', 'epoch']);
  const epochProgressValue = findNestedValue(syncStatus, [
    'epoch_progress',
    'progress',
    'epoch_completion',
  ]);
  const committeeIdValue = findNestedValue(localValidator, [
    'cluster_id',
    'committee_id',
    'active_cluster_id',
  ]) ?? findNestedValue(syncStatus, ['cluster_id', 'committee_id', 'active_cluster_id']);
  const viewValue = findNestedValue(syncStatus, [
    'current_view',
    'view_number',
    'view',
  ]);
  const quorumValue = findNestedValue(syncStatus, [
    'quorum_threshold',
    'quorum',
    'required_votes',
  ]);
  const votesCastValue = findNestedValue(localValidator, [
    'votes_cast',
    'vote_count',
    'votes',
  ]);
  const missedVotesValue = findNestedValue(localValidator, [
    'missed_votes',
    'votes_missed',
  ]);
  const missedProposalsValue = findNestedValue(localValidator, [
    'missed_proposals',
    'proposals_missed',
  ]);
  const slashedValue = findNestedValue(localValidator, ['slashed', 'is_slashed']);
  const proposalCountValue = findNestedValue(localValidator, [
    'proposal_count',
    'proposals_made',
    'proposals',
  ]);
  const protocolRows = [
    { label: 'Consensus Algorithm', value: protocolProfile.algorithm || 'N/A' },
    { label: 'Block Time', value: protocolProfile.block_time_secs ? `${protocolProfile.block_time_secs}s` : 'N/A' },
    { label: 'Epoch Length', value: protocolProfile.epoch_length ? `${protocolProfile.epoch_length} blocks` : 'N/A' },
    { label: 'Cluster Size', value: scalar(protocolProfile.validator_cluster_size) },
    { label: 'Max Validators', value: dynamicMaxValidators(protocolProfile.max_validators) },
    { label: 'VRF Rotation', value: protocolProfile.vrf_seed_epoch_interval ? `Every ${protocolProfile.vrf_seed_epoch_interval} epochs` : 'N/A' },
    { label: 'Bootnodes', value: protocolProfile.bootnode_count ? `${protocolProfile.bootnode_count} configured` : 'N/A' },
    { label: 'Snapshot Interval', value: protocolProfile.snapshot_interval_blocks ? `${protocolProfile.snapshot_interval_blocks} blocks` : 'N/A' },
  ];
  const authorityRows = [
    { label: 'Synergy Score', value: scoreValue !== undefined ? formatNumberValue(scoreValue, { maximumFractionDigits: 2 }) : 'N/A' },
    { label: 'Stake Bond', value: formatStakeValue(stakeValue) },
    { label: 'Blocks Produced', value: formatNumberValue(blocksProducedValue) },
    { label: 'Participation Signal', value: participationValue !== undefined ? formatPercentValue(participationValue) : 'N/A' },
    { label: 'Availability Signal', value: uptimeValue !== undefined ? formatPercentValue(uptimeValue) : 'N/A' },
    { label: 'Collaboration Signal', value: collaborationValue !== undefined ? formatPercentValue(collaborationValue) : 'N/A' },
    { label: 'Governance Weight', value: governanceWeightValue !== undefined ? formatNumberValue(governanceWeightValue, { maximumFractionDigits: 2 }) : 'N/A' },
    { label: 'Score Decay Rate', value: protocolProfile.synergy_score_decay_rate !== undefined ? formatPercentValue(protocolProfile.synergy_score_decay_rate) : 'N/A' },
  ];
  const committeeRows = [
    { label: 'Current Epoch', value: formatNumberValue(currentEpochValue) },
    { label: 'Epoch Progress', value: epochProgressValue !== undefined ? formatPercentValue(epochProgressValue) : 'N/A' },
    { label: 'Committee / Cluster ID', value: scalar(committeeIdValue) },
    { label: 'Validator Registry', value: localValidator ? 'Present in active validator activity' : 'Not observed yet' },
    { label: 'VRF Enabled', value: formatBooleanPill(protocolProfile.vrf_enabled) },
    { label: 'VRF Seed Interval', value: protocolProfile.vrf_seed_epoch_interval ? `${protocolProfile.vrf_seed_epoch_interval} epochs` : 'N/A' },
    { label: 'Max Synergy / Epoch', value: formatNumberValue(protocolProfile.max_synergy_points_per_epoch) },
    { label: 'Max Tasks / Validator', value: formatNumberValue(protocolProfile.max_tasks_per_validator) },
  ];
  const finalityRows = [
    { label: 'Network Head', value: formatNumberValue(networkMaxHeight) },
    { label: 'Local Height', value: formatNumberValue(localHeight) },
    { label: 'Block Lag', value: formatNumberValue(blockLag) },
    { label: 'Peer Count', value: formatNumberValue(nodeDetails?.status?.peer_count) },
    { label: 'Syncing', value: formatBooleanPill(nodeDetails?.status?.syncing) },
    { label: 'Current View', value: formatNumberValue(viewValue) },
    { label: 'Quorum Target', value: formatNumberValue(quorumValue) },
    { label: 'Latest Signatures', value: signatureAlgorithms.length ? signatureAlgorithms.join(', ') : 'No signature metadata observed' },
  ];
  const accountabilityRows = [
    { label: 'Votes Cast', value: formatNumberValue(votesCastValue) },
    { label: 'Missed Votes', value: formatNumberValue(missedVotesValue) },
    { label: 'Proposal Count', value: formatNumberValue(proposalCountValue) },
    { label: 'Missed Proposals', value: formatNumberValue(missedProposalsValue) },
    { label: 'Slashed', value: formatBooleanPill(slashedValue) },
    {
      label: 'Reward Weights',
      value: compactLines([
        protocolProfile.reward_weighting?.task_accuracy !== undefined
          ? `accuracy ${formatPercentValue(protocolProfile.reward_weighting.task_accuracy)}`
          : '',
        protocolProfile.reward_weighting?.uptime !== undefined
          ? `uptime ${formatPercentValue(protocolProfile.reward_weighting.uptime)}`
          : '',
        protocolProfile.reward_weighting?.collaboration !== undefined
          ? `collaboration ${formatPercentValue(protocolProfile.reward_weighting.collaboration)}`
          : '',
      ]),
    },
    {
      label: 'Snapshotting',
      value: protocolProfile.snapshotting_enabled
        ? `Enabled every ${formatNumberValue(protocolProfile.snapshot_interval_blocks)} blocks`
        : 'Disabled',
    },
  ];
  const capitalRows = [
    { label: 'Node Wallet', value: economicsProfile.node_address || node?.node_address || 'N/A', code: true },
    { label: 'Token', value: economicsProfile.token_symbol || 'SNRG' },
    { label: 'Genesis Allocation Type', value: economicsGenesis.allocation_type || 'N/A' },
    { label: 'Genesis Funded Total', value: formatSnrgValue(economicsGenesis.balance_snrg) },
    { label: 'Genesis Bonded Stake', value: formatSnrgValue(economicsGenesis.stake_snrg) },
    { label: 'Genesis Liquid Wallet', value: formatSnrgValue(economicsGenesis.liquid_snrg) },
    { label: 'Genesis Description', value: economicsGenesis.description || 'N/A' },
    { label: 'Genesis Source', value: economicsGenesis.source_path || 'N/A', code: true },
  ];
  const liveEconomicsRows = [
    { label: 'Current Wallet Balance', value: formatSnrgValue(economicsLive.wallet_balance_snrg) },
    { label: 'Current Bonded Stake', value: formatSnrgValue(economicsLive.staked_balance_snrg) },
    { label: 'Current Total Position', value: formatSnrgValue(economicsLive.current_total_position_snrg) },
    { label: 'Net Position vs Genesis', value: formatSignedSnrgValue(economicsLive.net_position_delta_snrg) },
    { label: 'Historical Rewards Earned', value: formatSnrgValue(economicsLive.historical_earned_snrg) },
    { label: 'Pending Rewards', value: formatSnrgValue(economicsLive.pending_rewards_snrg) },
    { label: 'Estimated APY', value: formatPercentValue(economicsLive.estimated_apy) },
    { label: 'Commission Rate', value: formatPercentValue(economicsLive.commission_rate) },
    { label: 'Staking Entries', value: formatNumberValue(economicsLive.staking_entry_count) },
  ];
  const incentiveRows = [
    { label: 'Synergy Multiplier', value: economicsLive.synergy_multiplier !== undefined ? `${formatNumberValue(economicsLive.synergy_multiplier, { maximumFractionDigits: 3 })}x` : 'N/A' },
    { label: 'Total Score', value: formatNumberValue(synergyBreakdown.total_score, { maximumFractionDigits: 2 }) },
    { label: 'Normalized Score', value: formatNumberValue(synergyComponents.normalized_score, { maximumFractionDigits: 2 }) },
    { label: 'Stake Weight', value: formatNumberValue(synergyComponents.stake_weight, { maximumFractionDigits: 2 }) },
    { label: 'Reputation', value: formatNumberValue(synergyComponents.reputation, { maximumFractionDigits: 2 }) },
    { label: 'Contribution Index', value: formatNumberValue(synergyComponents.contribution_index, { maximumFractionDigits: 2 }) },
    { label: 'Cartelization Penalty', value: formatNumberValue(synergyComponents.cartelization_penalty, { maximumFractionDigits: 2 }) },
    { label: 'Rank', value: formatNumberValue(synergyBreakdown.rank) },
    { label: 'Percentile', value: formatPercentValue(synergyBreakdown.percentile) },
    { label: 'Score Updated', value: formatUnixTimestamp(synergyComponents.last_updated) },
  ];
  const economicsSummaryStats = [
    { label: 'Wallet', value: formatSnrgValue(economicsLive.wallet_balance_snrg) },
    { label: 'Bonded', value: formatSnrgValue(economicsLive.staked_balance_snrg) },
    { label: 'Earned', value: formatSnrgValue(economicsLive.historical_earned_snrg) },
    { label: 'Pending', value: formatSnrgValue(economicsLive.pending_rewards_snrg) },
    { label: 'APY', value: formatPercentValue(economicsLive.estimated_apy) },
    { label: 'Net vs Genesis', value: formatSignedSnrgValue(economicsLive.net_position_delta_snrg) },
  ];
  const consensusSummaryStats = [
    {
      label: 'Synergy Score',
      value:
        scoreValue !== undefined
          ? formatNumberValue(scoreValue, { maximumFractionDigits: 2 })
          : 'N/A',
    },
    { label: 'Current Epoch', value: formatNumberValue(currentEpochValue) },
    { label: 'Committee / Cluster', value: scalar(committeeIdValue) },
    {
      label: 'Participation',
      value:
        participationValue !== undefined ? formatPercentValue(participationValue) : 'N/A',
    },
    { label: 'Blocks Produced', value: formatNumberValue(blocksProducedValue) },
    { label: 'Latest Signatures', value: signatureAlgorithms.length ? signatureAlgorithms.join(', ') : 'N/A' },
  ];
  if (scoreValue === undefined) {
    telemetryGaps.push('Synergy Score is not exposed in the current validator activity payload for this node yet.');
  }
  if (currentEpochValue === undefined) {
    telemetryGaps.push('Current epoch and rotation progress are not exposed by the current sync-status RPC payload.');
  }
  if (viewValue === undefined) {
    telemetryGaps.push('View-change telemetry is not exposed by the current RPC surface yet.');
  }
  const sectionLinks = [
    ['overview', 'Overview'],
    ...(protocolProfile.loaded ? [['posy', 'PoSy']] : []),
    ...(economicsProfile.loaded || displayNodeAddress !== 'N/A' ? [['economics', 'Economics']] : []),
    ['execution', 'Execution'],
    ['control', 'Control'],
    ['atlas', 'Atlas'],
    ['rpc', 'RPC'],
  ];
  const controlSection = nodeDetails ? (
    <section id="control" className="monitor-control-shell">
      <div className="monitor-card-heading">
        <div>
          <p className="monitor-card-kicker">Control Plane</p>
          <h4>Node Actions</h4>
        </div>
      </div>
      <p className="monitor-control-hint">{control?.configuration_hint || 'No control configuration found.'}</p>

      <div className="monitor-control-buttons">
        <button
          className="monitor-btn"
          disabled={!control?.start_configured || !!controlBusyAction || (isBootstrapNode && !validatorQuorumReady)}
          onClick={() => handleControlAction('start')}
        >
          {controlBusyAction === 'start' ? 'Starting...' : 'Start'}
        </button>
        <button
          className="monitor-btn"
          disabled={!control?.stop_configured || !!controlBusyAction}
          onClick={() => handleControlAction('stop')}
        >
          {controlBusyAction === 'stop' ? 'Stopping...' : 'Stop'}
        </button>
        <button
          className="monitor-btn"
          disabled={!control?.restart_configured || !!controlBusyAction || (isBootstrapNode && !validatorQuorumReady)}
          onClick={() => handleControlAction('restart')}
        >
          {controlBusyAction === 'restart' ? 'Restarting...' : 'Restart'}
        </button>
        <button
          className="monitor-btn"
          disabled={!control?.status_configured || !!controlBusyAction}
          onClick={() => handleControlAction('status')}
        >
          {controlBusyAction === 'status' ? 'Querying...' : 'Status'}
        </button>
        <button
          className="monitor-btn"
          disabled={!control?.setup_configured || !!controlBusyAction}
          onClick={() => handleControlAction('setup')}
        >
          {controlBusyAction === 'setup' ? 'Installing...' : 'Install'}
        </button>
        <button
          className="monitor-btn"
          disabled={!control?.export_logs_configured || !!controlBusyAction}
          onClick={() => handleControlAction('export_logs')}
        >
          {controlBusyAction === 'export_logs' ? 'Exporting Logs...' : 'Export Logs'}
        </button>
        <button
          className="monitor-btn"
          disabled={!control?.view_chain_data_configured || !!controlBusyAction}
          onClick={() => handleControlAction('view_chain_data')}
        >
          {controlBusyAction === 'view_chain_data' ? 'Loading Chain Data...' : 'View Chain Data'}
        </button>
        <button
          className="monitor-btn"
          disabled={!control?.export_chain_data_configured || !!controlBusyAction}
          onClick={() => handleControlAction('export_chain_data')}
        >
          {controlBusyAction === 'export_chain_data' ? 'Exporting Chain Data...' : 'Export Chain Data'}
        </button>
        <button
          className="monitor-btn monitor-btn-primary"
          disabled={exportBusy || !!controlBusyAction}
          onClick={handleExportNodeData}
        >
          {exportBusy ? 'Exporting Node Snapshot...' : 'Export Node Snapshot'}
        </button>
        <button
          className="monitor-btn monitor-btn-warning"
          disabled={!control?.sync_node_configured || !!controlBusyAction || isBootstrapNode}
          onClick={() => {
            const approved = window.confirm(
              'Sync node from peers?\n\nThis runs "nodectl sync" to catch the node up from peers and then auto-start it after sync completes. The operation can take up to 2 hours for a node that is far behind.\n\nThe node must be stopped before syncing.',
            );
            if (approved) {
              handleControlAction('sync_node');
            }
          }}
          title="Catch the node up from peers and auto-start it after sync completes. Use for late-joining or long-offline non-validator nodes."
        >
          {controlBusyAction === 'sync_node' ? 'Syncing...' : 'Sync Node'}
        </button>
        <button
          className="monitor-btn monitor-btn-agent"
          disabled={!agentUpdateAvailable || !!controlBusyAction}
          onClick={() => {
            const approved = window.confirm(
              localMachineMatch
                ? 'Update the local agent for this machine?\n\nThis reinstalls the bundled agent binary from the control panel resources and restarts the local agent service/process.\n\nNo SSH keys are required, but this only works when you are running the control panel on the same physical machine as the selected node.'
                : 'Update the agent on this node?\n\nThis pushes the latest agent binary to the remote machine via SSH and restarts the agent service.\n\nPrerequisite: run scripts/build-sidecars.sh first to compile binaries.\n\nThis operation uses SSH directly — it works even when the remote agent is offline or running an outdated version.',
            );
            if (approved) {
              if (localMachineMatch) {
                handleLocalAgentUpdate();
              } else {
                handleControlAction('update_agent');
              }
            }
          }}
          title={agentUpdateTitle}
        >
          {controlBusyAction === 'update_agent' ? 'Updating Agent...' : agentUpdateLabel}
        </button>
        <button
          className="monitor-btn monitor-btn-danger"
          disabled={!resetChainAction?.configured || !!controlBusyAction}
          onClick={() => {
            const approved = window.confirm(
              'Reset chain to genesis for this node?\n\nThis stops the node and deletes all local chain state. The node will NOT restart automatically — use Start or Start All when ready.',
            );
            if (approved) {
              handleControlAction('reset_chain');
            }
          }}
          title="Stop node and delete chain data. Node will not auto-restart."
        >
          {controlBusyAction === 'reset_chain' ? 'Resetting Chain...' : 'Reset Chain (Genesis)'}
        </button>
      </div>

      {voteOnlyPromoteVisible && (
        <div className="monitor-action-group">
          <h5>Vote-only Recovery Input</h5>
          <label className="monitor-inline-field">
            <span>Vote-only rejoin height</span>
            <input
              inputMode="numeric"
              pattern="[0-9]*"
              value={voteOnlyRejoinHeight}
              onChange={(event) => setVoteOnlyRejoinHeight(event.target.value)}
              placeholder="Finalized block height"
            />
          </label>
        </div>
      )}

      {customActionsVisible.length > 0 && (
        <div className="monitor-action-group">
          <h5>Custom Machine Operations</h5>
          <div className="monitor-control-buttons">
            {customActionsVisible.map((action) => (
              <button
                key={action.key}
                className="monitor-btn"
                disabled={!action.configured || !!controlBusyAction}
                onClick={() => handleControlAction(action.key)}
                title={action.description}
              >
                {controlBusyAction === action.key ? 'Running...' : action.label}
              </button>
            ))}
          </div>
        </div>
      )}

      {roleOperations.length > 0 && (
        <div className="monitor-action-group">
          <h5>Role-Specific Operations</h5>
          <div className="monitor-control-buttons">
            {roleOperations.map((action) => (
              <button
                key={action.key}
                className="monitor-btn"
                disabled={!action.configured || !!controlBusyAction}
                onClick={() => handleControlAction(action.key)}
                title={action.description}
              >
                {controlBusyAction === action.key ? 'Running...' : action.label}
              </button>
            ))}
          </div>
        </div>
      )}

      {controlResult && (
        <div className={`monitor-control-result ${controlResult.success ? 'monitor-control-ok' : 'monitor-control-fail'}`}>
          <p>
            <strong>Action:</strong> {controlResult.action} | <strong>Success:</strong>{' '}
            {String(controlResult.success)} | <strong>Exit:</strong> {controlResult.exit_code}
          </p>
          <p><strong>Command:</strong> <code>{controlResult.command}</code></p>
          {controlResult.stdout && (
            <details>
              <summary>stdout</summary>
              <pre>{controlResult.stdout}</pre>
            </details>
          )}
          {controlResult.stderr && (
            <details>
              <summary>stderr</summary>
              <pre>{controlResult.stderr}</pre>
            </details>
          )}
        </div>
      )}

      {exportResult && (
        <div className={`monitor-control-result ${exportResult.ok ? 'monitor-control-ok' : 'monitor-control-fail'}`}>
          <p>
            <strong>Export Success:</strong> {String(exportResult.ok)} | <strong>When:</strong>{' '}
            {formatLocalTimestamp(exportResult.exported_at_utc)}
          </p>
          {exportResult.ok ? (
            <>
              <p><strong>File:</strong> <code>{exportResult.file_path}</code></p>
              <p><strong>Bytes:</strong> {exportResult.bytes}</p>
            </>
          ) : (
            <p><strong>Error:</strong> {exportResult.error}</p>
          )}
        </div>
      )}
    </section>
  ) : null;

  return (
    <section className="monitor-shell monitor-shell-node">
      <div className="monitor-page-hero monitor-page-hero-node">
        <div className="monitor-hero-copy">
          <p className="monitor-hero-eyebrow">Node Slot Diagnostics</p>
          <h2 className="monitor-hero-title">
            {node?.node_slot_id || nodeSlotId}
            {' '}
            /
            {' '}
            {node?.role || 'unknown-role'}
          </h2>
          <p className="monitor-hero-summary">
            {statusSummary}
            {' '}
            Role execution summary:
            {' '}
            {roleExecution?.summary || 'No execution assessment available yet.'}
          </p>
          <div className="monitor-inline-pills">
            <span className={`monitor-inline-pill monitor-inline-pill-${heroTone}`}>
              {displayNodeStatus}
            </span>
            <span className="monitor-inline-pill">
              Physical
              {' '}
              {node?.physical_machine_id || 'N/A'}
            </span>
            <span className="monitor-inline-pill">
              Node Alias
              {' '}
              {node?.node_alias || 'N/A'}
            </span>
            <span className="monitor-inline-pill">
              Captured
              {' '}
              {formatLocalTimestamp(nodeDetails?.captured_at_utc)}
            </span>
          </div>
        </div>
        <div className="monitor-hero-actions">
          <Link className="monitor-link-btn" to="/">
            Back to Fleet Matrix
          </Link>
          <div className="monitor-node-nav">
            <Link
              className={`monitor-link-btn ${previousNode ? '' : 'monitor-link-btn-disabled'}`}
              to={previousNode ? `/node/${encodeURIComponent(previousNode.node.node_slot_id)}` : '#'}
              onClick={(event) => {
                if (!previousNode) event.preventDefault();
              }}
            >
              Previous Node
            </Link>
            <Link
              className={`monitor-link-btn ${nextNode ? '' : 'monitor-link-btn-disabled'}`}
              to={nextNode ? `/node/${encodeURIComponent(nextNode.node.node_slot_id)}` : '#'}
              onClick={(event) => {
                if (!nextNode) event.preventDefault();
              }}
            >
              Next Node
            </Link>
          </div>
          <button className="monitor-btn monitor-btn-primary" onClick={() => { fetchNodeDetails(); fetchSnapshot(); }}>
            Refresh Node
          </button>
          <label className="monitor-toggle">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(event) => setAutoRefresh(event.target.checked)}
            />
            Auto-refresh
          </label>
          <label className="monitor-refresh-select">
            Interval
            <select
              value={refreshSeconds}
              onChange={(event) => setRefreshSeconds(Number(event.target.value))}
              disabled={!autoRefresh}
            >
              {REFRESH_SECONDS_OPTIONS.map((seconds) => (
                <option key={seconds} value={seconds}>
                  {seconds}s
                </option>
              ))}
            </select>
          </label>
        </div>
      </div>

      <div className="monitor-stat-grid">
        {healthStats.map((stat) => (
          <article key={stat.label} className={`monitor-stat-card ${stat.tone ? `monitor-stat-card-${stat.tone}` : ''}`}>
            <span className="monitor-stat-label">{stat.label}</span>
            <strong className="monitor-stat-value">{stat.value}</strong>
          </article>
        ))}
      </div>

      <nav className="monitor-section-nav">
        {sectionLinks.map(([id, label]) => (
          <button
            key={id}
            type="button"
            className="monitor-section-nav-chip"
            onClick={() => scrollToSection(id)}
          >
            {label}
          </button>
        ))}
      </nav>

      {controlSection}

      {detailsError && (
        <div className="monitor-error-box">
          <strong>Node detail error:</strong> {detailsError}
        </div>
      )}

      {!detailsError
        && configuredChainId !== null
        && observedChainId !== null
        && configuredChainId !== observedChainId && (
          <div className="monitor-error-box">
            <strong>Chain ID mismatch:</strong>
            {' '}
            Installed config expects
            {' '}
            <code>{configuredChainId}</code>
            {' '}
            but RPC is reporting
            {' '}
            <code>{observedChainId}</code>
            .
          </div>
      )}

      {!detailsError && nodeDetails && (
        <div className="monitor-node-layout">
          <div className="monitor-node-main">
            <section id="overview" className="monitor-detail-grid monitor-detail-grid-overview">
              <article className="monitor-detail-card monitor-detail-card-identity">
                <div className="monitor-card-heading">
                  <div>
                    <p className="monitor-card-kicker">Identity</p>
                    <h4>Slot and Host Mapping</h4>
                  </div>
                  <span className={`monitor-execution-pill monitor-execution-${heroTone}`}>
                    {nodeStatus}
                  </span>
                </div>
                <dl className="monitor-data-list">
                  {quickFacts.map((fact) => (
                    <div key={fact.label} className="monitor-data-row">
                      <dt>{fact.label}</dt>
                      <dd>{fact.code ? <code>{fact.value}</code> : fact.value}</dd>
                    </div>
                  ))}
                </dl>
              </article>

              <article className="monitor-detail-card monitor-detail-card-runtime">
                <div className="monitor-card-heading">
                  <div>
                    <p className="monitor-card-kicker">Runtime</p>
                    <h4>Node Process Snapshot</h4>
                  </div>
                </div>
                <dl className="monitor-data-list">
                  {runtimeFacts.map((fact) => (
                    <div key={fact.label} className="monitor-data-row">
                      <dt>{fact.label}</dt>
                      <dd>{fact.code ? <code>{fact.value}</code> : fact.value}</dd>
                    </div>
                  ))}
                </dl>
              </article>

              <article className="monitor-detail-card monitor-detail-card-diagnostics">
                <div className="monitor-card-heading">
                  <div>
                    <p className="monitor-card-kicker">Diagnostics</p>
                    <h4>Role-Specific Readout</h4>
                  </div>
                </div>
                {roleDiagnosticsEntries.length === 0 ? (
                  <p className="monitor-empty-state">No role diagnostics available.</p>
                ) : (
                  <dl className="monitor-data-list">
                    {roleDiagnosticsEntries.map(([key, value]) => (
                      <div key={key} className="monitor-data-row">
                        <dt>{titleizeKey(key)}</dt>
                        <dd className="monitor-detail-value">{scalar(value)}</dd>
                      </div>
                    ))}
                  </dl>
                )}
              </article>
            </section>

            {protocolProfile.loaded && (
              <section id="posy" className="monitor-posy-shell">
                <div className="monitor-card-heading">
                  <div>
                    <p className="monitor-card-kicker">Proof-of-Synergy</p>
                    <h4>Consensus Authority, Rotation, and Finality</h4>
                  </div>
                </div>
                <p className="monitor-posy-lede">
                  PoSy is a deterministic-finality BFT model with cooperative weighting. These
                  cards surface the actual protocol constants from this node’s config and the live
                  authority/finality signals currently exposed by RPC.
                </p>
                <div className="monitor-detail-grid monitor-posy-grid">
                  <article className="monitor-detail-card">
                    <div className="monitor-card-heading">
                      <div>
                        <p className="monitor-card-kicker">Protocol Constants</p>
                        <h4>Configured PoSy Envelope</h4>
                      </div>
                    </div>
                    <dl className="monitor-data-list">
                      {protocolRows.map((fact) => (
                        <div key={fact.label} className="monitor-data-row">
                          <dt>{fact.label}</dt>
                          <dd>{fact.value}</dd>
                        </div>
                      ))}
                    </dl>
                  </article>

                  {isAuthorityRole && (
                    <article className="monitor-detail-card">
                      <div className="monitor-card-heading">
                        <div>
                          <p className="monitor-card-kicker">Authority Primitive</p>
                          <h4>Synergy Score and Cooperative Weighting</h4>
                        </div>
                      </div>
                      <dl className="monitor-data-list">
                        {authorityRows.map((fact) => (
                          <div key={fact.label} className="monitor-data-row">
                            <dt>{fact.label}</dt>
                            <dd>{fact.value}</dd>
                          </div>
                        ))}
                      </dl>
                    </article>
                  )}

                  {isAuthorityRole && (
                    <article className="monitor-detail-card">
                      <div className="monitor-card-heading">
                        <div>
                          <p className="monitor-card-kicker">Cluster Rotation</p>
                          <h4>Epoch and Committee Surface</h4>
                        </div>
                      </div>
                      <dl className="monitor-data-list">
                        {committeeRows.map((fact) => (
                          <div key={fact.label} className="monitor-data-row">
                            <dt>{fact.label}</dt>
                            <dd>{fact.value}</dd>
                          </div>
                        ))}
                      </dl>
                    </article>
                  )}

                  {isAuthorityRole && (
                    <article className="monitor-detail-card">
                      <div className="monitor-card-heading">
                        <div>
                          <p className="monitor-card-kicker">Finality Pipeline</p>
                          <h4>Propose, Vote, Commit Signals</h4>
                        </div>
                      </div>
                      <dl className="monitor-data-list">
                        {finalityRows.map((fact) => (
                          <div key={fact.label} className="monitor-data-row">
                            <dt>{fact.label}</dt>
                            <dd>{fact.value}</dd>
                          </div>
                        ))}
                      </dl>
                    </article>
                  )}

                  {isAuthorityRole && (
                    <article className="monitor-detail-card">
                      <div className="monitor-card-heading">
                        <div>
                          <p className="monitor-card-kicker">Accountability</p>
                          <h4>Fault Memory and Recovery Signals</h4>
                        </div>
                      </div>
                      <dl className="monitor-data-list">
                        {accountabilityRows.map((fact) => (
                          <div key={fact.label} className="monitor-data-row">
                            <dt>{fact.label}</dt>
                            <dd>{fact.value}</dd>
                          </div>
                        ))}
                      </dl>
                    </article>
                  )}
                </div>

                {isAuthorityRole && telemetryGaps.length > 0 && (
                  <div className="monitor-posy-gaps">
                    <div className="monitor-card-heading">
                      <div>
                        <p className="monitor-card-kicker">Telemetry Gaps</p>
                        <h4>Not Yet Exposed By RPC</h4>
                      </div>
                    </div>
                    <div className="monitor-note-stack">
                      {telemetryGaps.map((note) => (
                        <p key={note}>{note}</p>
                      ))}
                    </div>
                  </div>
                )}
              </section>
            )}

            <section id="economics" className="monitor-economics-shell">
              <div className="monitor-card-heading">
                <div>
                  <p className="monitor-card-kicker">Economics</p>
                  <h4>SNRG Wallet, Bond, and Reward Surface</h4>
                </div>
              </div>
              <p className="monitor-posy-lede">
                This section separates funded capital from currently bonded stake and live rewards.
                Genesis values come from the current workspace genesis file; live values come from
                node RPC where available.
              </p>
              <div className="monitor-detail-grid monitor-economics-grid">
                <article className="monitor-detail-card">
                  <div className="monitor-card-heading">
                    <div>
                      <p className="monitor-card-kicker">Capital Base</p>
                      <h4>Genesis Funding Model</h4>
                    </div>
                  </div>
                  <dl className="monitor-data-list">
                    {capitalRows.map((fact) => (
                      <div key={fact.label} className="monitor-data-row">
                        <dt>{fact.label}</dt>
                        <dd>{fact.code ? <code>{fact.value}</code> : fact.value}</dd>
                      </div>
                    ))}
                  </dl>
                </article>

                <article className="monitor-detail-card">
                  <div className="monitor-card-heading">
                    <div>
                      <p className="monitor-card-kicker">Live Position</p>
                      <h4>Wallet, Bond, and Earnings</h4>
                    </div>
                  </div>
                  <dl className="monitor-data-list">
                    {liveEconomicsRows.map((fact) => (
                      <div key={fact.label} className="monitor-data-row">
                        <dt>{fact.label}</dt>
                        <dd>{fact.value}</dd>
                      </div>
                    ))}
                  </dl>
                </article>

                <article className="monitor-detail-card">
                  <div className="monitor-card-heading">
                    <div>
                      <p className="monitor-card-kicker">Incentive Profile</p>
                      <h4>Synergy-Weighted Reward Inputs</h4>
                    </div>
                  </div>
                  <dl className="monitor-data-list">
                    {incentiveRows.map((fact) => (
                      <div key={fact.label} className="monitor-data-row">
                        <dt>{fact.label}</dt>
                        <dd>{fact.value}</dd>
                      </div>
                    ))}
                  </dl>
                </article>

                <article className="monitor-detail-card monitor-economics-history-card">
                  <div className="monitor-card-heading">
                    <div>
                      <p className="monitor-card-kicker">Reward History</p>
                      <h4>Latest Reward Accrual Entries</h4>
                    </div>
                  </div>
                  {recentRewardHistory.length === 0 ? (
                    <p className="monitor-empty-state">
                      No reward history was returned for this node yet.
                    </p>
                  ) : (
                    <div className="monitor-economics-history">
                      {recentRewardHistory.map((entry, index) => (
                        <div key={`${entry?.timestamp || 'reward'}-${index}`} className="monitor-economics-history-row">
                          <div>
                            <strong>{formatSnrgValue(entry?.amount_snrg)}</strong>
                            <span>{entry?.reward_type || 'validator'}</span>
                          </div>
                          <div>
                            <strong>
                              Block
                              {' '}
                              {formatNumberValue(entry?.block_number)}
                            </strong>
                            <span>{formatUnixTimestamp(entry?.timestamp)}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </article>
              </div>

              {economicsGaps.length > 0 && (
                <div className="monitor-economics-gaps">
                  <div className="monitor-card-heading">
                    <div>
                      <p className="monitor-card-kicker">Telemetry Gaps</p>
                      <h4>Economics Data Still Missing</h4>
                    </div>
                  </div>
                  <div className="monitor-note-stack">
                    {economicsGaps.map((note) => (
                      <p key={note}>{note}</p>
                    ))}
                  </div>
                </div>
              )}
            </section>

            <section id="execution" className="monitor-execution-shell">
              <div className="monitor-execution-header">
                <div>
                  <p className="monitor-card-kicker">Execution</p>
                  <h4>Role Execution Status</h4>
                </div>
                <span className={`monitor-execution-pill monitor-execution-${roleExecution?.overall_status || 'unknown'}`}>
                  {roleExecution?.overall_status || 'unknown'}
                </span>
              </div>
              <p className="monitor-control-hint">{roleExecution?.summary || 'No execution assessment available.'}</p>
              <div className="monitor-execution-scoreboard">
                <article className="monitor-mini-stat monitor-mini-stat-pass">
                  <span>Pass</span>
                  <strong>{countByStatus(roleExecution?.checks, 'pass')}</strong>
                </article>
                <article className="monitor-mini-stat monitor-mini-stat-warn">
                  <span>Warn</span>
                  <strong>{countByStatus(roleExecution?.checks, 'warn')}</strong>
                </article>
                <article className="monitor-mini-stat monitor-mini-stat-fail">
                  <span>Fail</span>
                  <strong>{countByStatus(roleExecution?.checks, 'fail')}</strong>
                </article>
              </div>
              <div className="monitor-execution-table-wrap">
                <table className="monitor-execution-table">
                  <thead>
                    <tr>
                      <th>Check</th>
                      <th>Status</th>
                      <th>Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(roleExecution?.checks || []).map((check) => (
                      <tr key={check.key}>
                        <td>{check.label}</td>
                        <td>
                          <span className={`monitor-check-pill monitor-check-${check.status}`}>
                            {check.status}
                          </span>
                        </td>
                        <td>{check.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="monitor-role-notes">
              <div className="monitor-card-heading">
                <div>
                  <p className="monitor-card-kicker">Operational Notes</p>
                  <h4>What This Slot Should Be Doing</h4>
                </div>
              </div>
              <div className="monitor-note-stack">
                {(nodeDetails.role_notes || []).map((note, idx) => (
                  <p key={`${node?.node_slot_id}-note-${idx}`}>{note}</p>
                ))}
              </div>
            </section>

            <section id="atlas" className="monitor-atlas-shell">
              <div className="monitor-execution-header">
                <div>
                  <p className="monitor-card-kicker">Explorer</p>
                  <h4>Atlas Explorer Bridge</h4>
                </div>
                <span className={`monitor-execution-pill monitor-execution-${atlas?.enabled ? 'healthy' : 'unknown'}`}>
                  {atlas?.enabled ? 'connected' : 'not-configured'}
                </span>
              </div>
              {!atlas?.enabled ? (
                <p className="monitor-control-hint">
                  Atlas link integration is not configured. Set <code>ATLAS_BASE_URL</code> or
                  <code> EXPLORER_URL</code> in the current workspace <code>hosts.env</code>.
                </p>
              ) : (
                <div className="monitor-atlas-links">
                  {atlas.home_url && (
                    <a href={atlas.home_url} target="_blank" rel="noreferrer" className="monitor-link-btn">
                      Atlas Home
                    </a>
                  )}
                  {atlas.transactions_url && (
                    <a href={atlas.transactions_url} target="_blank" rel="noreferrer" className="monitor-link-btn">
                      Transactions
                    </a>
                  )}
                  {atlas.wallets_url && (
                    <a href={atlas.wallets_url} target="_blank" rel="noreferrer" className="monitor-link-btn">
                      Wallets
                    </a>
                  )}
                  {atlas.contracts_url && (
                    <a href={atlas.contracts_url} target="_blank" rel="noreferrer" className="monitor-link-btn">
                      Contracts
                    </a>
                  )}
                  {atlas.latest_block_url && (
                    <a href={atlas.latest_block_url} target="_blank" rel="noreferrer" className="monitor-link-btn">
                      Latest Block
                    </a>
                  )}
                  {atlas.latest_transaction_url && (
                    <a href={atlas.latest_transaction_url} target="_blank" rel="noreferrer" className="monitor-link-btn">
                      Latest Transaction
                    </a>
                  )}
                  {atlas.node_wallet_url && (
                    <a href={atlas.node_wallet_url} target="_blank" rel="noreferrer" className="monitor-link-btn">
                      Node Wallet
                    </a>
                  )}
                </div>
              )}
              {atlas?.latest_transaction_hash && (
                <p className="monitor-control-hint">
                  Latest tx hash: <code>{atlas.latest_transaction_hash}</code>
                </p>
              )}
            </section>

            <section id="rpc" className="monitor-rpc-shell">
              <div className="monitor-card-heading">
                <div>
                  <p className="monitor-card-kicker">RPC</p>
                  <h4>Direct Diagnostic Payloads</h4>
                </div>
                <span className="monitor-inline-pill">
                  {Array.isArray(nodeDetails.rpc.errors) ? nodeDetails.rpc.errors.length : 0}
                  {' '}
                  error(s)
                </span>
              </div>
              <div className="monitor-rpc-grid">
                <article className="monitor-rpc-card">
                  <h4>synergy_nodeInfo</h4>
                  <pre>{jsonPretty(nodeDetails.rpc.node_info)}</pre>
                </article>
                <article className="monitor-rpc-card">
                  <h4>synergy_getNodeStatus</h4>
                  <pre>{jsonPretty(nodeDetails.rpc.node_status)}</pre>
                </article>
                <article className="monitor-rpc-card">
                  <h4>synergy_getSyncStatus</h4>
                  <pre>{jsonPretty(nodeDetails.rpc.sync_status)}</pre>
                </article>
                <article className="monitor-rpc-card">
                  <h4>synergy_getPeerInfo</h4>
                  <pre>{jsonPretty(nodeDetails.rpc.peer_info)}</pre>
                </article>
                <article className="monitor-rpc-card">
                  <h4>synergy_getValidatorActivity</h4>
                  <pre>{jsonPretty(nodeDetails.rpc.validator_activity)}</pre>
                </article>
                <article className="monitor-rpc-card">
                  <h4>synergy_getTokenBalance</h4>
                  <pre>{jsonPretty(nodeDetails.rpc.token_balance)}</pre>
                </article>
                <article className="monitor-rpc-card">
                  <h4>synergy_getStakingInfo</h4>
                  <pre>{jsonPretty(nodeDetails.rpc.staking_info)}</pre>
                </article>
                <article className="monitor-rpc-card">
                  <h4>synergy_getStakedBalance</h4>
                  <pre>{jsonPretty(nodeDetails.rpc.staked_balance)}</pre>
                </article>
                <article className="monitor-rpc-card">
                  <h4>synergy_getSynergyScoreBreakdown</h4>
                  <pre>{jsonPretty(nodeDetails.rpc.synergy_score_breakdown)}</pre>
                </article>
                <article className="monitor-rpc-card">
                  <h4>synergy_getLatestBlock</h4>
                  <pre>{jsonPretty(nodeDetails.rpc.latest_block)}</pre>
                </article>
                <article className="monitor-rpc-card">
                  <h4>SXCP: relayer set + attestations</h4>
                  <pre>{jsonPretty({ relayer_set: nodeDetails.rpc.relayer_set, attestations: nodeDetails.rpc.attestations })}</pre>
                </article>
                <article className="monitor-rpc-card">
                  <h4>synergy_getDivergenceStatus</h4>
                  <pre>{jsonPretty(nodeDetails.rpc.divergence_status)}</pre>
                </article>
                <article className="monitor-rpc-card">
                  <h4>synergy_getQuarantineStatus</h4>
                  <pre>{jsonPretty(nodeDetails.rpc.quarantine_status)}</pre>
                </article>
                <article className="monitor-rpc-card">
                  <h4>synergy_getSelfHealStatus</h4>
                  <pre>{jsonPretty(nodeDetails.rpc.self_heal_status)}</pre>
                </article>
                <article className="monitor-rpc-card">
                  <h4>synergy_getSnapshotCatalog</h4>
                  <pre>{jsonPretty(nodeDetails.rpc.snapshot_catalog)}</pre>
                </article>
                <article className="monitor-rpc-card">
                  <h4>synergy_getShadowStatus</h4>
                  <pre>{jsonPretty(nodeDetails.rpc.shadow_status)}</pre>
                </article>
                <article className="monitor-rpc-card">
                  <h4>synergy_getRejoinEligibility</h4>
                  <pre>{jsonPretty(nodeDetails.rpc.rejoin_eligibility)}</pre>
                </article>
              </div>
            </section>
          </div>

          <aside className="monitor-node-sidecar">
            <section className="monitor-sidecar-card">
              <p className="monitor-card-kicker">Operator Snapshot</p>
              <h4>At-a-Glance</h4>
              <div className="monitor-sidecar-stat-list">
                {healthStats.map((stat) => (
                  <div key={stat.label} className="monitor-sidecar-stat">
                    <span>{stat.label}</span>
                    <strong>{stat.value}</strong>
                  </div>
                ))}
              </div>
            </section>

            <section className="monitor-sidecar-card">
              <p className="monitor-card-kicker">SNRG Position</p>
              <h4>Wallet and Bond</h4>
              <div className="monitor-sidecar-stat-list">
                {economicsSummaryStats.map((stat) => (
                  <div key={stat.label} className="monitor-sidecar-stat">
                    <span>{stat.label}</span>
                    <strong>{stat.value}</strong>
                  </div>
                ))}
              </div>
            </section>

            {isAuthorityRole && (
              <section className="monitor-sidecar-card">
                <p className="monitor-card-kicker">Consensus Surface</p>
                <h4>Score, Epoch, and Committee</h4>
                <div className="monitor-sidecar-stat-list">
                  {consensusSummaryStats.map((stat) => (
                    <div key={stat.label} className="monitor-sidecar-stat">
                      <span>{stat.label}</span>
                      <strong>{stat.value}</strong>
                    </div>
                  ))}
                </div>
              </section>
            )}

            <section className="monitor-sidecar-card">
              <p className="monitor-card-kicker">Available Actions</p>
              <h4>Current Action Sets</h4>
              <div className="monitor-tag-cluster">
                {customActionsVisible.map((action) => (
                  <span key={action.key} className={`monitor-action-tag ${action.configured ? '' : 'monitor-action-tag-disabled'}`}>
                    {action.label}
                  </span>
                ))}
                {roleOperations.map((action) => (
                  <span key={action.key} className={`monitor-action-tag monitor-action-tag-role ${action.configured ? '' : 'monitor-action-tag-disabled'}`}>
                    {action.label}
                  </span>
                ))}
              </div>
            </section>

            {Array.isArray(nodeDetails.rpc.errors) && nodeDetails.rpc.errors.length > 0 && (
              <section className="monitor-sidecar-card monitor-sidecar-card-alert">
                <p className="monitor-card-kicker">Attention</p>
                <h4>RPC Diagnostics Errors</h4>
                <div className="monitor-sidecar-list">
                  {nodeDetails.rpc.errors.map((item) => (
                    <p key={item}>{item}</p>
                  ))}
                </div>
              </section>
            )}
          </aside>
        </div>
      )}
    </section>
  );
}

export default NetworkMonitorNodePage;

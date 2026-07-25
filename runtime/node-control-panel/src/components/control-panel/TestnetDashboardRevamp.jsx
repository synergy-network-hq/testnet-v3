import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { openPath, resolvePeerTopology, invoke } from '../../lib/desktopClient';
import { SNRGButton } from '../../styles/SNRGButton';
import { useControlPanel } from './ControlPanelProvider';
import {
  formatNumber,
  formatPercent,
  formatRuntimeDuration,
  formatScore,
  networkHealthSummary,
  nodeBlockHeightDetail,
  nodeBlockHeightValue,
  nodeRuntimeLabel,
  nodeRuntimeTone,
  nodeSyncPercent,
  roleTypeLabel,
  safeArray,
  simplifyLogEntry,
  statusTone,
} from './controlPanelModel';
import {
  ActivityFeed,
  EmptyPanel,
  JarvisCard,
  MetricBars,
  MetricCard,
  PanelCard,
  SectionHeader,
  StatusPill,
  TopologyMap,
} from './ControlPanelShared';
import HealthTrendChart from './charts/HealthTrendChart';
import PeerTrendChart from './charts/PeerTrendChart';
import ResourceTrendChart from './charts/ResourceTrendChart';
import PeerGlobe from './PeerGlobe';
import PeerGlobeLegend from './PeerGlobeLegend';
import ActionAuditStream from './ActionAuditStream';
import JsonInspectorPanel from './JsonInspectorPanel';
import ValidatorCatchUpCard from './ValidatorCatchUpCard';
import {
  boostSyncAction,
  registerWithSeedsAction,
  restartNodeAction,
  runNodeControlAction,
  syncCatchUpRejoinAction,
} from './controlPanelActions';

function sliceByTimeRange(points = [], timeRange = '6h') {
  const durationMs = {
    '30m': 30 * 60 * 1000,
    '1h': 60 * 60 * 1000,
    '6h': 6 * 60 * 60 * 1000,
    '24h': 24 * 60 * 60 * 1000,
  }[timeRange] || 6 * 60 * 60 * 1000;
  const cutoff = Date.now() - durationMs;
  return points.filter((point) => Number(point?.at) >= cutoff);
}

function buildBootstrapPeerRecords(liveStatus) {
  return safeArray(liveStatus?.bootnodes).map((entry, index) => ({
    id: entry?.host || `bootnode-${index}`,
    address: `${entry?.host || 'bootstrap'}:${entry?.port || 5622}`,
    publicAddress: `${entry?.host || 'bootstrap'}:${entry?.port || 5622}`,
    version: 'bootstrap',
    lastSeen: entry?.reachable ? Date.now() : Date.now() - 90_000,
    latencyMs: Number(entry?.latency_ms) || null,
    direction: 'outbound',
  }));
}

function buildSeverityBins(entries = []) {
  const buckets = new Map();
  safeArray(entries).forEach((entry) => {
    const at = new Date(entry?.timestamp_utc || Date.now());
    at.setSeconds(0, 0);
    const key = at.getTime();
    const current = buckets.get(key) || { id: `bin-${key}`, at: key, info: 0, warn: 0, error: 0 };
    const level = String(entry?.level || 'INFO').toUpperCase();
    if (level === 'ERROR') current.error += 1;
    else if (level === 'WARN') current.warn += 1;
    else current.info += 1;
    buckets.set(key, current);
  });
  return Array.from(buckets.values()).sort((left, right) => left.at - right.at);
}

function buildPrimaryAction(selectedNodeLive) {
  if (!selectedNodeLive?.is_running) {
    return { kind: 'start', label: 'Start node', tone: 'lime' };
  }
  if ((Number(selectedNodeLive?.sync_gap) || 0) > 48) {
    return { kind: 'sync-catch-up', label: 'Sync Catch Up', tone: 'purple' };
  }
  return { kind: 'refresh', label: 'Reconnect', tone: 'blue' };
}

function buildChecklist({ selectedNodeLive, networkStats, activityItems }) {
  const hasWarnings = activityItems.some((item) => item.tone === 'warn' || item.tone === 'bad');
  return [
    {
      id: 'runtime',
      label: selectedNodeLive?.is_running ? 'Node runtime is online' : 'Start the node runtime',
      detail: selectedNodeLive?.is_running
        ? 'The control panel can see the process heartbeat.'
        : 'The process is stopped right now.',
      done: selectedNodeLive?.is_running === true,
    },
    {
      id: 'sync',
      label: (Number(selectedNodeLive?.sync_gap) || 0) <= 2 ? 'Keep sync within range' : 'Wait for sync to complete',
      detail: (Number(selectedNodeLive?.sync_gap) || 0) <= 2
        ? 'The node is keeping up with the live chain.'
        : `${formatNumber(selectedNodeLive?.sync_gap)} blocks remain before the node is fully caught up.`,
      done: (Number(selectedNodeLive?.sync_gap) || 0) <= 2,
    },
    {
      id: 'network',
      label: networkStats.healthyBootnodes > 0 ? 'Network entry points are reachable' : 'Check network connection',
      detail: networkStats.healthyBootnodes > 0
        ? `${formatNumber(networkStats.healthyBootnodes)} bootstrap services are responding.`
        : 'Bootstrap reachability is failing, so peer discovery will stall.',
      done: networkStats.healthyBootnodes > 0,
    },
    {
      id: 'logs',
      label: hasWarnings ? 'Review the recent warnings' : 'No urgent warnings are active',
      detail: hasWarnings
        ? 'Read the important moments feed before taking the next action.'
        : 'The recent activity feed looks routine.',
      done: !hasWarnings,
    },
  ];
}

function renderChecklist(items) {
  return (
    <div className="cp-guidance-checklist">
      {items.map((item) => (
        <article key={item.id} className={`cp-guidance-step ${item.done ? 'is-complete' : ''}`}>
          <div className="cp-guidance-marker">{item.done ? '✓' : String(items.indexOf(item) + 1)}</div>
          <div>
            <strong>{item.label}</strong>
            <p>{item.detail}</p>
          </div>
        </article>
      ))}
    </div>
  );
}

function dashboardMetrics(selectedNode, selectedNodeLive, networkStats, liveStatus) {
  return [
    {
      label: 'Node status',
      value: nodeRuntimeLabel(selectedNodeLive),
      detail: nodeBlockHeightDetail(selectedNodeLive, liveStatus),
      tone: nodeRuntimeTone(selectedNodeLive),
      icon: 'monitor_heart',
    },
    {
      label: 'Network connection',
      value: `${formatNumber(selectedNodeLive?.local_peer_count ?? networkStats.totalPeers)} peers`,
      detail: networkStats.healthyBootnodes > 0 ? 'Discovery path is active' : 'Discovery path needs attention',
      tone: networkStats.healthyBootnodes > 0 ? 'cyan' : 'warn',
      icon: 'hub',
    },
    {
      label: 'Rewards status',
      value: selectedNode?.role_display_name ? roleTypeLabel(selectedNode.role_display_name) : 'Waiting',
      detail: 'Open Earnings for payout and participation detail',
      tone: 'purple',
      icon: 'savings',
    },
  ];
}

export default function TestnetDashboardRevamp({ onLaunchSetup }) {
  const navigate = useNavigate();
  const {
    actionAudit,
    error,
    liveStatus,
    loading,
    network,
    networkStats,
    nodes,
    nodeLiveById,
    recordAction,
    refresh,
    selectedNode,
    selectedNodeLive,
    selectedRole,
    setSelectedNodeId,
    telemetryHistory,
    timeRange,
    setTimeRange,
    viewMode,
    viewProfile,
  } = useControlPanel();

  const [actionBusy, setActionBusy] = useState('');
  const [notice, setNotice] = useState('');
  const [nodeLogBundle, setNodeLogBundle] = useState(null);
  const [logsLoading, setLogsLoading] = useState(false);
  const [catchUpResult, setCatchUpResult] = useState(null);
  const [bootstrapTopology, setBootstrapTopology] = useState({
    points: [],
    regionSummary: [],
    routes: [],
  });

  useEffect(() => {
    if (!notice) {
      return undefined;
    }

    const timer = window.setTimeout(() => setNotice(''), 3600);
    return () => window.clearTimeout(timer);
  }, [notice]);

  useEffect(() => {
    let cancelled = false;

    const loadTopology = async () => {
      const topology = await resolvePeerTopology({
        peers: buildBootstrapPeerRecords(liveStatus),
        localNode: selectedNode,
        bootnodes: liveStatus?.bootnodes,
      });
      if (!cancelled) {
        setBootstrapTopology(topology);
      }
    };

    void loadTopology();
    return () => {
      cancelled = true;
    };
  }, [liveStatus, selectedNode]);

  useEffect(() => {
    if (!selectedNode) {
      setNodeLogBundle(null);
      setLogsLoading(false);
      return undefined;
    }

    let cancelled = false;
    const loadLogs = async () => {
      if (!cancelled) {
        setLogsLoading(true);
      }
      try {
        const bundle = await invoke('testnet_get_node_logs', {
          nodeId: selectedNode.id,
          lines: viewMode === 'developer' ? 220 : 120,
        });
        if (!cancelled) {
          setNodeLogBundle(bundle || null);
        }
      } catch {
        if (!cancelled) {
          setNodeLogBundle(null);
        }
      } finally {
        if (!cancelled) {
          setLogsLoading(false);
        }
      }
    };

    void loadLogs();
    const intervalId = window.setInterval(loadLogs, viewMode === 'developer' ? 3000 : 5000);
    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [selectedNode, viewMode]);

  const handleAction = async (kind) => {
    if (!selectedNode) {
      return;
    }

    setActionBusy(kind);
    try {
      let message = '';
      if (kind === 'start') {
        const result = await runNodeControlAction({ node: selectedNode, network, action: 'start' });
        message = result.message;
      } else if (kind === 'restart') {
        message = await restartNodeAction({ node: selectedNode, network });
      } else if (kind === 'sync-catch-up') {
        const actionResult = await syncCatchUpRejoinAction({ node: selectedNode, network });
        setCatchUpResult(actionResult.result || null);
        message = actionResult.message;
      } else if (kind === 'boost') {
        message = await boostSyncAction(selectedNode.id);
      } else if (kind === 'refresh') {
        message = await registerWithSeedsAction(selectedNode.id);
      } else {
        const result = await runNodeControlAction({ node: selectedNode, network, action: kind });
        message = result.message;
      }

      recordAction({
        title: `${kind} action`,
        detail: message,
        status: 'good',
        source: 'dashboard',
        command: kind,
      });
      setNotice(message);
      await refresh({ silent: true });
    } catch (actionError) {
      const detail = String(actionError);
      recordAction({
        title: `${kind} action failed`,
        detail,
        status: 'bad',
        source: 'dashboard',
        command: kind,
      });
      setNotice(detail);
    } finally {
      setActionBusy('');
    }
  };

  const handleCatchUpRepair = (action) => {
    if (action === 'rewards') {
      navigate('/rewards');
      return;
    }
    if (action === 'diagnostics') {
      navigate(viewMode === 'developer' ? '/diagnostics' : '/settings');
      return;
    }
    if (action === 'settings') {
      navigate('/settings');
      return;
    }
    if (action === 'register-seeds') {
      void handleAction('refresh');
      return;
    }
    void handleAction(action);
  };

  const handleCopyValidatorAddress = async () => {
    if (!selectedNode?.node_address) {
      setNotice('No validator address is available to copy.');
      return;
    }

    try {
      await navigator.clipboard.writeText(selectedNode.node_address);
      setNotice('Full validator address copied.');
    } catch (copyError) {
      setNotice(String(copyError));
    }
  };

  const healthSummary = useMemo(() => networkHealthSummary(liveStatus), [liveStatus]);
  const nodeHistory = useMemo(
    () => sliceByTimeRange(telemetryHistory.byNodeId?.[selectedNode?.id] || [], timeRange),
    [selectedNode?.id, telemetryHistory.byNodeId, timeRange],
  );
  const networkHistory = useMemo(
    () => sliceByTimeRange(telemetryHistory.network || [], timeRange),
    [telemetryHistory.network, timeRange],
  );
  const activityItems = useMemo(
    () => safeArray(nodeLogBundle?.entries).slice(-10).reverse().map((entry) => simplifyLogEntry(entry, viewMode)),
    [nodeLogBundle?.entries, viewMode],
  );
  const criticalEvents = useMemo(
    () => activityItems.filter((item) => item.tone === 'warn' || item.tone === 'bad'),
    [activityItems],
  );
  const checklistItems = useMemo(
    () => buildChecklist({ selectedNodeLive, networkStats, activityItems }),
    [activityItems, networkStats, selectedNodeLive],
  );
  const primaryAction = buildPrimaryAction(selectedNodeLive);
  const syncPercent = nodeSyncPercent(selectedNodeLive, liveStatus);
  const heroNarrative = selectedNode
    ? (viewMode === 'basic'
      ? `${selectedNode.display_label || 'Your node'} is ${nodeRuntimeLabel(selectedNodeLive).toLowerCase()}. ${healthSummary.detail}`
      : `${selectedNode.display_label || 'Selected node'} is ${nodeRuntimeLabel(selectedNodeLive).toLowerCase()} with ${formatNumber(selectedNodeLive?.local_peer_count ?? networkStats.totalPeers)} visible peers.`)
    : 'Provision a node to populate the dashboard.';

  const basicMetrics = dashboardMetrics(selectedNode, selectedNodeLive, networkStats, liveStatus);
  const chartSeries = [
    {
      key: 'peers',
      label: 'Peer count',
      tone: 'cyan',
      values: nodeHistory.map((entry) => ({ at: entry.at, value: entry.localPeerCount })),
    },
    {
      key: 'syncLag',
      label: 'Sync lag',
      tone: 'warn',
      values: nodeHistory.map((entry) => ({ at: entry.at, value: entry.syncGap })),
    },
    {
      key: 'score',
      label: 'Health score',
      tone: 'purple',
      values: nodeHistory.map((entry) => ({ at: entry.at, value: entry.score })),
    },
  ];
  const healthSeries = nodeHistory.map((entry) => ({
    at: entry.at,
    value: entry.isRunning ? Math.max(10, 100 - Math.min(90, entry.syncGap)) : 0,
  }));
  const signalBars = [
    {
      id: 'sync',
      label: 'Sync',
      value: formatPercent(syncPercent, 0),
      detail: nodeBlockHeightDetail(selectedNodeLive, liveStatus),
      numericValue: syncPercent,
      tone: nodeRuntimeTone(selectedNodeLive),
    },
    {
      id: 'peers',
      label: 'Peers',
      value: formatNumber(selectedNodeLive?.local_peer_count ?? networkStats.totalPeers),
      detail: 'Visible sessions',
      numericValue: Number(selectedNodeLive?.local_peer_count ?? networkStats.totalPeers ?? 0),
      tone: 'cyan',
    },
    {
      id: 'score',
      label: 'Score',
      value: formatScore(selectedNodeLive?.synergy_score),
      detail: selectedNodeLive?.synergy_score_status || 'Waiting for telemetry',
      numericValue: Number(selectedNodeLive?.synergy_score ?? 0),
      tone: 'purple',
    },
    {
      id: 'runtime',
      label: 'Uptime',
      value: formatRuntimeDuration(selectedNodeLive?.process_uptime_secs),
      detail: selectedNodeLive?.is_running ? 'Process heartbeat is healthy' : 'Process is stopped',
      numericValue: Number(selectedNodeLive?.process_uptime_secs ?? 0),
      tone: selectedNodeLive?.is_running ? 'good' : 'warn',
    },
  ];
  const severityBins = useMemo(() => buildSeverityBins(nodeLogBundle?.entries), [nodeLogBundle?.entries]);

  if (!loading && !nodes.length) {
    return (
      <EmptyPanel
        title="No node workspaces yet"
        copy="Launch Jarvis setup to provision the first Synergy node on this machine."
        actionLabel="Launch Setup"
        onAction={onLaunchSetup}
      />
    );
  }

  return (
    <div className="cp-page-stack">
      <SectionHeader
        eyebrow={viewProfile.label}
        title={viewProfile.navLabels.dashboard}
        copy={heroNarrative}
        actions={(
          <>
            <div className="cp-chip-row">
              {['30m', '1h', '6h', '24h'].map((option) => (
                <button
                  key={option}
                  type="button"
                  className={`cp-chip cp-chip-button ${timeRange === option ? 'is-active' : ''}`}
                  onClick={() => setTimeRange(option)}
                >
                  {option}
                </button>
              ))}
            </div>
            <SNRGButton variant="blue" size="sm" onClick={() => void refresh()}>
              Refresh
            </SNRGButton>
          </>
        )}
      />

      {(notice || error) ? (
        <div className={`cp-inline-notice tone-${statusTone(notice || error)}`}>
          {notice || error}
        </div>
      ) : null}

      {selectedNode ? (
        <>
          {viewMode === 'basic' ? (
            <div className="cp-dashboard-grid">
              <div className="cp-dashboard-main">
                <PanelCard
                  className="cp-health-banner"
                  eyebrow="Overview"
                  title={healthSummary.title}
                  detail={healthSummary.detail}
                  action={<StatusPill tone={healthSummary.tone}>{nodeRuntimeLabel(selectedNodeLive)}</StatusPill>}
                >
                  <div className="cp-health-banner-body">
                    <p>{heroNarrative}</p>
                    <SNRGButton
                      variant={primaryAction.tone}
                      size="sm"
                      disabled={Boolean(actionBusy)}
                      onClick={() => void handleAction(primaryAction.kind)}
                    >
                      {actionBusy === primaryAction.kind ? 'Working...' : primaryAction.label}
                    </SNRGButton>
                  </div>
                </PanelCard>

                <ValidatorCatchUpCard
                  node={selectedNode}
                  nodeLive={selectedNodeLive}
                  liveStatus={liveStatus}
                  lastResult={catchUpResult}
                  actionBusy={actionBusy}
                  mode={viewMode}
                  onRun={() => void handleAction('sync-catch-up')}
                  onRepair={handleCatchUpRepair}
                />

                <div className="cp-metric-grid cp-metric-grid-dashboard">
                  {basicMetrics.map((metric) => (
                    <MetricCard key={metric.label} {...metric} />
                  ))}
                </div>

                <HealthTrendChart
                  title="Is my node keeping up?"
                  detail="A simple read on block-following and sync health."
                  data={healthSeries}
                  tone={nodeRuntimeTone(selectedNodeLive)}
                />

                <PanelCard title="Next steps checklist" detail="The safest next actions for this node right now.">
                  {renderChecklist(checklistItems)}
                </PanelCard>

                <ActivityFeed
                  title="Recent important moments"
                  detail={logsLoading ? 'Refreshing important activity...' : 'Natural-language highlights from the node workspace.'}
                  items={activityItems}
                />
              </div>

              <div className="cp-dashboard-side">
                <JarvisCard
                  mode={viewMode}
                  title="What this means"
                  message={heroNarrative}
                  chips={[
                    nodeRuntimeLabel(selectedNodeLive),
                    `${formatPercent(syncPercent, 0)} sync`,
                    `${formatNumber(selectedNodeLive?.local_peer_count ?? networkStats.totalPeers)} peers`,
                  ]}
                />

                <PanelCard title="Quick facts" detail="A short operator summary.">
                  <div className="cp-definition-list">
                    <div className="cp-definition-item cp-definition-item-full">
                      <span>Validator address</span>
                      <code className="cp-full-address">{selectedNode.node_address || 'Not reported yet'}</code>
                    </div>
                    <div className="cp-definition-item">
                      <span>Uptime</span>
                      <strong>{formatRuntimeDuration(selectedNodeLive?.process_uptime_secs)}</strong>
                    </div>
                    <div className="cp-definition-item">
                      <span>Last update</span>
                      <strong>{selectedNode?.updated_at_utc ? new Date(selectedNode.updated_at_utc).toLocaleString() : 'Unknown'}</strong>
                    </div>
                    <div className="cp-definition-item">
                      <span>Current role</span>
                      <strong>{roleTypeLabel(selectedNode.role_display_name)}</strong>
                    </div>
                    <div className="cp-definition-item">
                      <span>Connection count</span>
                      <strong>{formatNumber(selectedNodeLive?.local_peer_count ?? networkStats.totalPeers)} visible peers</strong>
                    </div>
                  </div>
                  <div className="cp-button-grid">
                    <SNRGButton variant="blue" size="sm" disabled={!selectedNode.node_address} onClick={() => void handleCopyValidatorAddress()}>
                      Copy Validator Address
                    </SNRGButton>
                    <SNRGButton as={Link} to="/node" variant="purple" size="sm">
                      Node Details
                    </SNRGButton>
                  </div>
                </PanelCard>

                <PanelCard
                  title="Peer regions"
                  detail="A small preview of where your node can currently see bootstrap entry points."
                  action={<SNRGButton as={Link} to="/connectivity" variant="blue" size="sm">Open Connections</SNRGButton>}
                >
                  <PeerGlobe
                    points={bootstrapTopology.points}
                    routes={bootstrapTopology.routes}
                    regionSummary={bootstrapTopology.regionSummary}
                    mode="basic"
                  />
                  <PeerGlobeLegend />
                </PanelCard>
              </div>
            </div>
          ) : viewMode === 'advanced' ? (
            <>
              <div className="cp-node-selector">
                {nodes.map((node) => (
                  <button
                    key={node.id}
                    type="button"
                    className={`cp-node-chip ${selectedNode?.id === node.id ? 'is-active' : ''}`}
                    onClick={() => setSelectedNodeId(node.id)}
                  >
                    <span>{node.display_label || roleTypeLabel(node.role_display_name)}</span>
                    <strong>{nodeRuntimeLabel(nodeLiveById[node.id] || null)}</strong>
                  </button>
                ))}
              </div>

              <div className="cp-dashboard-grid">
                <div className="cp-dashboard-main">
                  <PanelCard
                    className="cp-hero-panel"
                    eyebrow="Operational summary"
                    title={selectedNode.display_label || roleTypeLabel(selectedNode.role_display_name)}
                    detail={selectedRole?.authority_plane || 'Operator workspace'}
                    action={<StatusPill tone={nodeRuntimeTone(selectedNodeLive)}>{nodeRuntimeLabel(selectedNodeLive)}</StatusPill>}
                  >
                    <div className="cp-hero-layout">
                      <div className="cp-hero-copy">
                        <h2>Fast operational view</h2>
                        <p>{heroNarrative}</p>
                      </div>
                      <div className="cp-action-stack">
                        <SNRGButton variant="blue" size="sm" onClick={() => void handleAction('refresh')}>Reconnect peers</SNRGButton>
                        <SNRGButton variant="purple" size="sm" onClick={() => openPath(selectedNode.workspace_directory)}>Open workspace</SNRGButton>
                        <SNRGButton as={Link} to="/logs" variant="blue" size="sm">Open logs</SNRGButton>
                      </div>
                    </div>
                  </PanelCard>

                  <ValidatorCatchUpCard
                    node={selectedNode}
                    nodeLive={selectedNodeLive}
                    liveStatus={liveStatus}
                    lastResult={catchUpResult}
                    actionBusy={actionBusy}
                    mode={viewMode}
                    onRun={() => void handleAction('sync-catch-up')}
                    onRepair={handleCatchUpRepair}
                  />

                  <div className="cp-metric-grid cp-metric-grid-dashboard">
                    <MetricCard label="Health" value={nodeRuntimeLabel(selectedNodeLive)} detail={healthSummary.detail} tone={nodeRuntimeTone(selectedNodeLive)} icon="monitor_heart" />
                    <MetricCard label="Active peers" value={formatNumber(selectedNodeLive?.local_peer_count ?? networkStats.totalPeers)} detail="Visible from the selected node" tone="cyan" icon="hub" />
                    <MetricCard label="Sync lag" value={`${formatNumber(selectedNodeLive?.sync_gap ?? 0)} blocks`} detail={nodeBlockHeightDetail(selectedNodeLive, liveStatus)} tone={nodeRuntimeTone(selectedNodeLive)} icon="sync" />
                    <MetricCard label="Reward status" value={formatScore(selectedNodeLive?.synergy_score)} detail="Open Rewards for payout detail" tone="purple" icon="savings" />
                    <MetricCard label="RPC" value={networkStats.publicRpcOnline ? 'Online' : 'Checking'} detail="Public chain visibility" tone={networkStats.publicRpcOnline ? 'good' : 'warn'} icon="lan" />
                    <MetricCard label="Last action" value={actionAudit[0]?.title || 'None yet'} detail={actionAudit[0]?.detail || 'No recent machine actions'} tone={actionAudit[0]?.status || 'neutral'} icon="bolt" />
                  </div>

                  <PeerTrendChart title="Operational trend panel" detail="Peer count, sync lag, and score across the selected time range." series={chartSeries} />

                  <PanelCard
                    title="Topology summary"
                    detail="Compact interactive preview of regional peer posture."
                    action={<SNRGButton as={Link} to="/connectivity" variant="blue" size="sm">Open Connectivity</SNRGButton>}
                  >
                    <PeerGlobe
                      points={bootstrapTopology.points}
                      routes={bootstrapTopology.routes}
                      regionSummary={bootstrapTopology.regionSummary}
                      mode="advanced"
                    />
                    <PeerGlobeLegend />
                  </PanelCard>

                  <PanelCard title="Alerts and anomalies" detail="The loudest operational signals right now.">
                    <div className="cp-alert-stack">
                      {(criticalEvents.length ? criticalEvents : [{
                        id: 'steady-state',
                        title: 'No unresolved warnings',
                        detail: 'The recent event stream looks steady for the selected node.',
                        tone: 'good',
                        time: 'now',
                      }]).map((item) => (
                        <article key={item.id} className={`cp-alert-item tone-${item.tone || 'neutral'}`}>
                          <strong>{item.title}</strong>
                          <p>{item.detail}</p>
                          <small>{item.time}</small>
                        </article>
                      ))}
                    </div>
                  </PanelCard>

                  <MetricBars title="Quick diagnostics" detail="Operator checks for connection quality, score, runtime, and bootstrap reachability." items={signalBars} />
                </div>

                <div className="cp-dashboard-side">
                  <JarvisCard
                    mode={viewMode}
                    title="Operator guidance"
                    message={criticalEvents.length
                      ? 'The recent warning trail suggests you should review the logs and connectivity views before taking destructive actions.'
                      : 'The node looks stable. Use the trend panel and diagnostics cluster to confirm there is no hidden drift.'}
                    chips={[
                      `${formatNumber(criticalEvents.length)} anomalies`,
                      `${formatNumber(actionAudit.length)} recent actions`,
                      `${timeRange} window`,
                    ]}
                  />

                  <PanelCard title="Recent actions" detail="Machine actions performed in this workspace.">
                    <ActionAuditStream entries={actionAudit.slice(0, 6)} emptyMessage="No dashboard actions have been recorded yet." />
                  </PanelCard>

                  <PanelCard title="Quick tools" detail="Jump straight into deeper operational surfaces.">
                    <div className="cp-button-grid">
                      <SNRGButton as={Link} to={`/node/${selectedNode.id}`} variant="blue" size="sm">Node details</SNRGButton>
                      <SNRGButton as={Link} to="/connectivity" variant="purple" size="sm">Refresh topology</SNRGButton>
                      <SNRGButton as={Link} to="/rewards" variant="blue" size="sm">Open rewards</SNRGButton>
                      <SNRGButton variant="blue" size="sm" onClick={() => void handleAction('boost')}>Boost peers</SNRGButton>
                    </div>
                  </PanelCard>
                </div>
              </div>
            </>
          ) : (
            <div className="cp-dashboard-grid">
              <div className="cp-dashboard-main">
                <PanelCard
                  className="cp-hero-panel"
                  eyebrow="Runtime"
                  title={selectedNode.display_label || roleTypeLabel(selectedNode.role_display_name)}
                  detail={selectedNode.workspace_directory || 'Workspace pending'}
                  action={<StatusPill tone={nodeRuntimeTone(selectedNodeLive)} live>{nodeRuntimeLabel(selectedNodeLive)}</StatusPill>}
                >
                  <div className="cp-hero-layout">
                    <div className="cp-hero-copy">
                      <h2>Dense telemetry cockpit</h2>
                      <p>{heroNarrative}</p>
                    </div>
                    <div className="cp-action-stack">
                      <SNRGButton variant="blue" size="sm" onClick={() => void refresh()}>Reload snapshot</SNRGButton>
                      <SNRGButton variant="purple" size="sm" onClick={() => openPath(`${selectedNode.workspace_directory}/logs`)}>Open logs folder</SNRGButton>
                      <SNRGButton variant="blue" size="sm" onClick={() => openPath(selectedNode.workspace_directory)}>Open workspace</SNRGButton>
                      <SNRGButton variant="blue" size="sm" onClick={() => recordAction({
                        title: 'Copied raw status JSON',
                        detail: 'Use the raw inspector panel to copy the live payload.',
                        status: 'info',
                        source: 'runtime',
                      })}>Copy raw status JSON</SNRGButton>
                    </div>
                  </div>
                </PanelCard>

                <ValidatorCatchUpCard
                  node={selectedNode}
                  nodeLive={selectedNodeLive}
                  liveStatus={liveStatus}
                  lastResult={catchUpResult}
                  actionBusy={actionBusy}
                  mode={viewMode}
                  onRun={() => void handleAction('sync-catch-up')}
                  onRepair={handleCatchUpRepair}
                />

                <div className="cp-metric-grid cp-metric-grid-dashboard cp-metric-grid-dense">
                  <MetricCard label="Head height" value={formatNumber(nodeBlockHeightValue(selectedNodeLive, liveStatus))} detail="Local runtime head" tone={nodeRuntimeTone(selectedNodeLive)} icon="data_usage" />
                  <MetricCard label="Peer count" value={formatNumber(selectedNodeLive?.local_peer_count)} detail="Inbound + outbound sessions" tone="cyan" icon="hub" />
                  <MetricCard label="Sync lag" value={`${formatNumber(selectedNodeLive?.sync_gap ?? 0)} blocks`} detail="Gap to best visible network height" tone="warn" icon="sync" />
                  <MetricCard label="Score" value={formatScore(selectedNodeLive?.synergy_score)} detail={selectedNodeLive?.synergy_score_status || 'Telemetry pending'} tone="purple" icon="auto_graph" />
                  <MetricCard label="RPC latency" value={selectedNodeLive?.local_rpc_ready === false ? 'Starting' : 'Ready'} detail={selectedNodeLive?.local_rpc_status || 'Local RPC status'} tone={selectedNodeLive?.local_rpc_ready === false ? 'warn' : 'good'} icon="lan" />
                  <MetricCard label="Uptime" value={formatRuntimeDuration(selectedNodeLive?.process_uptime_secs)} detail="Process uptime" tone="good" icon="schedule" />
                  <MetricCard label="Event throughput" value={`${formatNumber(severityBins.slice(-1)[0]?.info ?? 0)} / min`} detail="Latest log bucket" tone="cyan" icon="timeline" />
                  <MetricCard label="Last action latency" value={actionAudit[0] ? 'Captured' : 'Waiting'} detail={actionAudit[0]?.title || 'No recorded action yet'} tone={actionAudit[0]?.status || 'neutral'} icon="bolt" />
                </div>

                <PeerTrendChart title="Telemetry chart stack" detail="Runtime, network, and sync traces derived from the live polling loop." series={chartSeries} />

                <div className="cp-split-grid">
                  <ResourceTrendChart title="Machine diagnostics" detail="Resource traces surfaced by the runtime snapshot." data={nodeHistory} />
                  <PanelCard title="Protocol snapshot" detail="Bootstraps, regions, and route posture for the selected runtime.">
                    <PeerGlobe
                      points={bootstrapTopology.points}
                      routes={bootstrapTopology.routes}
                      regionSummary={bootstrapTopology.regionSummary}
                      mode="developer"
                    />
                    <PeerGlobeLegend />
                  </PanelCard>
                </div>

                <PanelCard title="Action audit stream" detail="Raw local actions with source and timing.">
                  <ActionAuditStream entries={actionAudit.slice(0, 10)} emptyMessage="The runtime action stream is quiet right now." />
                </PanelCard>
              </div>

              <div className="cp-dashboard-side">
                <JsonInspectorPanel
                  title="Raw inspector"
                  value={{
                    selectedNode,
                    selectedNodeLive,
                    networkStats,
                  }}
                  emptyMessage="Runtime state will appear here after the first snapshot."
                />

                <PanelCard title="Subsystem health" detail="Key runtime planes for the selected node.">
                  <div className="cp-metric-grid">
                    <MetricCard label="P2P" value={formatNumber(selectedNodeLive?.local_peer_count)} detail="Visible sessions" tone="cyan" icon="hub" />
                    <MetricCard label="RPC" value={selectedNodeLive?.local_rpc_ready === false ? 'Starting' : 'Ready'} detail={selectedNodeLive?.local_rpc_status || 'Waiting'} tone={selectedNodeLive?.local_rpc_ready === false ? 'warn' : 'good'} icon="lan" />
                    <MetricCard label="Control-service" value="Online" detail="Desktop bridge is live" tone="good" icon="developer_board" />
                    <MetricCard label="Log pipeline" value={logsLoading ? 'Updating' : 'Ready'} detail={`${formatNumber(safeArray(nodeLogBundle?.entries).length)} entries buffered`} tone={logsLoading ? 'warn' : 'good'} icon="receipt_long" />
                  </div>
                </PanelCard>

                <JarvisCard
                  mode={viewMode}
                  title="Developer guidance"
                  message="Use the dock for shell and RPC work, the audit stream for action receipts, and the raw inspector when two subsystems disagree."
                  chips={[
                    `${formatNumber(actionAudit.length)} local actions`,
                    `${formatNumber(nodeHistory.length)} live points`,
                    `${timeRange} retained`,
                  ]}
                />
              </div>
            </div>
          )}
        </>
      ) : (
        <EmptyPanel
          title="Waiting for node selection"
          copy="A workspace exists, but the panel has not selected it yet."
          actionLabel="Refresh"
          onAction={() => void refresh()}
        />
      )}
    </div>
  );
}

import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { invoke, resolvePeerTopology } from '../../lib/desktopClient';
import { normalizePeerInfoPayload } from '../../lib/testnetPeerInfo';
import { SNRGButton } from '../../styles/SNRGButton';
import { useControlPanel } from './ControlPanelProvider';
import {
  buildLatencyBars,
  buildTopologyModel,
  formatNumber,
  localRpcEndpointForNode,
  queryLocalRpc,
  safeArray,
  statusTone,
} from './controlPanelModel';
import {
  ActivityFeed,
  JarvisCard,
  MetricBars,
  MetricCard,
  PanelCard,
  SectionHeader,
  StatusPill,
  TopologyMap,
} from './ControlPanelShared';
import PeerGlobe from './PeerGlobe';
import PeerGlobeLegend from './PeerGlobeLegend';
import PeerDetailsDrawer from './PeerDetailsDrawer';
import PeerGraph from './PeerGraph';
import PeerTable from './PeerTable';
import ActionAuditStream from './ActionAuditStream';
import { boostSyncAction, registerWithSeedsAction } from './controlPanelActions';

function buildConnectionProblems(localPeerInfoError, readinessReport) {
  const items = [];
  if (localPeerInfoError) {
    items.push({
      id: 'peer-error',
      title: 'Peer inspection needs attention',
      detail: localPeerInfoError,
      tone: 'bad',
      time: 'now',
    });
  }

  safeArray(readinessReport?.checks)
    .filter((check) => /warn|fail|error/i.test(String(check?.status || '')))
    .slice(0, 3)
    .forEach((check) => {
      items.push({
        id: check.id,
        title: check.label,
        detail: check.detail,
        tone: 'warn',
        time: readinessReport?.overall_status || 'Readiness',
      });
    });

  if (!items.length) {
    items.push({
      id: 'steady',
      title: 'No connection warnings are active',
      detail: 'The current peer posture looks stable for the selected node.',
      tone: 'good',
      time: 'now',
    });
  }

  return items;
}

function connectionQuality(selectedNodeLive, readinessReport) {
  const peerCount = Number(selectedNodeLive?.local_peer_count || 0);
  const readinessTone = statusTone(readinessReport?.overall_status);

  if (peerCount >= 4 && readinessTone !== 'bad') {
    return {
      label: 'Good',
      detail: 'The node can currently see enough peers to stay healthy.',
      tone: 'good',
    };
  }
  if (peerCount >= 2) {
    return {
      label: 'Fair',
      detail: 'The node is connected, but the peer set is thin and worth watching.',
      tone: 'warn',
    };
  }
  return {
    label: 'Poor',
    detail: 'The node does not currently have enough live peers to be comfortable.',
    tone: 'bad',
  };
}

export default function ControlPanelConnectivityPage() {
  const {
    error,
    knownValidatorAddressesByHost,
    liveStatus,
    networkStats,
    nodeLiveById,
    peerRegionFilter,
    recordAction,
    refresh,
    selectedNode,
    selectedNodeLive,
    selectedPeerId,
    setPeerRegionFilter,
    setSelectedPeerId,
    validatorNodesByAddress,
    viewMode,
    viewProfile,
  } = useControlPanel();

  const [localPeerInfo, setLocalPeerInfo] = useState(null);
  const [localPeerInfoError, setLocalPeerInfoError] = useState('');
  const [localPeerLoading, setLocalPeerLoading] = useState(false);
  const [readinessReport, setReadinessReport] = useState(null);
  const [readinessLoading, setReadinessLoading] = useState(false);
  const [actionBusy, setActionBusy] = useState('');
  const [notice, setNotice] = useState('');
  const [peerTopology, setPeerTopology] = useState({
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
    if (!selectedNode || !selectedNodeLive?.is_running || selectedNodeLive?.local_rpc_ready !== true) {
      setLocalPeerInfo(null);
      setLocalPeerInfoError('');
      setLocalPeerLoading(false);
      return undefined;
    }

    let cancelled = false;
    const endpoint = localRpcEndpointForNode(selectedNode, selectedNodeLive);

    const fetchPeerInfo = async (showSpinner = false) => {
      if (showSpinner && !cancelled) {
        setLocalPeerLoading(true);
      }

      try {
        const peerInfo = await queryLocalRpc(endpoint, 'synergy_getPeerInfo', []);
        if (!cancelled) {
          setLocalPeerInfo(normalizePeerInfoPayload(peerInfo, knownValidatorAddressesByHost));
          setLocalPeerInfoError('');
        }
      } catch (peerError) {
        if (!cancelled) {
          setLocalPeerInfo(null);
          setLocalPeerInfoError(String(peerError));
        }
      } finally {
        if (!cancelled) {
          setLocalPeerLoading(false);
        }
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

  useEffect(() => {
    if (!selectedNode) {
      setReadinessReport(null);
      setReadinessLoading(false);
      return undefined;
    }

    let cancelled = false;
    const fetchReadiness = async (showSpinner = false) => {
      if (showSpinner && !cancelled) {
        setReadinessLoading(true);
      }

      try {
        const report = await invoke('testnet_get_node_readiness', { nodeId: selectedNode.id });
        if (!cancelled) {
          setReadinessReport(report);
        }
      } catch (readinessError) {
        if (!cancelled) {
          setReadinessReport(null);
          setNotice(`Readiness check failed: ${String(readinessError)}`);
        }
      } finally {
        if (!cancelled) {
          setReadinessLoading(false);
        }
      }
    };

    void fetchReadiness(true);
    const intervalId = window.setInterval(() => {
      void fetchReadiness(false);
    }, 15000);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [selectedNode]);

  useEffect(() => {
    let cancelled = false;

    const loadTopology = async () => {
      const topology = await resolvePeerTopology({
        peers: safeArray(localPeerInfo?.peers),
        localNode: selectedNode,
        bootnodes: liveStatus?.bootnodes,
      });
      if (!cancelled) {
        setPeerTopology(topology);
      }
    };

    void loadTopology();
    return () => {
      cancelled = true;
    };
  }, [liveStatus?.bootnodes, localPeerInfo?.peers, selectedNode]);

  const handleAction = async (kind) => {
    if (!selectedNode) {
      return;
    }

    setActionBusy(kind);
    try {
      const message = kind === 'boost'
        ? await boostSyncAction(selectedNode.id)
        : await registerWithSeedsAction(selectedNode.id);
      setNotice(message);
      recordAction({
        title: kind === 'boost' ? 'Reconnect peers' : 'Refresh topology',
        detail: message,
        status: 'good',
        source: 'connectivity',
        command: kind,
      });
      await refresh({ silent: true });
    } catch (actionError) {
      const detail = String(actionError);
      setNotice(detail);
      recordAction({
        title: `${kind} failed`,
        detail,
        status: 'bad',
        source: 'connectivity',
        command: kind,
      });
    } finally {
      setActionBusy('');
    }
  };

  const topologyModel = useMemo(
    () => buildTopologyModel({
      selectedNode,
      selectedNodeLive,
      localPeerInfo,
      liveStatus,
      validatorNodesByAddress,
      nodeLiveById,
      viewMode,
    }),
    [liveStatus, localPeerInfo, nodeLiveById, selectedNode, selectedNodeLive, validatorNodesByAddress, viewMode],
  );
  const latencyBars = useMemo(
    () => buildLatencyBars({ localPeerInfo, liveStatus }),
    [liveStatus, localPeerInfo],
  );
  const readinessHeadline = readinessReport
    ? `${readinessReport.ready_count}/${readinessReport.total_count} checks passed`
    : (readinessLoading ? 'Checking node readiness…' : 'Readiness not loaded');
  const livePeerCards = safeArray(localPeerInfo?.peers).slice(0, viewMode === 'developer' ? 8 : 5);
  const filteredPoints = peerRegionFilter === 'all'
    ? peerTopology.points
    : peerTopology.points.filter((peer) => peer.region === peerRegionFilter);
  const selectedPeer = peerTopology.points.find((peer) => peer.id === selectedPeerId) || null;
  const connectionStatus = connectionQuality(selectedNodeLive, readinessReport);
  const connectionProblems = buildConnectionProblems(localPeerInfoError, readinessReport);

  const exportPeerSnapshot = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(peerTopology, null, 2));
      setNotice('Peer snapshot copied to the clipboard.');
      recordAction({
        title: 'Exported peer snapshot',
        detail: 'The current topology snapshot was copied to the clipboard.',
        status: 'good',
        source: 'connectivity',
        command: 'copy-peer-snapshot',
      });
    } catch (copyError) {
      setNotice(String(copyError));
    }
  };

  return (
    <div className="cp-page-stack">
      <SectionHeader
        eyebrow={viewProfile.label}
        title={viewProfile.navLabels.connectivity}
        copy={viewMode === 'basic'
          ? 'This view answers one question first: is the node connected well enough to stay healthy?'
          : viewMode === 'advanced'
            ? 'Inspect regional spread, visible peers, and route quality from a real topology surface.'
            : 'Inspect raw peer posture, logical topology, and transport-facing visibility from one workspace.'}
        actions={(
          <>
            {viewMode !== 'basic' ? (
              <div className="cp-chip-row">
                {['all', ...peerTopology.regionSummary.map((entry) => entry.region)].map((region) => (
                  <button
                    key={region}
                    type="button"
                    className={`cp-chip cp-chip-button ${peerRegionFilter === region ? 'is-active' : ''}`}
                    onClick={() => setPeerRegionFilter(region)}
                  >
                    {region}
                  </button>
                ))}
              </div>
            ) : null}
            <SNRGButton variant="blue" size="sm" onClick={() => void refresh()}>
              Refresh
            </SNRGButton>
            <SNRGButton
              variant="blue"
              size="sm"
              disabled={actionBusy === 'boost' || !selectedNode}
              onClick={() => void handleAction('boost')}
            >
              {actionBusy === 'boost' ? 'Reconnecting…' : 'Reconnect peers'}
            </SNRGButton>
          </>
        )}
      />

      {(notice || error || localPeerInfoError) ? (
        <div className={`cp-inline-notice tone-${statusTone(notice || error || localPeerInfoError)}`}>
          {notice || error || localPeerInfoError}
        </div>
      ) : null}

      {viewMode === 'basic' ? (
        <div className="cp-dashboard-grid">
          <div className="cp-dashboard-main">
            <PanelCard
              title="Simple globe summary"
              detail={localPeerLoading
                ? 'Refreshing the latest peer view…'
                : 'Friendly regional view of the network around this node.'}
            >
              {peerTopology.points.length ? (
                <>
                  <PeerGlobe
                    points={peerTopology.points}
                    routes={peerTopology.routes}
                    regionSummary={peerTopology.regionSummary}
                    mode="basic"
                  />
                  <PeerGlobeLegend />
                </>
              ) : (
                <TopologyMap title="Connection preview" detail="Waiting for local peer visibility." model={topologyModel} />
              )}
            </PanelCard>

            <PanelCard title="Connection quality" detail="A plain-language summary of current peer posture.">
              <div className={`cp-inline-notice tone-${connectionStatus.tone}`}>
                <strong>{connectionStatus.label}</strong> {connectionStatus.detail}
              </div>
            </PanelCard>

            <ActivityFeed title="Recent connection problems" detail="Plain-language connection warnings and readiness issues." items={connectionProblems} />

            <PanelCard title="Bootstrap helper" detail="If peer count is low, this tells you what the node is likely waiting on.">
              <p className="cp-panel-inline-note">
                {networkStats.healthyBootnodes > 0
                  ? `Bootstrap services are responding (${formatNumber(networkStats.healthyBootnodes)} healthy). If peers are still low, the node is probably waiting for more sessions to complete.`
                  : 'Bootstrap services are not responding right now, so the node is waiting on the discovery path before it can build a larger peer set.'}
              </p>
            </PanelCard>
          </div>

          <div className="cp-dashboard-side">
            <JarvisCard
              mode={viewMode}
              title="Assistant guidance"
              message={connectionStatus.detail}
              chips={[
                `${formatNumber(selectedNodeLive?.local_peer_count ?? 0)} peers`,
                readinessReport?.overall_status || 'Readiness pending',
                `${formatNumber(peerTopology.regionSummary.length)} regions`,
              ]}
            />

            <PanelCard title="Quick facts" detail="Friendly network facts for the selected node.">
              <div className="cp-definition-list">
                <div className="cp-definition-item">
                  <span>Visible peers</span>
                  <strong>{formatNumber(selectedNodeLive?.local_peer_count ?? 0)}</strong>
                </div>
                <div className="cp-definition-item">
                  <span>Pending peers</span>
                  <strong>{formatNumber(Math.max(0, (selectedNodeLive?.local_peer_count ?? 0) - peerTopology.points.length))}</strong>
                </div>
                <div className="cp-definition-item">
                  <span>Last successful response</span>
                  <strong>{peerTopology.points[0]?.lastSeenAt || 'Unknown'}</strong>
                </div>
              </div>
            </PanelCard>

            <PanelCard title="Simple regional summary" detail="How many regions are represented right now.">
              <div className="cp-plan-list">
                {peerTopology.regionSummary.length ? peerTopology.regionSummary.map((entry) => (
                  <p key={entry.region}>{entry.region}: {formatNumber(entry.peerCount)} peers</p>
                )) : <p>You currently do not have enough visible peers to build a regional picture yet.</p>}
              </div>
            </PanelCard>
          </div>
        </div>
      ) : viewMode === 'advanced' ? (
        <div className="cp-dashboard-grid">
          <div className="cp-dashboard-main">
            <PanelCard
              title="Interactive peer globe"
              detail={localPeerLoading ? 'Refreshing live peer sessions…' : `${formatNumber(peerTopology.points.length)} peers resolved from the selected node.`}
              action={(
                <div className="cp-chip-row">
                  <SNRGButton variant="blue" size="sm" onClick={exportPeerSnapshot}>Export peer snapshot</SNRGButton>
                  <SNRGButton
                    variant="blue"
                    size="sm"
                    disabled={actionBusy === 'register' || !selectedNode}
                    onClick={() => void handleAction('register')}
                  >
                    {actionBusy === 'register' ? 'Refreshing…' : 'Refresh topology'}
                  </SNRGButton>
                </div>
              )}
            >
              <PeerGlobe
                points={filteredPoints}
                routes={peerTopology.routes.filter((route) => filteredPoints.some((peer) => peer.id === route.toPeerId))}
                regionSummary={peerTopology.regionSummary}
                selectedRegion={peerRegionFilter}
                onSelectRegion={(region) => setPeerRegionFilter((current) => current === region ? 'all' : region)}
                selectedPeerId={selectedPeerId}
                onSelectPeer={(peer) => setSelectedPeerId(peer.id)}
                mode="advanced"
              />
              <PeerGlobeLegend />
            </PanelCard>

            <MetricBars
              title="Route quality charts"
              detail="Peer heartbeat freshness and bootstrap latency distribution."
              items={latencyBars}
            />

            <PanelCard title="Visible peers table" detail="Filtered peer visibility for the selected region.">
              <PeerTable peers={filteredPoints} selectedPeerId={selectedPeerId} onSelectPeer={(peer) => setSelectedPeerId(peer.id)} mode="advanced" />
            </PanelCard>

            <PanelCard title="Bootstrap services / seed services" detail="Separate from normal peer sessions.">
              <div className="cp-endpoint-list">
                {safeArray(liveStatus?.bootnodes).map((entry, index) => (
                  <div key={`${entry?.host || 'bootnode'}-${index}`} className="cp-endpoint-item">
                    <div>
                      <strong>{entry?.host || `Bootnode ${index + 1}`}</strong>
                      <span>{entry?.detail || 'Bootstrap relay probe'}</span>
                    </div>
                    <div className="cp-endpoint-meta">
                      <StatusPill tone={entry?.reachable ? 'good' : 'warn'}>
                        {entry?.reachable ? 'Reachable' : 'Pending'}
                      </StatusPill>
                      <small>{entry?.latency_ms != null ? `${entry.latency_ms} ms` : 'Waiting'}</small>
                    </div>
                  </div>
                ))}
              </div>
            </PanelCard>
          </div>

          <div className="cp-dashboard-side">
            <JarvisCard
              mode={viewMode}
              title="Alert summary"
              message={connectionProblems[0]?.detail || 'Peer posture looks stable.'}
              chips={[
                `${formatNumber(filteredPoints.length)} filtered peers`,
                `${formatNumber(peerTopology.regionSummary.length)} regions`,
                readinessReport?.overall_status || 'Readiness pending',
              ]}
            />

            <PanelCard title="Region summary" detail="Click a region on the globe or here to filter the peer table.">
              <div className="cp-plan-list">
                {peerTopology.regionSummary.map((entry) => (
                  <button
                    key={entry.region}
                    type="button"
                    className={`cp-peer-region-button ${peerRegionFilter === entry.region ? 'is-active' : ''}`}
                    onClick={() => setPeerRegionFilter((current) => current === entry.region ? 'all' : entry.region)}
                  >
                    <strong>{entry.region}</strong>
                    <span>{formatNumber(entry.peerCount)} peers</span>
                  </button>
                ))}
              </div>
            </PanelCard>

            <PanelCard title="Selected peer" detail="The current row or marker selection appears here.">
              <PeerDetailsDrawer peer={selectedPeer} mode="advanced" />
            </PanelCard>
          </div>
        </div>
      ) : (
        <div className="cp-dashboard-grid">
          <div className="cp-dashboard-main">
            <PanelCard
              title="Interactive globe"
              detail={`${formatNumber(filteredPoints.length)} raw peer sessions visible from the selected node.`}
              action={(
                <div className="cp-chip-row">
                  <button type="button" className="cp-chip cp-chip-button" onClick={() => setPeerRegionFilter('all')}>
                    Reset view
                  </button>
                  <button type="button" className="cp-chip cp-chip-button" onClick={exportPeerSnapshot}>
                    Copy peer snapshot JSON
                  </button>
                </div>
              )}
            >
              <PeerGlobe
                points={filteredPoints}
                routes={peerTopology.routes.filter((route) => filteredPoints.some((peer) => peer.id === route.toPeerId))}
                regionSummary={peerTopology.regionSummary}
                selectedRegion={peerRegionFilter}
                onSelectRegion={(region) => setPeerRegionFilter((current) => current === region ? 'all' : region)}
                selectedPeerId={selectedPeerId}
                onSelectPeer={(peer) => setSelectedPeerId(peer.id)}
                mode="developer"
              />
              <PeerGlobeLegend />
            </PanelCard>

            <PanelCard title="Logical topology graph" detail="A role- and health-aware graph of the visible sessions.">
              <PeerGraph peers={filteredPoints} selectedPeerId={selectedPeerId} onSelectPeer={(peer) => setSelectedPeerId(peer.id)} />
            </PanelCard>

            <div className="cp-metric-grid cp-metric-grid-dashboard cp-metric-grid-dense">
              <MetricCard label="Inbound / outbound" value={formatNumber(filteredPoints.length)} detail="Raw session visibility" tone="cyan" icon="hub" />
              <MetricCard label="Reconnect attempts" value={actionBusy ? 'Running' : 'Idle'} detail="Use Reconnect peers to reseed from the current node." tone={actionBusy ? 'warn' : 'good'} icon="refresh" />
              <MetricCard label="Protocol mismatches" value={formatNumber(filteredPoints.filter((peer) => !peer.protocolVersion).length)} detail="Peers missing version metadata" tone="warn" icon="warning" />
              <MetricCard label="Stale sessions" value={formatNumber(filteredPoints.filter((peer) => peer.health === 'stale').length)} detail="No recent heartbeat" tone="bad" icon="portable_wifi_off" />
            </div>

            <PanelCard title="Raw peer session table" detail="Sortable and filterable transport-facing rows.">
              <PeerTable peers={filteredPoints} selectedPeerId={selectedPeerId} onSelectPeer={(peer) => setSelectedPeerId(peer.id)} mode="developer" />
            </PanelCard>
          </div>

          <div className="cp-dashboard-side">
            <PanelCard title="Selected peer inspector" detail="Raw metadata and timing for the current peer selection.">
              <PeerDetailsDrawer peer={selectedPeer} mode="developer" />
            </PanelCard>

            <PanelCard title="Seed / bootstrap inspector" detail="Bootstrap services remain separate from ordinary peers.">
              <div className="cp-endpoint-list">
                {safeArray(liveStatus?.bootnodes).map((entry, index) => (
                  <div key={`${entry?.host || 'bootnode'}-${index}`} className="cp-endpoint-item">
                    <div>
                      <strong>{entry?.host || `Bootnode ${index + 1}`}</strong>
                      <span>{entry?.detail || 'Bootstrap relay probe'}</span>
                    </div>
                    <small>{entry?.latency_ms != null ? `${entry.latency_ms} ms` : 'Waiting'}</small>
                  </div>
                ))}
              </div>
            </PanelCard>

            <PanelCard title="P2P warning stream" detail="Connection warnings and recent topology trouble.">
              <ActivityFeed title="Warnings" detail={readinessHeadline} items={connectionProblems} />
            </PanelCard>

            <PanelCard title="Action audit trail" detail="Local connectivity actions and receipts.">
              <ActionAuditStream entries={[]} emptyMessage="Connectivity actions will appear here as you run them." />
            </PanelCard>
          </div>
        </div>
      )}
    </div>
  );
}

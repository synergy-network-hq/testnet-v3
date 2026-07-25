import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { SNRGButton } from '../../styles/SNRGButton';
import { invoke } from '../../lib/desktopClient';
import { useControlPanel } from './ControlPanelProvider';
import {
  effectiveLocalChainHeight,
  formatNumber,
  formatRuntimeDuration,
  nodeRuntimeLabel,
  nodeRuntimeTone,
} from './controlPanelModel';
import {
  MetricCard,
  PanelCard,
  SectionHeader,
  StatusPill,
} from './ControlPanelShared';
import ActionAuditStream from './ActionAuditStream';
import JsonInspectorPanel from './JsonInspectorPanel';
import ValidatorLiveStatusPanel from './ValidatorLiveStatusPanel';
import { getFeatureScreenByKey } from './controlPanelFeatureScreens';
import {
  boostSyncAction,
  registerWithSeedsAction,
  rejoinNetworkAction,
  restartNodeAction,
  runNodeControlAction,
  syncCatchUpRejoinAction,
} from './controlPanelActions';

const SYNC_READY_GAP = 2;
const REQUIRED_CHAIN_ID = '1264';
const REQUIRED_NETWORK_ID = 'synergy-testnet-v3';
const REQUIRED_FORK_HEIGHT = 204216;
const REQUIRED_FORK_PARENT_HEIGHT = 204215;
const REQUIRED_FORK_PARENT_HASH = 'e209bd7554a06dfb052d5ff7ffd5664efc05e6cd1c5cadc9d139fa5bb9072816';
const REQUIRED_CONSENSUS_ALGORITHM = 'FN-DSA';
const REQUIRED_PARSER_MODE = 'fail_closed';

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function readObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function camelOrSnake(value, camelKey, snakeKey) {
  const object = readObject(value);
  return object[camelKey] ?? object[snakeKey];
}

function formatBytes(bytes) {
  const numeric = Number(bytes);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    return '0 B';
  }
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const index = Math.min(Math.floor(Math.log(numeric) / Math.log(1024)), units.length - 1);
  return `${(numeric / (1024 ** index)).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function metric(label, value, detail, tone = 'neutral', icon = 'analytics', numericValue = null) {
  return { label, value, detail, tone, icon, numericValue };
}

function probeStatusCounts(snapshot) {
  const probes = safeArray(snapshot?.rpc?.probes);
  const passing = probes.filter((probe) => probe.status === 'pass').length;
  return { passing, total: probes.length, failing: probes.length - passing };
}

function firstProbe(snapshot, method) {
  return safeArray(snapshot?.rpc?.probes).find((probe) => probe.method === method) || null;
}

function firstTextValue(...values) {
  const value = values.find((candidate) => String(candidate ?? '').trim());
  return String(value ?? '').trim();
}

function compactHash(value) {
  const text = String(value ?? '').trim();
  if (!text) return 'not reported';
  return text.length > 22 ? `${text.slice(0, 10)}...${text.slice(-8)}` : text;
}

function probeResult(snapshot, method) {
  return readObject(firstProbe(snapshot, method)?.result);
}

function arrayProbeResult(snapshot, method) {
  const result = firstProbe(snapshot, method)?.result;
  return safeArray(result);
}

function readinessCounts(snapshot) {
  const readiness = readObject(snapshot?.readiness);
  const total = Number(readiness.total_count ?? readiness.totalCount ?? 0);
  const ready = Number(readiness.ready_count ?? readiness.readyCount ?? 0);
  return { ready, total, blocked: Math.max(0, total - ready) };
}

function logSummary(snapshot) {
  return readObject(snapshot?.logs?.summary);
}

function chainBlocks(snapshot) {
  return safeArray(snapshot?.chain?.blocks);
}

function graphSnapshot(snapshot) {
  const dagGraph = readObject(snapshot?.dag?.graph);
  if (safeArray(dagGraph.nodes).length || safeArray(dagGraph.edges).length) {
    return dagGraph;
  }
  return readObject(snapshot?.chain?.graph);
}

function mempoolTransactions(snapshot) {
  const structured = safeArray(snapshot?.mempool?.transactions);
  return structured.length ? structured : arrayProbeResult(snapshot, 'synergy_getTransactionPool');
}

function pendingTransactions(snapshot) {
  const structured = mempoolTransactions(snapshot);
  return structured.length ? structured : arrayProbeResult(snapshot, 'synergy_getPendingTransactions');
}

function nodeAddress(snapshot) {
  return snapshot?.node?.node_address || snapshot?.node?.nodeAddress || '';
}

function preflightCheck(activationReport, ids) {
  const idSet = new Set(ids.map((id) => String(id).toLowerCase()));
  return safeArray(activationReport?.checks).find((check) => {
    const checkId = String(check?.id || check?.check_id || check?.label || '').toLowerCase();
    return idSet.has(checkId) || ids.some((id) => checkId.includes(String(id).toLowerCase()));
  }) || null;
}

function preflightCheckPassed(activationReport, ids) {
  const check = preflightCheck(activationReport, ids);
  if (!check) {
    return false;
  }
  return String(check.status || check.result || '').toLowerCase() === 'pass' || check.passed === true;
}

function preflightCheckDetail(activationReport, ids, fallback) {
  const check = preflightCheck(activationReport, ids);
  return String(check?.detail || check?.message || check?.suggestion || fallback);
}

function preflightPassCount(activationReport) {
  const checks = safeArray(activationReport?.checks);
  return {
    passing: checks.filter((check) => String(check?.status || check?.result || '').toLowerCase() === 'pass' || check?.passed === true).length,
    total: checks.length,
  };
}

function selectedNodeRole(selectedNode, snapshot) {
  return String(selectedNode?.role_id || snapshot?.node?.role_id || snapshot?.node?.role || '').trim().toLowerCase();
}

function liveChainId(snapshot, activationReport) {
  return firstTextValue(
    snapshot?.chain_id,
    snapshot?.network?.chainId,
    snapshot?.network?.chain_id,
    snapshot?.live?.chain_id,
    firstProbe(snapshot, 'synergy_getChainId')?.result,
    camelOrSnake(activationReport, 'chainId', 'chain_id'),
  );
}

function liveNetworkId(snapshot, activationReport) {
  return firstTextValue(
    snapshot?.network_id,
    snapshot?.network?.networkId,
    snapshot?.network?.network_id,
    snapshot?.live?.network_id,
    camelOrSnake(activationReport, 'networkId', 'network_id'),
  );
}

function forkStatus(snapshot) {
  return readObject(
    snapshot?.consensus?.fork
      || snapshot?.consensus?.fork_status
      || snapshot?.consensusFork
      || snapshot?.fork
      || snapshot?.network?.consensusFork
      || snapshot?.network?.consensus_fork
      || snapshot?.live?.consensus_fork
      || snapshot?.live?.consensusFork,
  );
}

function selectedNodeLabel(snapshot, selectedNode) {
  return selectedNode?.display_label
    || selectedNode?.role_display_name
    || snapshot?.node?.display_label
    || snapshot?.node?.id
    || 'Node';
}

function buildMetrics(featureKey, snapshot, selectedNodeLive, networkStats) {
  const probes = probeStatusCounts(snapshot);
  const readiness = readinessCounts(snapshot);
  const logs = logSummary(snapshot);
  const blocks = chainBlocks(snapshot);
  const latestBlock = blocks[0] || {};
  const storage = readObject(snapshot?.storage);
  const graph = graphSnapshot(snapshot);
  const validation = probeResult(snapshot, 'synergy_getBlockValidationStatus');
  const slashing = probeResult(snapshot, 'synergy_getValidatorSlashingHistory');
  const pool = mempoolTransactions(snapshot);
  const pendingPool = pendingTransactions(snapshot);
  const mempoolStats = readObject(snapshot?.mempool?.stats);
  const dag = readObject(snapshot?.dag);
  const processCount = safeArray(snapshot?.diagnostics?.processes).length;

  const common = [
    metric('Runtime', nodeRuntimeLabel(selectedNodeLive), selectedNodeLive?.local_rpc_status || 'Runtime state read from control service', nodeRuntimeTone(selectedNodeLive), 'monitor_heart'),
    metric('Local height', formatNumber(effectiveLocalChainHeight(selectedNodeLive)), `Network tip ${formatNumber(selectedNodeLive?.best_network_height ?? networkStats.publicChainHeight ?? 0)}`, selectedNodeLive?.is_running ? 'cyan' : 'warn', 'layers'),
    metric('Readiness', `${formatNumber(readiness.ready)}/${formatNumber(readiness.total)}`, `${formatNumber(readiness.blocked)} checks need action`, readiness.blocked ? 'warn' : 'good', 'fact_check', readiness.ready),
    metric('RPC probes', `${formatNumber(probes.passing)}/${formatNumber(probes.total)}`, `${formatNumber(probes.failing)} probe failures`, probes.failing ? 'warn' : 'good', 'terminal', probes.passing),
  ];

  if (featureKey === 'alerts') {
    return [
      metric('Critical logs', formatNumber(logs.error_count || 0), 'ERROR entries from local logs', logs.error_count ? 'bad' : 'good', 'report', logs.error_count || 0),
      metric('Warnings', formatNumber(logs.warn_count || 0), 'WARN entries from local logs', logs.warn_count ? 'warn' : 'good', 'warning', logs.warn_count || 0),
      metric('Blocked checks', formatNumber(readiness.blocked), 'Failed readiness checks', readiness.blocked ? 'bad' : 'good', 'rule', readiness.blocked),
      metric('RPC failures', formatNumber(probes.failing), 'Failed live probes', probes.failing ? 'warn' : 'good', 'lan', probes.failing),
    ];
  }

  if (featureKey === 'validator') {
    return common;
  }

  if (featureKey === 'validatorOnboarding') {
    const chainId = liveChainId(snapshot, null);
    const networkId = liveNetworkId(snapshot, null);
    const fork = forkStatus(snapshot);
    const reportedForkHeight = Number(fork.fork_height ?? fork.forkHeight ?? 0);
    const reportedAlgorithm = String(fork.new_consensus_algorithm || fork.newConsensusAlgorithm || '').trim();
    const reportedParserMode = String(fork.parser_mode || fork.parserMode || '').trim();
    return [
      metric('Chain ID', chainId || 'Not reported', `Required ${REQUIRED_CHAIN_ID}`, chainId === REQUIRED_CHAIN_ID ? 'good' : 'warn', 'tag'),
      metric('Network', networkId || 'Not reported', REQUIRED_NETWORK_ID, networkId === REQUIRED_NETWORK_ID ? 'good' : 'warn', 'hub'),
      metric('Fork height', reportedForkHeight ? formatNumber(reportedForkHeight) : 'Not reported', `Required ${formatNumber(REQUIRED_FORK_HEIGHT)}`, reportedForkHeight === REQUIRED_FORK_HEIGHT ? 'good' : 'warn', 'call_split'),
      metric('Consensus', reportedAlgorithm || 'Not reported', `Parser ${reportedParserMode || 'not reported'}`, reportedAlgorithm === REQUIRED_CONSENSUS_ALGORITHM && reportedParserMode === REQUIRED_PARSER_MODE ? 'good' : 'warn', 'how_to_reg'),
    ];
  }

  if (featureKey === 'security' || featureKey === 'identity') {
    return [
      metric('Identity address', nodeAddress(snapshot) ? 'Present' : 'Missing', nodeAddress(snapshot), nodeAddress(snapshot) ? 'good' : 'bad', 'badge'),
      metric('Key files', formatNumber(readObject(safeArray(snapshot?.storage?.sections).find((item) => item.label === 'keys'))?.files || 0), 'Files in workspace keys folder', 'purple', 'key'),
      metric('Slashing events', formatNumber(safeArray(slashing.slashingEvents).length), 'Reported by slashing RPC', safeArray(slashing.slashingEvents).length ? 'bad' : 'good', 'gpp_maybe'),
      metric('Readiness', `${formatNumber(readiness.ready)}/${formatNumber(readiness.total)}`, 'Security-relevant readiness checks', readiness.blocked ? 'warn' : 'good', 'shield'),
    ];
  }

  if (featureKey === 'consensus') {
    return [
      metric('Latest block', formatNumber(latestBlock.number ?? latestBlock.block_index ?? latestBlock.blockNumber ?? 0), 'Latest local block returned by RPC', 'cyan', 'account_tree'),
      metric('Active validators', formatNumber(validation.active_validators ?? 0), `${formatNumber(validation.total_validators ?? 0)} total validators in validation RPC`, 'purple', 'groups'),
      metric('Sync gap', formatNumber(selectedNodeLive?.sync_gap ?? 0), 'Blocks behind visible network tip', Number(selectedNodeLive?.sync_gap || 0) > SYNC_READY_GAP ? 'warn' : 'good', 'sync'),
      metric('Recent blocks', formatNumber(blocks.length), 'Block range returned by local RPC', blocks.length ? 'good' : 'warn', 'view_timeline'),
    ];
  }

  if (featureKey === 'dag') {
    const certificateValue = dag.certificates;
    const certificateCount = Array.isArray(certificateValue)
      ? certificateValue.length
      : safeArray(readObject(certificateValue).certificates).length;
    const dagStatus = dag.available ? 'Dedicated DAG' : 'PoSy fallback';
    return [
      metric('DAG source', dagStatus, dag.detail || 'DAG snapshot source', dag.available ? 'good' : 'warn', 'schema'),
      metric('Vertices', formatNumber(safeArray(dag.vertices).length || safeArray(graph.nodes).length), 'Dedicated DAG vertices or finalized evidence nodes', 'cyan', 'account_tree'),
      metric('Certificates', formatNumber(certificateCount), 'Availability/certification evidence returned by node RPC', certificateCount ? 'good' : 'warn', 'verified'),
      metric('Parent links', formatNumber(safeArray(graph.edges).length), 'Graph links returned by DAG or PoSy evidence', 'purple', 'share'),
    ];
  }

  if (featureKey === 'transactions') {
    return [
      metric('Pending pool', formatNumber(pool.length || pendingPool.length), `Selected node mempool via ${snapshot?.mempool?.sourceMethod || 'RPC probe'}`, pool.length || pendingPool.length ? 'warn' : 'good', 'pending_actions'),
      metric('Latest block txs', formatNumber(safeArray(latestBlock.transactions).length), 'Transactions in latest local block', 'cyan', 'receipt_long'),
      metric('Avg gas price', formatNumber(mempoolStats.avgGasPriceNwei || 0), 'Average nWei gas price across pending transactions', 'purple', 'payments'),
      metric('RPC probes', `${formatNumber(probes.passing)}/${formatNumber(probes.total)}`, 'Transaction RPC health', probes.failing ? 'warn' : 'good', 'terminal'),
    ];
  }

  if (featureKey === 'storage') {
    const disk = readObject(storage.disk);
    const free = disk.availableBytes;
    return [
      metric('Workspace size', formatBytes(storage.workspaceBytes), `${formatNumber(storage.workspaceFiles || 0)} files`, 'blue', 'folder_open'),
      metric('Log data', formatBytes(readObject(safeArray(storage.sections).find((item) => item.label === 'logs'))?.bytes || 0), 'Local log footprint', 'cyan', 'receipt_long'),
      metric('Chain data', formatBytes(readObject(safeArray(storage.sections).find((item) => item.label === 'data'))?.bytes || 0), 'Runtime data folder', 'purple', 'database'),
      metric('Disk free', free != null ? formatBytes(free) : 'Disk probe pending', disk.mountPoint || 'Host disk probe', free != null ? 'good' : 'warn', 'hard_drive'),
    ];
  }

  if (featureKey === 'api') {
    const latencies = safeArray(snapshot?.rpc?.probes).map((probe) => Number(probe.latencyMs)).filter(Number.isFinite);
    const avgLatency = latencies.length ? Math.round(latencies.reduce((sum, value) => sum + value, 0) / latencies.length) : 0;
    return [
      metric('Endpoint', snapshot?.rpc?.endpoint || 'Endpoint not resolved', 'Selected node JSON-RPC endpoint', 'blue', 'terminal'),
      metric('Passing methods', `${formatNumber(probes.passing)}/${formatNumber(probes.total)}`, 'Live method probes', probes.failing ? 'warn' : 'good', 'fact_check'),
      metric('Average latency', `${formatNumber(avgLatency)} ms`, 'Mean probe latency', avgLatency > 500 ? 'warn' : 'good', 'speed'),
      metric('Chain ID', String(firstProbe(snapshot, 'synergy_getChainId')?.result || snapshot?.network?.chainId || ''), 'Live chain identifier', 'purple', 'tag'),
    ];
  }

  if (featureKey === 'maintenance') {
    return [
      metric('Runtime', nodeRuntimeLabel(selectedNodeLive), formatRuntimeDuration(selectedNodeLive?.process_uptime_secs), nodeRuntimeTone(selectedNodeLive), 'build_circle'),
      metric('Sync gap', formatNumber(selectedNodeLive?.sync_gap ?? 0), 'Use Sync Catch Up when behind', Number(selectedNodeLive?.sync_gap || 0) > SYNC_READY_GAP ? 'warn' : 'good', 'sync'),
      metric('Processes', formatNumber(processCount), 'Workspace runtime processes', processCount === 1 ? 'good' : 'warn', 'memory'),
      metric('Readiness', `${formatNumber(readiness.ready)}/${formatNumber(readiness.total)}`, 'Pre-maintenance checks', readiness.blocked ? 'warn' : 'good', 'rule'),
    ];
  }

  if (featureKey === 'diagnostics') {
    return [
      metric('Processes', formatNumber(processCount), 'Workspace runtime process matches', processCount === 1 ? 'good' : 'warn', 'memory'),
      metric('Listeners', String(readObject(snapshot?.diagnostics?.listeners).status ?? 'Captured'), 'Port listener command status', 'cyan', 'settings_ethernet'),
      metric('Disk command', String(readObject(snapshot?.diagnostics?.disk).status ?? 'Captured'), 'Disk command status', 'blue', 'hard_drive'),
      metric('Log entries', formatNumber(logs.total_entries || 0), 'Parsed from workspace logs', 'purple', 'receipt_long'),
    ];
  }

  if (featureKey === 'config') {
    const files = safeArray(snapshot?.config?.files);
    const present = files.filter((file) => file.exists).length;
    return [
      metric('Config files', `${formatNumber(present)}/${formatNumber(files.length)}`, 'Files read from workspace', present === files.length ? 'good' : 'warn', 'description'),
      metric('RPC endpoint', snapshot?.rpc?.endpoint || 'Endpoint not resolved', 'Resolved from node.toml', 'cyan', 'terminal'),
      metric('Chain ID', String(snapshot?.network?.chainId || ''), 'Bundled Testnet network profile', 'purple', 'tag'),
      metric('Bootstrap entries', formatNumber(safeArray(snapshot?.network?.bootnodes).length + safeArray(snapshot?.network?.seedServers).length), 'Bootnodes and seed servers in network profile', 'blue', 'hub'),
    ];
  }

  return common;
}

function buildChecks(featureKey, snapshot) {
  const readinessChecks = safeArray(snapshot?.readiness?.checks).map((check) => ({
    id: check.id || check.label,
    label: check.label || check.id,
    detail: check.detail || check.suggestion || 'Runtime check returned without detail.',
    status: check.status === 'pass' ? 'pass' : 'fail',
  }));
  const rpcChecks = safeArray(snapshot?.rpc?.probes).map((probe) => ({
    id: `rpc-${probe.method}`,
    label: probe.method,
    detail: probe.status === 'pass' ? `${probe.summary || 'Method responded'} in ${formatNumber(probe.latencyMs)} ms` : String(probe.detail || 'RPC probe failed'),
    status: probe.status === 'pass' ? 'pass' : 'fail',
  }));

  if (featureKey === 'validatorOnboarding') {
    const chainId = liveChainId(snapshot, null);
    const networkId = liveNetworkId(snapshot, null);
    const fork = forkStatus(snapshot);
    const forkHeight = Number(fork.fork_height ?? fork.forkHeight ?? 0);
    const parserMode = String(fork.parser_mode || fork.parserMode || '').trim();
    const algorithm = String(fork.new_consensus_algorithm || fork.newConsensusAlgorithm || '').trim();
    return [
      {
        id: 'chain-id',
        label: 'Canonical chain_id',
        detail: `Live value ${chainId || 'not reported'}; required ${REQUIRED_CHAIN_ID}.`,
        status: chainId === REQUIRED_CHAIN_ID ? 'pass' : 'fail',
      },
      {
        id: 'network-id',
        label: 'Canonical network_id',
        detail: `Live value ${networkId || 'not reported'}; required ${REQUIRED_NETWORK_ID}.`,
        status: networkId === REQUIRED_NETWORK_ID ? 'pass' : 'fail',
      },
      {
        id: 'fork-height',
        label: 'Checkpointed FN-DSA fork',
        detail: `Live fork height ${forkHeight || 'not reported'}; required ${formatNumber(REQUIRED_FORK_HEIGHT)}.`,
        status: forkHeight === REQUIRED_FORK_HEIGHT ? 'pass' : 'fail',
      },
      {
        id: 'parser-mode',
        label: 'Fail-closed parser mode',
        detail: `Live parser mode ${parserMode || 'not reported'}; required ${REQUIRED_PARSER_MODE}.`,
        status: parserMode === REQUIRED_PARSER_MODE && algorithm === REQUIRED_CONSENSUS_ALGORITHM ? 'pass' : 'fail',
      },
    ];
  }

  if (featureKey === 'config') {
    return safeArray(snapshot?.config?.files).map((file) => ({
      id: file.path,
      label: file.path?.split('/').slice(-2).join('/') || 'config file',
      detail: file.exists ? `${formatBytes(file.bytes)} read from workspace` : 'File was not found in this workspace.',
      status: file.exists ? 'pass' : 'fail',
    }));
  }

  if (featureKey === 'diagnostics') {
    return [
      ...safeArray(snapshot?.diagnostics?.processes).map((process) => ({
        id: `pid-${process.pid}`,
        label: `Process ${process.pid}`,
        detail: `Runtime process has been alive for ${formatRuntimeDuration(process.uptimeSecs)}.`,
        status: 'pass',
      })),
      {
        id: 'listeners',
        label: 'Port listeners command',
        detail: readObject(snapshot?.diagnostics?.listeners).stdout || readObject(snapshot?.diagnostics?.listeners).stderr || 'Listener command completed.',
        status: readObject(snapshot?.diagnostics?.listeners).status === 0 ? 'pass' : 'fail',
      },
      {
        id: 'disk',
        label: 'Disk command',
        detail: readObject(snapshot?.diagnostics?.disk).stdout || readObject(snapshot?.diagnostics?.disk).stderr || 'Disk command completed.',
        status: readObject(snapshot?.diagnostics?.disk).status === 0 ? 'pass' : 'fail',
      },
    ];
  }

  return [...readinessChecks, ...rpcChecks].slice(0, 10);
}

function buildTable(featureKey, snapshot) {
  const blocks = chainBlocks(snapshot);
  const graph = graphSnapshot(snapshot);

  if (featureKey === 'alerts') {
    const logRows = safeArray(snapshot?.logs?.entries)
      .filter((entry) => ['WARN', 'ERROR'].includes(String(entry.level || '').toUpperCase()))
      .slice(0, 8)
      .map((entry) => [
        String(entry.level || 'INFO').toUpperCase(),
        entry.module || entry.source_label || 'runtime',
        entry.message || entry.raw || '',
        entry.timestamp_utc || 'No timestamp',
      ]);
    const checkRows = safeArray(snapshot?.readiness?.checks)
      .filter((check) => check.status !== 'pass')
      .slice(0, 6)
      .map((check) => ['CHECK', check.label || check.id, check.detail || check.suggestion || '', snapshot?.readiness?.generated_at_utc || 'Current']);
    return {
      title: 'Incident evidence',
      columns: ['Severity', 'Signal', 'Detail', 'Time'],
      rows: [...logRows, ...checkRows],
    };
  }

  if (featureKey === 'storage') {
    return {
      title: 'Workspace storage',
      columns: ['Section', 'Bytes', 'Files', 'Path'],
      rows: safeArray(snapshot?.storage?.sections).map((section) => [
        section.label,
        formatBytes(section.bytes),
        formatNumber(section.files),
        section.path,
      ]),
    };
  }

  if (featureKey === 'api') {
    return {
      title: 'RPC method probes',
      columns: ['Method', 'Status', 'Latency', 'Result'],
      rows: safeArray(snapshot?.rpc?.probes).map((probe) => [
        probe.method,
        probe.status,
        `${formatNumber(probe.latencyMs)} ms`,
        probe.summary || String(probe.detail || ''),
      ]),
    };
  }

  if (featureKey === 'diagnostics') {
    return {
      title: 'Machine command output',
      columns: ['Check', 'Status', 'Output'],
      rows: [
        ['Listeners', String(readObject(snapshot?.diagnostics?.listeners).status ?? 'captured'), readObject(snapshot?.diagnostics?.listeners).stdout || readObject(snapshot?.diagnostics?.listeners).stderr || ''],
        ['Disk', String(readObject(snapshot?.diagnostics?.disk).status ?? 'captured'), readObject(snapshot?.diagnostics?.disk).stdout || readObject(snapshot?.diagnostics?.disk).stderr || ''],
      ],
    };
  }

  if (featureKey === 'config') {
    return {
      title: 'Config files',
      columns: ['File', 'Bytes', 'Modified', 'Path'],
      rows: safeArray(snapshot?.config?.files).map((file) => [
        file.path?.split('/').pop() || 'file',
        file.exists ? formatBytes(file.bytes) : 'Missing',
        file.modifiedAtUtc || 'No timestamp',
        file.path,
      ]),
    };
  }

  if (featureKey === 'transactions') {
    const pool = mempoolTransactions(snapshot);
    const latestTransactions = safeArray(blocks[0]?.transactions);
    return {
      title: 'Selected node mempool',
      columns: ['Hash', 'State', 'Amount/Fee', 'Source'],
      rows: [
        ...pool.slice(0, 8).map((tx) => [
          tx.hash || tx.tx_hash || tx.id || 'pending transaction',
          tx.status || 'pending',
          tx.amount || tx.fee || tx.gas || '0',
          'pool',
        ]),
        ...latestTransactions.slice(0, 8).map((tx) => [
          tx.hash || tx.tx_hash || tx.id || 'block transaction',
          tx.status || 'confirmed',
          tx.amount || tx.fee || tx.gas || '0',
          `block ${formatNumber(blocks[0]?.number ?? blocks[0]?.block_index ?? 0)}`,
        ]),
      ],
    };
  }

  if (featureKey === 'validatorOnboarding') {
    const fork = forkStatus(snapshot);
    return {
      title: 'Post-fork onboarding requirements',
      columns: ['Gate', 'Required', 'Live value', 'Status'],
      rows: [
        ['chain_id', REQUIRED_CHAIN_ID, liveChainId(snapshot, null) || 'not reported', liveChainId(snapshot, null) === REQUIRED_CHAIN_ID ? 'pass' : 'check'],
        ['network_id', REQUIRED_NETWORK_ID, liveNetworkId(snapshot, null) || 'not reported', liveNetworkId(snapshot, null) === REQUIRED_NETWORK_ID ? 'pass' : 'check'],
        ['fork_height', formatNumber(REQUIRED_FORK_HEIGHT), Number(fork.fork_height ?? fork.forkHeight ?? 0) ? formatNumber(fork.fork_height ?? fork.forkHeight) : 'not reported', Number(fork.fork_height ?? fork.forkHeight ?? 0) === REQUIRED_FORK_HEIGHT ? 'pass' : 'check'],
        ['consensus', REQUIRED_CONSENSUS_ALGORITHM, fork.new_consensus_algorithm || fork.newConsensusAlgorithm || 'not reported', String(fork.new_consensus_algorithm || fork.newConsensusAlgorithm || '') === REQUIRED_CONSENSUS_ALGORITHM ? 'pass' : 'check'],
        ['parser_mode', REQUIRED_PARSER_MODE, fork.parser_mode || fork.parserMode || 'not reported', String(fork.parser_mode || fork.parserMode || '') === REQUIRED_PARSER_MODE ? 'pass' : 'check'],
      ],
    };
  }

  if (featureKey === 'dag') {
    const dag = readObject(snapshot?.dag);
    const vertices = safeArray(dag.vertices);
    if (vertices.length) {
      return {
        title: 'DAG vertex evidence',
        columns: ['Vertex', 'Round/Height', 'Author', 'Certified'],
        rows: vertices.slice(0, 16).map((vertex, index) => [
          vertex.id || vertex.vertex_id || vertex.hash || `vertex-${index}`,
          formatNumber(vertex.round ?? vertex.height ?? vertex.block_height ?? 0),
          vertex.author || vertex.validator || vertex.validator_id || '',
          String(vertex.certified ?? vertex.available ?? false),
        ]),
      };
    }
    return {
      title: dag.available ? 'DAG graph evidence' : 'PoSy finalized block evidence',
      columns: ['Height', 'Hash', 'Parent', 'Validator'],
      rows: blocks.slice(0, 16).map((block) => [
        formatNumber(block.number ?? block.block_index ?? block.blockNumber ?? 0),
        block.hash || '',
        block.parentHash || block.parent_hash || block.previous_hash || '',
        block.validator || block.validator_id || '',
      ]),
    };
  }

  return {
    title: featureKey === 'consensus' ? 'Recent consensus blocks' : 'Live RPC evidence',
    columns: ['Height', 'Hash', 'Validator', 'Transactions'],
    rows: blocks.slice(0, 12).map((block) => [
      formatNumber(block.number ?? block.block_index ?? block.blockNumber ?? 0),
      block.hash || '',
      block.validator || block.validator_id || '',
      formatNumber(safeArray(block.transactions).length),
    ]),
  };
}

function FeatureChecklist({ items }) {
  return (
    <PanelCard title="Live checks">
      <div className="cp-feature-checklist">
        {items.length ? items.map((item) => (
          <article key={item.id} className={`cp-feature-check tone-${item.status === 'pass' ? 'good' : 'warn'} ${item.status === 'pass' ? 'is-done' : ''}`}>
            <span className="material-icons" aria-hidden="true">{item.status === 'pass' ? 'check_circle' : 'radio_button_unchecked'}</span>
            <div>
              <strong>{item.label}</strong>
              <p>{item.detail}</p>
            </div>
          </article>
        )) : (
          <div className="cp-empty-inline">The live snapshot returned zero actionable checks.</div>
        )}
      </div>
    </PanelCard>
  );
}

function FeatureTable({ table }) {
  return (
    <PanelCard title={table.title}>
      <div className="cp-feature-table">
        <div className="cp-feature-table-row cp-feature-table-head">
          {table.columns.map((column) => <span key={column}>{column}</span>)}
        </div>
        {table.rows.length ? table.rows.map((row, rowIndex) => (
          <div key={`${row.join('-')}-${rowIndex}`} className="cp-feature-table-row">
            {row.map((cell, index) => (
              <span key={`${index}-${String(cell).slice(0, 40)}`} className={index === 0 ? 'is-primary' : ''}>{String(cell)}</span>
            ))}
          </div>
        )) : (
          <div className="cp-empty-inline">The live source returned zero rows for this screen.</div>
        )}
      </div>
    </PanelCard>
  );
}

function LiveGraphVisual({ snapshot }) {
  const graph = graphSnapshot(snapshot);
  const nodes = safeArray(graph.nodes).slice(0, 18);
  const nodeById = new Map(nodes.map((node, index) => [node.id, {
    ...node,
    x: 8 + (index % 6) * 17,
    y: 24 + Math.floor(index / 6) * 28,
  }]));
  const edges = safeArray(graph.edges)
    .map((edge) => ({ from: nodeById.get(edge.from), to: nodeById.get(edge.to) }))
    .filter((edge) => edge.from && edge.to);
  const nodeLabel = (height) => {
    const text = String(height ?? '').replace(/[^\d]/g, '');
    return text ? `#${text.slice(-4)}` : '#0';
  };

  return (
    <div className="cp-feature-visual cp-feature-live-runtime">
      {nodes.length ? (
        <svg viewBox="0 0 112 100" role="img" aria-label="Live block parent graph">
          {edges.map((edge, index) => (
            <line key={`${edge.from.id}-${edge.to.id}-${index}`} x1={edge.from.x} y1={edge.from.y} x2={edge.to.x} y2={edge.to.y} />
          ))}
          {Array.from(nodeById.values()).map((node) => (
            <g key={node.id || node.height} transform={`translate(${node.x} ${node.y})`}>
              <circle r="5.5" className="tone-cyan" />
              <text x="0" y="14" textAnchor="middle">{nodeLabel(node.height)}</text>
            </g>
          ))}
        </svg>
      ) : (
        <div className="cp-empty-inline">The node returned zero recent block graph rows.</div>
      )}
    </div>
  );
}

function hasLiveGraph(snapshot) {
  const graph = graphSnapshot(snapshot);
  return safeArray(graph.nodes).length > 0;
}

function ValidatorOnboardingWorkflow({
  snapshot,
  activationReport,
  onboardingResult,
  selectedNode,
  selectedNodeLive,
  actionBusy,
  onAction,
}) {
  const fork = forkStatus(snapshot);
  const chainId = liveChainId(snapshot, activationReport);
  const networkId = liveNetworkId(snapshot, activationReport);
  const role = selectedNodeRole(selectedNode, snapshot);
  const isValidator = role === 'validator';
  const parserMode = String(fork.parser_mode || fork.parserMode || '').trim();
  const algorithm = String(fork.new_consensus_algorithm || fork.newConsensusAlgorithm || '').trim();
  const forkHeight = Number(fork.fork_height ?? fork.forkHeight ?? 0);
  const forkParentHash = String(fork.parent_hash || fork.parentHash || '').trim();
  const preflightCounts = preflightPassCount(activationReport);
  const canStake = camelOrSnake(activationReport, 'canStake', 'can_stake') === true;
  const activationPolicy = camelOrSnake(activationReport, 'onboardingPolicy', 'onboarding_policy');
  const activationPolicyAllowed = camelOrSnake(activationPolicy, 'activationAllowed', 'activation_allowed') === true;
  const validatorSetSnapshot = readObject(camelOrSnake(activationPolicy, 'validatorSetSnapshot', 'validator_set_snapshot'));
  const validatorSetActive = safeArray(camelOrSnake(validatorSetSnapshot, 'activeValidators', 'active_validators'));
  const validatorSetPending = safeArray(camelOrSnake(validatorSetSnapshot, 'pendingValidators', 'pending_validators'));
  const validatorSetJailed = safeArray(camelOrSnake(validatorSetSnapshot, 'jailedValidators', 'jailed_validators'));
  const policyGates = [
    ['Source majority', camelOrSnake(activationPolicy, 'sourceMajority', 'source_majority')],
    ['Shadow epoch', camelOrSnake(activationPolicy, 'shadowEpoch', 'shadow_epoch')],
    ['Duty gates', camelOrSnake(activationPolicy, 'dutyGates', 'duty_gates')],
    ['Secure validator network', camelOrSnake(activationPolicy, 'validatorVpn', 'validator_vpn')],
    ['Epoch validator set', camelOrSnake(activationPolicy, 'epochValidatorSet', 'epoch_validator_set')],
    ['Epoch boundary', camelOrSnake(activationPolicy, 'epochBoundary', 'epoch_boundary')],
  ].map(([label, gate]) => {
    const status = String(camelOrSnake(gate, 'status', 'status') || 'blocked').toLowerCase();
    return {
      label,
      status,
      tone: status === 'pass' ? 'good' : status === 'failed' ? 'bad' : 'warn',
      detail: String(camelOrSnake(gate, 'detail', 'detail') || 'Evidence not available yet.'),
    };
  });
  const preflightCanActivate = camelOrSnake(activationReport, 'canActivate', 'can_activate') === true;
  const canActivate = preflightCanActivate && activationPolicyAllowed;
  const activationStatus = String(camelOrSnake(activationReport, 'overallStatus', 'overall_status') || '').trim();
  const syncReady = preflightCheckPassed(activationReport, ['sync-gap', 'synced'])
    || (selectedNodeLive?.is_running && selectedNodeLive?.local_rpc_ready !== false && (Number(selectedNodeLive?.sync_gap) || 0) <= SYNC_READY_GAP);
  const peersReady = preflightCheckPassed(activationReport, ['peers-visible', 'peers_connected'])
    || Number(selectedNodeLive?.local_peer_count || 0) >= 2;
  const seedReady = preflightCheckPassed(activationReport, ['seed-registration', 'seed_registered']);
  const canonicalReady = chainId === REQUIRED_CHAIN_ID
    && networkId === REQUIRED_NETWORK_ID
    && preflightCheckPassed(activationReport, ['canonical-workspace-genesis', 'canonical-chain-state', 'canonical_genesis']);
  const forkReady = forkHeight === REQUIRED_FORK_HEIGHT
    && forkParentHash === REQUIRED_FORK_PARENT_HASH
    && algorithm === REQUIRED_CONSENSUS_ALGORITHM
    && parserMode === REQUIRED_PARSER_MODE;
  const keyReady = preflightCheckPassed(activationReport, [
    'fndsa',
    'fn-dsa',
    'consensus-key',
    'consensus_key',
    'validator-consensus-key',
  ]) || forkReady;
  const fundingReady = preflightCheckPassed(activationReport, ['funding', 'balance', 'wallet-balance']);
  const stakeReady = preflightCheckPassed(activationReport, ['stake', 'staked', 'bonded']);
  const activeReady = String(readObject(probeResult(snapshot, 'synergy_getValidator')).status || '').toLowerCase() === 'active';
  const validatorTransportReady = preflightCheckPassed(activationReport, ['validator-vpn-route', 'validator_vpn_route', 'public-endpoint', 'public_p2p_endpoint']);
  const publicHost = String(selectedNode?.public_host || selectedNodeLive?.public_host || '').trim();
  const publicP2pPort = Number(selectedNodeLive?.public_p2p_port || selectedNodeLive?.p2p_port || selectedNode?.public_p2p_port || 5622);
  const validatorTransport = publicHost ? `${publicHost}:${publicP2pPort}` : validatorTransportReady ? 'secure private route verified' : 'not configured';
  const p2pReachabilityStatus = seedReady
    ? 'network reachable'
    : validatorTransportReady
      ? 'validator transport configured; waiting for peer visibility'
      : 'secure validator route not verified';
  const consensusActivationStatus = activeReady
    ? 'active consensus validator'
    : canActivate
      ? 'ready for explicit consensus activation'
      : 'not consensus-active';
  const validatorSetRows = [
    ['epoch', camelOrSnake(validatorSetSnapshot, 'epochId', 'epoch_id')],
    ['version', camelOrSnake(validatorSetSnapshot, 'validatorSetVersion', 'validator_set_version')],
    ['local status', camelOrSnake(validatorSetSnapshot, 'localValidatorStatus', 'local_validator_status')],
    ['quorum threshold', camelOrSnake(validatorSetSnapshot, 'quorumThreshold', 'quorum_threshold')],
    ['active / pending / jailed', `${formatNumber(validatorSetActive.length)} / ${formatNumber(validatorSetPending.length)} / ${formatNumber(validatorSetJailed.length)}`],
    ['local set hash', compactHash(camelOrSnake(validatorSetSnapshot, 'localValidatorSetHash', 'local_validator_set_hash'))],
    ['network set hash', compactHash(camelOrSnake(validatorSetSnapshot, 'networkValidatorSetHash', 'network_validator_set_hash'))],
    ['protocol', camelOrSnake(validatorSetSnapshot, 'protocolVersion', 'protocol_version')],
  ];

  const steps = [
    {
      id: 'role',
      label: 'Select a validator',
      done: isValidator,
      detail: `Selected role ${role || 'not reported'}. Onboarding must add a validator through activation, not by changing genesis.`,
      actions: null,
    },
    {
      id: 'canonical',
      label: 'Prove canonical chain continuity',
      done: canonicalReady,
      detail: preflightCheckDetail(activationReport, ['canonical-workspace-genesis', 'canonical-chain-state', 'canonical_genesis'], `Required chain_id ${REQUIRED_CHAIN_ID} and network_id ${REQUIRED_NETWORK_ID}.`),
      actions: (
        <>
          <SNRGButton variant="blue" size="sm" disabled={actionBusy === 'resync-time'} onClick={() => onAction({ id: 'resync-time', label: 'Resync Time' })}>
            {actionBusy === 'resync-time' ? 'Resyncing...' : 'Resync Time'}
          </SNRGButton>
          <SNRGButton variant="blue" size="sm" disabled={actionBusy === 'activation-preflight'} onClick={() => onAction({ id: 'activation-preflight', label: 'Activation Preflight' })}>
            {actionBusy === 'activation-preflight' ? 'Checking...' : 'Run Preflight'}
          </SNRGButton>
        </>
      ),
    },
    {
      id: 'fork',
      label: 'Use checkpointed FN-DSA fork metadata',
      done: forkReady && keyReady,
      detail: `Required fork ${formatNumber(REQUIRED_FORK_HEIGHT)}, parent ${formatNumber(REQUIRED_FORK_PARENT_HEIGHT)}, ${REQUIRED_CONSENSUS_ALGORITHM}, parser ${REQUIRED_PARSER_MODE}. Live fork ${forkHeight || 'not reported'}.`,
      actions: (
        <SNRGButton variant="blue" size="sm" disabled={actionBusy === 'activation-preflight'} onClick={() => onAction({ id: 'activation-preflight', label: 'Activation Preflight' })}>
          Verify Metadata
        </SNRGButton>
      ),
    },
    {
      id: 'sync',
      label: 'Restore or catch up from post-fork state',
      done: syncReady && peersReady && seedReady,
      detail: preflightCheckDetail(activationReport, ['sync-gap', 'synced'], `Current lag ${formatNumber(selectedNodeLive?.sync_gap ?? 0)} blocks with ${formatNumber(selectedNodeLive?.local_peer_count ?? 0)} visible peers.`),
      actions: (
        <>
          <SNRGButton variant="purple" size="sm" disabled={actionBusy === 'sync-catch-up'} onClick={() => onAction({ id: 'sync-catch-up', label: 'Sync Catch Up' })}>
            {actionBusy === 'sync-catch-up' ? 'Syncing...' : 'Sync Catch Up'}
          </SNRGButton>
          <SNRGButton variant="blue" size="sm" disabled={actionBusy === 'register-seeds'} onClick={() => onAction({ id: 'register-seeds', label: 'Refresh Seeds' })}>
            Refresh Seeds
          </SNRGButton>
        </>
      ),
    },
    {
      id: 'stake',
      label: stakeReady ? 'Stake is bonded' : 'Fund and bond validator stake',
      done: fundingReady && stakeReady,
      detail: preflightCheckDetail(activationReport, ['stake', 'staked', 'bonded', 'funding', 'balance'], 'Stake action remains disabled until the validator wallet funding and bonding checks pass.'),
      actions: (
        <SNRGButton variant="purple" size="sm" disabled={!canStake || actionBusy === 'stake-validator'} onClick={() => onAction({ id: 'stake-validator', label: 'Stake Validator' })}>
          {actionBusy === 'stake-validator' ? 'Staking...' : 'Stake Validator'}
        </SNRGButton>
      ),
    },
    {
      id: 'activate',
      label: activeReady ? 'Validator is active' : 'Activate at the safe gate',
      done: activeReady,
      detail: activationPolicyAllowed
        ? (activationStatus || 'Activation is allowed only after preflight, fork metadata, sync, peer, funding, stake, source-majority, shadow, duty-gate, secure-network, validator-set, and epoch-boundary checks pass.')
        : 'Activation is blocked until source-majority proof, a full shadow epoch, closed duty gates, secure validator network, latest EpochValidatorSet, and epoch boundary are proven.',
      actions: (
        <>
          <SNRGButton variant="blue" size="sm" disabled={actionBusy === 'activation-preflight'} onClick={() => onAction({ id: 'activation-preflight', label: 'Activation Preflight' })}>
            Refresh Gate
          </SNRGButton>
          <SNRGButton variant="lime" size="sm" disabled={!canActivate || actionBusy === 'activate-validator'} onClick={() => onAction({ id: 'activate-validator', label: 'Activate Validator' })}>
            {actionBusy === 'activate-validator' ? 'Activating...' : 'Activate Validator'}
          </SNRGButton>
        </>
      ),
    },
  ];
  const openStep = steps.find((step) => !step.done)?.id;
  const recoveryStep = safeArray(onboardingResult?.steps).find((step) => step.id === 'recover-local-fork');

  return (
    <PanelCard
      title="Onboarding gate"
      detail="The selected node must pass every gate before it can become a post-fork validator."
      action={<StatusPill tone={canActivate || activeReady ? 'good' : 'warn'}>{activeReady ? 'Active' : canActivate ? 'Ready' : 'Gated'}</StatusPill>}
    >
      {recoveryStep ? (
        <div className={`cp-inline-notice ${recoveryStep.status === 'pass' ? 'tone-good' : 'tone-warn'}`}>
          <strong>{recoveryStep.label}</strong>
          <span>{recoveryStep.detail}</span>
        </div>
      ) : null}
      <div className="cp-guidance-actions">
        <SNRGButton
          variant="blue"
          size="sm"
          disabled={!isValidator || actionBusy === 'verify-validator-onboarding'}
          onClick={() => onAction({ id: 'verify-validator-onboarding', label: 'Verify Onboarding' })}
        >
          {actionBusy === 'verify-validator-onboarding' ? 'Verifying...' : 'Verify Onboarding'}
        </SNRGButton>
        <SNRGButton
          variant="lime"
          size="sm"
          disabled={!isValidator || actionBusy === 'run-validator-onboarding'}
          onClick={() => onAction({ id: 'run-validator-onboarding', label: 'Run Safe Onboarding' })}
        >
          {actionBusy === 'run-validator-onboarding' ? 'Running...' : 'Run Safe Onboarding'}
        </SNRGButton>
        <SNRGButton
          variant="purple"
          size="sm"
          disabled={!isValidator || actionBusy === 'request-validator-rejoin'}
          onClick={() => onAction({ id: 'request-validator-rejoin', label: 'Request Rejoin' })}
        >
          {actionBusy === 'request-validator-rejoin' ? 'Arming...' : 'Request Rejoin'}
        </SNRGButton>
        <SNRGButton variant="blue" size="sm" disabled={actionBusy === 'resync-time'} onClick={() => onAction({ id: 'resync-time', label: 'Resync Time' })}>
          {actionBusy === 'resync-time' ? 'Resyncing...' : 'Resync Time'}
        </SNRGButton>
      </div>

      <div className="cp-definition-list cp-definition-list-compact">
        <div className="cp-definition-item">
          <span>chain_id</span>
          <strong>{chainId || 'not reported'}</strong>
        </div>
        <div className="cp-definition-item">
          <span>network_id</span>
          <strong>{networkId || 'not reported'}</strong>
        </div>
        <div className="cp-definition-item">
          <span>fork height</span>
          <strong>{forkHeight ? formatNumber(forkHeight) : 'not reported'}</strong>
        </div>
        <div className="cp-definition-item">
          <span>preflight</span>
          <strong>{preflightCounts.total ? `${formatNumber(preflightCounts.passing)}/${formatNumber(preflightCounts.total)}` : 'not run'}</strong>
        </div>
        <div className="cp-definition-item">
          <span>validator transport</span>
          <strong>{validatorTransport}</strong>
        </div>
        <div className="cp-definition-item">
          <span>P2P reachability</span>
          <strong>{p2pReachabilityStatus}</strong>
        </div>
        <div className="cp-definition-item">
          <span>consensus activation</span>
          <strong>{consensusActivationStatus}</strong>
        </div>
      </div>

      <div className="cp-inline-note">
        Validator reachability is transport-only. A reachable validator remains outside consensus until the validator-set activation gate explicitly approves it.
      </div>

      <div className="cp-definition-list cp-definition-list-compact" aria-label="Epoch validator set">
        {validatorSetRows.map(([label, value]) => (
          <div className="cp-definition-item" key={label}>
            <span>{label}</span>
            <strong>{firstTextValue(value) || 'not reported'}</strong>
          </div>
        ))}
      </div>

      <div className="cp-onboarding-policy-grid" aria-label="Activation policy evidence">
        {policyGates.map((gate) => (
          <article key={gate.label} className={`cp-onboarding-policy-card tone-${gate.tone}`}>
            <div>
              <span>{gate.label}</span>
              <strong>{gate.status}</strong>
            </div>
            <p>{gate.detail}</p>
          </article>
        ))}
      </div>

      <div className="cp-guidance-checklist cp-validator-activation-guide">
        {steps.map((step, index) => (
          <article key={step.id} className={`cp-guidance-step ${step.done ? 'is-complete' : ''} ${step.id === openStep ? 'is-active' : ''}`}>
            <div className="cp-guidance-marker">{step.done ? 'OK' : String(index + 1)}</div>
            <div>
              <div className="cp-guidance-step-head">
                <strong>{step.label}</strong>
                {step.id === openStep ? <StatusPill tone="warn">Current gate</StatusPill> : null}
              </div>
              <p>{step.detail}</p>
              {step.actions ? <div className="cp-guidance-actions">{step.actions}</div> : null}
            </div>
          </article>
        ))}
      </div>
    </PanelCard>
  );
}

function buildRuntimeActionsForFeature(featureKey, selectedNodeLive) {
  const common = {
    refresh: { id: 'refresh-live-state', label: 'Refresh Live State', variant: 'blue', requiresNode: false },
    readiness: { id: 'run-readiness-check', label: 'Run Readiness Check', variant: 'lime' },
    logs: { id: 'inspect-recent-logs', label: 'Inspect Recent Logs', variant: 'blue' },
    start: { id: 'start-node', label: selectedNodeLive?.is_running ? 'Node Running' : 'Start Node', variant: 'lime' },
    stop: { id: 'stop-node', label: 'Stop Node', variant: 'red' },
    restart: { id: 'restart-node', label: 'Restart Runtime', variant: 'purple' },
    boost: { id: 'boost-sync', label: 'Boost Sync', variant: 'lime' },
    catchUp: { id: 'sync-catch-up', label: 'Sync Catch Up', variant: 'purple' },
    register: { id: 'register-seeds', label: 'Refresh Seeds', variant: 'blue' },
    rejoin: { id: 'rejoin-network', label: 'Rejoin Network', variant: 'purple' },
    requestRejoin: { id: 'request-validator-rejoin', label: 'Request Rejoin', variant: 'purple' },
    timeSync: { id: 'resync-time', label: 'Resync Time', variant: 'blue' },
    verifyOnboarding: { id: 'verify-validator-onboarding', label: 'Verify Onboarding', variant: 'blue' },
    onboarding: { id: 'run-validator-onboarding', label: 'Run Safe Onboarding', variant: 'lime' },
    preflight: { id: 'activation-preflight', label: 'Activation Preflight', variant: 'lime' },
    stake: { id: 'stake-validator', label: 'Stake Validator', variant: 'purple' },
    activate: { id: 'activate-validator', label: 'Activate Validator', variant: 'blue' },
    settings: { id: 'open-settings', label: 'Open Settings', variant: 'blue', requiresNode: false },
  };

  const actionMap = {
    alerts: [common.refresh, common.readiness, common.logs],
    validator: [common.verifyOnboarding, common.onboarding, common.requestRejoin, common.timeSync, common.preflight, common.catchUp, common.activate, common.register],
    validatorOnboarding: [common.verifyOnboarding, common.onboarding, common.requestRejoin, common.timeSync, common.preflight, common.catchUp, common.register, common.stake, common.activate],
    security: [common.readiness, common.logs, common.refresh],
    identity: [common.readiness, common.preflight, common.logs],
    consensus: [common.refresh, common.readiness, common.register, common.catchUp],
    dag: [common.refresh, common.logs, common.boost],
    transactions: [common.logs, common.refresh, common.readiness],
    storage: [common.refresh, common.logs, common.settings],
    api: [common.refresh, common.readiness, common.logs],
    maintenance: [common.restart, common.catchUp, common.rejoin, common.boost, common.stop],
    diagnostics: [common.refresh, common.logs, common.readiness],
    config: [common.refresh, common.readiness, common.logs],
  };

  return actionMap[featureKey] || [common.refresh, common.readiness];
}

export default function ControlPanelFeaturePage({ screenKey }) {
  const feature = getFeatureScreenByKey(screenKey);
  const navigate = useNavigate();
  const {
    actionAudit,
    liveStatus,
    network,
    networkStats,
    recordAction,
    refresh,
    selectedNode,
    selectedNodeLive,
    viewMode,
  } = useControlPanel();
  const [snapshot, setSnapshot] = useState(null);
  const [snapshotError, setSnapshotError] = useState('');
  const [activationReport, setActivationReport] = useState(null);
  const [onboardingResult, setOnboardingResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [notice, setNotice] = useState('');
  const [actionBusy, setActionBusy] = useState('');

  const loadSnapshot = async () => {
    if (!feature) return;
    setLoading(true);
    try {
      const nextSnapshot = await invoke('testnet_get_feature_snapshot', {
        input: {
          screenKey: feature.key,
          nodeId: selectedNode?.id,
        },
      });
      setSnapshot(nextSnapshot || null);
      setSnapshotError('');
      if ((feature.key === 'validator' || feature.key === 'validatorOnboarding') && selectedNode?.id) {
        try {
          const report = await invoke('testnet_get_validator_activation_preflight', { nodeId: selectedNode.id });
          setActivationReport(report || null);
        } catch (error) {
          setActivationReport({ error: String(error), checks: [] });
        }
      } else {
        setActivationReport(null);
      }
    } catch (error) {
      setSnapshot(null);
      setActivationReport(null);
      setSnapshotError(String(error));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadSnapshot();
  }, [feature?.key, selectedNode?.id, liveStatus]);

  const metrics = useMemo(
    () => buildMetrics(feature?.key, snapshot || {}, selectedNodeLive, networkStats),
    [feature?.key, networkStats, selectedNodeLive, snapshot],
  );
  const checks = useMemo(
    () => buildChecks(feature?.key, snapshot || {}),
    [feature?.key, snapshot],
  );
  const table = useMemo(
    () => buildTable(feature?.key, snapshot || {}),
    [feature?.key, snapshot],
  );
  const runtimeActions = buildRuntimeActionsForFeature(feature?.key, selectedNodeLive);
  const featureTitle = feature?.modeTitles?.[viewMode] || feature?.title;
  const featureCopy = feature?.modeCopy?.[viewMode] || feature?.description;
  const isValidatorLifecycle = feature?.key === 'validator';
  const isValidatorWorkflow = feature?.key === 'validatorOnboarding';
  const showGraphHero = !isValidatorLifecycle && hasLiveGraph(snapshot || {});
  const showEvidenceTable = !isValidatorLifecycle || table.rows.length > 0;

  if (!feature) {
    return null;
  }

  const handleAction = async (action) => {
    if (!selectedNode && action.requiresNode !== false) {
      setNotice('No node is selected.');
      return;
    }

    setActionBusy(action.id);
    try {
      let detail = '';
      if (action.id === 'refresh-live-state') {
        await refresh({ silent: false });
        await loadSnapshot();
        detail = 'Live state refreshed from the control service.';
      } else if (action.id === 'start-node') {
        const response = await runNodeControlAction({ node: selectedNode, network, action: 'start' });
        detail = response?.message || 'Node start requested.';
        await refresh({ silent: true });
      } else if (action.id === 'stop-node') {
        const response = await runNodeControlAction({ node: selectedNode, network, action: 'stop' });
        detail = response?.message || 'Node stop requested.';
        await refresh({ silent: true });
      } else if (action.id === 'restart-node') {
        detail = await restartNodeAction({ node: selectedNode, network });
        await refresh({ silent: true });
      } else if (action.id === 'boost-sync') {
        detail = await boostSyncAction(selectedNode.id);
        await refresh({ silent: true });
      } else if (action.id === 'sync-catch-up') {
        const result = await syncCatchUpRejoinAction({ node: selectedNode, network });
        detail = result?.message || 'Sync Catch Up completed.';
        await refresh({ silent: true });
      } else if (action.id === 'register-seeds') {
        detail = await registerWithSeedsAction(selectedNode.id);
        await refresh({ silent: true });
      } else if (action.id === 'rejoin-network') {
        detail = await rejoinNetworkAction({ node: selectedNode, network });
        await refresh({ silent: true });
      } else if (action.id === 'resync-time') {
        const response = await runNodeControlAction({ node: selectedNode, network, action: 'resync-time' });
        detail = response?.message || 'Machine time resync action completed.';
        await refresh({ silent: true });
      } else if (action.id === 'verify-validator-onboarding') {
        const result = await invoke('testnet_run_validator_onboarding', {
          input: {
            nodeId: selectedNode.id,
            dryRun: true,
            autoResyncTime: false,
            autoStart: false,
            autoStake: false,
            autoActivate: false,
          },
        });
        setOnboardingResult(result);
        setActivationReport(result?.preflight || null);
        detail = result?.message || 'Validator onboarding proof check completed.';
      } else if (action.id === 'run-validator-onboarding') {
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
        setOnboardingResult(result);
        setActivationReport(result?.preflight || result?.catch_up?.preflight || result?.stake?.preflight || result?.activation?.preflight || null);
        detail = result?.message || 'Validator onboarding run completed.';
        await refresh({ silent: true });
      } else if (action.id === 'request-validator-rejoin') {
        const result = await invoke('testnet_request_validator_rejoin', {
          input: { nodeId: selectedNode.id },
        });
        detail = result?.message || 'Validator rejoin request armed for the next epoch entry window.';
        await refresh({ silent: true });
      } else if (action.id === 'run-readiness-check') {
        const report = await invoke('testnet_get_node_readiness', { nodeId: selectedNode.id });
        detail = `Readiness ${report?.overall_status || 'reported'}: ${formatNumber(report?.ready_count)} of ${formatNumber(report?.total_count)} checks passing.`;
      } else if (action.id === 'inspect-recent-logs') {
        const bundle = await invoke('testnet_get_node_logs', { nodeId: selectedNode.id, lines: 80 });
        const entries = safeArray(bundle?.entries);
        const latest = entries[entries.length - 1];
        detail = entries.length
          ? `Loaded ${formatNumber(entries.length)} log entries. Latest: ${latest?.level || 'INFO'} ${latest?.message || latest?.raw || 'runtime event'}.`
          : 'The log reader returned zero entries for the selected node.';
      } else if (action.id === 'activation-preflight') {
        const result = await invoke('testnet_get_validator_activation_preflight', { nodeId: selectedNode.id });
        setActivationReport(result || null);
        const ready = result?.canActivate || result?.can_activate;
        detail = ready ? 'Validator activation preflight is passing.' : 'Validator activation preflight returned blocking checks.';
      } else if (action.id === 'stake-validator') {
        const result = await invoke('testnet_stake_validator', {
          input: {
            nodeId: selectedNode.id,
            displayName: selectedNode.display_label || selectedNode.role_display_name || 'Validator',
          },
        });
        const stakeStatus = String(result?.status || '').toLowerCase();
        let nextReport = result?.preflight || null;
        detail = result?.message || `Validator stake submitted${result?.tx_hash ? `: ${result.tx_hash}` : ''}.`;
        if (stakeStatus === 'submitted' || stakeStatus === 'already-bonded' || stakeStatus === 'already_bonded') {
          const onboarding = await invoke('testnet_run_validator_onboarding', {
            input: {
              nodeId: selectedNode.id,
              dryRun: false,
              autoResyncTime: true,
              autoStart: true,
              autoStake: false,
              autoActivate: true,
            },
          });
          nextReport = onboarding?.preflight
            || onboarding?.catch_up?.preflight
            || onboarding?.stake?.preflight
            || onboarding?.activation?.preflight
            || nextReport;
          detail = `${detail} ${onboarding?.message || 'Autonomous onboarding resumed after stake.'}`;
        }
        setActivationReport(nextReport);
      } else if (action.id === 'activate-validator') {
        const result = await invoke('testnet_activate_validator', {
          input: {
            nodeId: selectedNode.id,
            displayName: selectedNode.display_label || selectedNode.role_display_name || 'Validator',
          },
        });
        setActivationReport(result?.preflight || null);
        detail = result?.message || `Validator activation submitted${result?.tx_hash ? `: ${result.tx_hash}` : ''}.`;
      } else if (action.id === 'open-settings') {
        navigate('/settings');
        detail = 'Opened Settings.';
      }

      setNotice(detail);
      recordAction({
        title: action.label,
        detail,
        status: action.id.startsWith('stop') ? 'warn' : 'info',
        source: feature.key,
        command: action.id,
        payload: {
          screen: feature.key,
          nodeId: selectedNode?.id || null,
          viewMode,
        },
      });
      await loadSnapshot();
    } catch (error) {
      const detail = String(error);
      setNotice(detail);
      recordAction({
        title: `${action.label} failed`,
        detail,
        status: 'error',
        source: feature.key,
        command: action.id,
        payload: {
          screen: feature.key,
          nodeId: selectedNode?.id || null,
          viewMode,
        },
      });
    } finally {
      setActionBusy('');
    }
  };

  return (
    <div className="cp-page-stack cp-feature-page">
      <SectionHeader
        eyebrow={feature.eyebrow}
        title={featureTitle}
        copy={featureCopy}
        actions={(
          <>
            <StatusPill tone={feature.tone}>{feature.label}</StatusPill>
            <SNRGButton variant="blue" size="sm" onClick={() => void loadSnapshot()} disabled={loading}>
              {loading ? 'Refreshing...' : 'Refresh'}
            </SNRGButton>
          </>
        )}
      />

      {snapshotError ? <div className="cp-inline-notice tone-bad">{snapshotError}</div> : null}
      {notice ? <div className="cp-inline-notice">{notice}</div> : null}

      <div className="cp-dashboard-grid cp-feature-grid">
        <div className="cp-dashboard-main">
          {showGraphHero ? (
            <PanelCard
              className="cp-feature-hero"
              eyebrow={selectedNodeLabel(snapshot, selectedNode)}
              title={`${feature.label} live workspace`}
              detail={`Snapshot generated ${snapshot?.generatedAtUtc || 'after refresh'} from local control-service and node RPC sources.`}
              action={<StatusPill tone={nodeRuntimeTone(selectedNodeLive)} live>{nodeRuntimeLabel(selectedNodeLive)}</StatusPill>}
            >
              <LiveGraphVisual snapshot={snapshot || {}} />
            </PanelCard>
          ) : null}

          {isValidatorLifecycle || isValidatorWorkflow ? (
            <ValidatorLiveStatusPanel
              node={selectedNode}
              nodeLive={selectedNodeLive}
              liveStatus={liveStatus}
              viewMode={viewMode}
              screenKey={feature.key}
            />
          ) : null}

          {isValidatorWorkflow ? (
            <ValidatorOnboardingWorkflow
              snapshot={snapshot || {}}
              activationReport={activationReport}
              onboardingResult={onboardingResult}
              selectedNode={selectedNode}
              selectedNodeLive={selectedNodeLive}
              actionBusy={actionBusy}
              onAction={handleAction}
            />
          ) : null}

          <div className="cp-metric-grid cp-metric-grid-dashboard">
            {metrics.map((item) => (
              <MetricCard key={`${feature.key}-${item.label}`} {...item} />
            ))}
          </div>

          <div className="cp-split-grid">
            <FeatureChecklist items={checks} />
            <PanelCard title={`${feature.label} actions`} detail="These controls call the production control-service action path and record action receipts.">
              <div className="cp-feature-action-grid">
                {runtimeActions.map((action) => (
                  <SNRGButton
                    key={action.id}
                    variant={action.variant}
                    size="sm"
                    onClick={() => void handleAction(action)}
                    disabled={actionBusy === action.id || (!selectedNode && action.requiresNode !== false) || (action.id === 'start-node' && selectedNodeLive?.is_running)}
                  >
                    {actionBusy === action.id ? 'Working...' : action.label}
                  </SNRGButton>
                ))}
              </div>
            </PanelCard>
          </div>

          {showEvidenceTable ? <FeatureTable table={table} /> : null}
        </div>

        <div className="cp-dashboard-side">
          <PanelCard title="Current node context" detail={selectedNodeLabel(snapshot, selectedNode)}>
            <div className="cp-definition-list">
              <div className="cp-definition-item">
                <span>Address</span>
                <strong>{nodeAddress(snapshot) || 'No node address reported'}</strong>
              </div>
              <div className="cp-definition-item">
                <span>RPC endpoint</span>
                <strong>{snapshot?.rpc?.endpoint || 'No endpoint reported'}</strong>
              </div>
              <div className="cp-definition-item">
                <span>Runtime</span>
                <strong>{nodeRuntimeLabel(selectedNodeLive)}</strong>
              </div>
              <div className="cp-definition-item">
                <span>Sync gap</span>
                <strong>{formatNumber(selectedNodeLive?.sync_gap ?? 0)}</strong>
              </div>
            </div>
          </PanelCard>

          <PanelCard title="Recent action audit">
            <div className="cp-panel-scroll cp-panel-scroll-tight">
              <ActionAuditStream entries={actionAudit.slice(0, 10)} emptyMessage="No actions recorded for this session yet." />
            </div>
          </PanelCard>

          {viewMode === 'developer' ? (
            <JsonInspectorPanel
              title="Production snapshot"
              value={snapshot}
              emptyMessage="Refresh to load the production snapshot."
            />
          ) : null}

          {feature.key === 'config' && viewMode === 'developer' ? (
            safeArray(snapshot?.config?.files).filter((file) => file.contents).slice(0, 3).map((file) => (
              <PanelCard key={file.path} title={file.path?.split('/').pop() || 'config'}>
                <pre className="cp-json-inspector">{file.contents}</pre>
              </PanelCard>
            ))
          ) : null}

          <PanelCard title="Related">
            <div className="cp-button-grid">
              <SNRGButton as={Link} to="/node" variant="blue" size="sm">Node Details</SNRGButton>
              <SNRGButton as={Link} to="/logs" variant="purple" size="sm">Logs</SNRGButton>
            </div>
          </PanelCard>
        </div>
      </div>
    </div>
  );
}

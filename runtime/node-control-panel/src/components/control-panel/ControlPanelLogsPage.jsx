import { useDeferredValue, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { invoke, openPath } from '../../lib/desktopClient';
import { SNRGButton } from '../../styles/SNRGButton';
import { useControlPanel } from './ControlPanelProvider';
import {
  buildLogLevelCounts,
  formatNumber,
  formatTimestamp,
  safeArray,
  simplifyLogEntry,
  statusTone,
} from './controlPanelModel';
import {
  ActivityFeed,
  EmptyPanel,
  JarvisCard,
  MetricBars,
  PanelCard,
  SectionHeader,
} from './ControlPanelShared';
import LogPayloadInspector from './LogPayloadInspector';
import LogSourceSidebar from './LogSourceSidebar';
import VirtualLogStream from './VirtualLogStream';
import SeverityTimelineChart from './charts/SeverityTimelineChart';

const TIME_RANGE_OPTIONS = [
  ['1h', '1h'],
  ['6h', '6h'],
  ['24h', '24h'],
  ['7d', '7d'],
];

const DEVELOPER_TABS = [
  ['live', 'Live stream'],
  ['structured', 'Structured events'],
  ['tails', 'File tails'],
  ['json', 'Raw JSON'],
  ['search', 'Search results'],
];

function copyText(value) {
  if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
    return navigator.clipboard.writeText(String(value || ''));
  }
  throw new Error('Clipboard access requires the desktop runtime.');
}

function buildEntryKey(entry, index) {
  return [
    entry?.source_id || 'log',
    entry?.timestamp_utc || 'no-time',
    entry?.level || 'INFO',
    entry?.module || 'runtime',
    entry?.raw || entry?.message || `row-${index}`,
  ].join('|');
}

function parseTimestampMs(value) {
  if (!value) {
    return 0;
  }
  const numeric = Date.parse(value);
  return Number.isFinite(numeric) ? numeric : 0;
}

function timeRangeToMs(rangeKey) {
  switch (rangeKey) {
    case '1h':
      return 60 * 60 * 1000;
    case '24h':
      return 24 * 60 * 60 * 1000;
    case '7d':
      return 7 * 24 * 60 * 60 * 1000;
    case '6h':
    default:
      return 6 * 60 * 60 * 1000;
  }
}

function classifySubsystem(entry) {
  const haystack = `${entry?.module || ''} ${entry?.message || ''} ${entry?.raw || ''}`.toLowerCase();
  if (/(peer|mesh|bootstrap|seed|dial|transport|session|gossip|discovery)/.test(haystack)) {
    return 'network';
  }
  if (/(block|consensus|quorum|validator|epoch|height|sync|chain)/.test(haystack)) {
    return 'chain';
  }
  if (/(rpc|ws|grpc|http|jsonrpc)/.test(haystack)) {
    return 'rpc';
  }
  if (/(config|workspace|path|manifest|runtime|service|process|startup)/.test(haystack)) {
    return 'runtime';
  }
  return 'general';
}

function matchesSearch(entry, query) {
  if (!query) {
    return true;
  }
  const haystack = [
    entry?.source_label,
    entry?.module,
    entry?.message,
    entry?.raw,
  ].join(' ').toLowerCase();
  return haystack.includes(query);
}

function matchesSeverity(entry, severity) {
  const level = String(entry?.level || 'INFO').toUpperCase();
  if (severity === 'all') {
    return true;
  }
  if (severity === 'critical') {
    return level === 'ERROR';
  }
  if (severity === 'warnings') {
    return level === 'WARN';
  }
  if (severity === 'debug') {
    return level === 'DEBUG' || level === 'TRACE';
  }
  return level === severity.toUpperCase();
}

function buildTimelineBins(entries, rangeKey) {
  const spanMs = timeRangeToMs(rangeKey);
  const stepMs = rangeKey === '7d'
    ? 12 * 60 * 60 * 1000
    : rangeKey === '24h'
      ? 2 * 60 * 60 * 1000
      : 30 * 60 * 1000;
  const now = Date.now();
  const cutoff = now - spanMs;
  const buckets = new Map();

  entries.forEach((entry) => {
    const at = parseTimestampMs(entry?.timestamp_utc);
    if (!at || at < cutoff) {
      return;
    }
    const bucketAt = Math.floor(at / stepMs) * stepMs;
    const current = buckets.get(bucketAt) || {
      id: `bin-${bucketAt}`,
      at: bucketAt,
      label: formatTimestamp(bucketAt),
      info: 0,
      warn: 0,
      error: 0,
    };
    const level = String(entry?.level || 'INFO').toUpperCase();
    if (level === 'ERROR') {
      current.error += 1;
    } else if (level === 'WARN') {
      current.warn += 1;
    } else {
      current.info += 1;
    }
    buckets.set(bucketAt, current);
  });

  return Array.from(buckets.values()).sort((left, right) => left.at - right.at);
}

function buildNarrativeFeed(entries, mode) {
  const grouped = new Map();
  entries.forEach((entry) => {
    const simplified = simplifyLogEntry(entry, mode);
    const groupKey = `${simplified.title}|${simplified.tone}|${entry?.source_label || 'node'}`;
    const current = grouped.get(groupKey) || {
      id: groupKey,
      title: simplified.title,
      detail: simplified.detail,
      tone: simplified.tone,
      time: simplified.time,
      count: 0,
    };
    current.count += 1;
    current.time = simplified.time;
    current.detail = current.count > 1
      ? `${simplified.detail} (${formatNumber(current.count)} related events)`
      : simplified.detail;
    grouped.set(groupKey, current);
  });

  return Array.from(grouped.values())
    .slice(-12)
    .reverse();
}

function buildSourceStats(sources, entries) {
  return safeArray(sources).map((source) => {
    const sourceEntries = entries.filter((entry) => entry?.source_id === source.id);
    const errorCount = sourceEntries.filter((entry) => String(entry?.level || '').toUpperCase() === 'ERROR').length;
    const warnCount = sourceEntries.filter((entry) => String(entry?.level || '').toUpperCase() === 'WARN').length;
    return {
      ...source,
      errorCount,
      warnCount,
      lastSeenLabel: source.modified_at_utc ? formatTimestamp(source.modified_at_utc) : 'Unknown',
    };
  });
}

function buildSeverityItems(levelCounts) {
  return [
    {
      id: 'info',
      label: 'Info',
      value: formatNumber(levelCounts.INFO || 0),
      detail: 'Routine state changes',
      numericValue: Number(levelCounts.INFO || 0),
      tone: 'good',
    },
    {
      id: 'warnings',
      label: 'Warnings',
      value: formatNumber(levelCounts.WARN || 0),
      detail: 'Needs attention soon',
      numericValue: Number(levelCounts.WARN || 0),
      tone: 'warn',
    },
    {
      id: 'critical',
      label: 'Critical',
      value: formatNumber(levelCounts.ERROR || 0),
      detail: 'Immediate operator review',
      numericValue: Number(levelCounts.ERROR || 0),
      tone: 'bad',
    },
  ];
}

function formatStreamLine(entry) {
  return {
    id: entry.entryKey,
    time: formatTimestamp(entry.timestamp_utc),
    tone: simplifyLogEntry(entry, 'developer').tone,
    level: String(entry.level || 'INFO').toUpperCase(),
    sourceLabel: entry.source_label || 'Node',
    module: entry.module || 'runtime',
    raw: entry.raw || entry.message,
    detail: entry.message || entry.raw,
    metadata: entry.metadata || null,
    path: entry.source_path || '',
  };
}

export default function ControlPanelLogsPage() {
  const {
    actionAudit,
    error,
    recordAction,
    refresh,
    selectedNode,
    setViewMode,
    timeRange,
    setTimeRange,
    viewMode,
  } = useControlPanel();

  const [bundle, setBundle] = useState(null);
  const [loading, setLoading] = useState(false);
  const [logsError, setLogsError] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [subsystemFilter, setSubsystemFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [selectedSourceId, setSelectedSourceId] = useState('');
  const [selectedTimelineId, setSelectedTimelineId] = useState('');
  const [selectedEntryId, setSelectedEntryId] = useState('');
  const [advancedRender, setAdvancedRender] = useState('interpreted');
  const [developerTab, setDeveloperTab] = useState('live');
  const [streamPaused, setStreamPaused] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [showBasicTechnical, setShowBasicTechnical] = useState(false);
  const [bookmarkedEntryIds, setBookmarkedEntryIds] = useState([]);

  const deferredSearch = useDeferredValue(search.trim().toLowerCase());
  const logsDirectory = selectedNode ? `${selectedNode.workspace_directory}/logs` : null;

  useEffect(() => {
    if (!selectedNode) {
      setBundle(null);
      setLoading(false);
      setLogsError('');
      return undefined;
    }

    let cancelled = false;

    const loadLogs = async () => {
      if (viewMode === 'developer' && streamPaused) {
        return;
      }
      if (!cancelled) {
        setLoading(true);
      }
      try {
        const nextBundle = await invoke('testnet_get_node_logs', {
          nodeId: selectedNode.id,
          lines: viewMode === 'developer' ? 1200 : viewMode === 'advanced' ? 480 : 260,
        });
        if (!cancelled) {
          setBundle(nextBundle || null);
          setLogsError('');
        }
      } catch (loadError) {
        if (!cancelled) {
          setBundle(null);
          setLogsError(String(loadError));
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    void loadLogs();
    const intervalId = window.setInterval(() => {
      void loadLogs();
    }, viewMode === 'developer' ? 2400 : viewMode === 'advanced' ? 3600 : 5200);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [selectedNode, streamPaused, viewMode]);

  const decoratedEntries = useMemo(
    () => safeArray(bundle?.entries).map((entry, index) => ({
      ...entry,
      entryKey: buildEntryKey(entry, index),
      subsystem: classifySubsystem(entry),
    })),
    [bundle?.entries],
  );

  const sourceStats = useMemo(
    () => buildSourceStats(bundle?.sources, decoratedEntries),
    [bundle?.sources, decoratedEntries],
  );

  const baseEntries = useMemo(() => {
    const cutoff = Date.now() - timeRangeToMs(timeRange);
    return decoratedEntries.filter((entry) => {
      const timestampMs = parseTimestampMs(entry.timestamp_utc);
      if (timestampMs && timestampMs < cutoff) {
        return false;
      }
      if (selectedSourceId && entry.source_id !== selectedSourceId) {
        return false;
      }
      if (subsystemFilter !== 'all' && entry.subsystem !== subsystemFilter) {
        return false;
      }
      if (!matchesSearch(entry, deferredSearch)) {
        return false;
      }
      return true;
    });
  }, [decoratedEntries, deferredSearch, selectedSourceId, subsystemFilter, timeRange]);

  const timelineBins = useMemo(
    () => buildTimelineBins(baseEntries, timeRange),
    [baseEntries, timeRange],
  );

  const streamEntries = useMemo(() => {
    const timelineFilter = selectedTimelineId
      ? timelineBins.find((entry) => entry.id === selectedTimelineId)
      : null;
    const nextEntries = baseEntries.filter((entry) => {
      if (!matchesSeverity(entry, severityFilter)) {
        return false;
      }
      if (!timelineFilter) {
        return true;
      }
      const activeStep = timelineBins.length > 1
        ? Math.max(1, timelineBins[1].at - timelineBins[0].at)
        : Math.max(1, timeRangeToMs(timeRange) / 8);
      const at = parseTimestampMs(entry.timestamp_utc);
      return at >= timelineFilter.at && at < timelineFilter.at + activeStep;
    });
    return nextEntries.sort((left, right) => (
      parseTimestampMs(left.timestamp_utc) - parseTimestampMs(right.timestamp_utc)
    ));
  }, [baseEntries, selectedTimelineId, severityFilter, timeRange, timelineBins]);

  const selectedEntry = useMemo(
    () => streamEntries.find((entry) => entry.entryKey === selectedEntryId) || streamEntries[streamEntries.length - 1] || null,
    [selectedEntryId, streamEntries],
  );

  useEffect(() => {
    if (!streamEntries.length) {
      setSelectedEntryId('');
      return;
    }
    if (!streamEntries.some((entry) => entry.entryKey === selectedEntryId)) {
      setSelectedEntryId(streamEntries[streamEntries.length - 1].entryKey);
    }
  }, [selectedEntryId, streamEntries]);

  useEffect(() => {
    if (selectedTimelineId && !timelineBins.some((entry) => entry.id === selectedTimelineId)) {
      setSelectedTimelineId('');
    }
  }, [selectedTimelineId, timelineBins]);

  const simplifiedEntries = useMemo(
    () => streamEntries.map((entry) => ({
      ...simplifyLogEntry(entry, viewMode === 'basic' ? 'basic' : viewMode === 'advanced' ? 'advanced' : 'developer'),
      id: entry.entryKey,
    })),
    [streamEntries, viewMode],
  );

  const levelCounts = useMemo(
    () => buildLogLevelCounts(streamEntries),
    [streamEntries],
  );
  const severityItems = useMemo(
    () => buildSeverityItems(levelCounts),
    [levelCounts],
  );
  const narrativeFeed = useMemo(
    () => buildNarrativeFeed(streamEntries, viewMode === 'basic' ? 'basic' : 'advanced'),
    [streamEntries, viewMode],
  );

  const incidentClues = useMemo(
    () => buildNarrativeFeed(streamEntries.filter((entry) => ['ERROR', 'WARN'].includes(String(entry.level || '').toUpperCase())), 'advanced'),
    [streamEntries],
  );

  const selectedSource = useMemo(
    () => sourceStats.find((source) => source.id === selectedSourceId) || null,
    [selectedSourceId, sourceStats],
  );

  const developerRows = useMemo(
    () => streamEntries.map(formatStreamLine),
    [streamEntries],
  );
  const bookmarkedRows = useMemo(
    () => developerRows.filter((entry) => bookmarkedEntryIds.includes(entry.id)),
    [bookmarkedEntryIds, developerRows],
  );

  const renderDeveloperViewport = () => {
    if (developerTab === 'json') {
      return (
        <LogPayloadInspector
          entry={selectedEntry ? {
            ...selectedEntry,
            time: formatTimestamp(selectedEntry.timestamp_utc),
            sourceLabel: selectedEntry.source_label,
          } : bundle}
        />
      );
    }

    if (developerTab === 'tails') {
      if (!selectedSource) {
        return <div className="cp-empty-inline">Select a source file in the sidebar to tail it here.</div>;
      }
      const tailText = streamEntries
        .filter((entry) => entry.source_id === selectedSource.id)
        .slice(-180)
        .map((entry) => `[${formatTimestamp(entry.timestamp_utc)}] [${entry.level}] ${entry.raw || entry.message}`)
        .join('\n');

      return <pre className="cp-logs-terminal">{tailText || 'No lines matched the selected file in this window.'}</pre>;
    }

    if (developerTab === 'structured') {
      return (
        <div className="cp-logs-scroll">
          <div className="cp-logs-table">
            <div className="cp-logs-table-head">
              <span>Time</span>
              <span>Severity</span>
              <span>Source</span>
              <span>Message</span>
            </div>
            {developerRows.map((entry) => (
              <button
                key={entry.id}
                type="button"
                className={`cp-logs-table-row cp-logs-table-row-button ${selectedEntryId === entry.id ? 'is-active' : ''}`}
                onClick={() => setSelectedEntryId(entry.id)}
              >
                <span className="cp-logs-table-time">{entry.time}</span>
                <span className={`cp-logs-table-severity tone-${entry.tone}`}>{entry.level}</span>
                <span className="cp-logs-table-source">{entry.sourceLabel}</span>
                <span className="cp-logs-table-message">{entry.detail}</span>
              </button>
            ))}
          </div>
        </div>
      );
    }

    const rows = developerTab === 'search'
      ? (deferredSearch ? developerRows : bookmarkedRows)
      : developerRows;

    return (
      <VirtualLogStream
        entries={rows}
        selectedEntryId={selectedEntryId}
        onSelectEntry={(entry) => setSelectedEntryId(entry.id)}
        autoScroll={autoScroll && !streamPaused && developerTab === 'live'}
      />
    );
  };

  const handleCopyFilteredLogs = async () => {
    try {
      const payload = streamEntries
        .map((entry) => `[${formatTimestamp(entry.timestamp_utc)}] [${entry.level}] [${entry.source_label}] ${entry.raw || entry.message}`)
        .join('\n');
      await copyText(payload || 'No matching log lines.');
      recordAction({
        title: 'Copied filtered logs',
        detail: `${formatNumber(streamEntries.length)} lines copied to the clipboard.`,
        status: 'good',
        source: 'logs-page',
      });
    } catch (copyError) {
      recordAction({
        title: 'Copy logs failed',
        detail: String(copyError),
        status: 'bad',
        source: 'logs-page',
      });
    }
  };

  const handleCopySelectedLine = async () => {
    if (!selectedEntry) {
      return;
    }
    try {
      await copyText(`[${formatTimestamp(selectedEntry.timestamp_utc)}] [${selectedEntry.level}] ${selectedEntry.raw || selectedEntry.message}`);
      recordAction({
        title: 'Copied selected line',
        detail: selectedEntry.source_label || 'Runtime log entry copied.',
        status: 'good',
        source: 'logs-page',
      });
    } catch (copyError) {
      recordAction({
        title: 'Copy selected line failed',
        detail: String(copyError),
        status: 'bad',
        source: 'logs-page',
      });
    }
  };

  const toggleBookmark = () => {
    if (!selectedEntry) {
      return;
    }
    setBookmarkedEntryIds((current) => (
      current.includes(selectedEntry.entryKey)
        ? current.filter((entryId) => entryId !== selectedEntry.entryKey)
        : [...current, selectedEntry.entryKey]
    ));
  };

  if (!selectedNode) {
    return (
      <EmptyPanel
        title="No node selected for logs"
        copy="Provision or select a node to see activity, source health, and runtime traces."
        actionLabel="Refresh"
        onAction={() => void refresh()}
      />
    );
  }

  const title = viewMode === 'basic' ? 'Activity' : viewMode === 'advanced' ? 'Logs' : 'Runtime Logs';
  const eyebrow = viewMode === 'basic' ? 'Recent Story' : viewMode === 'advanced' ? 'Operational Feed' : 'Incident Response';

  return (
    <div className="cp-page-stack">
      <SectionHeader
        eyebrow={eyebrow}
        title={title}
        copy={viewMode === 'basic'
          ? 'See what happened recently without reading a raw machine log.'
          : viewMode === 'advanced'
            ? 'Filter the operational event stream by severity, subsystem, source, and time window.'
            : 'Inspect raw runtime events, payloads, source files, and search results with developer controls.'}
        actions={(
          <>
            <SNRGButton variant="blue" size="sm" onClick={() => void refresh()}>
              Refresh State
            </SNRGButton>
            {logsDirectory ? (
              <SNRGButton variant="blue" size="sm" onClick={() => openPath(logsDirectory)}>
                Open Log Folder
              </SNRGButton>
            ) : null}
            <SNRGButton variant="purple" size="sm" onClick={() => void handleCopyFilteredLogs()}>
              Export Visible
            </SNRGButton>
          </>
        )}
      />

      {(logsError || error) ? (
        <div className={`cp-inline-notice tone-${statusTone(logsError || error)}`}>
          {logsError || error}
        </div>
      ) : null}

      {viewMode === 'basic' ? (
        <div className="cp-dashboard-grid">
          <div className="cp-dashboard-main">
            <JarvisCard
              mode="basic"
              title="Here is what happened recently"
              message={narrativeFeed[0]
                ? `${narrativeFeed[0].title}. ${narrativeFeed[0].detail}`
                : 'Jarvis will summarize the story here after the next activity arrives.'}
              chips={[
                `${formatNumber(streamEntries.length)} visible events`,
                `${formatNumber(sourceStats.filter((source) => source.available).length)} sources`,
                loading ? 'Updating' : 'Current',
              ]}
            />

            <MetricBars
              title="Severity summary"
              detail="A simple split between routine activity, warnings, and critical events."
              items={severityItems}
            />

            <ActivityFeed
              title="Important moments"
              detail={streamEntries.length ? `${formatNumber(streamEntries.length)} recent events matched your filters.` : 'No recent events matched the current view.'}
              items={narrativeFeed}
              emptyMessage="The activity feed will populate after the next log refresh."
            />

            <PanelCard
              title="Why this matters / what to do next"
              detail="Guided help stays plain-language first in Basic mode."
            >
              <div className="cp-checklist">
                <div className="cp-checklist-item">
                  <strong>Keep an eye on warnings first.</strong>
                  <small>Warnings usually mean the node is still working, but something changed that deserves a quick check.</small>
                </div>
                <div className="cp-checklist-item">
                  <strong>Errors are your next safe escalation point.</strong>
                  <small>If critical entries appear repeatedly, open the detailed logs or move to Advanced mode for source and time filters.</small>
                </div>
                <div className="cp-checklist-item">
                  <strong>Use technical details only when you need them.</strong>
                  <small>Basic mode keeps raw paths and stack-like output out of the way until you deliberately expand them.</small>
                </div>
              </div>
            </PanelCard>

            {showBasicTechnical ? (
              <PanelCard title="Technical details" detail="Optional raw details for the currently selected event.">
                <LogPayloadInspector entry={selectedEntry ? {
                  ...selectedEntry,
                  time: formatTimestamp(selectedEntry.timestamp_utc),
                  sourceLabel: selectedEntry.source_label,
                } : null}
                />
              </PanelCard>
            ) : null}
          </div>

          <div className="cp-dashboard-side">
            <PanelCard title="Simple filters" detail="Keep the view short and readable.">
              <div className="cp-chip-row cp-chip-row-wrap">
                {[
                  ['all', 'All'],
                  ['warnings', 'Warnings'],
                  ['critical', 'Errors'],
                ].map(([value, label]) => (
                  <button
                    key={value}
                    type="button"
                    className={`cp-chip cp-chip-button ${severityFilter === value ? 'is-active' : ''}`}
                    onClick={() => setSeverityFilter(value)}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </PanelCard>

            <PanelCard title="Source summary" detail="High-level source groups only.">
              <div className="cp-panel-scroll cp-panel-scroll-tight">
                <div className="cp-definition-list">
                  {sourceStats.slice(0, 6).map((source) => (
                    <div key={source.id} className="cp-definition-item">
                      <span>{source.label}</span>
                      <strong>{formatNumber(source.line_count)} lines</strong>
                    </div>
                  ))}
                </div>
              </div>
            </PanelCard>

            <PanelCard title="Open full details" detail="Switch to a denser log workflow only when you need it.">
              <div className="cp-button-grid">
                <SNRGButton variant="purple" size="sm" onClick={() => setViewMode('advanced')}>
                  Open Detailed Logs
                </SNRGButton>
                <SNRGButton variant="blue" size="sm" onClick={() => setShowBasicTechnical((current) => !current)}>
                  {showBasicTechnical ? 'Hide Technical Details' : 'Show Technical Details'}
                </SNRGButton>
                <SNRGButton as={Link} to={`/node/${selectedNode.id}`} variant="blue" size="sm">
                  Open My Node
                </SNRGButton>
              </div>
            </PanelCard>
          </div>
        </div>
      ) : null}

      {viewMode === 'advanced' ? (
        <div className="cp-dashboard-grid">
          <div className="cp-dashboard-main">
            <JarvisCard
              mode="advanced"
              title="Log interpretation"
              message={incidentClues[0]
                ? `${incidentClues[0].title}. ${incidentClues[0].detail}`
                : 'This view keeps timestamps, sources, and filter depth visible so operational problems are easier to isolate.'}
              chips={[
                `${formatNumber(streamEntries.length)} events`,
                selectedSource ? selectedSource.label : 'All sources',
                timeRange,
              ]}
            />

            <PanelCard title="Filters" detail="Narrow the stream without dropping into terminal grep.">
              <div className="cp-log-filter-grid">
                <label className="cp-form-field">
                  <span>Search</span>
                  <input
                    type="text"
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    placeholder="Search source, module, or message"
                  />
                </label>
                <div className="cp-inline-field">
                  <span>Severity</span>
                  <div className="cp-chip-row cp-chip-row-wrap">
                    {[
                      ['all', 'All'],
                      ['warnings', 'Warnings'],
                      ['critical', 'Errors'],
                      ['info', 'Info'],
                    ].map(([value, label]) => (
                      <button
                        key={value}
                        type="button"
                        className={`cp-chip cp-chip-button ${severityFilter === value ? 'is-active' : ''}`}
                        onClick={() => setSeverityFilter(value)}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="cp-inline-field">
                  <span>Subsystem</span>
                  <div className="cp-chip-row cp-chip-row-wrap">
                    {[
                      ['all', 'All'],
                      ['network', 'Network'],
                      ['chain', 'Chain'],
                      ['rpc', 'RPC'],
                      ['runtime', 'Runtime'],
                    ].map(([value, label]) => (
                      <button
                        key={value}
                        type="button"
                        className={`cp-chip cp-chip-button ${subsystemFilter === value ? 'is-active' : ''}`}
                        onClick={() => setSubsystemFilter(value)}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="cp-inline-field">
                  <span>Time range</span>
                  <div className="cp-chip-row cp-chip-row-wrap">
                    {TIME_RANGE_OPTIONS.map(([value, label]) => (
                      <button
                        key={value}
                        type="button"
                        className={`cp-chip cp-chip-button ${timeRange === value ? 'is-active' : ''}`}
                        onClick={() => setTimeRange(value)}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </PanelCard>

            <MetricBars
              title="Severity mix"
              detail="Current event distribution in the filtered operational stream."
              items={severityItems}
            />

            <SeverityTimelineChart
              bins={timelineBins}
              selectedId={selectedTimelineId}
              onSelect={(entry) => setSelectedTimelineId((current) => (current === entry.id ? '' : entry.id))}
            />

            <PanelCard
              title="Event stream"
              detail={advancedRender === 'interpreted'
                ? 'Interpreted events keep the stream readable while still preserving source and time.'
                : 'Semi-raw mode keeps the source line and timestamp intact.'}
              action={(
                <div className="cp-chip-row">
                  <button
                    type="button"
                    className={`cp-chip cp-chip-button ${advancedRender === 'interpreted' ? 'is-active' : ''}`}
                    onClick={() => setAdvancedRender('interpreted')}
                  >
                    Interpreted
                  </button>
                  <button
                    type="button"
                    className={`cp-chip cp-chip-button ${advancedRender === 'semi-raw' ? 'is-active' : ''}`}
                    onClick={() => setAdvancedRender('semi-raw')}
                  >
                    Semi-raw
                  </button>
                </div>
              )}
            >
              {advancedRender === 'interpreted' ? (
                <div className="cp-panel-scroll cp-panel-scroll-medium">
                  <div className="cp-activity-feed">
                    {simplifiedEntries.length ? simplifiedEntries.slice().reverse().map((item) => (
                      <article key={item.id} className={`cp-activity-item tone-${item.tone || 'neutral'}`}>
                        <div className="cp-activity-marker"></div>
                        <div className="cp-activity-copy">
                          <div className="cp-activity-head">
                            <strong>{item.title}</strong>
                            <span>{item.time}</span>
                          </div>
                          <p>{item.detail}</p>
                        </div>
                      </article>
                    )) : <div className="cp-empty-inline">No log events match the current filters.</div>}
                  </div>
                </div>
              ) : (
                <div className="cp-logs-scroll">
                  <div className="cp-logs-table">
                    <div className="cp-logs-table-head">
                      <span>Time</span>
                      <span>Severity</span>
                      <span>Source</span>
                      <span>Message</span>
                    </div>
                    {streamEntries.length ? streamEntries.slice().reverse().map((entry) => (
                      <button
                        key={entry.entryKey}
                        type="button"
                        className={`cp-logs-table-row cp-logs-table-row-button ${selectedEntryId === entry.entryKey ? 'is-active' : ''}`}
                        onClick={() => setSelectedEntryId(entry.entryKey)}
                      >
                        <span className="cp-logs-table-time">{formatTimestamp(entry.timestamp_utc)}</span>
                        <span className={`cp-logs-table-severity tone-${statusTone(entry.level)}`}>{entry.level}</span>
                        <span className="cp-logs-table-source">{entry.source_label}</span>
                        <span className="cp-logs-table-message">{entry.raw || entry.message}</span>
                      </button>
                    )) : (
                      <div className="cp-logs-table-row">
                        <span className="cp-logs-table-time">—</span>
                        <span className="cp-logs-table-severity tone-neutral">—</span>
                        <span className="cp-logs-table-source">—</span>
                        <span className="cp-logs-table-message">No log events match the current filters.</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </PanelCard>

            <PanelCard title="Log source list" detail="Click a source to scope the stream to that file or subsystem.">
              <div className="cp-panel-scroll cp-panel-scroll-medium">
                <LogSourceSidebar
                  sources={sourceStats}
                  selectedSourceId={selectedSourceId}
                  onSelectSource={(source) => setSelectedSourceId((current) => (current === source.id ? '' : source.id))}
                />
              </div>
            </PanelCard>
          </div>

          <div className="cp-dashboard-side">
            <PanelCard title="Filtered source panel" detail="The currently scoped source and its recent behavior.">
              {selectedSource ? (
                <div className="cp-definition-list">
                  <div className="cp-definition-item">
                    <span>Source</span>
                    <strong>{selectedSource.label}</strong>
                  </div>
                  <div className="cp-definition-item">
                    <span>Kind</span>
                    <strong>{selectedSource.kind || 'runtime'}</strong>
                  </div>
                  <div className="cp-definition-item">
                    <span>Warnings / errors</span>
                    <strong>{formatNumber(selectedSource.warnCount)} / {formatNumber(selectedSource.errorCount)}</strong>
                  </div>
                  <div className="cp-definition-item">
                    <span>Last seen</span>
                    <strong>{selectedSource.lastSeenLabel}</strong>
                  </div>
                  <div className="cp-definition-item">
                    <span>Path</span>
                    <strong>{selectedSource.path || 'Path not reported'}</strong>
                  </div>
                </div>
              ) : (
                <div className="cp-empty-inline">Select a source to inspect its file path, event volume, and last update time.</div>
              )}
            </PanelCard>

            <ActivityFeed
              title="Recent incident clues"
              detail="Warnings and errors stay fixed-height here so the rest of the layout does not shift."
              items={incidentClues}
              emptyMessage="Recent incident clues will appear after the next warning or error."
              fixedLines={10}
            />

            <PanelCard title="Export / open file actions" detail="Use these when you need the raw file or want to share the filtered slice.">
              <div className="cp-button-grid">
                <SNRGButton variant="blue" size="sm" onClick={() => void handleCopyFilteredLogs()}>
                  Copy Filtered Logs
                </SNRGButton>
                {selectedSource?.path ? (
                  <SNRGButton variant="blue" size="sm" onClick={() => openPath(selectedSource.path)}>
                    Open Selected File
                  </SNRGButton>
                ) : null}
                {logsDirectory ? (
                  <SNRGButton variant="purple" size="sm" onClick={() => openPath(logsDirectory)}>
                    Open Log Folder
                  </SNRGButton>
                ) : null}
                {selectedTimelineId ? (
                  <SNRGButton variant="blue" size="sm" onClick={() => setSelectedTimelineId('')}>
                    Clear Timeline Filter
                  </SNRGButton>
                ) : null}
              </div>
            </PanelCard>
          </div>
        </div>
      ) : null}

      {viewMode === 'developer' ? (
        <div className="cp-dashboard-grid">
          <div className="cp-dashboard-main">
            <PanelCard title="Runtime controls" detail="Pause the stream, pin searches, and jump between raw views.">
              <div className="cp-log-tab-strip">
                {DEVELOPER_TABS.map(([value, label]) => (
                  <button
                    key={value}
                    type="button"
                    className={`cp-chip cp-chip-button ${developerTab === value ? 'is-active' : ''}`}
                    onClick={() => setDeveloperTab(value)}
                  >
                    {label}
                  </button>
                ))}
              </div>
              <div className="cp-log-filter-grid">
                <label className="cp-form-field">
                  <span>Search / pin</span>
                  <input
                    type="text"
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    placeholder="Pin a search across raw logs and results"
                  />
                </label>
                <div className="cp-inline-field">
                  <span>Stream controls</span>
                  <div className="cp-chip-row cp-chip-row-wrap">
                    <button
                      type="button"
                      className={`cp-chip cp-chip-button ${streamPaused ? 'is-active' : ''}`}
                      onClick={() => setStreamPaused((current) => !current)}
                    >
                      {streamPaused ? 'Resume' : 'Pause'}
                    </button>
                    <button
                      type="button"
                      className={`cp-chip cp-chip-button ${autoScroll ? 'is-active' : ''}`}
                      onClick={() => setAutoScroll((current) => !current)}
                    >
                      {autoScroll ? 'Autoscroll On' : 'Autoscroll Off'}
                    </button>
                    <button type="button" className="cp-chip cp-chip-button" onClick={toggleBookmark}>
                      {selectedEntry && bookmarkedEntryIds.includes(selectedEntry.entryKey) ? 'Unbookmark' : 'Bookmark Selected'}
                    </button>
                    <button type="button" className="cp-chip cp-chip-button" onClick={() => void handleCopySelectedLine()}>
                      Copy Selected Line
                    </button>
                  </div>
                </div>
                <div className="cp-inline-field">
                  <span>Filters</span>
                  <div className="cp-chip-row cp-chip-row-wrap">
                    {[
                      ['all', 'All'],
                      ['warnings', 'Warnings'],
                      ['critical', 'Errors'],
                      ['debug', 'Debug'],
                    ].map(([value, label]) => (
                      <button
                        key={value}
                        type="button"
                        className={`cp-chip cp-chip-button ${severityFilter === value ? 'is-active' : ''}`}
                        onClick={() => setSeverityFilter(value)}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </PanelCard>

            <PanelCard
              title={developerTab === 'search' ? 'Search results' : developerTab === 'json' ? 'Raw JSON' : developerTab === 'tails' ? 'Selected file tail' : 'Large live viewport'}
              detail={developerTab === 'search'
                ? (deferredSearch
                  ? `Pinned search results for "${deferredSearch}".`
                  : 'No pinned search yet. Bookmarked entries will appear here until you search.')
                : developerTab === 'json'
                  ? 'Inspect the selected event payload without losing its surrounding context.'
                  : developerTab === 'tails'
                    ? 'Tail the currently selected file or source.'
                    : 'This viewport preserves exact timestamps, source names, and raw event lines.'}
              action={(
                <div className="cp-chip-row">
                  <button
                    type="button"
                    className={`cp-chip cp-chip-button ${timeRange === '1h' ? 'is-active' : ''}`}
                    onClick={() => setTimeRange('1h')}
                  >
                    1h
                  </button>
                  <button
                    type="button"
                    className={`cp-chip cp-chip-button ${timeRange === '6h' ? 'is-active' : ''}`}
                    onClick={() => setTimeRange('6h')}
                  >
                    6h
                  </button>
                  <button
                    type="button"
                    className={`cp-chip cp-chip-button ${timeRange === '24h' ? 'is-active' : ''}`}
                    onClick={() => setTimeRange('24h')}
                  >
                    24h
                  </button>
                  <button type="button" className="cp-chip cp-chip-button" onClick={() => void handleCopyFilteredLogs()}>
                    Export
                  </button>
                </div>
              )}
            >
              {renderDeveloperViewport()}
            </PanelCard>

            <SeverityTimelineChart
              bins={timelineBins}
              selectedId={selectedTimelineId}
              onSelect={(entry) => setSelectedTimelineId((current) => (current === entry.id ? '' : entry.id))}
            />

            <PanelCard title="Event payload inspector" detail="Select a row in the viewport to inspect its structured payload.">
              <LogPayloadInspector entry={selectedEntry ? {
                ...selectedEntry,
                time: formatTimestamp(selectedEntry.timestamp_utc),
                sourceLabel: selectedEntry.source_label,
              } : null}
              />
            </PanelCard>
          </div>

          <div className="cp-dashboard-side">
            <PanelCard title="File / source sidebar" detail="Select a source to tail or scope the stream.">
              <div className="cp-panel-scroll cp-panel-scroll-tight">
                <LogSourceSidebar
                  sources={sourceStats}
                  selectedSourceId={selectedSourceId}
                  onSelectSource={(source) => setSelectedSourceId((current) => (current === source.id ? '' : source.id))}
                />
              </div>
            </PanelCard>

            <ActivityFeed
              title="Recent errors"
              detail="This rail stays fixed-height and scrolls internally so the main viewport does not jump."
              items={incidentClues}
              emptyMessage="Recent errors will appear here after the next warning or failure."
              fixedLines={10}
            />

            <JarvisCard
              mode="developer"
              title="Developer hints"
              message={selectedEntry
                ? `Selected ${selectedEntry.source_label || 'runtime'} entry at ${formatTimestamp(selectedEntry.timestamp_utc)}. Use the dock to tail files or run RPC checks while this payload stays pinned.`
                : 'Use the dock to tail files, run JSON-RPC checks, and compare command receipts with the raw event stream.'}
              chips={[
                `${formatNumber(bookmarkedEntryIds.length)} bookmarks`,
                streamPaused ? 'Paused' : 'Streaming',
                selectedSource ? selectedSource.label : 'All sources',
              ]}
            />

            <PanelCard title="Raw stack / payload preview" detail="A fast preview of the selected payload or bundle summary.">
              <LogPayloadInspector entry={selectedEntry ? {
                ...selectedEntry,
                time: formatTimestamp(selectedEntry.timestamp_utc),
                sourceLabel: selectedEntry.source_label,
              } : {
                metadata: {
                  summary: bundle?.summary || null,
                  sources: sourceStats.slice(0, 6),
                  recentActions: actionAudit.slice(0, 6),
                },
              }}
              />
            </PanelCard>
          </div>
        </div>
      ) : null}
    </div>
  );
}

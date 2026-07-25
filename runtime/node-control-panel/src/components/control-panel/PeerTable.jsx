import { useMemo, useState } from 'react';

function sortPeers(peers, sortKey, sortDirection) {
  const sorted = [...peers];
  sorted.sort((left, right) => {
    const leftValue = left?.[sortKey];
    const rightValue = right?.[sortKey];
    if (leftValue === rightValue) return 0;
    if (leftValue == null) return 1;
    if (rightValue == null) return -1;
    if (typeof leftValue === 'number' && typeof rightValue === 'number') {
      return sortDirection === 'asc' ? leftValue - rightValue : rightValue - leftValue;
    }
    return sortDirection === 'asc'
      ? String(leftValue).localeCompare(String(rightValue))
      : String(rightValue).localeCompare(String(leftValue));
  });
  return sorted;
}

export default function PeerTable({
  peers = [],
  selectedPeerId = '',
  onSelectPeer = null,
  mode = 'basic',
}) {
  const [sortKey, setSortKey] = useState('latencyMs');
  const [sortDirection, setSortDirection] = useState('asc');

  const sortedPeers = useMemo(
    () => sortPeers(peers, sortKey, sortDirection),
    [peers, sortDirection, sortKey],
  );

  const toggleSort = (key) => {
    if (key === sortKey) {
      setSortDirection((current) => (current === 'asc' ? 'desc' : 'asc'));
      return;
    }
    setSortKey(key);
    setSortDirection(key === 'latencyMs' ? 'asc' : 'desc');
  };

  if (!sortedPeers.length) {
    return <div className="cp-empty-inline">Peer rows will appear when the node exposes visible sessions.</div>;
  }

  return (
    <div className="cp-peer-table">
      <div className="cp-peer-table-head">
        {[
          ['label', 'Peer'],
          ['region', 'Region'],
          ['health', 'Health'],
          ['latencyMs', 'Latency'],
          ['sessionAgeSec', 'Session age'],
          ['lastSeenAt', 'Last seen'],
        ].map(([key, label]) => (
          <button key={key} type="button" onClick={() => toggleSort(key)}>
            {label}
          </button>
        ))}
      </div>
      {sortedPeers.map((peer) => (
        <button
          key={peer.id}
          type="button"
          className={`cp-peer-table-row ${selectedPeerId === peer.id ? 'is-active' : ''}`}
          onClick={() => onSelectPeer?.(peer)}
        >
          <span>{peer.label}</span>
          <span>{peer.region || 'Unknown'}</span>
          <span>{peer.health || 'pending'}</span>
          <span>{peer.latencyMs != null ? `${peer.latencyMs} ms` : '—'}</span>
          <span>{peer.sessionAgeSec != null ? `${peer.sessionAgeSec}s` : '—'}</span>
          <span>{peer.lastSeenAt || 'Unknown'}</span>
          {mode === 'developer' ? <small>{peer.peerId || peer.id}</small> : null}
        </button>
      ))}
    </div>
  );
}


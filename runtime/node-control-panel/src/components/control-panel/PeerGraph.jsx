import { useMemo } from 'react';

function buildNodePositions(peers = []) {
  return peers.map((peer, index) => {
    const angle = (Math.PI * 2 * index) / Math.max(peers.length, 1);
    return {
      ...peer,
      x: 50 + 34 * Math.cos(angle),
      y: 50 + 28 * Math.sin(angle),
    };
  });
}

export default function PeerGraph({
  peers = [],
  onSelectPeer = null,
  selectedPeerId = '',
}) {
  const nodes = useMemo(() => buildNodePositions(peers), [peers]);

  if (!nodes.length) {
    return <div className="cp-empty-inline">The logical graph will appear when peer sessions are visible.</div>;
  }

  return (
    <div className="cp-peer-graph">
      <svg viewBox="0 0 100 100" className="cp-peer-graph-svg" role="img" aria-label="Logical peer graph">
        {nodes.map((peer) => (
          <line
            key={`edge-${peer.id}`}
            x1="50"
            y1="50"
            x2={peer.x}
            y2={peer.y}
            className={`tone-${peer.healthTone || 'neutral'}`}
          />
        ))}
        <circle cx="50" cy="50" r="5" className="cp-peer-graph-center" />
        {nodes.map((peer) => (
          <g
            key={peer.id}
            className={`cp-peer-graph-node ${selectedPeerId === peer.id ? 'is-active' : ''}`}
            onClick={() => onSelectPeer?.(peer)}
            role="button"
            tabIndex={0}
            onKeyDown={(event) => {
              if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                onSelectPeer?.(peer);
              }
            }}
          >
            <circle cx={peer.x} cy={peer.y} r="3.8" className={`tone-${peer.healthTone || 'neutral'}`} />
            <text x={peer.x} y={peer.y + 8}>{peer.shortLabel || peer.label}</text>
          </g>
        ))}
      </svg>
    </div>
  );
}


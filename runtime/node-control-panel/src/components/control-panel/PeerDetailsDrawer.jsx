import { truncateMiddle } from './controlPanelModel';

function renderValue(label, value) {
  return (
    <div className="cp-definition-item">
      <span>{label}</span>
      <strong>{value || 'Not reported'}</strong>
    </div>
  );
}

export default function PeerDetailsDrawer({
  peer = null,
  mode = 'basic',
}) {
  if (!peer) {
    return (
      <div className="cp-empty-inline">Select a peer marker or table row to inspect it here.</div>
    );
  }

  return (
    <div className="cp-peer-drawer">
      <div className="cp-peer-drawer-head">
        <strong>{peer.label || truncateMiddle(peer.peerId || peer.id || 'Peer')}</strong>
        <span>{peer.region || 'Unknown region'}</span>
      </div>
      <div className="cp-definition-list">
        {renderValue('Role', peer.role || 'unknown')}
        {renderValue('Health', peer.health || 'pending')}
        {renderValue('Latency', peer.latencyMs != null ? `${peer.latencyMs} ms` : 'Not measured')}
        {renderValue('Direction', peer.direction || 'unknown')}
        {renderValue('Session age', peer.sessionAgeSec != null ? `${peer.sessionAgeSec}s` : 'Unknown')}
        {renderValue('Last seen', peer.lastSeenAt || 'Unknown')}
        {renderValue('Version', peer.peerVersion || peer.protocolVersion || 'Not reported')}
        {mode === 'developer' ? renderValue('Peer ID', peer.peerId || peer.id || 'Not reported') : null}
        {mode === 'developer' ? renderValue('Transport', peer.transport || 'Not reported') : null}
      </div>
      {mode === 'developer' ? (
        <pre className="cp-json-block">{JSON.stringify(peer, null, 2)}</pre>
      ) : null}
    </div>
  );
}

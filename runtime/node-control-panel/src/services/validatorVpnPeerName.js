export function validatorVpnPeerName({ nodeId, peerName } = {}) {
  const source = String(nodeId || peerName || '').trim().toLowerCase();
  const normalized = source
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^[._-]+|[._-]+$/g, '')
    .replace(/[-_.]{2,}/g, '-');
  const base = normalized || 'node';
  const prefixed = base.startsWith('validator-') ? base : `validator-${base}`;
  return prefixed.slice(0, 63).replace(/[._-]+$/g, '') || 'validator-node';
}

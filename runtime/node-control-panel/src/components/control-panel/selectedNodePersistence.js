export const CONTROL_PANEL_SELECTED_NODE_ID_STORAGE_KEY = 'synergy:node-control-panel:selected-node-id:v1';

function safeGetStorage() {
  if (typeof window === 'undefined') {
    return null;
  }

  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

function readStorage(storage, key) {
  if (!storage) {
    return null;
  }
  try {
    return storage.getItem(key);
  } catch {
    return null;
  }
}

function writeStorage(storage, key, value) {
  if (!storage) {
    return false;
  }
  try {
    storage.setItem(key, value);
    return true;
  } catch {
    return false;
  }
}

function removeStorage(storage, key) {
  if (!storage) {
    return;
  }
  try {
    storage.removeItem(key);
  } catch {
    // Storage availability should not impact selection.
  }
}

function normalizeNodeId(value) {
  const normalized = String(value || '').trim();
  return normalized || '';
}

export function getSelectedNodeStorage() {
  return safeGetStorage();
}

export function resolveSelectedNodeId({ persistedNodeId, nodes } = {}) {
  const normalized = normalizeNodeId(persistedNodeId);
  const candidateNodes = Array.isArray(nodes) ? nodes : [];
  if (candidateNodes.some((node) => String(node?.id || '') === normalized)) {
    return normalized;
  }

  const fallback = candidateNodes[0]?.id || '';
  return String(fallback || '').trim();
}

export function readPersistedSelectedNodeId({ storage } = {}) {
  const sourceStorage = storage || getSelectedNodeStorage();
  const raw = readStorage(sourceStorage, CONTROL_PANEL_SELECTED_NODE_ID_STORAGE_KEY);
  return normalizeNodeId(raw);
}

export function persistSelectedNodeId({ storage, nodeId } = {}) {
  const normalized = normalizeNodeId(nodeId);
  const targetStorage = storage || getSelectedNodeStorage();
  if (!normalized) {
    removeStorage(targetStorage, CONTROL_PANEL_SELECTED_NODE_ID_STORAGE_KEY);
    return false;
  }
  return writeStorage(targetStorage, CONTROL_PANEL_SELECTED_NODE_ID_STORAGE_KEY, normalized);
}

export function clearPersistedSelectedNodeId({ storage } = {}) {
  removeStorage(storage || getSelectedNodeStorage(), CONTROL_PANEL_SELECTED_NODE_ID_STORAGE_KEY);
}

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  CONTROL_PANEL_SELECTED_NODE_ID_STORAGE_KEY,
  clearPersistedSelectedNodeId,
  persistSelectedNodeId,
  readPersistedSelectedNodeId,
  resolveSelectedNodeId,
} from '../../src/components/control-panel/selectedNodePersistence.js';

class MemoryStorage {
  constructor() {
    this.values = new Map();
  }

  getItem(key) {
    return this.values.has(key) ? this.values.get(key) : null;
  }

  setItem(key, value) {
    this.values.set(key, String(value));
  }

  removeItem(key) {
    this.values.delete(key);
  }
}

const nodes = [
  { id: 'validator-1' },
  { id: 'validator-2' },
  { id: 'validator-3' },
];

test('restores persisted selected node only when it still exists in the loaded nodes', () => {
  const storage = new MemoryStorage();
  storage.setItem(CONTROL_PANEL_SELECTED_NODE_ID_STORAGE_KEY, 'validator-2');

  assert.equal(readPersistedSelectedNodeId({ storage }), 'validator-2');
  assert.equal(
    resolveSelectedNodeId({ persistedNodeId: readPersistedSelectedNodeId({ storage }), nodes }),
    'validator-2',
  );
});

test('falls back deterministically for stale IDs and updates persistence with the fallback', () => {
  const storage = new MemoryStorage();
  storage.setItem(CONTROL_PANEL_SELECTED_NODE_ID_STORAGE_KEY, 'validator-7');

  const resolved = resolveSelectedNodeId({
    persistedNodeId: readPersistedSelectedNodeId({ storage }),
    nodes,
  });
  assert.equal(resolved, 'validator-1');
  assert.equal(persistSelectedNodeId({ storage, nodeId: resolved }), true);
  assert.equal(storage.getItem(CONTROL_PANEL_SELECTED_NODE_ID_STORAGE_KEY), 'validator-1');
});

test('drops persisted selection when the saved node disappears and remains deterministic', () => {
  const storage = new MemoryStorage();
  const resolved = resolveSelectedNodeId({
    persistedNodeId: 'validator-3',
    nodes: [{ id: 'a-node' }, { id: 'b-node' }],
  });
  assert.equal(resolved, 'a-node');
  persistSelectedNodeId({ storage, nodeId: resolved });
  assert.equal(storage.getItem(CONTROL_PANEL_SELECTED_NODE_ID_STORAGE_KEY), 'a-node');
});

test('clears persistence for an empty selection', () => {
  const storage = new MemoryStorage();
  persistSelectedNodeId({ storage, nodeId: 'validator-1' });
  clearPersistedSelectedNodeId({ storage });
  assert.equal(storage.getItem(CONTROL_PANEL_SELECTED_NODE_ID_STORAGE_KEY), null);
});

test('retains restored selection through loading/empty nodes until authoritative nodes load', () => {
  const storage = new MemoryStorage();
  storage.setItem(CONTROL_PANEL_SELECTED_NODE_ID_STORAGE_KEY, 'validator-7');
  let hasAuthoritativeState = false;
  let selectedNodeId = readPersistedSelectedNodeId({ storage });

  const resolveAndPersist = (nodes) => {
    if (!hasAuthoritativeState) {
      return;
    }
    if (!nodes.length) {
      selectedNodeId = '';
    } else {
      selectedNodeId = resolveSelectedNodeId({
        persistedNodeId: selectedNodeId,
        nodes,
      });
    }
    persistSelectedNodeId({ storage, nodeId: selectedNodeId });
  };

  resolveAndPersist([]);
  assert.equal(selectedNodeId, 'validator-7');
  assert.equal(storage.getItem(CONTROL_PANEL_SELECTED_NODE_ID_STORAGE_KEY), 'validator-7');

  hasAuthoritativeState = true;
  resolveAndPersist([
    { id: 'validator-7' },
    { id: 'validator-8' },
  ]);

  assert.equal(selectedNodeId, 'validator-7');
  assert.equal(storage.getItem(CONTROL_PANEL_SELECTED_NODE_ID_STORAGE_KEY), 'validator-7');
});

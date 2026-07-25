import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { executeOperationThroughPty } from '../../src/features/operations/operationExecution.js';

const require = createRequire(import.meta.url);
const { createPtyManager } = require('../../electron/pty-manager.cjs');

class FakeTerminal {
  constructor() {
    this.writes = [];
    this.dataHandler = null;
    this.exitHandler = null;
  }

  onData(handler) { this.dataHandler = handler; }
  onExit(handler) { this.exitHandler = handler; }
  write(value) { this.writes.push(value); }
  resize() {}
  kill() { this.exitHandler?.({ exitCode: 143, signal: 15 }); }
  emitData(value) { this.dataHandler?.(value); }
}

test('an Operations action writes its allowlisted audit line and persists service output once', async () => {
  const spawned = [];
  const ptyOutput = [];
  const manager = createPtyManager({
    ptyModule: {
      spawn() {
        const terminal = new FakeTerminal();
        spawned.push(terminal);
        return terminal;
      },
    },
    onOutput: (payload) => ptyOutput.push(payload),
  });
  const opened = manager.openSession({ name: 'Node shell:validator-7' }, 7);
  const operation = {
    actionId: 'operations.network-vpn.view-connected-peers',
    label: 'View Connected Peers',
    displayCommand: 'synergy node peers connected',
    binding: { serviceCommand: 'testnet_get_feature_snapshot' },
  };
  const transcript = [];

  const execution = await executeOperationThroughPty({
    operation,
    terminalName: 'Node shell:validator-7',
    openTerminalSession: async () => opened,
    writeAllowlistedOperation: async (sessionId, actionId) => manager.writeAllowlistedOperation(sessionId, actionId, 7),
    handler: async () => ({ stdout: 'service output once' }),
    appendTerminalOutput: async (sessionId, output) => {
      transcript.push(output);
      manager.appendOutput(sessionId, output, 7);
    },
    completionDetail: () => 'Service action completed.',
  });

  assert.equal(execution.sessionId, opened.sessionId);
  assert.equal(spawned.length, 1);
  assert.equal(spawned[0].writes.length, 1);
  assert.match(spawned[0].writes[0], /\$ synergy node peers connected/);
  assert.match(spawned[0].writes[0], /^printf '\\n%s\\n' /);

  spawned[0].emitData('allowlisted command output\n');
  assert.equal(ptyOutput.at(-1).data, 'allowlisted command output\n');
  assert.equal(ptyOutput.filter((entry) => entry.data === 'allowlisted command output\n').length, 1, 'the PTY output event must be delivered once');

  assert.equal(transcript.length, 3, 'start, service output, and completion must be appended once');
  assert.match(transcript[0], /\[operation\] Starting View Connected Peers/);
  assert.match(transcript[1], /service output once/);
  assert.match(transcript[2], /OK View Connected Peers: Service action completed\./);
  assert.match(manager.getSessionState(opened.sessionId, 7).output, /service output once/);
  assert.match(manager.getSessionState(opened.sessionId, 7).output, /OK View Connected Peers/);

  assert.throws(
    () => manager.writeAllowlistedOperation(opened.sessionId, 'operations.injected.arbitrary-command', 7),
    /not allowlisted/,
  );

  const operationsSource = readFileSync(new URL('../../src/components/control-panel-v18/ControlPanelV18.jsx', import.meta.url), 'utf8');
  const executionSource = readFileSync(new URL('../../src/features/operations/operationExecution.js', import.meta.url), 'utf8');
  assert.match(operationsSource, /writeAllowlistedOperation/);
  assert.match(operationsSource, /executeOperationThroughPty\(\{/);
  assert.match(operationsSource, /operation,\s*terminalName:/);
  assert.match(executionSource, /writeAllowlistedOperation\(sessionId, actionId\)/);
  assert.match(executionSource, /appendTerminalOutput\(sessionId, transcript\)/);
  assert.doesNotMatch(executionSource, /operation\.displayCommand\)/);
  assert.doesNotMatch(operationsSource, /emitOperationTerminalEvent|createOperationTerminalEvent/);
});

console.log('Operation PTY bridge QA passed: allowlisted action input, single PTY output, single service-output transcript, and injection rejection.');

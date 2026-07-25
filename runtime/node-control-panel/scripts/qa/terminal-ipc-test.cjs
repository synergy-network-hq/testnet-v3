const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createPtyManager } = require('../../electron/pty-manager.cjs');
const { setupTerminalIpc } = require('../../electron/ipc/terminal-ipc.cjs');

class FakeTerminal {
  constructor() {
    this.writes = [];
    this.resizes = [];
    this.dataHandler = null;
    this.exitHandler = null;
    this.killCount = 0;
  }

  onData(handler) { this.dataHandler = handler; }
  onExit(handler) { this.exitHandler = handler; }
  write(value) { this.writes.push(value); }
  resize(cols, rows) { this.resizes.push([cols, rows]); }
  kill() {
    this.killCount += 1;
    this.exitHandler?.({ exitCode: 143, signal: 15 });
  }
  emitData(value) { this.dataHandler?.(value); }
  emitExit(result) { this.exitHandler?.(result); }
}

const spawned = [];
const fakePty = {
  spawn() {
    const terminal = new FakeTerminal();
    spawned.push(terminal);
    return terminal;
  },
};

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'synergy-terminal-ipc-'));
const audits = [];
const exits = [];
const manager = createPtyManager({
  ptyModule: fakePty,
  onAudit: (event) => audits.push(event),
  onExit: (event) => exits.push(event),
});

async function run() {
  const opened = manager.openSession({ cwd: tempDir, cols: 20, rows: 5, name: 'Test shell' }, 10);
  assert.equal(opened.status, 'running');
  assert.deepEqual(manager.listSessions(10)[0].cwd, tempDir);
  assert.equal(manager.listSessions(10)[0].output, '');
  assert.deepEqual(manager.listSessions(11), []);

  manager.writeInput(opened.sessionId, 'printf hello\r', 10);
  assert.deepEqual(spawned[0].writes, ['printf hello\r']);
  assert.equal(manager.getSessionState(opened.sessionId, 10).history[0].command, 'printf hello');
  assert.throws(() => manager.writeInput(opened.sessionId, 'echo no\r', 11), /not owned/);

  manager.resizeSession(opened.sessionId, 1, 999, 10);
  assert.deepEqual(spawned[0].resizes, [[40, 200]]);
  manager.interruptSession(opened.sessionId, 10);
  assert.equal(spawned[0].writes.at(-1), '\u0003');

  spawned[0].emitExit({ exitCode: 130, signal: 2 });
  assert.equal(manager.getSessionState(opened.sessionId, 10).status, 'exited');
  assert.throws(() => manager.writeInput(opened.sessionId, 'echo no\r', 10), /already exited/);
  await new Promise((resolve) => setTimeout(resolve, 80));
  assert.equal(exits[0].exitCode, 130);

  const handlers = new Map();
  const ipcMain = { handle(channel, handler) { handlers.set(channel, handler); } };
  setupTerminalIpc(ipcMain, manager);
  assert.deepEqual(
    [...handlers.keys()].sort(),
    [
      'desktop:append-terminal-output',
      'desktop:clear-terminal-output',
      'desktop:close-terminal-session',
      'desktop:get-terminal-session',
      'desktop:interrupt-terminal-session',
      'desktop:list-terminal-sessions',
      'desktop:open-terminal-session',
      'desktop:resize-terminal',
      'desktop:write-allowlisted-operation',
      'desktop:write-terminal-input',
    ],
  );

  const second = manager.openSession({ cwd: tempDir, name: 'Persistent named shell' }, 10);
  spawned[1].emitData('before-route-unmount\n');
  const reopened = handlers.get('desktop:open-terminal-session')(
    { sender: { id: 10 } },
    { cwd: tempDir, name: 'Persistent named shell', reuseExisting: true },
  );
  assert.equal(reopened.sessionId, second.sessionId);
  assert.equal(reopened.reused, true);
  assert.equal(spawned.length, 2, 'reconnecting to a named session must reuse the existing PTY');
  assert.equal(handlers.get('desktop:list-terminal-sessions')({ sender: { id: 10 } }).length, 1);
  const reconnectState = handlers.get('desktop:get-terminal-session')({ sender: { id: 10 } }, reopened.sessionId);
  assert.equal(reconnectState.status, 'running');
  assert.equal(reconnectState.name, 'Persistent named shell');
  assert.equal(reconnectState.output, 'before-route-unmount\n');
  assert.equal(spawned[1].killCount, 0, 'reconnecting to a named running session must not kill its PTY');
  const bridged = handlers.get('desktop:write-allowlisted-operation')(
    { sender: { id: 10 } },
    { sessionId: second.sessionId, actionId: 'operations.network-vpn.view-connected-peers' },
  );
  assert.equal(bridged.command, 'synergy node peers connected');
  assert.match(spawned[1].writes.at(-1), /synergy node peers connected/);
  assert.throws(
    () => handlers.get('desktop:close-terminal-session')({ sender: { id: 11 } }, second.sessionId),
    /not owned/,
  );
  handlers.get('desktop:close-terminal-session')({ sender: { id: 10 } }, second.sessionId);
  assert.equal(spawned[1].killCount, 1, 'an explicit close remains the only cleanup that kills the PTY');
  assert.throws(() => manager.getSessionState(second.sessionId, 10), /Unknown terminal session/);
}

run()
  .then(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
    console.log(`Terminal IPC QA passed: ${audits.length} audit events, ${exits.length} exit events.`);
  })
  .catch((error) => {
    fs.rmSync(tempDir, { recursive: true, force: true });
    console.error(error);
    process.exitCode = 1;
  });

const assert = require('node:assert/strict');
const { createPtyManager } = require('../../electron/pty-manager.cjs');

class FakeReplayTerminal {
  constructor() {
    this.dataHandler = null;
    this.exitHandler = null;
  }

  onData(handler) { this.dataHandler = handler; }
  onExit(handler) { this.exitHandler = handler; }
  write() {}
  resize() {}
  kill() { this.exitHandler?.({ exitCode: 143, signal: 15 }); }
  emitData(value) { this.dataHandler?.(value); }
}

const output = [];
const audits = [];
const events = [];
let manager;

const exitPromise = new Promise((resolve, reject) => {
  const timeout = setTimeout(() => reject(new Error('Timed out waiting for the host PTY to exit.')), 15_000);
  manager = createPtyManager({
    onOutput(payload) {
      const data = String(payload?.data || '');
      output.push(data);
      events.push({ type: 'output', data });
    },
    onAudit(payload) {
      audits.push(payload);
    },
    onExit(payload) {
      clearTimeout(timeout);
      events.push({ type: 'exit', payload });
      resolve(payload);
    },
  });
});

async function run() {
  const marker = `SYNERGY_PTY_OK_${process.pid}`;
  const stderrMarker = `SYNERGY_PTY_STDERR_${process.pid}`;
  const opened = manager.openSession({
    cols: 92,
    rows: 26,
    cwd: process.cwd(),
    name: 'Operations PTY QA',
  });

  assert.ok(opened.sessionId, 'PTY session must return an id');
  assert.equal(opened.cwd, process.cwd());
  assert.ok(opened.shell, 'PTY session must report the host shell');
  assert.deepEqual(manager.listSessions(), [{
      sessionId: opened.sessionId,
      cwd: process.cwd(),
      name: 'Operations PTY QA',
      shell: opened.shell,
      cols: 92,
      rows: 26,
      history: [],
      output: '',
      outputSequence: 0,
      status: 'running',
      exitCode: null,
      signal: null,
  }]);

  assert.deepEqual(manager.resizeSession(opened.sessionId, 104, 34), {
    sessionId: opened.sessionId,
    cols: 104,
    rows: 34,
  });

  const command = process.platform === 'win32'
    ? `echo ${marker} & echo ${stderrMarker} 1>&2 & cd & exit\r\n`
    : `printf '${marker}\\n'; printf '${stderrMarker}\\n' >&2; pwd; exit\r`;
  assert.equal(manager.writeInput(opened.sessionId, command), true);

  const exited = await exitPromise;
  assert.equal(exited.sessionId, opened.sessionId);
  assert.equal(exited.exitCode, 0);

  const transcript = output.join('').replaceAll('\r', '');
  assert.match(transcript, new RegExp(marker));
  assert.match(transcript, new RegExp(stderrMarker));
  assert.match(transcript, new RegExp(process.cwd().replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.equal(events.at(-1)?.type, 'exit', 'PTY exit must be emitted after the final output event');
  assert.equal(manager.listSessions().length, 0);
  assert.ok(audits.some((event) => event.title === 'Terminal session opened'));
  assert.ok(audits.some((event) => event.title === 'Terminal session closed' && event.status === 'good'));

  const replayTerminals = [];
  const replayManager = createPtyManager({
    ptyModule: {
      spawn() {
        const terminal = new FakeReplayTerminal();
        replayTerminals.push(terminal);
        return terminal;
      },
    },
  });
  const replayed = replayManager.openSession({
    name: 'Bounded replay QA',
  });

  const replayChunk = 'old-output\n'.repeat(10_000);
  for (let index = 0; index < 9; index += 1) {
    replayTerminals[0].emitData(index === 8 ? `${replayChunk}tail-after-trim\n` : replayChunk);
  }
  const replayState = replayManager.getSessionState(replayed.sessionId);
  assert.ok(Buffer.byteLength(replayState.output, 'utf8') <= 1024 * 1024);
  assert.match(replayState.output, /tail-after-trim\n$/);
  assert.equal(replayState.outputSequence, 9);
  replayManager.closeAllSessions();

  console.log(`Host PTY QA passed with ${opened.shell} in ${opened.cwd}.`);
}

run().catch((error) => {
  manager?.closeAllSessions();
  console.error(error);
  process.exitCode = 1;
});

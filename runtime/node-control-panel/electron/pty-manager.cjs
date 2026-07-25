const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const pty = require('node-pty');
const operationPtyAllowlist = require('./operation-pty-allowlist.json');

// node-pty can report exit before the PTY read stream has delivered its final data.
const PTY_OUTPUT_DRAIN_GRACE_MS = 50;
const MAX_OUTPUT_HISTORY_BYTES = 1024 * 1024;

function resolveShell() {
  if (process.platform === 'win32') {
    return process.env.COMSPEC || 'powershell.exe';
  }
  return process.env.SHELL || '/bin/bash';
}

function resolveShellArgs(shellPath) {
  if (process.platform === 'win32') {
    return shellPath.toLowerCase().includes('powershell')
      ? ['-NoLogo']
      : [];
  }
  const basename = path.basename(shellPath);
  return basename === 'bash' || basename === 'zsh' ? ['-l'] : [];
}

function resolveCwd(requestedCwd) {
  const candidate = String(requestedCwd || '').trim();
  if (!candidate) return os.homedir();
  try {
    if (fs.statSync(candidate).isDirectory()) return candidate;
  } catch {
    // A stale node workspace should not prevent the local terminal from opening.
  }
  return os.homedir();
}

function cwdFromTerminalData(data) {
  const match = String(data || '').match(/\u001b\]7;file:\/\/[^/]*([^\u0007\u001b]*)\u0007/);
  if (!match?.[1]) return null;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return match[1];
  }
}

function createPtyManager({
  onOutput = () => {},
  onExit = () => {},
  onAudit = () => {},
  ptyModule = pty,
} = {}) {
  const sessions = new Map();
  let nextId = 1;

  function getSession(sessionId, ownerId = null) {
    const session = sessions.get(sessionId);
    if (!session) {
      throw new Error(`Unknown terminal session: ${sessionId}`);
    }
    if (ownerId != null && session.ownerId !== ownerId) {
      throw new Error(`Terminal session ${sessionId} is not owned by this window.`);
    }
    return session;
  }

  function emitAudit(event) {
    onAudit({
      at: Date.now(),
      source: 'terminal',
      ...event,
    });
  }

  function openSession(options = {}, ownerId = null) {
    const shell = resolveShell();
    const cwd = resolveCwd(options.cwd);
    const cols = normalizeDimension(options.cols, 120, 40, 500);
    const rows = normalizeDimension(options.rows, 30, 12, 200);
    const name = String(options.name || 'Shell').trim() || 'Shell';
    if (options.reuseExisting === true) {
      const existing = Array.from(sessions.values()).find((session) =>
        session.ownerId === ownerId
          && session.name === name
          && session.status === 'running',
      );
      if (existing) {
        emitAudit({
          title: 'Terminal session resumed',
          detail: `${existing.name} resumed in ${existing.cwd}.`,
          status: 'good',
          command: existing.shell,
          sessionId: existing.id,
          ownerId: existing.ownerId,
        });
        return {
          ...sessionState(existing),
          reused: true,
        };
      }
    }
    const sessionId = String(nextId++);
    const terminal = ptyModule.spawn(shell, resolveShellArgs(shell), {
      name: 'xterm-256color',
      cols,
      rows,
      cwd,
      env: {
        ...process.env,
        TERM: 'xterm-256color',
      },
    });

    const session = {
      id: sessionId,
      terminal,
      shell,
      cwd,
      name,
      cols,
      rows,
      history: [],
      output: '',
      outputSequence: 0,
      pendingInput: '',
      ownerId,
      status: 'running',
      exitCode: null,
      signal: null,
    };
    sessions.set(sessionId, session);

    terminal.onData((data) => {
      const reportedCwd = cwdFromTerminalData(data);
      if (reportedCwd && fs.existsSync(reportedCwd)) session.cwd = reportedCwd;
      appendOutput(sessionId, data, session.ownerId);
    });

    terminal.onExit((result) => {
      session.status = 'exited';
      session.exitCode = result.exitCode;
      session.signal = result.signal;
      setTimeout(() => {
        emitAudit({
          title: 'Terminal session closed',
          detail: `${session.name} exited with code ${result.exitCode}.`,
          status: result.exitCode === 0 ? 'good' : 'bad',
          code: String(result.exitCode),
          sessionId,
          ownerId: session.ownerId,
        });
        onExit({
          sessionId,
          ownerId: session.ownerId,
          ...result,
        });
        sessions.delete(sessionId);
      }, PTY_OUTPUT_DRAIN_GRACE_MS);
    });

    emitAudit({
      title: 'Terminal session opened',
      detail: `${session.name} started in ${cwd}.`,
      status: 'good',
      command: shell,
      sessionId,
      ownerId,
    });

    return {
      ...sessionState(session),
      reused: false,
    };
  }

  function appendOutput(sessionId, output, ownerId = null) {
    const session = getSession(sessionId, ownerId);
    const data = String(output || '');
    if (!data) return sessionState(session);
    if (Buffer.byteLength(data, 'utf8') > 128 * 1024) {
      throw new Error('Terminal display output exceeds the 128 KiB event limit.');
    }
    session.output = trimOutputHistory(`${session.output}${data}`);
    session.outputSequence += 1;
    onOutput({
      sessionId,
      data,
      sequence: session.outputSequence,
      cwd: session.cwd,
      ownerId: session.ownerId,
    });
    return sessionState(session);
  }

  function clearSessionOutput(sessionId, ownerId = null) {
    const session = getSession(sessionId, ownerId);
    session.output = '';
    session.outputSequence += 1;
    return sessionState(session);
  }

  function writeInput(sessionId, input, ownerId = null) {
    const session = getSession(sessionId, ownerId);
    if (session.status !== 'running') {
      throw new Error(`Terminal session ${sessionId} has already exited.`);
    }
    const data = String(input || '');
    if (data.length > 128 * 1024) {
      throw new Error('Terminal input exceeds the 128 KiB session limit.');
    }
    session.terminal.write(data);
    session.pendingInput += data;
    const lines = session.pendingInput.split(/\r\n|\r|\n/);
    session.pendingInput = lines.pop() || '';
    lines
      .map((line) => line.trim())
      .filter(Boolean)
      .forEach((command) => {
        session.history.push({ at: Date.now(), command });
        if (session.history.length > 100) session.history.shift();
        emitAudit({
          title: 'Terminal command',
          detail: command,
          status: 'info',
          command,
          sessionId,
          ownerId: session.ownerId,
        });
      });
    return true;
  }

  function writeAllowlistedOperation(sessionId, actionId, ownerId = null) {
    const normalizedActionId = String(actionId || '').trim();
    const command = operationPtyAllowlist[normalizedActionId];
    if (!command) {
      throw new Error(`Operation is not allowlisted for PTY execution: ${normalizedActionId || 'unknown'}`);
    }

    // The action itself remains owned by nodeService/control-service. The PTY
    // receives only a fixed allowlisted command label, never renderer-provided
    // shell text.
    const auditLine = `$ ${command}`;
    const shellLiteral = `'${auditLine.replace(/'/g, "'\\''")}'`;
    const input = `printf '\\n%s\\n' ${shellLiteral}\r`;
    writeInput(sessionId, input, ownerId);
    return {
      actionId: normalizedActionId,
      command,
      sessionId: String(sessionId),
    };
  }

  function resizeSession(sessionId, cols, rows, ownerId = null) {
    const session = getSession(sessionId, ownerId);
    if (session.status !== 'running') return sessionState(session);
    const nextCols = normalizeDimension(cols, 120, 40, 500);
    const nextRows = normalizeDimension(rows, 30, 12, 200);
    session.terminal.resize(nextCols, nextRows);
    session.cols = nextCols;
    session.rows = nextRows;
    return {
      sessionId,
      cols: nextCols,
      rows: nextRows,
    };
  }

  function interruptSession(sessionId, ownerId = null) {
    const session = getSession(sessionId, ownerId);
    if (session.status !== 'running') return false;
    session.terminal.write('\u0003');
    return true;
  }

  function closeSession(sessionId, ownerId = null) {
    const session = getSession(sessionId, ownerId);
    if (session.status === 'running') session.terminal.kill();
    sessions.delete(sessionId);
    return true;
  }

  function normalizeDimension(value, fallback, minimum, maximum) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) return fallback;
    return Math.max(minimum, Math.min(maximum, Math.trunc(numeric)));
  }

  function trimOutputHistory(value) {
    const buffer = Buffer.from(String(value || ''), 'utf8');
    if (buffer.length <= MAX_OUTPUT_HISTORY_BYTES) return buffer.toString('utf8');
    return buffer.subarray(buffer.length - MAX_OUTPUT_HISTORY_BYTES).toString('utf8');
  }

  function sessionState(session) {
    return {
      sessionId: session.id,
      cwd: session.cwd,
      name: session.name,
      shell: session.shell,
      cols: session.cols,
      rows: session.rows,
      history: session.history,
      output: session.output,
      outputSequence: session.outputSequence,
      status: session.status,
      exitCode: session.exitCode,
      signal: session.signal,
    };
  }

  function getSessionState(sessionId, ownerId = null) {
    return sessionState(getSession(sessionId, ownerId));
  }

  function listSessions(ownerId = null) {
    return Array.from(sessions.values())
      .filter((session) => ownerId == null || session.ownerId === ownerId)
      .map(sessionState);
  }

  function closeAllSessions() {
    Array.from(sessions.keys()).forEach((sessionId) => {
      try {
        closeSession(sessionId);
      } catch {
        // Ignore already-closed sessions during shutdown.
      }
    });
  }

  return {
    appendOutput,
    clearSessionOutput,
    closeAllSessions,
    closeSession,
    getSessionState,
    interruptSession,
    listSessions,
    openSession,
    resizeSession,
    writeAllowlistedOperation,
    writeInput,
  };
}

module.exports = {
  createPtyManager,
};

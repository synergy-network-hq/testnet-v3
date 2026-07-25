import { useCallback, useEffect, useRef, useState } from 'react';
import { FitAddon } from '@xterm/addon-fit';
import { Terminal } from '@xterm/xterm';
import {
  Check,
  Clipboard,
  ClipboardPaste,
  Eraser,
  PlugZap,
  RefreshCw,
  Square,
  TriangleAlert,
  Unplug,
} from 'lucide-react';
import {
  clearTerminalOutput,
  closeTerminalSession,
  interruptTerminalSession,
  onTerminalExit,
  onTerminalOutput,
  openTerminalSession,
  readClipboardText,
  resizeTerminal,
  writeTerminalInput,
} from '../../lib/desktopClient';
import '@xterm/xterm/css/xterm.css';
import './DeveloperTerminalDock.css';

const DEFAULT_CWD = undefined;
const DEFAULT_TITLE = 'Operations terminal';
const MAX_PENDING_PTY_SESSIONS = 8;
const MAX_PENDING_PTY_EVENTS_PER_SESSION = 500;

export function operationTerminalSessionName(node, title = DEFAULT_TITLE) {
  return `${title}:${String(node?.id || 'local')}`;
}

function nodeWorkspace(node) {
  return node?.workspace_directory
    || node?.workspaceDirectory
    || node?.data_directory
    || node?.dataDirectory
    || DEFAULT_CWD;
}

function errorText(error) {
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return String(error || 'The terminal bridge returned an unknown error.');
}

function statusLabel(status) {
  switch (status) {
    case 'connecting':
      return 'Connecting';
    case 'connected':
      return 'Live PTY';
    case 'error':
      return 'Connection error';
    case 'exited':
      return 'Session exited';
    default:
      return 'Disconnected';
  }
}

function statusTone(status) {
  if (status === 'connected') return 'is-live';
  if (status === 'connecting') return 'is-pending';
  if (status === 'error' || status === 'exited') return 'is-error';
  return 'is-idle';
}

function statusHelp(status) {
  switch (status) {
    case 'connecting':
      return 'The Control Panel is opening a local shell on this machine.';
    case 'connected':
      return 'This is a live terminal connected to the machine where the Control Panel is installed.';
    case 'error':
      return 'The terminal could not connect. Reconnect opens a fresh local shell session.';
    case 'exited':
      return 'The shell session ended. Reconnect starts a new local terminal.';
    default:
      return 'The terminal is not connected. Reconnect starts a local shell.';
  }
}

async function copyText(value) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }

  const textarea = document.createElement('textarea');
  textarea.value = value;
  textarea.setAttribute('readonly', 'true');
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand('copy');
  textarea.remove();
  if (!copied) {
    throw new Error('Clipboard access was denied.');
  }
}

export default function DeveloperTerminalDock({
  node = null,
  cwd = '',
  title = DEFAULT_TITLE,
  className = '',
}) {
  const terminalRootRef = useRef(null);
  const terminalRef = useRef(null);
  const fitAddonRef = useRef(null);
  const fitFrameRef = useRef(null);
  const lastTerminalSizeRef = useRef({ cols: 0, rows: 0 });
  const sessionIdRef = useRef('');
  const connectAttemptRef = useRef(0);
  const mountedRef = useRef(false);
  const pendingPtyOutputRef = useRef(new Map());
  const [status, setStatus] = useState('disconnected');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [session, setSession] = useState(null);

  const resolvedCwd = cwd || nodeWorkspace(node);
  const sessionName = operationTerminalSessionName(node, title);
  const sessionHelp = session
    ? `Session ${session.id} is running ${session.shell || 'the default shell'} on this machine.`
    : 'Input is sent to a local shell after the terminal connects.';
  const cwdHelp = session?.cwd || resolvedCwd
    ? `Commands run from ${session?.cwd || resolvedCwd}.`
    : 'Commands start in the shell home directory when no node workspace is selected.';

  const setFailure = useCallback((nextError) => {
    setStatus('error');
    setError(errorText(nextError));
    setNotice('');
  }, []);

  const fitTerminal = useCallback(() => {
    if (fitFrameRef.current !== null) return;

    const scheduleFit = typeof window !== 'undefined' && typeof window.requestAnimationFrame === 'function'
      ? (callback) => window.requestAnimationFrame(callback)
      : (callback) => setTimeout(callback, 0);
    fitFrameRef.current = scheduleFit(() => {
      fitFrameRef.current = null;
      if (!mountedRef.current) return;

      const terminal = terminalRef.current;
      const fitAddon = fitAddonRef.current;
      if (!terminal || !fitAddon) return;

      try {
        fitAddon.fit();
        const nextSize = { cols: terminal.cols, rows: terminal.rows };
        const previousSize = lastTerminalSizeRef.current;
        if (nextSize.cols === previousSize.cols && nextSize.rows === previousSize.rows) return;
        lastTerminalSizeRef.current = nextSize;
        const sessionId = sessionIdRef.current;
        if (sessionId) {
          void resizeTerminal(sessionId, terminal.cols, terminal.rows).catch((nextError) => {
            if (sessionId === sessionIdRef.current) {
              setFailure(nextError);
            }
          });
        }
      } catch (nextError) {
        setFailure(nextError);
      }
    });
  }, [setFailure]);

  const closeSession = useCallback(async (sessionId = sessionIdRef.current) => {
    if (!sessionId) return;
    if (sessionId === sessionIdRef.current) {
      sessionIdRef.current = '';
      setSession(null);
    }
    pendingPtyOutputRef.current.delete(sessionId);
    try {
      await closeTerminalSession(sessionId);
    } catch {
      // The PTY may already have exited between the exit event and cleanup.
    }
  }, []);

  const connect = useCallback(async () => {
    const attempt = connectAttemptRef.current + 1;
    connectAttemptRef.current = attempt;
    const previousSessionId = sessionIdRef.current;
    sessionIdRef.current = '';
    setSession(null);
    setStatus('connecting');
    setError('');
    setNotice('');

    if (previousSessionId) {
      await closeSession(previousSessionId);
    }

    const terminal = terminalRef.current;
    if (!terminal || !mountedRef.current || attempt !== connectAttemptRef.current) return;

    try {
      const fitAddon = fitAddonRef.current;
      fitAddon?.fit();
      lastTerminalSizeRef.current = { cols: terminal.cols, rows: terminal.rows };
      const opened = await openTerminalSession({
        cwd: resolvedCwd || undefined,
        name: sessionName,
        cols: terminal.cols,
        rows: terminal.rows,
        reuseExisting: true,
      });

      if (!mountedRef.current || attempt !== connectAttemptRef.current) {
        // A newer mount can reuse this named PTY before this stale async call
        // resumes (notably under React Strict Mode). Keep it available for the
        // current dock instead of tearing down the session it just reused.
        return;
      }

      const nextSessionId = String(opened?.sessionId || '');
      if (!nextSessionId) {
        throw new Error('The terminal bridge opened a session without an id.');
      }

      sessionIdRef.current = nextSessionId;
      const replay = String(opened?.output || '');
      if (replay) terminal.write(replay);
      const replaySequence = Number(opened?.outputSequence || 0);
      const pendingOutput = pendingPtyOutputRef.current.get(nextSessionId) || [];
      pendingOutput
        .filter((payload) => Number(payload?.sequence || 0) > replaySequence)
        .forEach((payload) => terminal.write(String(payload?.data || '')));
      pendingPtyOutputRef.current.delete(nextSessionId);
      setSession({
        cwd: opened.cwd || resolvedCwd || '',
        id: nextSessionId,
        shell: opened.shell || '',
      });
      setStatus('connected');
      terminal.focus();
      await resizeTerminal(nextSessionId, terminal.cols, terminal.rows);
    } catch (nextError) {
      if (mountedRef.current && attempt === connectAttemptRef.current) {
        setFailure(nextError);
      }
    }
  }, [closeSession, resolvedCwd, sessionName, setFailure]);

  useEffect(() => {
    mountedRef.current = true;
    const terminal = new Terminal({
      allowProposedApi: false,
      cursorBlink: true,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
      fontSize: 12,
      lineHeight: 1.35,
      scrollback: 5000,
      theme: {
        background: '#071014',
        black: '#071014',
        blue: '#79a8ff',
        brightBlack: '#64748b',
        brightBlue: '#9ec1ff',
        brightCyan: '#78efff',
        brightGreen: '#72f5b2',
        brightMagenta: '#d5b6ff',
        brightRed: '#ff9b9b',
        brightWhite: '#f5f7fa',
        brightYellow: '#ffe08a',
        cursor: '#72f5b2',
        cyan: '#4bd9e8',
        foreground: '#e8eef2',
        green: '#42d994',
        magenta: '#b99cff',
        red: '#f47782',
        selectionBackground: 'rgba(75, 217, 232, 0.28)',
        white: '#e8eef2',
        yellow: '#f3c969',
      },
    });
    const fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);
    terminal.open(terminalRootRef.current);
    terminalRef.current = terminal;
    fitAddonRef.current = fitAddon;
    fitAddon.fit();
    lastTerminalSizeRef.current = { cols: terminal.cols, rows: terminal.rows };

    const resizeObserver = typeof ResizeObserver === 'function'
      ? new ResizeObserver(() => fitTerminal())
      : null;
    if (resizeObserver && terminalRootRef.current) {
      resizeObserver.observe(terminalRootRef.current);
    }
    window.addEventListener('resize', fitTerminal);

    const inputDisposable = terminal.onData((input) => {
      const sessionId = sessionIdRef.current;
      if (!sessionId) return;
      void writeTerminalInput(sessionId, input).catch((nextError) => {
        if (sessionId === sessionIdRef.current) {
          setFailure(nextError);
        }
      });
    });

    return () => {
      mountedRef.current = false;
      connectAttemptRef.current += 1;
      resizeObserver?.disconnect();
      window.removeEventListener('resize', fitTerminal);
      if (fitFrameRef.current !== null) {
        if (typeof window.cancelAnimationFrame === 'function') {
          window.cancelAnimationFrame(fitFrameRef.current);
        } else {
          clearTimeout(fitFrameRef.current);
        }
        fitFrameRef.current = null;
      }
      inputDisposable.dispose();
      sessionIdRef.current = '';
      terminal.dispose();
      terminalRef.current = null;
      fitAddonRef.current = null;
    };
  }, [closeSession, fitTerminal, setFailure]);

  useEffect(() => {
    const stopOutput = onTerminalOutput((payload) => {
      const outputSessionId = String(payload?.sessionId || '');
      if (!outputSessionId) return;
      if (outputSessionId === sessionIdRef.current) {
        terminalRef.current?.write(String(payload?.data || ''));
        return;
      }
      const pending = pendingPtyOutputRef.current.get(outputSessionId) || [];
      pending.push(payload);
      pendingPtyOutputRef.current.set(outputSessionId, pending.slice(-MAX_PENDING_PTY_EVENTS_PER_SESSION));
      while (pendingPtyOutputRef.current.size > MAX_PENDING_PTY_SESSIONS) {
        const oldestSessionId = pendingPtyOutputRef.current.keys().next().value;
        if (!oldestSessionId) break;
        pendingPtyOutputRef.current.delete(oldestSessionId);
      }
    });
    const stopExit = onTerminalExit((payload) => {
      const outputSessionId = String(payload?.sessionId || '');
      if (!outputSessionId) return;
      pendingPtyOutputRef.current.delete(outputSessionId);
      if (outputSessionId !== sessionIdRef.current) return;
      sessionIdRef.current = '';
      setSession(null);
      setStatus(Number(payload?.exitCode) === 0 ? 'disconnected' : 'exited');
      if (Number(payload?.exitCode) !== 0) {
        setError(`The shell exited with code ${payload?.exitCode ?? 'unknown'}.`);
      }
    });
    return () => {
      stopOutput();
      stopExit();
      pendingPtyOutputRef.current.clear();
    };
  }, [setFailure]);

  useEffect(() => {
    void connect();
  }, [connect]);

  const clearDisplay = async () => {
    terminalRef.current?.clear();
    terminalRef.current?.focus();
    const sessionId = sessionIdRef.current;
    if (sessionId) {
      try {
        await clearTerminalOutput(sessionId);
      } catch (nextError) {
        setFailure(nextError);
        return;
      }
    }
    setNotice('Terminal display and replay history cleared.');
  };

  const pasteClipboard = async () => {
    const sessionId = sessionIdRef.current;
    if (!sessionId) {
      setNotice('Connect the terminal before pasting.');
      return;
    }
    try {
      const value = await readClipboardText();
      if (!value) {
        setNotice('The clipboard does not contain text.');
        return;
      }
      await writeTerminalInput(sessionId, value);
      setNotice('Clipboard text pasted into the terminal.');
      terminalRef.current?.focus();
    } catch (nextError) {
      setFailure(nextError);
    }
  };

  const copySelection = async () => {
    const selection = terminalRef.current?.getSelection() || '';
    if (!selection) {
      setNotice('Select terminal text before copying.');
      return;
    }

    try {
      await copyText(selection);
      setNotice('Selected terminal text copied.');
    } catch {
      setNotice('Clipboard access was denied.');
    }
  };

  const disconnect = () => {
    connectAttemptRef.current += 1;
    void closeSession();
    setStatus('disconnected');
    setError('');
    setNotice('Terminal disconnected.');
  };

  const interrupt = async () => {
    const sessionId = sessionIdRef.current;
    if (!sessionId) return;
    try {
      await interruptTerminalSession(sessionId);
      setNotice('Interrupt sent to the terminal.');
      terminalRef.current?.focus();
    } catch (nextError) {
      setFailure(nextError);
    }
  };

  return (
    <section className={`v18-terminal-dock ${className}`.trim()} aria-label={title}>
      <header className="v18-terminal-dock__head">
        <div className="v18-terminal-dock__heading">
          <span>Interactive terminal</span>
          <strong>{title}</strong>
          <div className={`v18-terminal-dock__status ${statusTone(status)}`} role="status" aria-live="polite" title={statusHelp(status)}>
            <i aria-hidden="true" />
            {statusLabel(status)}
          </div>
        </div>
        <div className="v18-terminal-dock__actions">
          <button type="button" className="v18-terminal-dock__icon-button" onClick={() => void copySelection()} title="Copy selected terminal text" aria-label="Copy selected terminal text">
            <Clipboard size={15} />
          </button>
          <button type="button" className="v18-terminal-dock__icon-button" onClick={() => void pasteClipboard()} disabled={status !== 'connected'} title="Paste clipboard text into terminal" aria-label="Paste clipboard text into terminal">
            <ClipboardPaste size={15} />
          </button>
          <button type="button" className="v18-terminal-dock__icon-button" onClick={() => void clearDisplay()} title="Clear terminal display" aria-label="Clear terminal display">
            <Eraser size={15} />
          </button>
          {status === 'connected' ? (
            <button type="button" className="v18-terminal-dock__icon-button" onClick={() => void interrupt()} title="Interrupt running terminal command" aria-label="Interrupt running terminal command">
              <Square size={15} />
            </button>
          ) : null}
          {status === 'connected' ? (
            <button type="button" className="v18-terminal-dock__icon-button" onClick={disconnect} title="Disconnect terminal" aria-label="Disconnect terminal">
              <Unplug size={15} />
            </button>
          ) : (
            <button type="button" className="v18-terminal-dock__icon-button is-primary" onClick={() => void connect()} disabled={status === 'connecting'} title="Reconnect terminal" aria-label="Reconnect terminal">
              {status === 'connecting' ? <RefreshCw className="is-spinning" size={15} /> : <PlugZap size={15} />}
            </button>
          )}
        </div>
      </header>

      {error ? (
        <div className="v18-terminal-dock__error" role="alert">
          <TriangleAlert size={16} aria-hidden="true" />
          <span>{error}</span>
          <button type="button" onClick={() => void connect()} disabled={status === 'connecting'} title="Open a new local terminal session on this machine.">Reconnect</button>
        </div>
      ) : null}

      <div
        ref={terminalRootRef}
        className="v18-terminal-dock__root"
        onClick={() => terminalRef.current?.focus()}
        role="application"
        aria-label="Live PTY terminal"
      />

      <footer className="v18-terminal-dock__foot">
        <span title={notice || sessionHelp}>{notice || (session ? `PTY ${session.id}${session.shell ? ` · ${session.shell}` : ''}` : 'Input is sent directly to the installed machine shell.')}</span>
        <span title={cwdHelp}>{session?.cwd || resolvedCwd || 'Shell home directory'}</span>
        {status === 'connected' ? <Check size={14} aria-label="Terminal connected" /> : null}
      </footer>
    </section>
  );
}

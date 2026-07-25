import { useEffect, useMemo, useRef } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';

function terminalTheme() {
  return {
    background: '#06131f',
    foreground: '#edf6ff',
    cursor: '#4be6f7',
    selectionBackground: 'rgba(75, 230, 247, 0.24)',
    black: '#04101b',
    red: '#ff7d88',
    green: '#3ef7a1',
    yellow: '#ffcb65',
    blue: '#70a7ff',
    magenta: '#b48cff',
    cyan: '#4be6f7',
    white: '#edf6ff',
  };
}

export default function TerminalSessionView({
  sessionId = '',
  output = '',
  title = 'Terminal',
  quickCommands = [],
  onOpen = null,
  onResize = null,
  onWrite = null,
}) {
  const terminalRootRef = useRef(null);
  const terminalRef = useRef(null);
  const fitAddonRef = useRef(null);
  const outputCursorRef = useRef(0);
  const resizeObserverRef = useRef(null);

  const mergedOutput = useMemo(() => String(output || ''), [output]);

  useEffect(() => {
    const terminal = new Terminal({
      fontFamily: '"JetBrains Mono Local", "JetBrains Mono", monospace',
      fontSize: 12.5,
      lineHeight: 1.35,
      cursorBlink: true,
      theme: terminalTheme(),
      scrollback: 2000,
      allowProposedApi: false,
    });
    const fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);
    terminal.open(terminalRootRef.current);
    fitAddon.fit();

    terminal.onData((data) => {
      if (sessionId) {
        void onWrite?.(sessionId, data);
      }
    });

    const resize = () => {
      try {
        fitAddon.fit();
        if (sessionId) {
          void onResize?.(sessionId, terminal.cols, terminal.rows);
        }
      } catch {
        // Ignore layout glitches during transitions.
      }
    };

    resizeObserverRef.current = new ResizeObserver(resize);
    resizeObserverRef.current.observe(terminalRootRef.current);
    terminalRef.current = terminal;
    fitAddonRef.current = fitAddon;

    return () => {
      resizeObserverRef.current?.disconnect();
      terminal.dispose();
      terminalRef.current = null;
      fitAddonRef.current = null;
      outputCursorRef.current = 0;
    };
  }, [onResize, onWrite, sessionId]);

  useEffect(() => {
    if (!sessionId) {
      void onOpen?.();
    }
  }, [onOpen, sessionId]);

  useEffect(() => {
    if (!terminalRef.current) {
      return;
    }

    if (outputCursorRef.current > mergedOutput.length) {
      terminalRef.current.reset();
      outputCursorRef.current = 0;
    }

    const nextChunk = mergedOutput.slice(outputCursorRef.current);
    if (nextChunk) {
      terminalRef.current.write(nextChunk);
      outputCursorRef.current = mergedOutput.length;
    }
  }, [mergedOutput]);

  const runQuickCommand = async (command) => {
    if (!sessionId || !command) {
      return;
    }
    await onWrite?.(sessionId, `${command}\r`);
  };

  const clearTerminal = () => {
    terminalRef.current?.clear();
  };

  return (
    <div className="cp-terminal-session">
      <div className="cp-terminal-session-head">
        <div>
          <strong>{title}</strong>
          <span>{sessionId ? `Live session ${sessionId}` : 'Opening session...'}</span>
        </div>
        <div className="cp-chip-row">
          {quickCommands.slice(0, 3).map((command) => (
            <button
              key={command}
              type="button"
              className="cp-chip cp-chip-button"
              onClick={() => void runQuickCommand(command)}
            >
              {command.length > 18 ? `${command.slice(0, 18)}…` : command}
            </button>
          ))}
          <button type="button" className="cp-chip cp-chip-button" onClick={clearTerminal}>
            Clear
          </button>
        </div>
      </div>
      <div ref={terminalRootRef} className="cp-terminal-root"></div>
    </div>
  );
}


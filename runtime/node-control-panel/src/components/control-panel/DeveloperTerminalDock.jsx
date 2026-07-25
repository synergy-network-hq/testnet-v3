import { useEffect, useMemo, useState } from 'react';
import {
  closeTerminalSession,
  onTerminalAudit,
  onTerminalExit,
  onTerminalOutput,
  openTerminalSession,
  resizeTerminal,
  writeTerminalInput,
} from '../../lib/desktopClient';
import { useControlPanel } from './ControlPanelProvider';
import { localRpcEndpointForNode, queryLocalRpc } from './controlPanelModel';
import TerminalTabs from './TerminalTabs';
import TerminalSessionView from './TerminalSessionView';
import ActionAuditStream from './ActionAuditStream';
import JsonInspectorPanel from './JsonInspectorPanel';

const DOCK_HEIGHT_STORAGE_KEY = 'synergy:testnet:terminal-dock-height:v1';
const DOCK_COLLAPSED_STORAGE_KEY = 'synergy:testnet:terminal-dock-collapsed:v1';

function readDockHeight() {
  if (typeof window === 'undefined') {
    return 320;
  }
  const stored = Number(window.localStorage.getItem(DOCK_HEIGHT_STORAGE_KEY));
  return Number.isFinite(stored) ? Math.max(220, Math.min(stored, 560)) : 320;
}

function readDockCollapsed() {
  if (typeof window === 'undefined') {
    return false;
  }
  return window.localStorage.getItem(DOCK_COLLAPSED_STORAGE_KEY) === '1';
}

function buildDockTabs(selectedNode) {
  const workspaceRoot = selectedNode?.workspace_directory || '';
  const logsPath = workspaceRoot ? `${workspaceRoot}/logs` : '';
  const nodeLogCommand = logsPath
    ? `ls "${logsPath}" && tail -f "${logsPath}"/synergy-testnet.log`
    : 'pwd';

  return [
    {
      id: 'shell',
      label: 'Shell',
      type: 'terminal',
      title: 'Shell',
      cwd: workspaceRoot || undefined,
      quickCommands: ['pwd', 'ls', 'ps aux | grep synergy'],
    },
    {
      id: 'file-tail',
      label: 'File Tail',
      type: 'terminal',
      title: 'File Tail',
      cwd: workspaceRoot || undefined,
      quickCommands: [nodeLogCommand, 'ls logs', 'grep -n "ERROR" -R logs'],
    },
    {
      id: 'rpc-console',
      label: 'RPC Console',
      type: 'rpc',
      title: 'RPC Console',
    },
    {
      id: 'command-output',
      label: 'Command Output',
      type: 'audit',
      title: 'Action Output',
    },
  ];
}

export default function DeveloperTerminalDock() {
  const {
    actionAudit,
    recordAction,
    selectedNode,
    selectedNodeLive,
    viewProfile,
  } = useControlPanel();
  const [dockHeight, setDockHeight] = useState(() => readDockHeight());
  const [collapsed, setCollapsed] = useState(() => readDockCollapsed());
  const [activeTabId, setActiveTabId] = useState('shell');
  const [tabSessions, setTabSessions] = useState({});
  const [terminalAudit, setTerminalAudit] = useState([]);
  const [rpcMethod, setRpcMethod] = useState('synergy_getNodeStatus');
  const [rpcParams, setRpcParams] = useState('[]');
  const [rpcResult, setRpcResult] = useState(null);
  const [rpcError, setRpcError] = useState('');
  const tabs = useMemo(() => buildDockTabs(selectedNode), [selectedNode]);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }
    window.localStorage.setItem(DOCK_HEIGHT_STORAGE_KEY, String(dockHeight));
  }, [dockHeight]);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }
    window.localStorage.setItem(DOCK_COLLAPSED_STORAGE_KEY, collapsed ? '1' : '0');
  }, [collapsed]);

  useEffect(() => {
    const stopOutput = onTerminalOutput((payload) => {
      setTabSessions((current) => {
        const next = { ...current };
        const tabId = Object.keys(current).find((key) => current[key]?.sessionId === payload.sessionId);
        if (!tabId) {
          return current;
        }
        next[tabId] = {
          ...next[tabId],
          output: `${next[tabId].output || ''}${payload.data || ''}`,
        };
        return next;
      });
    });

    const stopExit = onTerminalExit((payload) => {
      setTabSessions((current) => {
        const next = { ...current };
        const tabId = Object.keys(current).find((key) => current[key]?.sessionId === payload.sessionId);
        if (!tabId) {
          return current;
        }
        next[tabId] = {
          ...next[tabId],
          exited: true,
        };
        return next;
      });
    });

    const stopAudit = onTerminalAudit((payload) => {
      setTerminalAudit((current) => [payload, ...current].slice(0, 120));
    });

    return () => {
      stopOutput();
      stopExit();
      stopAudit();
    };
  }, []);

  useEffect(() => () => {
    Object.values(tabSessions).forEach((session) => {
      if (session?.sessionId) {
        void closeTerminalSession(session.sessionId);
      }
    });
  }, [tabSessions]);

  useEffect(() => {
    if (!viewProfile.showEmbeddedTerminal) {
      setCollapsed(true);
    }
  }, [viewProfile.showEmbeddedTerminal]);

  if (!viewProfile.showEmbeddedTerminal) {
    return null;
  }

  const activeTab = tabs.find((tab) => tab.id === activeTabId) || tabs[0];
  const activeSessionState = tabSessions[activeTab.id] || {};

  const ensureSession = async (tab) => {
    if (tab.type !== 'terminal' || tabSessions[tab.id]?.sessionId) {
      return tabSessions[tab.id]?.sessionId || '';
    }

    const session = await openTerminalSession({
      cwd: tab.cwd,
      name: tab.title,
    });

    setTabSessions((current) => ({
      ...current,
      [tab.id]: {
        sessionId: session.sessionId,
        output: current[tab.id]?.output || '',
      },
    }));

    return session.sessionId;
  };

  const mergedAudit = [...terminalAudit, ...actionAudit]
    .sort((left, right) => Number(right.at || 0) - Number(left.at || 0));

  const submitRpcQuery = async (event) => {
    event.preventDefault();
    if (!selectedNode) {
      return;
    }

    setRpcError('');
    try {
      const params = JSON.parse(rpcParams || '[]');
      const endpoint = localRpcEndpointForNode(selectedNode, selectedNodeLive);
      const result = await queryLocalRpc(endpoint, rpcMethod, Array.isArray(params) ? params : [params]);
      setRpcResult(result);
      recordAction({
        title: 'RPC query',
        detail: `${rpcMethod} returned successfully.`,
        status: 'good',
        source: 'developer-dock',
        command: rpcMethod,
      });
    } catch (error) {
      setRpcError(String(error));
      recordAction({
        title: 'RPC query failed',
        detail: String(error),
        status: 'bad',
        source: 'developer-dock',
        command: rpcMethod,
      });
    }
  };

  const beginResize = (event) => {
    const startingY = event.clientY;
    const startingHeight = dockHeight;
    const onMove = (moveEvent) => {
      setDockHeight(Math.max(220, Math.min(560, startingHeight - (moveEvent.clientY - startingY))));
    };
    const onUp = () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  };

  return (
    <aside
      className={`cp-terminal-dock ${collapsed ? 'is-collapsed' : ''}`}
      style={{ '--cp-terminal-dock-height': `${dockHeight}px` }}
    >
      <div className="cp-terminal-dock-handle" onMouseDown={beginResize}></div>
      <div className="cp-terminal-dock-head">
        <div>
          <span className="cp-eyebrow">Developer Dock</span>
          <h3>Persistent tooling</h3>
        </div>
        <div className="cp-chip-row">
          <button type="button" className="cp-chip cp-chip-button" onClick={() => setCollapsed((current) => !current)}>
            {collapsed ? 'Expand' : 'Collapse'}
          </button>
        </div>
      </div>

      {!collapsed ? (
        <div className="cp-terminal-dock-body">
          <TerminalTabs tabs={tabs} activeTabId={activeTab.id} onChange={setActiveTabId} />

          {activeTab.type === 'terminal' ? (
            <TerminalSessionView
              key={activeTab.id}
              sessionId={activeSessionState.sessionId}
              output={activeSessionState.output || ''}
              title={activeTab.title}
              quickCommands={activeTab.quickCommands}
              onOpen={() => ensureSession(activeTab)}
              onResize={resizeTerminal}
              onWrite={writeTerminalInput}
            />
          ) : null}

          {activeTab.type === 'audit' ? (
            <div className="cp-terminal-panel">
              <ActionAuditStream entries={mergedAudit} emptyMessage="Developer actions and command receipts will appear here." />
            </div>
          ) : null}

          {activeTab.type === 'rpc' ? (
            <div className="cp-terminal-panel">
              <form className="cp-rpc-console" onSubmit={submitRpcQuery}>
                <label className="cp-form-field">
                  <span>Method</span>
                  <input value={rpcMethod} onChange={(event) => setRpcMethod(event.target.value)} />
                </label>
                <label className="cp-form-field">
                  <span>Params JSON</span>
                  <textarea value={rpcParams} onChange={(event) => setRpcParams(event.target.value)} rows={4}></textarea>
                </label>
                <button type="submit" className="cp-chip cp-chip-button">Run query</button>
              </form>
              {rpcError ? <div className="cp-inline-notice tone-bad">{rpcError}</div> : null}
              <JsonInspectorPanel title="RPC result" value={rpcResult} emptyMessage="Run a local JSON-RPC query to inspect its response." />
            </div>
          ) : null}
        </div>
      ) : null}
    </aside>
  );
}

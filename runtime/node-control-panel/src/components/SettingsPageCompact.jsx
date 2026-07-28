import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getVersion, invoke, openPath } from '../lib/desktopClient';
import {
  fetchTestnetLiveStatus,
  fetchTestnetState,
  peekTestnetLiveStatus,
  peekTestnetState,
} from '../lib/testnetPageData';
import { useDeveloperMode } from '../lib/developerMode';
import { SNRGButton } from '../styles/SNRGButton';

function detectPlatformKind(operatingSystem) {
  const text = String(operatingSystem || '').toLowerCase();
  if (text.includes('windows')) return 'windows';
  if (text.includes('mac') || text.includes('darwin') || text.includes('os x')) return 'macos';
  if (text.includes('linux')) return 'linux';
  return 'unknown';
}

function formatPlatformLabel(platformKind) {
  if (platformKind === 'macos') return 'macOS';
  if (platformKind === 'linux') return 'Linux';
  if (platformKind === 'windows') return 'Windows';
  return 'Unknown';
}

function formatPath(path) {
  return String(path || '').trim() || 'Not available';
}

function formatEndpointStatus(items) {
  const total = Array.isArray(items) ? items.length : 0;
  const reachable = Array.isArray(items) ? items.filter((item) => item?.reachable).length : 0;
  return `${reachable}/${total}`;
}

function SettingsCard({ kicker, title, children, actions = null }) {
  return (
    <section className="settings-shell-panel settings-shell-compact-card">
      <div className="settings-shell-panel-header">
        <div>
          <p className="settings-shell-panel-kicker">{kicker}</p>
          <h3>{title}</h3>
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}

function Definition({ label, value, detail }) {
  return (
    <div className="settings-shell-definition-row">
      <span className="settings-shell-definition-label">{label}</span>
      <div className="settings-shell-definition-value">
        <strong>{value}</strong>
        {detail ? <small>{detail}</small> : null}
      </div>
    </div>
  );
}

export default function SettingsPageCompact() {
  const navigate = useNavigate();
  const [developerModeEnabled, setDeveloperModeEnabled] = useDeveloperMode();
  const [state, setState] = useState(() => peekTestnetState());
  const [liveStatus, setLiveStatus] = useState(() => peekTestnetLiveStatus());
  const [version, setVersion] = useState('');
  const [status, setStatus] = useState('');
  const [eraseBusy, setEraseBusy] = useState(false);
  const [timeSyncBusy, setTimeSyncBusy] = useState(false);
  const [confirmDeveloperOpen, setConfirmDeveloperOpen] = useState(false);
  const [confirmText, setConfirmText] = useState('');

  useEffect(() => {
    let cancelled = false;
    void getVersion().then((nextVersion) => {
      if (!cancelled) setVersion(String(nextVersion || ''));
    }).catch(() => {});
    void Promise.allSettled([
      fetchTestnetState({ force: true }),
      fetchTestnetLiveStatus({ force: true }),
    ]).then(([stateResult, liveResult]) => {
      if (cancelled) return;
      if (stateResult.status === 'fulfilled') setState(stateResult.value);
      if (liveResult.status === 'fulfilled') setLiveStatus(liveResult.value);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const storageRoot = useMemo(() => {
    const home = state?.device_profile?.home_directory;
    if (!home) return '';
    return `${home.replace(/[\\/]+$/, '')}/.synergy/testnet`;
  }, [state?.device_profile?.home_directory]);
  const fork = state?.consensus_fork || state?.network_profile?.consensus_fork || {};

  const provisionedNodes = Array.isArray(state?.nodes) ? state.nodes : [];
  const localNodeForTimeSync = provisionedNodes[0] || null;
  const platformKind = useMemo(
    () => detectPlatformKind(state?.device_profile?.operating_system),
    [state?.device_profile?.operating_system],
  );
  const platformLabel = formatPlatformLabel(platformKind);
  const canEraseThisPlatform = platformKind !== 'unknown';
  const eraseLabel = platformKind === 'macos'
    ? 'Erase macOS Node Data'
    : platformKind === 'linux'
      ? 'Erase Linux Node Data'
      : platformKind === 'windows'
        ? 'Erase Windows Node Data'
        : 'Erase Local Node Data';

  const handleDeveloperToggle = () => {
    if (developerModeEnabled) {
      setDeveloperModeEnabled(false);
      return;
    }
    setConfirmDeveloperOpen(true);
  };

  const handleEraseLocalData = async () => {
    if (!canEraseThisPlatform || confirmText !== 'ERASE') {
      return;
    }
    setEraseBusy(true);
    setStatus(`Erasing local ${platformLabel} node data...`);
    try {
      const result = await invoke('testnet_erase_local_machine_data', {
        targetOs: platformKind,
      });
      setStatus(result?.message || `Erased local ${platformLabel} node data.`);
      setConfirmText('');
    } catch (error) {
      setStatus(String(error));
    } finally {
      setEraseBusy(false);
    }
  };

  const handleResyncTime = async () => {
    if (!localNodeForTimeSync?.id) {
      setStatus('Provision a local node before running machine time resync.');
      return;
    }
    setTimeSyncBusy(true);
    setStatus('Resyncing machine time...');
    try {
      const result = await invoke('testnet_node_control', {
        input: {
          nodeId: localNodeForTimeSync.id,
          action: 'resync-time',
        },
      });
      setStatus(result?.message || 'Machine time resync action completed.');
    } catch (error) {
      setStatus(String(error));
    } finally {
      setTimeSyncBusy(false);
    }
  };

  return (
    <section className="nodecp-settings-page settings-shell-page settings-shell-compact">
      <div className="settings-shell-hero">
        <div className="settings-shell-hero-copy">
          <p className="nodecp-page-kicker">Settings</p>
          <h2 className="nodecp-page-title">Control Panel Settings</h2>
        </div>
        <div className="settings-shell-hero-actions">
          <SNRGButton variant="lime" size="md" onClick={handleResyncTime} disabled={!localNodeForTimeSync || timeSyncBusy}>
            {timeSyncBusy ? 'Resyncing...' : 'Resync Time'}
          </SNRGButton>
          <SNRGButton variant="blue" size="md" onClick={() => storageRoot && openPath(storageRoot)} disabled={!storageRoot}>
            Open Workspace
          </SNRGButton>
        </div>
      </div>

      {status ? <div className="settings-shell-status settings-shell-status-warn"><span>{status}</span></div> : null}

      <div className="settings-shell-main-grid settings-shell-compact-grid">
        <SettingsCard kicker="General" title="General Preferences">
          <div className="settings-shell-definition-grid">
            <Definition label="App" value="Synergy Node Control Panel" detail={version || 'Version not reported'} />
            <Definition label="Environment" value={state?.display_name || 'Testnet'} detail={`chain_id ${state?.chain_id || state?.network_profile?.chain_id || 1266} / network_id ${state?.network_id || state?.network_profile?.network_id || 'synergy-testnet-v3'}`} />
            <Definition label="Genesis Consensus" value={fork?.new_consensus_algorithm || 'ML-DSA-65'} detail={`height ${fork?.fork_height ?? 0}, network ${state?.network_id || state?.network_profile?.network_id || 'synergy-testnet-v3'}, parser ${fork?.parser_mode || 'fail_closed'}`} />
            <Definition label="Machine" value={state?.device_profile?.hostname || 'Unknown'} detail={state?.device_profile?.operating_system || 'Local operator host'} />
          </div>
        </SettingsCard>

        <SettingsCard
          kicker="View Mode"
          title="Operator Experience"
          actions={(
            <SNRGButton variant={developerModeEnabled ? 'red' : 'purple'} size="sm" onClick={handleDeveloperToggle}>
              {developerModeEnabled ? 'Disable Developer View' : 'Enable Developer View'}
            </SNRGButton>
          )}
        >
          <div className="settings-shell-definition-grid">
            <Definition label="Default views" value={developerModeEnabled ? 'Basic, Advanced, Developer' : 'Basic, Advanced'} detail="Developer stays hidden until enabled here." />
            <Definition label="Developer View" value={developerModeEnabled ? 'Enabled' : 'Hidden'} detail="Raw diagnostics, configuration, and protocol inspectors." />
          </div>
        </SettingsCard>

        <SettingsCard
          kicker="Updates"
          title="App Updates"
          actions={<SNRGButton variant="blue" size="sm" onClick={() => setStatus(`Update check started for v${version || 'current'}.`)}>Check for Updates</SNRGButton>}
        >
          <div className="settings-shell-definition-grid">
            <Definition label="Installed version" value={version || 'Unknown'} detail="Installer and updater metadata." />
            <Definition label="Channel" value="Stable" detail="Tag-driven release installers." />
          </div>
        </SettingsCard>

        <SettingsCard
          kicker="Workspace"
          title="Workspace + Local Data"
          actions={<SNRGButton variant="blue" size="sm" onClick={() => storageRoot && openPath(storageRoot)} disabled={!storageRoot}>Open Folder</SNRGButton>}
        >
          <div className="settings-shell-definition-grid">
            <Definition label="Workspace root" value={formatPath(storageRoot)} />
            <Definition label="Provisioned nodes" value={String(provisionedNodes.length)} detail="This release manages one node per machine." />
            <Definition label="Bootnodes online" value={formatEndpointStatus(liveStatus?.bootnodes)} detail="Public bootstrap listeners responding." />
          </div>
        </SettingsCard>

        <SettingsCard kicker="Diagnostics" title="Shortcuts">
          <div className="settings-shell-definition-grid">
            <Definition label="Network" value={liveStatus?.discovery_status || 'Unknown'} detail={liveStatus?.discovery_detail || 'Waiting for live check'} />
            <Definition label="Public RPC" value={liveStatus?.public_rpc_online ? 'Online' : 'Not responding'} detail={liveStatus?.public_rpc_endpoint || 'No endpoint reported'} />
          </div>
          <div className="settings-shell-definition-actions">
            <SNRGButton variant="purple" size="sm" onClick={() => navigate('/diagnostics')}>Open Diagnostics</SNRGButton>
            <SNRGButton variant="blue" size="sm" onClick={() => navigate('/help')}>Open Help</SNRGButton>
          </div>
        </SettingsCard>

        <details className="settings-shell-panel settings-shell-danger-zone">
          <summary>
            <span>
              <span className="settings-shell-panel-kicker">Danger Zone</span>
              <strong>Destructive Local Actions</strong>
            </span>
            <span className={`settings-shell-badge ${canEraseThisPlatform ? 'warn' : 'bad'}`}>{platformLabel}</span>
          </summary>
          <div className="settings-shell-feature-card">
            <div className="settings-shell-feature-copy">
              <span className="settings-shell-feature-kicker">Clean Install Reset</span>
              <strong>{eraseLabel}</strong>
              <p>This stops local Synergy processes and removes this machine&apos;s local Testnet workspace. Remote validators and remote chain data are not changed.</p>
            </div>
          </div>
          <label className="settings-shell-port-field">
            <span className="settings-shell-port-label">Type ERASE to confirm</span>
            <input value={confirmText} onChange={(event) => setConfirmText(event.target.value)} placeholder="ERASE" />
          </label>
          <div className="settings-shell-definition-actions">
            <SNRGButton variant="red" size="sm" disabled={!canEraseThisPlatform || confirmText !== 'ERASE' || eraseBusy} onClick={handleEraseLocalData}>
              {eraseBusy ? 'Erasing...' : eraseLabel}
            </SNRGButton>
          </div>
        </details>
      </div>

      {confirmDeveloperOpen ? (
        <div className="nodedetail-modal-backdrop" onClick={() => setConfirmDeveloperOpen(false)}>
          <div className="nodedetail-modal" onClick={(event) => event.stopPropagation()}>
            <h3>Enable Developer View?</h3>
            <p className="nodedetail-modal-body">
              Developer View exposes raw diagnostics, configuration, and advanced node operations. Use it only if you understand the controls.
            </p>
            <div className="nodedetail-modal-actions">
              <SNRGButton variant="blue" size="sm" onClick={() => setConfirmDeveloperOpen(false)}>Cancel</SNRGButton>
              <SNRGButton
                variant="purple"
                size="sm"
                onClick={() => {
                  setDeveloperModeEnabled(true);
                  setConfirmDeveloperOpen(false);
                }}
              >
                Enable Developer View
              </SNRGButton>
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}

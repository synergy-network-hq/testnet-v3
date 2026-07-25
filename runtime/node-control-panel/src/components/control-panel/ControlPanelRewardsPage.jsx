import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { showSaveDialog, invoke, writeTextFile } from '../../lib/desktopClient';
import { SNRGButton } from '../../styles/SNRGButton';
import { useControlPanel } from './ControlPanelProvider';
import {
  formatNumber,
  formatPercent,
  formatTimestamp,
  nodeRuntimeLabel,
  safeArray,
  statusTone,
} from './controlPanelModel';
import {
  ActivityFeed,
  EmptyPanel,
  JarvisCard,
  MetricBars,
  MetricCard,
  PanelCard,
  SectionHeader,
} from './ControlPanelShared';
import JsonInspectorPanel from './JsonInspectorPanel';
import RewardsTrendChart from './charts/RewardsTrendChart';

function readObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function formatSnrg(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return '—';
  }
  return numeric.toLocaleString(undefined, {
    minimumFractionDigits: numeric > 0 && numeric < 100 ? 2 : 0,
    maximumFractionDigits: 2,
  });
}

const CONNECTED_WALLET_STORAGE_KEY = 'synergy:testnet:connected-wallet:v1';

function readConnectedWalletAddress() {
  if (typeof window === 'undefined') {
    return '';
  }
  try {
    return window.localStorage.getItem(CONNECTED_WALLET_STORAGE_KEY) || '';
  } catch {
    return '';
  }
}

function writeConnectedWalletAddress(address) {
  if (typeof window === 'undefined') {
    return;
  }
  try {
    if (address) {
      window.localStorage.setItem(CONNECTED_WALLET_STORAGE_KEY, address);
    } else {
      window.localStorage.removeItem(CONNECTED_WALLET_STORAGE_KEY);
    }
  } catch {
    // Wallet persistence is optional.
  }
}

function parseSnrgAmount(value) {
  const normalized = String(value || '').trim();
  if (!/^\d+$/.test(normalized)) {
    throw new Error('Enter a whole-number SNRG amount.');
  }
  const amount = Number(normalized);
  if (!Number.isSafeInteger(amount) || amount <= 0) {
    throw new Error('Enter a positive whole-number SNRG amount.');
  }
  return amount;
}

function isValidatorNode(node) {
  const role = String(node?.role_id || node?.role || node?.roleId || '').toLowerCase();
  return role.includes('validator');
}

function truncateMiddle(value, left = 10, right = 8) {
  const text = String(value || '');
  if (text.length <= left + right + 3) {
    return text || 'None';
  }
  return `${text.slice(0, left)}...${text.slice(-right)}`;
}

function formatPercentValue(value, digits = 2) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return '—';
  }
  return `${numeric.toFixed(digits)}%`;
}

function formatRewardTime(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return 'Unknown';
  }
  return new Date(numeric * 1000).toLocaleString();
}

function normalizeRewardsPayload(payload) {
  const root = readObject(payload);
  const live = readObject(root.live);
  const telemetry = readObject(root.telemetry);
  const genesis = readObject(root.genesis);

  if (root.live) {
    return {
      loaded: root.loaded !== false,
      root,
      live,
      telemetry,
      genesis,
      rewardHistory: safeArray(live.reward_history),
      pendingRewardsSnrg: live.pending_rewards_snrg,
      totalEarnedSnrg: live.historical_earned_snrg,
      stakedBalanceSnrg: live.staked_balance_snrg,
      walletBalanceSnrg: live.wallet_balance_snrg,
      currentTotalPositionSnrg: live.current_total_position_snrg,
      netPositionDeltaSnrg: live.net_position_delta_snrg,
      estimatedApy: live.estimated_apy,
      commissionRate: live.commission_rate,
      stakingEntryCount: live.staking_entry_count,
      synergyMultiplier: live.synergy_multiplier,
      synergyBreakdown: readObject(live.synergy_breakdown),
      synergyComponents: readObject(live.synergy_components),
      tokenSymbol: root.token_symbol || 'SNRG',
    };
  }

  return {
    loaded: true,
    root,
    live: root,
    telemetry,
    genesis,
    rewardHistory: safeArray(root.reward_history),
    pendingRewardsSnrg: root.pending_rewards,
    totalEarnedSnrg: root.total_earned,
    stakedBalanceSnrg: root.staked_amount,
    walletBalanceSnrg: null,
    currentTotalPositionSnrg: null,
    netPositionDeltaSnrg: null,
    estimatedApy: root.estimated_apy,
    commissionRate: root.commission_rate,
    stakingEntryCount: null,
    synergyMultiplier: null,
    synergyBreakdown: {},
    synergyComponents: {},
    tokenSymbol: 'SNRG',
  };
}

function buildRewardSeries(history, spanDays) {
  const now = Date.now();
  const cutoff = now - (spanDays * 24 * 60 * 60 * 1000);
  const buckets = new Map();

  safeArray(history).forEach((entry) => {
    const at = Number(entry?.timestamp || 0) * 1000;
    if (!Number.isFinite(at) || at < cutoff) {
      return;
    }
    const bucketAt = Math.floor(at / (24 * 60 * 60 * 1000)) * (24 * 60 * 60 * 1000);
    const current = buckets.get(bucketAt) || {
      id: `reward-${bucketAt}`,
      at: bucketAt,
      value: 0,
    };
    current.value += Number(entry?.amount_snrg ?? entry?.amount ?? 0) || 0;
    buckets.set(bucketAt, current);
  });

  if (!buckets.size) {
    return [];
  }

  return Array.from(buckets.values()).sort((left, right) => left.at - right.at);
}

function participationState(selectedNodeLive) {
  if (!selectedNodeLive?.is_running) {
    return {
      label: 'Offline',
      detail: 'Rewards will stay empty while the runtime is stopped.',
      tone: 'bad',
    };
  }
  if (selectedNodeLive?.local_rpc_ready === false) {
    return {
      label: 'Starting',
      detail: 'The node is still bringing up its local runtime services.',
      tone: 'warn',
    };
  }
  if ((Number(selectedNodeLive?.sync_gap) || 0) > 2) {
    return {
      label: 'Catching up',
      detail: 'Rewards can lag while the validator is still syncing toward the live head.',
      tone: 'warn',
    };
  }
  return {
    label: 'Participating',
    detail: 'The runtime is online and close enough to the head to earn normally.',
    tone: 'good',
  };
}

function buildRewardEvents(history) {
  return safeArray(history)
    .slice()
    .sort((left, right) => Number(right?.timestamp || 0) - Number(left?.timestamp || 0))
    .slice(0, 12)
    .map((entry, index) => ({
      id: `${entry?.timestamp || 'reward'}-${entry?.block_number || index}`,
      title: `${entry?.reward_type || 'Validator reward'} +${formatSnrg(entry?.amount_snrg ?? entry?.amount)} SNRG`,
      detail: entry?.block_number ? `Recorded at block ${formatNumber(entry.block_number)}.` : 'Reward event returned by the control service.',
      time: formatRewardTime(entry?.timestamp),
      tone: 'good',
    }));
}

function buildCorrelationBars(payload, selectedNodeLive) {
  const live = payload.live;
  const participation = participationState(selectedNodeLive);
  return [
    {
      id: 'uptime',
      label: 'Rewards vs uptime',
      value: selectedNodeLive?.process_uptime_secs ? `${Math.round(Number(selectedNodeLive.process_uptime_secs) / 3600)}h` : 'Low',
      detail: 'Longer healthy runtimes reduce missed participation windows.',
      numericValue: Number(selectedNodeLive?.process_uptime_secs || 0) / 3600,
      tone: selectedNodeLive?.is_running ? 'good' : 'bad',
    },
    {
      id: 'participation',
      label: 'Rewards vs participation',
      value: participation.label,
      detail: participation.detail,
      numericValue: participation.tone === 'good' ? 100 : participation.tone === 'warn' ? 60 : 10,
      tone: participation.tone,
    },
    {
      id: 'peers',
      label: 'Rewards vs peer health',
      value: `${formatNumber(selectedNodeLive?.local_peer_count || 0)} peers`,
      detail: 'A visible peer set improves the odds of steady participation.',
      numericValue: Number(selectedNodeLive?.local_peer_count || 0),
      tone: Number(selectedNodeLive?.local_peer_count || 0) > 0 ? 'cyan' : 'bad',
    },
    {
      id: 'synergy',
      label: 'Rewards vs synergy score',
      value: payload.synergyMultiplier != null ? `${Number(payload.synergyMultiplier).toFixed(2)}x` : 'Pending',
      detail: 'The incentive multiplier only appears when the RPC surface exposes score detail.',
      numericValue: Number(payload.synergyMultiplier || 0),
      tone: payload.synergyMultiplier != null ? 'purple' : 'neutral',
    },
  ];
}

export default function ControlPanelRewardsPage() {
  const {
    error,
    recordAction,
    refresh,
    selectedNode,
    selectedNodeLive,
    viewMode,
  } = useControlPanel();

  const [rewardsData, setRewardsData] = useState(null);
  const [rewardsLoading, setRewardsLoading] = useState(false);
  const [rewardsError, setRewardsError] = useState('');
  const [exportBusy, setExportBusy] = useState(false);
  const [workflowNotice, setWorkflowNotice] = useState('');
  const [walletInput, setWalletInput] = useState(() => readConnectedWalletAddress());
  const [connectedWallet, setConnectedWallet] = useState(() => readConnectedWalletAddress());
  const [stakeAmountSnrg, setStakeAmountSnrg] = useState('50000');
  const [unstakeAmountSnrg, setUnstakeAmountSnrg] = useState('');
  const [withdrawAmountSnrg, setWithdrawAmountSnrg] = useState('');
  const [stakeBusy, setStakeBusy] = useState('');

  useEffect(() => {
    if (!selectedNode) {
      setRewardsData(null);
      setRewardsError('');
      setRewardsLoading(false);
      return undefined;
    }

    let cancelled = false;

    const loadRewards = async () => {
      if (!cancelled) {
        setRewardsLoading(true);
      }
      try {
        const nextRewards = await invoke('get_rewards_data', { nodeId: selectedNode.id });
        if (!cancelled) {
          setRewardsData(nextRewards || null);
          setRewardsError('');
        }
      } catch (loadError) {
        if (!cancelled) {
          setRewardsData(null);
          setRewardsError(String(loadError));
        }
      } finally {
        if (!cancelled) {
          setRewardsLoading(false);
        }
      }
    };

    void loadRewards();
    return () => {
      cancelled = true;
    };
  }, [selectedNode]);

  const payload = useMemo(
    () => normalizeRewardsPayload(rewardsData),
    [rewardsData],
  );
  const participation = useMemo(
    () => participationState(selectedNodeLive),
    [selectedNodeLive],
  );
  const rewardEvents = useMemo(
    () => buildRewardEvents(payload.rewardHistory),
    [payload.rewardHistory],
  );
  const sevenDaySeries = useMemo(
    () => buildRewardSeries(payload.rewardHistory, 7),
    [payload.rewardHistory],
  );
  const thirtyDaySeries = useMemo(
    () => buildRewardSeries(payload.rewardHistory, 30),
    [payload.rewardHistory],
  );
  const correlationBars = useMemo(
    () => buildCorrelationBars(payload, selectedNodeLive),
    [payload, selectedNodeLive],
  );

  const missingRewardNotes = [
    !selectedNodeLive?.is_running ? 'The node is not running right now.' : '',
    selectedNodeLive?.local_rpc_ready === false ? 'The node is still starting its local runtime services.' : '',
    (Number(selectedNodeLive?.sync_gap) || 0) > 2 ? 'The node is behind the live chain head, so rewards may lag until sync catches up.' : '',
    Number(selectedNodeLive?.local_peer_count || 0) <= 0 ? 'The node has no visible peers, which can block steady participation.' : '',
    ...safeArray(payload.telemetry.telemetry_gaps || []),
  ].filter(Boolean).slice(0, 6);

  const recentHistory = useMemo(
    () => safeArray(payload.rewardHistory)
      .slice()
      .sort((left, right) => Number(right?.timestamp || 0) - Number(left?.timestamp || 0))
      .slice(0, 10),
    [payload.rewardHistory],
  );

  const exportRawData = async () => {
    if (!selectedNode || exportBusy) {
      return;
    }
    setExportBusy(true);
    try {
      const defaultPath = await showSaveDialog({
        defaultPath: `${selectedNode.id || 'node'}-rewards-ledger.json`,
        filters: [{ name: 'JSON', extensions: ['json'] }],
      });
      if (!defaultPath) {
        return;
      }
      const snapshot = {
        exportedAt: new Date().toISOString(),
        nodeId: selectedNode.id,
        nodeLabel: selectedNode.display_label || selectedNode.role_display_name || selectedNode.id,
        rewards: rewardsData,
      };
      await writeTextFile(defaultPath, JSON.stringify(snapshot, null, 2));
      recordAction({
        title: 'Exported rewards data',
        detail: defaultPath,
        status: 'good',
        source: 'rewards-page',
      });
    } catch (exportError) {
      recordAction({
        title: 'Reward export failed',
        detail: String(exportError),
        status: 'bad',
        source: 'rewards-page',
      });
    } finally {
      setExportBusy(false);
    }
  };

  const connectWallet = async () => {
    const address = walletInput.trim();
    if (!address) {
      setConnectedWallet('');
      writeConnectedWalletAddress('');
      setWorkflowNotice('Connected wallet cleared.');
      return;
    }
    setConnectedWallet(address);
    writeConnectedWalletAddress(address);
    if (selectedNode && isValidatorNode(selectedNode)) {
      try {
        await invoke('testnet_set_validator_owner', {
          input: {
            nodeId: selectedNode.id,
            ownerWalletAddress: address,
          },
        });
        await invoke('testnet_publish_validator_profile_to_atlas', {
          input: { nodeId: selectedNode.id },
        }).catch(() => null);
        await refresh({ silent: true });
        setWorkflowNotice(`Connected wallet ${truncateMiddle(address)} and registered it as this validator's Atlas owner.`);
        return;
      } catch (ownerError) {
        setWorkflowNotice(String(ownerError));
        return;
      }
    }
    setWorkflowNotice(`Connected wallet ${truncateMiddle(address)}.`);
  };

  const copyDepositAddress = async () => {
    try {
      await navigator.clipboard.writeText(selectedNode.node_address || '');
      setWorkflowNotice('Deposit address copied.');
    } catch {
      setWorkflowNotice(`Deposit address: ${selectedNode.node_address || 'Not reported by node registry'}`);
    }
  };

  const runStakeWorkflow = async (kind) => {
    if (!selectedNode || stakeBusy) {
      return;
    }

    setStakeBusy(kind);
    try {
      let result = null;
      if (kind === 'stake') {
        const amountSnrg = parseSnrgAmount(stakeAmountSnrg);
        result = await invoke('testnet_stake_validator', {
          input: {
            nodeId: selectedNode.id,
            amountSnrg,
          },
        });
        const stakeStatus = String(result?.status || '').toLowerCase();
        if (
          isValidatorNode(selectedNode)
          && (stakeStatus === 'submitted' || stakeStatus === 'already-bonded' || stakeStatus === 'already_bonded')
        ) {
          const onboarding = await invoke('testnet_run_validator_onboarding', {
            input: {
              nodeId: selectedNode.id,
              dryRun: false,
              autoResyncTime: true,
              autoStart: true,
              autoStake: false,
              autoActivate: true,
            },
          });
          result = {
            ...result,
            onboarding,
          };
        }
      } else if (kind === 'unstake') {
        const amountSnrg = parseSnrgAmount(unstakeAmountSnrg);
        result = await invoke('testnet_unstake_validator', {
          input: {
            nodeId: selectedNode.id,
            amountSnrg,
          },
        });
      } else if (kind === 'withdraw') {
        const amountSnrg = parseSnrgAmount(withdrawAmountSnrg);
        if (!connectedWallet) {
          throw new Error('Connect a wallet before withdrawing.');
        }
        result = await invoke('testnet_transfer_validator_tokens', {
          input: {
            nodeId: selectedNode.id,
            destinationAddress: connectedWallet,
            amountSnrg,
          },
        });
      }

      const baseMessage = result?.message || `${kind} request submitted${result?.tx_hash ? `: ${result.tx_hash}` : ''}.`;
      const message = result?.onboarding?.message
        ? `${baseMessage} ${result.onboarding.message}`
        : baseMessage;
      setWorkflowNotice(message);
      recordAction({
        title: `${kind} rewards workflow`,
        detail: message,
        status: 'good',
        source: 'rewards-page',
        command: kind,
      });
      await refresh({ silent: true });
    } catch (workflowError) {
      const detail = String(workflowError);
      setWorkflowNotice(detail);
      recordAction({
        title: `${kind} rewards workflow failed`,
        detail,
        status: 'bad',
        source: 'rewards-page',
        command: kind,
      });
    } finally {
      setStakeBusy('');
    }
  };

  if (!selectedNode) {
    return (
      <EmptyPanel
        title="No node selected for earnings"
        copy="Select or provision a node to inspect reward flow and validator economics."
        actionLabel="Refresh"
        onAction={() => void refresh()}
      />
    );
  }

  return (
    <div className="cp-page-stack">
      <SectionHeader
        eyebrow={viewMode === 'basic' ? 'Rewards View' : viewMode === 'advanced' ? 'Operator Economics' : 'Proof Surface'}
        title={viewMode === 'basic' ? 'Rewards + Stake' : viewMode === 'advanced' ? 'Rewards + Stake' : 'Rewards + Ledger'}
        copy={viewMode === 'basic'
          ? 'Track wallet, stake, rewards, and the simple conditions that affect earnings.'
          : viewMode === 'advanced'
            ? 'Inspect validator wallet, stake, reward flow, fetch diagnostics, and recent payout history.'
            : 'Expose the reward and accounting pipeline with enough raw context to prove what is happening.'}
        actions={(
          <>
            <SNRGButton variant="blue" size="sm" onClick={() => void refresh()}>
              Refresh State
            </SNRGButton>
            <SNRGButton as={Link} to={`/node/${selectedNode.id}`} variant="blue" size="sm">
              Node Details
            </SNRGButton>
            <SNRGButton variant="purple" size="sm" onClick={() => void exportRawData()} disabled={exportBusy}>
              {exportBusy ? 'Exporting…' : 'Export Raw Data'}
            </SNRGButton>
          </>
        )}
      />

      {(rewardsError || error) ? (
        <div className={`cp-inline-notice tone-${statusTone(rewardsError || error)}`}>
          {rewardsError || error}
        </div>
      ) : null}

      {workflowNotice ? (
        <div className={`cp-inline-notice tone-${statusTone(workflowNotice)}`}>
          {workflowNotice}
        </div>
      ) : null}

      <PanelCard
        title={viewMode === 'developer' ? 'Wallet + Stake workflow' : 'Wallet + Stake'}
        detail="Connect the payout wallet, copy the validator deposit address, and manage validator economics from this screen."
        action={<SNRGButton variant="blue" size="sm" onClick={() => void connectWallet()}>{connectedWallet ? 'Update Wallet' : 'Connect Wallet'}</SNRGButton>}
      >
        <div className="cp-metric-grid cp-metric-grid-dashboard">
          <MetricCard label="Wallet balance" value={`${formatSnrg(payload.walletBalanceSnrg)} ${payload.tokenSymbol}`} detail={connectedWallet ? truncateMiddle(connectedWallet) : 'No wallet connected'} tone="cyan" icon="wallet" />
          <MetricCard label="Bonded stake" value={`${formatSnrg(payload.stakedBalanceSnrg)} ${payload.tokenSymbol}`} detail={participation.detail} tone={Number(payload.stakedBalanceSnrg) >= 50000 ? 'good' : 'warn'} icon="account_balance" />
          <MetricCard label="Pending rewards" value={`${formatSnrg(payload.pendingRewardsSnrg)} ${payload.tokenSymbol}`} detail="Claim and payout state" tone={Number(payload.pendingRewardsSnrg || 0) > 0 ? 'warn' : 'neutral'} icon="schedule" />
        </div>
        <div className="cp-wallet-control-grid">
          <label className="cp-form-field">
            <span>Wallet address</span>
            <input value={walletInput} onChange={(event) => setWalletInput(event.target.value)} placeholder="syns..." />
          </label>
          <SNRGButton variant="lime" size="sm" onClick={copyDepositAddress}>Copy Deposit Address</SNRGButton>
          <label className="cp-form-field">
            <span>Stake SNRG</span>
            <input value={stakeAmountSnrg} onChange={(event) => setStakeAmountSnrg(event.target.value)} inputMode="numeric" />
          </label>
          <SNRGButton variant="purple" size="sm" disabled={stakeBusy === 'stake'} onClick={() => void runStakeWorkflow('stake')}>
            {stakeBusy === 'stake' ? 'Staking...' : 'Stake'}
          </SNRGButton>
          <label className="cp-form-field">
            <span>Unstake SNRG</span>
            <input value={unstakeAmountSnrg} onChange={(event) => setUnstakeAmountSnrg(event.target.value)} inputMode="numeric" />
          </label>
          <SNRGButton variant="red" size="sm" disabled={stakeBusy === 'unstake'} onClick={() => void runStakeWorkflow('unstake')}>
            {stakeBusy === 'unstake' ? 'Unstaking...' : 'Unstake'}
          </SNRGButton>
          <label className="cp-form-field">
            <span>Withdraw SNRG</span>
            <input value={withdrawAmountSnrg} onChange={(event) => setWithdrawAmountSnrg(event.target.value)} inputMode="numeric" />
          </label>
          <SNRGButton variant="blue" size="sm" disabled={!connectedWallet || stakeBusy === 'withdraw'} onClick={() => void runStakeWorkflow('withdraw')}>
            {stakeBusy === 'withdraw' ? 'Withdrawing...' : 'Withdraw'}
          </SNRGButton>
        </div>
      </PanelCard>

      {viewMode === 'basic' ? (
        <div className="cp-dashboard-grid">
          <div className="cp-dashboard-main">
            <PanelCard title="Earnings at a glance" detail={rewardsLoading ? 'Refreshing reward totals…' : 'Today, this week, and what is still pending.'}>
              <div className="cp-metric-grid cp-metric-grid-dashboard">
                <MetricCard label="Latest day" value={`${formatSnrg(sevenDaySeries.at(-1)?.value || 0)} ${payload.tokenSymbol}`} detail="Most recent reward bucket returned by RPC" tone="good" icon="savings" />
                <MetricCard label="Total returned" value={`${formatSnrg(payload.totalEarnedSnrg)} ${payload.tokenSymbol}`} detail="Historical rewards returned by RPC" tone="cyan" icon="calendar_month" />
                <MetricCard label="Pending" value={`${formatSnrg(payload.pendingRewardsSnrg)} ${payload.tokenSymbol}`} detail="Waiting to settle or become claimable" tone={Number(payload.pendingRewardsSnrg || 0) > 0 ? 'warn' : 'neutral'} icon="schedule" />
              </div>
            </PanelCard>

            <RewardsTrendChart
              title="Simple earnings trend"
              detail="A compact 7-day vs 30-day picture of reward activity."
              shortWindow={sevenDaySeries}
              longWindow={thirtyDaySeries}
              shortLabel="7d"
              longLabel="30d"
            />

            <PanelCard title="Why rewards may be missing" detail="Basic mode keeps this explanation plain and direct.">
              <div className="cp-checklist">
                {(missingRewardNotes.length ? missingRewardNotes : [
                  'This node is online and close enough to the chain head to earn normally.',
                ]).map((note) => (
                  <div key={note} className="cp-checklist-item">
                    <strong>{note}</strong>
                    <small>Open My Node or Logs if you need more detail.</small>
                  </div>
                ))}
              </div>
            </PanelCard>

            <ActivityFeed
              title="Recent reward events"
              detail={rewardEvents.length ? 'Latest reward events returned by the control service.' : 'The control service reported zero reward events.'}
              items={rewardEvents.slice(0, 6)}
              emptyMessage="Reward history will populate after the node participates in blocks."
            />
          </div>

          <div className="cp-dashboard-side">
            <JarvisCard
              mode="basic"
              title="Plain-language summary"
              message={Number(payload.totalEarnedSnrg || 0) > 0
                ? `This node has reported ${formatSnrg(payload.totalEarnedSnrg)} ${payload.tokenSymbol} in historical rewards so far. ${participation.detail}`
                : `This page keeps the reward story simple: whether the node is participating and what usually blocks earnings. ${participation.detail}`}
              chips={[
                participation.label,
                `${formatSnrg(payload.pendingRewardsSnrg)} pending`,
                rewardsLoading ? 'Updating' : 'Current',
              ]}
            />

            <PanelCard title="Expected conditions" detail="Three simple requirements for normal earnings.">
              <div className="cp-checklist">
                <div className="cp-checklist-item">
                  <strong>Node online</strong>
                  <small>{nodeRuntimeLabel(selectedNodeLive)}</small>
                </div>
                <div className="cp-checklist-item">
                  <strong>Connected</strong>
                  <small>{Number(selectedNodeLive?.local_peer_count || 0)} visible peers.</small>
                </div>
                <div className="cp-checklist-item">
                  <strong>Participating</strong>
                  <small>{participation.detail}</small>
                </div>
              </div>
            </PanelCard>

            <PanelCard title="What to do if earnings are empty" detail="Use guided next steps before you escalate.">
              <div className="cp-button-grid">
                <SNRGButton as={Link} to={`/node/${selectedNode.id}`} variant="blue" size="sm">
                  Check My Node
                </SNRGButton>
                <SNRGButton as={Link} to="/logs" variant="purple" size="sm">
                  Open Activity
                </SNRGButton>
              </div>
            </PanelCard>
          </div>
        </div>
      ) : null}

      {viewMode === 'advanced' ? (
        <div className="cp-dashboard-grid">
          <div className="cp-dashboard-main">
            <div className="cp-metric-grid cp-metric-grid-dashboard">
              <MetricCard label="Total" value={`${formatSnrg(payload.totalEarnedSnrg)} ${payload.tokenSymbol}`} detail="Historical rewards earned" tone="good" icon="savings" />
              <MetricCard label="Pending" value={`${formatSnrg(payload.pendingRewardsSnrg)} ${payload.tokenSymbol}`} detail="Pending or unsettled rewards" tone="warn" icon="schedule" />
              <MetricCard label="Claimable" value={Number(payload.pendingRewardsSnrg || 0) > 0 ? `${formatSnrg(payload.pendingRewardsSnrg)} ${payload.tokenSymbol}` : 'None'} detail="Claimable once settlement is available" tone="cyan" icon="account_balance_wallet" />
              <MetricCard label="Participation" value={participation.label} detail={participation.detail} tone={participation.tone} icon="hub" />
            </div>

            <RewardsTrendChart
              title="Historical earnings chart"
              detail="Compare the near-term reward curve against the wider monthly window."
              shortWindow={sevenDaySeries}
              longWindow={thirtyDaySeries}
              shortLabel="Daily"
              longLabel="Monthly"
            />

            <PanelCard title="Breakdown panel" detail="Operator-level context around stake, multiplier, and position.">
              <div className="cp-definition-list">
                <div className="cp-definition-item">
                  <span>Bonded stake</span>
                  <strong>{formatSnrg(payload.stakedBalanceSnrg)} {payload.tokenSymbol}</strong>
                </div>
                <div className="cp-definition-item">
                  <span>Wallet balance</span>
                  <strong>{formatSnrg(payload.walletBalanceSnrg)} {payload.tokenSymbol}</strong>
                </div>
                <div className="cp-definition-item">
                  <span>Current total position</span>
                  <strong>{formatSnrg(payload.currentTotalPositionSnrg)} {payload.tokenSymbol}</strong>
                </div>
                <div className="cp-definition-item">
                  <span>Synergy multiplier</span>
                  <strong>{payload.synergyMultiplier != null ? `${Number(payload.synergyMultiplier).toFixed(2)}x` : 'Pending'}</strong>
                </div>
                <div className="cp-definition-item">
                  <span>Net vs genesis</span>
                  <strong>{payload.netPositionDeltaSnrg != null ? `${payload.netPositionDeltaSnrg >= 0 ? '+' : ''}${formatSnrg(payload.netPositionDeltaSnrg)} ${payload.tokenSymbol}` : 'Not reported'}</strong>
                </div>
              </div>
            </PanelCard>

            <PanelCard title="Reward fetch diagnostics" detail="Shows whether the current RPC surface is exposing the right economics data.">
              <div className="cp-definition-list">
                <div className="cp-definition-item">
                  <span>Last refresh</span>
                  <strong>{rewardsLoading ? 'Refreshing now' : 'Loaded in this session'}</strong>
                </div>
                <div className="cp-definition-item">
                  <span>Wallet balance RPC</span>
                  <strong>{payload.telemetry.token_balance_available === false ? 'Missing' : 'Available'}</strong>
                </div>
                <div className="cp-definition-item">
                  <span>Staking info RPC</span>
                  <strong>{payload.telemetry.staking_info_available === false ? 'Missing' : 'Available'}</strong>
                </div>
                <div className="cp-definition-item">
                  <span>Source</span>
                  <strong>{selectedNode.display_label || selectedNode.id}</strong>
                </div>
              </div>
              {safeArray(payload.telemetry.telemetry_gaps).length ? (
                <div className="cp-panel-inline-note">
                  {safeArray(payload.telemetry.telemetry_gaps).slice(0, 2).join(' ')}
                </div>
              ) : null}
            </PanelCard>

            <PanelCard title="Recent reward events table" detail="Recent reward activity with timestamps and block numbers.">
              <div className="cp-reward-table">
                <div className="cp-reward-table-head">
                  <span>Time</span>
                  <span>Type</span>
                  <span>Amount</span>
                  <span>Block</span>
                </div>
                {recentHistory.length ? recentHistory.map((entry, index) => (
                  <div key={`${entry?.timestamp || 'reward'}-${index}`} className="cp-reward-table-row">
                    <span>{formatRewardTime(entry?.timestamp)}</span>
                    <span>{entry?.reward_type || 'validator reward'}</span>
                    <strong>+{formatSnrg(entry?.amount_snrg ?? entry?.amount)} {payload.tokenSymbol}</strong>
                    <span>#{formatNumber(entry?.block_number)}</span>
                  </div>
                )) : (
                  <div className="cp-empty-inline">The control service reported zero reward events for this node.</div>
                )}
              </div>
            </PanelCard>
          </div>

          <div className="cp-dashboard-side">
            <JarvisCard
              mode="advanced"
              title="Economics summary"
              message={`Historical rewards: ${formatSnrg(payload.totalEarnedSnrg)} ${payload.tokenSymbol}. Pending: ${formatSnrg(payload.pendingRewardsSnrg)} ${payload.tokenSymbol}. ${participation.detail}`}
              chips={[
                formatPercentValue(payload.estimatedApy),
                formatPercentValue(payload.commissionRate),
                `${formatNumber(payload.stakingEntryCount || 0)} entries`,
              ]}
            />

            <PanelCard title="Pending / claim state" detail="Fast operator view of whether settlement is accumulating.">
              <div className="cp-definition-list">
                <div className="cp-definition-item">
                  <span>Pending rewards</span>
                  <strong>{formatSnrg(payload.pendingRewardsSnrg)} {payload.tokenSymbol}</strong>
                </div>
                <div className="cp-definition-item">
                  <span>Estimated APY</span>
                  <strong>{formatPercentValue(payload.estimatedApy)}</strong>
                </div>
                <div className="cp-definition-item">
                  <span>Commission</span>
                  <strong>{formatPercentValue(payload.commissionRate)}</strong>
                </div>
              </div>
            </PanelCard>

            <PanelCard title="Open detailed ledger / export" detail="Take the raw payload with you when you need to prove the economics state.">
              <div className="cp-button-grid">
                <SNRGButton variant="purple" size="sm" onClick={() => void exportRawData()} disabled={exportBusy}>
                  {exportBusy ? 'Exporting…' : 'Export Raw Data'}
                </SNRGButton>
                <SNRGButton as={Link} to="/logs" variant="blue" size="sm">
                  Open Logs
                </SNRGButton>
              </div>
            </PanelCard>
          </div>
        </div>
      ) : null}

      {viewMode === 'developer' ? (
        <div className="cp-dashboard-grid">
          <div className="cp-dashboard-main">
            <div className="cp-metric-grid cp-metric-grid-dashboard">
              <MetricCard label="Historical earned" value={`${formatSnrg(payload.totalEarnedSnrg)} ${payload.tokenSymbol}`} detail="Historical rewards" tone="good" icon="savings" />
              <MetricCard label="Pending rewards" value={`${formatSnrg(payload.pendingRewardsSnrg)} ${payload.tokenSymbol}`} detail="Unsettled or claimable" tone="warn" icon="schedule" />
              <MetricCard label="Bonded stake" value={`${formatSnrg(payload.stakedBalanceSnrg)} ${payload.tokenSymbol}`} detail="Current stake base" tone="cyan" icon="account_balance" />
              <MetricCard label="Wallet balance" value={`${formatSnrg(payload.walletBalanceSnrg)} ${payload.tokenSymbol}`} detail="Live liquid balance" tone="blue" icon="wallet" />
              <MetricCard label="Synergy multiplier" value={payload.synergyMultiplier != null ? `${Number(payload.synergyMultiplier).toFixed(2)}x` : 'Pending'} detail="Reward weighting multiplier" tone="purple" icon="auto_graph" />
              <MetricCard label="Pipeline" value={safeArray(payload.telemetry.telemetry_gaps).length ? 'Degraded' : 'Healthy'} detail="RPC visibility across reward inputs" tone={safeArray(payload.telemetry.telemetry_gaps).length ? 'warn' : 'good'} icon="lan" />
            </div>

            <RewardsTrendChart
              title="Historical chart set: earnings"
              detail="Near-term earnings versus the wider monthly history."
              shortWindow={sevenDaySeries}
              longWindow={thirtyDaySeries}
              shortLabel="7d"
              longLabel="30d"
            />

            <PanelCard title="Ledger / event table" detail="Rawer reward event context for operators and developers.">
              <div className="cp-reward-table cp-reward-table-developer">
                <div className="cp-reward-table-head">
                  <span>Record</span>
                  <span>Timestamp</span>
                  <span>Type</span>
                  <span>Amount</span>
                  <span>Block</span>
                </div>
                {recentHistory.length ? recentHistory.map((entry, index) => (
                  <div key={`${entry?.timestamp || 'reward'}-${index}`} className="cp-reward-table-row">
                    <span>{`${selectedNode.id}-${entry?.block_number || index}`}</span>
                    <span>{formatRewardTime(entry?.timestamp)}</span>
                    <span>{entry?.reward_type || 'validator reward'}</span>
                    <strong>+{formatSnrg(entry?.amount_snrg ?? entry?.amount)} {payload.tokenSymbol}</strong>
                    <span>#{formatNumber(entry?.block_number)}</span>
                  </div>
                )) : (
                  <div className="cp-empty-inline">No reward ledger rows are available yet.</div>
                )}
              </div>
            </PanelCard>

            <PanelCard title="Fetch and parser diagnostics" detail="Raw telemetry gaps and payload availability.">
              <div className="cp-definition-list">
                <div className="cp-definition-item">
                  <span>Token balance RPC</span>
                  <strong>{payload.telemetry.token_balance_available === false ? 'Not reported' : 'Available'}</strong>
                </div>
                <div className="cp-definition-item">
                  <span>Staking info RPC</span>
                  <strong>{payload.telemetry.staking_info_available === false ? 'Not reported' : 'Available'}</strong>
                </div>
                <div className="cp-definition-item">
                  <span>Staked balance RPC</span>
                  <strong>{payload.telemetry.staked_balance_available === false ? 'Derived from staking entries' : 'Available'}</strong>
                </div>
                <div className="cp-definition-item">
                  <span>Synergy breakdown RPC</span>
                  <strong>{payload.telemetry.synergy_breakdown_available === false ? 'Not reported' : 'Available'}</strong>
                </div>
              </div>
              {safeArray(payload.telemetry.telemetry_gaps).length ? (
                <div className="cp-checklist">
                  {safeArray(payload.telemetry.telemetry_gaps).map((gap) => (
                    <div key={gap} className="cp-checklist-item">
                      <strong>{gap}</strong>
                      <small>The raw payload inspector on the right keeps the original response visible.</small>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="cp-empty-inline">No telemetry gaps were reported in the current reward payload.</div>
              )}
            </PanelCard>

            <MetricBars
              title="Correlation widgets"
              detail="Correlate rewards with runtime uptime, participation, peer health, and incentive weighting."
              items={correlationBars}
            />
          </div>

          <div className="cp-dashboard-side">
            <PanelCard title="Raw reward source / payload inspector" detail="The unmodified reward payload returned by the control service.">
              <JsonInspectorPanel title="Reward payload" value={rewardsData} emptyMessage="No reward payload loaded yet." />
            </PanelCard>

            <PanelCard title="Reward pipeline status" detail="Quick proof of current economics visibility.">
              <div className="cp-definition-list">
                <div className="cp-definition-item">
                  <span>Current total position</span>
                  <strong>{formatSnrg(payload.currentTotalPositionSnrg)} {payload.tokenSymbol}</strong>
                </div>
                <div className="cp-definition-item">
                  <span>Net vs genesis</span>
                  <strong>{payload.netPositionDeltaSnrg != null ? `${payload.netPositionDeltaSnrg >= 0 ? '+' : ''}${formatSnrg(payload.netPositionDeltaSnrg)} ${payload.tokenSymbol}` : 'Not reported'}</strong>
                </div>
                <div className="cp-definition-item">
                  <span>Rank</span>
                  <strong>{payload.synergyBreakdown.rank != null ? formatNumber(payload.synergyBreakdown.rank) : 'Not reported'}</strong>
                </div>
                <div className="cp-definition-item">
                  <span>Percentile</span>
                  <strong>{payload.synergyBreakdown.percentile != null ? formatPercent(payload.synergyBreakdown.percentile, 1) : 'Not reported'}</strong>
                </div>
              </div>
            </PanelCard>

            <PanelCard title="Export raw data" detail="Preserve the exact reward payload and node context.">
              <div className="cp-button-grid">
                <SNRGButton variant="purple" size="sm" onClick={() => void exportRawData()} disabled={exportBusy}>
                  {exportBusy ? 'Exporting…' : 'Export Snapshot'}
                </SNRGButton>
                <SNRGButton as={Link} to="/logs" variant="blue" size="sm">
                  Cross-check With Logs
                </SNRGButton>
              </div>
            </PanelCard>

            <JarvisCard
              mode="developer"
              title="Developer notes"
              message={`This node reports ${formatSnrg(payload.totalEarnedSnrg)} ${payload.tokenSymbol} in historical rewards, ${formatSnrg(payload.pendingRewardsSnrg)} pending, and a runtime state of ${nodeRuntimeLabel(selectedNodeLive)}. Use the payload inspector and dock when you need to prove where the economics surface is drifting.`}
              chips={[
                formatPercentValue(payload.estimatedApy),
                `${formatNumber(payload.stakingEntryCount || 0)} staking entries`,
                formatTimestamp(new Date().toISOString()),
              ]}
            />
          </div>
        </div>
      ) : null}
    </div>
  );
}

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  CheckCircle2,
  Copy,
  Link2,
  RefreshCw,
  ShieldCheck,
  Unplug,
  Wallet,
} from 'lucide-react';
import WalletModal from '../../wallet-connection/components/wallet/WalletModal';
import {
  createWalletActionRequest,
  createWalletPairingSession,
  getWalletPairingConfig,
  pollWalletActionRequest,
  pollWalletPairingSession,
  qrToDataUrl,
  SYNERGY_TESTNET,
} from '../../wallet-connection/services/synergy-wallet';
import { synergyOnlyWalletConnectionConfig } from './synergyOnlyWalletConnectionConfig';
import { truncateMiddle } from '../control-panel/controlPanelModel';
import { desktopFetchJson } from '../../lib/desktopClient';
import {
  clearPersistedWalletSession,
  persistWalletSession as persistStoredWalletSession,
  readPersistedWalletSession,
  withWalletNetworkDefaults,
} from './walletSessionPersistence';

const CONTROL_PANEL_PAIRING_ORIGIN = 'https://nodes.synergy-network.io';
const CONTROL_PANEL_PAIRING_ROUTE = 'https://nodes.synergy-network.io/control-panel';
const CONTROL_PANEL_PAIRING_ICON_URL = 'https://nodes.synergy-network.io/control-panel-icon.png';
const CONTROL_PANEL_PAIRING_ENV = {
  ...import.meta.env,
  VITE_RELAY_WALLET_PAIRING_RELAY_URL:
    import.meta.env?.VITE_RELAY_WALLET_PAIRING_RELAY_URL ||
    import.meta.env?.VITE_SYNERGY_WALLET_PAIRING_RELAY_URL ||
    'https://relay.synergy-network.io/api/wallet-pairing',
};

function controlPanelPairingConfig() {
  return getWalletPairingConfig(CONTROL_PANEL_PAIRING_ENV);
}

function browserStorage(name) {
  if (typeof window === 'undefined') return null;
  try {
    return window[name] || null;
  } catch {
    return null;
  }
}

function readStoredWalletSession() {
  if (typeof window === 'undefined') return null;
  const stored = readPersistedWalletSession({
    storage: browserStorage('localStorage'),
    legacyStorage: browserStorage('sessionStorage'),
  });
  if (!stored) return null;
  try {
    const { session, wallet } = stored;
    return {
      wallet: {
        address: wallet.address,
        chainId: wallet.chainId ?? SYNERGY_TESTNET.chainIdDecimal,
        chainIdHex: wallet.chainIdHex ?? SYNERGY_TESTNET.chainIdHex,
        synId: wallet.synId || null,
        walletType: 'synergy',
        networkName: SYNERGY_TESTNET.displayName,
        source: 'mobile-pairing',
        canSign: true,
        provider: null,
      },
      session: {
        sessionId: session.sessionId,
        nonce: session.nonce || session.sessionId,
        pollUrl: session.pollUrl,
        relayUrl: session.relayUrl,
        expiresAt: session.expiresAt || null,
      },
    };
  } catch {
    return null;
  }
}

function persistWalletSession(wallet, session) {
  if (typeof window === 'undefined') return;
  persistStoredWalletSession({
    storage: browserStorage('localStorage') || browserStorage('sessionStorage'),
    wallet: withWalletNetworkDefaults(wallet, {
      chainId: SYNERGY_TESTNET.chainIdDecimal,
      chainIdHex: SYNERGY_TESTNET.chainIdHex,
    }),
    session,
  });
}

function clearStoredWalletSession() {
  if (typeof window === 'undefined') return;
  clearPersistedWalletSession({ storage: browserStorage('localStorage'), legacyStorage: browserStorage('sessionStorage') });
}

function providerStatusText(providerAvailable, status) {
  if (status === 'connected') return 'Synergy wallet connected';
  if (status === 'connecting') return 'Waiting for mobile approval';
  if (status === 'unavailable') return 'Mobile pairing unavailable';
  if (providerAvailable) return 'Mobile pairing ready';
  return 'Scan with Synergy Wallet mobile';
}

function sleep(ms) {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

function controlPanelPairingErrorMessage(error, fallback = 'Unable to start mobile Synergy Wallet pairing.') {
  const raw = typeof error === 'string' ? error : error?.message;
  if (!raw) return fallback;
  if (/origin is not allowed/i.test(raw) || /relay wallet pairing/i.test(raw)) {
    return 'Mobile Synergy Wallet pairing is not available from this app origin. Generate a new code and try again.';
  }
  return raw
    .replace(/\bRelay wallet pairing\b/gi, 'mobile Synergy Wallet pairing')
    .replace(/\bRelay requires\b/g, 'Synergy Testnet requires');
}

async function controlPanelPairingFetch(url, options = {}) {
  const desktopResult = await desktopFetchJson(url, options);
  if (!desktopResult) {
    return fetch(url, options);
  }
  return {
    ok: desktopResult.ok,
    status: desktopResult.status,
    statusText: desktopResult.statusText,
    json: async () => desktopResult.body || {},
  };
}

export default function SynergyWalletConnection({ onWalletChange, compact = false }) {
  const [storedSession] = useState(readStoredWalletSession);
  const [providerAvailable, setProviderAvailable] = useState(true);
  const [wallet, setWallet] = useState(() => storedSession?.wallet || null);
  const [status, setStatus] = useState(() => (storedSession ? 'connected' : 'disconnected'));
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [pairing, setPairing] = useState(() => ({
    config: controlPanelPairingConfig(),
    status: storedSession ? 'approved' : 'idle',
    message: storedSession ? 'Restored the approved Synergy Wallet connection for this control panel session.' : '',
    session: storedSession?.session || null,
    qrImage: null,
    deepLink: null,
    expiresAt: null,
  }));

  const applyMobileWallet = useCallback((connected) => {
    const normalized = {
      ...connected,
      provider: null,
      walletType: 'synergy',
      networkName: SYNERGY_TESTNET.displayName,
      source: 'mobile-pairing',
      canSign: true,
    };
    setWallet(normalized);
    setStatus('connected');
    setError('');
    onWalletChange?.(normalized);
    return normalized;
  }, [onWalletChange]);

  useEffect(() => {
    persistWalletSession(wallet, pairing.session);
  }, [pairing.session, wallet]);

  const startMobilePairing = useCallback(async () => {
    const config = controlPanelPairingConfig();
    setProviderAvailable(config.ok);
    setStatus('connecting');
    setModalOpen(true);
    setError('');
    setPairing((current) => ({
      ...current,
      config,
      status: 'starting',
      message: '',
      session: null,
      qrImage: null,
      deepLink: null,
      expiresAt: null,
    }));

    if (!config.ok) {
      const message = controlPanelPairingErrorMessage(config.message, 'Mobile Synergy Wallet pairing is unavailable.');
      setStatus('unavailable');
      setError(message);
      setPairing((current) => ({
        ...current,
        config,
        status: 'unavailable',
        message,
      }));
      return null;
    }

    try {
      const session = await createWalletPairingSession({
        config,
        fetchImpl: controlPanelPairingFetch,
        origin: CONTROL_PANEL_PAIRING_ORIGIN,
        route: CONTROL_PANEL_PAIRING_ROUTE,
        appName: 'Synergy Node Control Panel',
        iconUrl: CONTROL_PANEL_PAIRING_ICON_URL,
      });
      const qrImage = await qrToDataUrl(session.qrPayload);
      setPairing((current) => ({
        ...current,
        config,
        status: 'pending',
        message: 'Scan with Synergy Wallet mobile to approve this node control panel connection.',
        session,
        qrImage,
        deepLink: session.qrPayload,
        expiresAt: session.expiresAt,
      }));
      return session;
    } catch (pairingError) {
      const message = controlPanelPairingErrorMessage(pairingError, 'Unable to create Synergy Wallet mobile pairing session.');
      setStatus('unavailable');
      setError(message);
      setPairing((current) => ({
        ...current,
        config,
        status: 'error',
        message,
        session: null,
        qrImage: null,
        deepLink: null,
        expiresAt: null,
      }));
      return null;
    }
  }, []);

  useEffect(() => {
    if (pairing.status !== 'pending' || !pairing.session) return undefined;
    let cancelled = false;
    const poll = async () => {
      try {
        const result = await pollWalletPairingSession({ session: pairing.session, fetchImpl: controlPanelPairingFetch });
        if (cancelled) return;
        if (result.connected) {
          applyMobileWallet(result);
          setPairing((current) => ({
            ...current,
            status: 'approved',
            message: 'Synergy Wallet mobile approved this connection.',
          }));
          setModalOpen(false);
          return;
        }
        if (result.status !== 'pending') {
          const message = controlPanelPairingErrorMessage(result.error, 'Synergy Wallet mobile pairing did not complete.');
          setStatus('disconnected');
          setError(message);
          setPairing((current) => ({ ...current, status: result.status, message }));
        }
      } catch (pollError) {
        if (cancelled) return;
        const message = controlPanelPairingErrorMessage(pollError, 'Unable to poll Synergy Wallet mobile pairing session.');
        setStatus('unavailable');
        setError(message);
        setPairing((current) => ({ ...current, status: 'error', message }));
      }
    };
    const interval = window.setInterval(poll, 2000);
    void poll();
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [applyMobileWallet, pairing.session, pairing.status]);

  const openWalletModal = () => {
    setError('');
    setModalOpen(true);
  };

  const requestWalletAction = useCallback(async ({
    method,
    params = [],
    label = '',
    summary = '',
    metadata = {},
  } = {}) => {
    if (!wallet?.address) {
      throw new Error('Connect Synergy Wallet mobile before requesting a wallet action.');
    }
    if (!pairing.session) {
      throw new Error('The mobile wallet pairing session is not available. Reconnect with the QR code.');
    }

    const action = await createWalletActionRequest({
      session: pairing.session,
      method,
      params,
      label,
      summary,
      metadata: {
        ...metadata,
        account: wallet.address,
        source: 'node-control-panel',
      },
      fetchImpl: controlPanelPairingFetch,
    });
    const startedAt = Date.now();
    const timeoutMs = 5 * 60 * 1000;
    while (Date.now() - startedAt < timeoutMs) {
      const result = await pollWalletActionRequest({ action, fetchImpl: controlPanelPairingFetch });
      const actionStatus = String(result?.status || result?.state || '').toLowerCase();
      if (['completed', 'complete', 'approved', 'submitted', 'success', 'confirmed', 'included', 'committed', 'finalized'].includes(actionStatus)) {
        return result.result || result.response || result;
      }
      if (['rejected', 'denied', 'cancelled', 'canceled', 'failed', 'error', 'expired'].includes(actionStatus)) {
        throw new Error(result.error || result.message || `Synergy Wallet mobile action ${actionStatus}.`);
      }
      await sleep(2000);
    }
    throw new Error('Timed out waiting for Synergy Wallet mobile approval.');
  }, [pairing.session, wallet?.address]);

  useEffect(() => {
    if (wallet?.address) {
      onWalletChange?.({ ...wallet, requestWalletAction });
    }
  }, [onWalletChange, requestWalletAction, wallet]);

  const disconnect = () => {
    clearStoredWalletSession();
    setWallet(null);
    setStatus('disconnected');
    setError('');
    setPairing((current) => ({
      ...current,
      status: 'idle',
      message: '',
      session: null,
      qrImage: null,
      deepLink: null,
      expiresAt: null,
    }));
    onWalletChange?.(null);
  };

  const copyAddress = async () => {
    if (!wallet?.address || !navigator?.clipboard) return;
    await navigator.clipboard.writeText(wallet.address);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  const modalWallet = useMemo(() => ({
    ...wallet,
    address: wallet?.address || '',
    canSign: Boolean(wallet?.canSign),
    chainId: wallet?.chainId ?? SYNERGY_TESTNET.chainIdDecimal,
    chainIdHex: wallet?.chainIdHex ?? SYNERGY_TESTNET.chainIdHex,
    closeModal: () => setModalOpen(false),
    connectSynergyInjected: () => {
      setError('Browser Synergy Wallet support is coming soon. Use Mobile Wallet for this validator setup.');
      return null;
    },
    disconnect,
    error,
    hasSynergyProvider: providerAvailable,
    isConnected: status === 'connected' && Boolean(wallet?.address),
    modalOpen,
    networkName: wallet?.networkName || SYNERGY_TESTNET.displayName,
    openModal: () => setModalOpen(true),
    pairing,
    refresh: () => wallet,
    requestWalletAction,
    source: wallet?.source || 'mobile-pairing',
    startMobilePairing,
    status,
    walletType: 'synergy',
  }), [disconnect, error, modalOpen, pairing, providerAvailable, requestWalletAction, startMobilePairing, status, wallet]);

  return (
    <>
      <section className={`v18-wallet-card ${compact ? 'is-compact' : ''}`} data-wallet-policy="synergy-only">
        <div className="v18-wallet-card__head">
          <span className="v18-icon-bubble is-green"><Wallet size={18} /></span>
          <div>
            <h3>Synergy Wallet</h3>
            <p>{providerStatusText(providerAvailable, status)}</p>
          </div>
          <span className="v18-status-pill is-green">
            <ShieldCheck size={14} />
            Synergy only
          </span>
        </div>

        {wallet?.address ? (
          <div className="v18-wallet-connected">
            <div>
              <span>Connected wallet</span>
              <strong title={wallet.address}>{truncateMiddle(wallet.address, 10, 8)}</strong>
            </div>
            <div>
              <span>Network</span>
              <strong>{SYNERGY_TESTNET.displayName}</strong>
            </div>
            <div className="v18-wallet-actions">
              <button type="button" className="v18-icon-button" onClick={copyAddress} aria-label="Copy wallet address">
                <Copy size={16} />
              </button>
              <button type="button" className="v18-ghost-button" onClick={disconnect}>
                <Unplug size={16} />
                Disconnect
              </button>
            </div>
            {copied ? <span className="v18-inline-success"><CheckCircle2 size={14} /> Copied</span> : null}
          </div>
        ) : (
          <div className="v18-wallet-empty">
            <p>
              Connect your mobile Synergy Wallet to verify validator stake and owner permissions.
            </p>
            <button
              type="button"
              className="v18-primary-button"
              onClick={openWalletModal}
              disabled={status === 'connecting'}
            >
              {status === 'connecting' ? <RefreshCw size={16} className="v18-spin" /> : <Link2 size={16} />}
              {status === 'connecting' ? 'Connecting' : 'Connect Synergy Wallet'}
            </button>
          </div>
        )}

        {error ? <p className="v18-error-text">{error}</p> : null}
      </section>
      <WalletModal wallet={modalWallet} config={synergyOnlyWalletConnectionConfig} />
    </>
  );
}

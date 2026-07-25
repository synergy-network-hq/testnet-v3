import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useAccount, useConnectorClient, useDisconnect } from "wagmi";
import {
  connectInjectedWallet,
  createWalletPairingSession,
  getConnectedSynergyWallet,
  getInjectedSynergyProvider,
  getWalletPairingConfig,
  pollWalletPairingSession,
  providerCanSign,
  qrToDataUrl,
  SYNERGY_TESTNET,
} from "../services/synergy-wallet.js";
import {
  connectBitcoinWallet,
  connectNonEvmWallet,
  connectSolanaWallet,
  getConnectedBitcoinWallet,
  getConnectedNonEvmWallet,
  getConnectedSolanaWallet,
  getInjectedBitcoinProvider,
  getInjectedNonEvmProvider,
  getInjectedSolanaProvider,
} from "../services/nonEvm-wallet.js";
import { normalizeAccountSnapshot } from "../lib/accountSnapshot.js";

const GENERIC_NON_EVM_TYPES = [
  "cosmos",
  "osmosis",
  "celestia",
  "polkadot",
  "aptos",
  "sui",
  "cardano",
  "algorand",
  "tron",
  "ton",
  "xrp",
];

function formatProviderError(error) {
  const message = error?.message || String(error);
  if (/user rejected|denied/i.test(message)) return "Connection request was rejected.";
  if (/chain/i.test(message) && /unsupported|unrecognized/i.test(message)) {
    return "The selected wallet network is not supported yet.";
  }
  return message;
}

function getInjectedEvmProvider() {
  if (typeof window === "undefined") return null;
  return window.synergy?.ethereum
    || window.SynergyWallet?.ethereum
    || window.synergyWallet?.ethereum
    || window.ethereum
    || null;
}

function parseChainId(value) {
  if (typeof value === "number") return value;
  if (typeof value === "string" && value.startsWith("0x")) return Number.parseInt(value, 16);
  if (typeof value === "string") return Number.parseInt(value, 10);
  return null;
}

function chainIdToHex(value) {
  const numeric = parseChainId(value);
  return numeric ? `0x${numeric.toString(16)}` : null;
}

async function getConnectedEvmWallet(provider) {
  if (!provider?.request) return null;
  const accounts = await provider.request({ method: "eth_accounts" });
  if (!accounts?.[0]) return null;
  const chainIdHex = await provider.request({ method: "eth_chainId" });
  return {
    provider,
    address: accounts[0],
    chainId: parseChainId(chainIdHex),
    chainIdHex,
    synId: null,
    source: "evm-injected",
    canSign: true,
  };
}

async function connectEvmWallet(provider) {
  const accounts = await provider.request({ method: "eth_requestAccounts" });
  const chainIdHex = await provider.request({ method: "eth_chainId" });
  return {
    provider,
    address: accounts?.[0],
    chainId: parseChainId(chainIdHex),
    chainIdHex,
    synId: null,
    source: "evm-injected",
    canSign: true,
  };
}

function eip1193FromWalletClient(client) {
  if (!client?.request) return null;
  return {
    request: ({ method, params = [] }) => client.request({ method, params }),
  };
}

function walletTypeFromSource(source) {
  const normalized = String(source || "").toLowerCase();
  if (normalized.startsWith("evm")) return "evm";
  if (normalized.startsWith("solana")) return "solana";
  if (normalized.startsWith("bitcoin")) return "bitcoin";
  const genericType = GENERIC_NON_EVM_TYPES.find((type) => normalized.startsWith(type));
  if (genericType) return genericType;
  return "synergy";
}

export function useWallet() {
  const evmAccount = normalizeAccountSnapshot(useAccount());
  const { data: evmClient } = useConnectorClient();
  const { disconnect: disconnectEvmWallet } = useDisconnect();
  const evmProviderFromClient = useMemo(() => eip1193FromWalletClient(evmClient), [evmClient]);

  const [provider, setProvider] = useState(() => getInjectedSynergyProvider());
  const [address, setAddress] = useState(null);
  const [chainId, setChainId] = useState(null);
  const [chainIdHex, setChainIdHex] = useState(null);
  const [synId, setSynId] = useState(null);
  const [networkName, setNetworkName] = useState(null);
  const [source, setSource] = useState(null);
  const [canSign, setCanSign] = useState(false);
  const [activeWalletType, setActiveWalletType] = useState(null);
  const [status, setStatus] = useState("disconnected");
  const [error, setError] = useState(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [pairing, setPairing] = useState(() => ({
    config: getWalletPairingConfig(),
    status: "idle",
    message: "",
    session: null,
    qrImage: null,
    deepLink: null,
    expiresAt: null,
  }));
  const pollingRef = useRef(false);

  const applyConnection = useCallback((next) => {
    const nextProvider = next.provider || getInjectedSynergyProvider();
    const nextWalletType = walletTypeFromSource(next.source);
    setProvider(nextProvider);
    setAddress(next.address);
    setChainId(next.chainId ?? (nextWalletType === "synergy" ? SYNERGY_TESTNET.chainIdDecimal : null));
    setChainIdHex(next.chainIdHex ?? (nextWalletType === "synergy" ? SYNERGY_TESTNET.chainIdHex : null));
    setSynId(next.synId || null);
    setNetworkName(next.networkName || null);
    setSource(next.source || "synergy-injected");
    setActiveWalletType(nextWalletType);
    setCanSign(Boolean(next.canSign || providerCanSign(nextProvider)));
    setStatus("connected");
    setError(null);
  }, []);

  const clearConnection = useCallback(({ preserveType = false } = {}) => {
    setProvider(null);
    setAddress(null);
    setChainId(null);
    setChainIdHex(null);
    setSynId(null);
    setNetworkName(null);
    setSource(null);
    setCanSign(false);
    if (!preserveType) setActiveWalletType(null);
    setStatus("disconnected");
  }, []);

  const applyWagmiConnection = useCallback(() => {
    const nextProvider = evmProviderFromClient || getInjectedEvmProvider();
    if (!evmAccount.isConnected || !evmAccount.address || !nextProvider) return null;
    const connected = {
      provider: nextProvider,
      address: evmAccount.address,
      chainId: evmAccount.chainId,
      chainIdHex: chainIdToHex(evmAccount.chainId),
      synId: null,
      source: "evm-wagmi",
      canSign: true,
    };
    applyConnection(connected);
    return connected;
  }, [
    applyConnection,
    evmAccount.address,
    evmAccount.chainId,
    evmAccount.isConnected,
    evmProviderFromClient,
  ]);

  const refresh = useCallback(async () => {
    const nextProvider = activeWalletType === "evm"
      ? evmProviderFromClient || getInjectedEvmProvider()
      : activeWalletType === "synergy"
        ? getInjectedSynergyProvider()
        : activeWalletType === "solana"
          ? getInjectedSolanaProvider()
          : activeWalletType === "bitcoin"
            ? getInjectedBitcoinProvider()
            : GENERIC_NON_EVM_TYPES.includes(activeWalletType)
              ? getInjectedNonEvmProvider(activeWalletType)
            : null;
    setProvider(nextProvider);
    setCanSign(Boolean(
      activeWalletType === "evm"
        ? nextProvider?.request || providerCanSign(nextProvider)
        : activeWalletType === "solana"
          ? nextProvider?.signTransaction || nextProvider?.signAndSendTransaction || nextProvider?.signMessage || nextProvider?.request
          : activeWalletType === "bitcoin"
            ? nextProvider?.signMessage || nextProvider?.signPsbt || nextProvider?.signTransaction || nextProvider?.request
            : GENERIC_NON_EVM_TYPES.includes(activeWalletType)
              ? nextProvider?.request || nextProvider?.connect || nextProvider?.enable || nextProvider?.signMessage || nextProvider?.signTransaction
            : nextProvider?.request || providerCanSign(nextProvider),
    ));

    if (!nextProvider) {
      clearConnection();
      return;
    }

    try {
      if (activeWalletType === "evm") {
        if (applyWagmiConnection()) return;
        const connected = await getConnectedEvmWallet(nextProvider);
        if (connected?.address) applyConnection(connected);
        else if (String(source || "").startsWith("evm")) clearConnection();
        setError(null);
        return;
      }

      if (activeWalletType === "synergy") {
        const connected = await getConnectedSynergyWallet(nextProvider);
        if (connected?.address) {
          applyConnection({ ...connected, source: "synergy-injected" });
        } else if (source === "synergy-injected") {
          clearConnection();
        }
        setError(null);
        return;
      }

      if (activeWalletType === "solana") {
        const connected = await getConnectedSolanaWallet(nextProvider);
        if (connected?.address) {
          applyConnection({ ...connected, source: "solana-injected" });
        } else if (source === "solana-injected") {
          clearConnection();
        }
        setError(null);
        return;
      }

      if (activeWalletType === "bitcoin") {
        const connected = await getConnectedBitcoinWallet(nextProvider);
        if (connected?.address) {
          applyConnection({ ...connected, source: "bitcoin-injected" });
        } else if (source === "bitcoin-injected") {
          clearConnection();
        }
        setError(null);
        return;
      }

      if (GENERIC_NON_EVM_TYPES.includes(activeWalletType)) {
        const connected = await getConnectedNonEvmWallet(activeWalletType, nextProvider);
        if (connected?.address) {
          applyConnection(connected);
        }
        setError(null);
      }
    } catch (err) {
      setStatus("error");
      setError(formatProviderError(err));
    }
  }, [
    activeWalletType,
    address,
    applyConnection,
    applyWagmiConnection,
    clearConnection,
    evmProviderFromClient,
    source,
  ]);

  useEffect(() => {
    if (!evmAccount.isConnected || !evmAccount.address) {
      if (activeWalletType === "evm") clearConnection();
      return;
    }
    if (activeWalletType && activeWalletType !== "evm") return;
    applyWagmiConnection();
  }, [
    activeWalletType,
    applyWagmiConnection,
    clearConnection,
    evmAccount.address,
    evmAccount.isConnected,
  ]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (!provider?.on) return undefined;
    const onAccounts = (accounts) => {
      const nextAddress = accounts?.[0] || null;
      setAddress(nextAddress);
      setStatus(nextAddress ? "connected" : "disconnected");
      if (!nextAddress) setActiveWalletType(null);
    };
    const onChain = () => refresh();
    provider.on("accountsChanged", onAccounts);
    provider.on("chainChanged", onChain);
    return () => {
      provider.removeListener?.("accountsChanged", onAccounts);
      provider.removeListener?.("chainChanged", onChain);
    };
  }, [provider, refresh]);

  const activateEvm = useCallback(() => {
    if (activeWalletType === "synergy") clearConnection({ preserveType: true });
    setActiveWalletType("evm");
    applyWagmiConnection();
  }, [activeWalletType, applyWagmiConnection, clearConnection]);

  const connectEvmInjected = useCallback(async () => {
    setActiveWalletType("evm");
    const nextProvider = evmProviderFromClient || getInjectedEvmProvider();
    setProvider(nextProvider);

    if (evmAccount.isConnected && evmAccount.address && nextProvider) {
      const connected = applyWagmiConnection();
      if (connected) setModalOpen(false);
      return connected?.address || null;
    }

    if (!nextProvider) {
      setStatus("unavailable");
      setError("No EVM wallet provider was found.");
      return null;
    }

    setStatus("connecting");
    try {
      const connected = await connectEvmWallet(nextProvider);
      applyConnection({ ...connected, source: "evm-injected" });
      setModalOpen(false);
      return connected.address;
    } catch (err) {
      setStatus("error");
      setError(formatProviderError(err));
      return null;
    }
  }, [
    applyConnection,
    applyWagmiConnection,
    evmAccount.address,
    evmAccount.isConnected,
    evmProviderFromClient,
  ]);

  const connectSynergyInjected = useCallback(async () => {
    disconnectEvmWallet?.();
    setActiveWalletType("synergy");
    const synergyProvider = getInjectedSynergyProvider();
    setProvider(synergyProvider);

    if (!synergyProvider) {
      setStatus("unavailable");
      setError("No Synergy Wallet browser provider was found.");
      return null;
    }

    setStatus("connecting");
    try {
      const connected = { ...(await connectInjectedWallet(synergyProvider)), source: "synergy-injected" };
      applyConnection(connected);
      setModalOpen(false);
      return connected.address;
    } catch (err) {
      setStatus("error");
      setError(formatProviderError(err));
      return null;
    }
  }, [applyConnection, disconnectEvmWallet]);

  const connectSolanaInjected = useCallback(async () => {
    const solanaProvider = getInjectedSolanaProvider();
    setProvider(solanaProvider);

    if (!solanaProvider) {
      setStatus("unavailable");
      setError("No Solana wallet provider was found.");
      return null;
    }

    setStatus("connecting");
    try {
      const connected = await connectSolanaWallet(solanaProvider);
      setActiveWalletType("solana");
      applyConnection(connected);
      setModalOpen(false);
      return connected.address;
    } catch (err) {
      setStatus("error");
      setError(formatProviderError(err));
      return null;
    }
  }, [applyConnection]);

  const connectBitcoinInjected = useCallback(async () => {
    const bitcoinProvider = getInjectedBitcoinProvider();
    setProvider(bitcoinProvider);

    if (!bitcoinProvider) {
      setStatus("unavailable");
      setError("No Bitcoin wallet provider was found.");
      return null;
    }

    setStatus("connecting");
    try {
      const connected = await connectBitcoinWallet(bitcoinProvider);
      setActiveWalletType("bitcoin");
      applyConnection(connected);
      setModalOpen(false);
      return connected.address;
    } catch (err) {
      setStatus("error");
      setError(formatProviderError(err));
      return null;
    }
  }, [applyConnection]);

  const connectNonEvmNetwork = useCallback(async (networkId) => {
    const networkProvider = getInjectedNonEvmProvider(networkId);
    setProvider(networkProvider);

    if (!networkProvider) {
      setStatus("unavailable");
      setError(`No ${networkId} wallet provider was found.`);
      return null;
    }

    setStatus("connecting");
    try {
      const connected = await connectNonEvmWallet(networkId, networkProvider);
      setActiveWalletType(networkId);
      applyConnection(connected);
      setModalOpen(false);
      return connected.address;
    } catch (err) {
      setStatus("error");
      setError(formatProviderError(err));
      return null;
    }
  }, [applyConnection]);

  const startMobilePairing = useCallback(async () => {
    disconnectEvmWallet?.();
    setActiveWalletType("synergy");
    const config = getWalletPairingConfig();
    setPairing((current) => ({ ...current, config, status: "starting", message: "" }));
    setModalOpen(true);

    if (!config.ok) {
      setPairing((current) => ({
        ...current,
        config,
        status: "unavailable",
        message: config.message,
        session: null,
        qrImage: null,
        deepLink: null,
      }));
      return null;
    }

    try {
      const session = await createWalletPairingSession({ config });
      const qrImage = await qrToDataUrl(session.qrPayload);
      setPairing((current) => ({
        ...current,
        config,
        status: "pending",
        message: "Scan with Synergy Wallet to approve this Relay connection.",
        session,
        qrImage,
        deepLink: session.qrPayload,
        expiresAt: session.expiresAt,
      }));
      return session;
    } catch (err) {
      const message = formatProviderError(err);
      setPairing((current) => ({
        ...current,
        config,
        status: "error",
        message,
        session: null,
        qrImage: null,
        deepLink: null,
      }));
      setError(message);
      return null;
    }
  }, [disconnectEvmWallet]);

  useEffect(() => {
    if (pairing.status !== "pending" || !pairing.session || pollingRef.current) return undefined;
    let cancelled = false;
    pollingRef.current = true;

    const poll = async () => {
      try {
        const result = await pollWalletPairingSession({ session: pairing.session });
        if (cancelled) return;

        if (result.connected) {
          applyConnection({
            address: result.address,
            chainId: result.chainId,
            chainIdHex: result.chainIdHex,
            synId: result.synId,
            source: "mobile-pairing",
            canSign: false,
            provider: getInjectedSynergyProvider(),
          });
          setPairing((current) => ({
            ...current,
            status: "approved",
            message: "Synergy Wallet approved this Relay connection.",
          }));
          setModalOpen(false);
          return;
        }

        if (result.status !== "pending") {
          setPairing((current) => ({
            ...current,
            status: result.status,
            message: result.error || "Synergy Wallet pairing did not complete.",
          }));
          if (result.error) setError(result.error);
        }
      } catch (err) {
        if (cancelled) return;
        const message = formatProviderError(err);
        setPairing((current) => ({ ...current, status: "error", message }));
        setError(message);
      }
    };

    const interval = window.setInterval(poll, 2000);
    poll();
    return () => {
      cancelled = true;
      pollingRef.current = false;
      window.clearInterval(interval);
    };
  }, [applyConnection, pairing.session, pairing.status]);

  const connect = useCallback(async () => {
    setModalOpen(true);
    return null;
  }, []);

  const switchNetwork = useCallback(async (targetChainIdHex) => {
    const activeProvider = activeWalletType === "evm"
      ? evmProviderFromClient || provider || getInjectedEvmProvider()
      : provider || getInjectedSynergyProvider();
    if (!activeProvider?.request) {
      setStatus("unavailable");
      setError("No in-browser wallet provider was found.");
      return false;
    }
    try {
      if (activeWalletType === "evm") {
        await activeProvider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: targetChainIdHex }] });
      } else {
        await activeProvider.request({ method: "synergy_switchChain", params: [{ chainId: targetChainIdHex }] });
      }
      await refresh();
      return true;
    } catch (err) {
      setStatus("error");
      setError(formatProviderError(err));
      return false;
    }
  }, [activeWalletType, evmProviderFromClient, provider, refresh]);

  const disconnect = useCallback(() => {
    if (activeWalletType === "evm") disconnectEvmWallet?.();
    clearConnection();
    setError(null);
  }, [activeWalletType, clearConnection, disconnectEvmWallet, provider]);

  const evmProvider = activeWalletType === "evm" ? evmProviderFromClient || provider || getInjectedEvmProvider() : null;
  const hasEvmProvider = Boolean(evmProviderFromClient || getInjectedEvmProvider());
  const hasSynergyProvider = Boolean(getInjectedSynergyProvider());
  const hasSolanaProvider = Boolean(getInjectedSolanaProvider());
  const hasBitcoinProvider = Boolean(getInjectedBitcoinProvider());
  const portfolioAddress = activeWalletType === "evm" || activeWalletType === "synergy" ? address : null;

  const wallet = useMemo(
    () => ({
      provider,
      evmProvider,
      activeWalletType,
      walletType: activeWalletType,
      address,
      chainId,
      chainIdHex,
      synId,
      networkName,
      source,
      canSign,
      status,
      error,
      isConnected: status === "connected" && Boolean(address),
      hasInjectedProvider: Boolean(provider || hasEvmProvider || hasSynergyProvider || hasSolanaProvider || hasBitcoinProvider),
      hasEvmProvider,
      hasSynergyProvider,
      hasSolanaProvider,
      hasBitcoinProvider,
      evmAccount,
      pairing,
      modalOpen,
      portfolioAddress,
      openModal: () => setModalOpen(true),
      closeModal: () => setModalOpen(false),
      connect,
      activateEvm,
      connectEvmInjected,
      connectSynergyInjected,
      connectSolanaInjected,
      connectBitcoinInjected,
      connectNonEvmNetwork,
      connectInjected: connectSynergyInjected,
      startMobilePairing,
      refresh,
      switchNetwork,
      disconnect,
    }),
    [
      activeWalletType,
      activateEvm,
      address,
      canSign,
      chainId,
      chainIdHex,
      connect,
      connectEvmInjected,
      connectSynergyInjected,
      connectSolanaInjected,
      connectBitcoinInjected,
      connectNonEvmNetwork,
      disconnect,
      error,
      evmAccount,
      evmProvider,
      hasEvmProvider,
      hasSynergyProvider,
      hasSolanaProvider,
      hasBitcoinProvider,
      modalOpen,
      pairing,
      provider,
      refresh,
      portfolioAddress,
      source,
      startMobilePairing,
      status,
      switchNetwork,
      synId,
      networkName,
    ],
  );

  return wallet;
}

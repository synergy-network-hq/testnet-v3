function isBrowser() {
  return typeof window !== "undefined";
}

function normalizeSolanaPublicKey(value, provider) {
  return String(
    value?.publicKey?.toString?.() ||
      value?.publicKey?.toBase58?.() ||
      provider?.publicKey?.toString?.() ||
      provider?.publicKey?.toBase58?.() ||
      "",
  ).trim();
}

function normalizeBitcoinAddress(value) {
  if (Array.isArray(value)) return String(value[0] || "").trim();
  return String(value || "").trim();
}

function normalizeAddress(value) {
  if (Array.isArray(value)) return normalizeAddress(value[0]);
  if (typeof value === "string") return value.trim();
  return String(
    value?.address ||
      value?.account ||
      value?.accountId ||
      value?.account_id ||
      value?.publicKey?.toString?.() ||
      value?.publicKey?.toBase58?.() ||
      "",
  ).trim();
}

function walletProviderReady(provider) {
  return Boolean(provider?.request || provider?.connect || provider?.enable || provider?.signMessage || provider?.signTransaction);
}

const GENERIC_NON_EVM_WALLETS = {
  cosmos: {
    networkName: "Cosmos IBC",
    source: "cosmos-keplr",
    getProvider: () => window.keplr || window.leap || window.cosmostation?.providers?.keplr || null,
    connect: async (provider) => {
      const chainId = "cosmoshub-4";
      await provider.enable?.(chainId);
      const key = await provider.getKey?.(chainId);
      return key?.bech32Address || "";
    },
  },
  osmosis: {
    networkName: "Osmosis",
    source: "osmosis-keplr",
    getProvider: () => window.keplr || window.leap || window.cosmostation?.providers?.keplr || null,
    connect: async (provider) => {
      const chainId = "osmosis-1";
      await provider.enable?.(chainId);
      const key = await provider.getKey?.(chainId);
      return key?.bech32Address || "";
    },
  },
  celestia: {
    networkName: "Celestia",
    source: "celestia-keplr",
    getProvider: () => window.keplr || window.leap || window.cosmostation?.providers?.keplr || null,
    connect: async (provider) => {
      const chainId = "celestia";
      await provider.enable?.(chainId);
      const key = await provider.getKey?.(chainId);
      return key?.bech32Address || "";
    },
  },
  polkadot: {
    networkName: "Polkadot",
    source: "polkadot-injected",
    getProvider: () => {
      const providers = window.injectedWeb3 || {};
      return providers["polkadot-js"] || providers.talisman || Object.values(providers)[0] || null;
    },
    connect: async (provider) => {
      const extension = await provider.enable?.("Synergy Relay");
      const accounts = await extension?.accounts?.get?.();
      return normalizeAddress(accounts);
    },
  },
  aptos: {
    networkName: "Aptos",
    source: "aptos-injected",
    getProvider: () => window.aptos || window.petra || window.martian || null,
    connect: async (provider) => {
      const response = await provider.connect?.();
      const account = response || await provider.account?.();
      return normalizeAddress(account);
    },
  },
  sui: {
    networkName: "Sui",
    source: "sui-injected",
    getProvider: () => window.suiWallet || window.slush || window.sui || null,
    connect: async (provider) => {
      const response = await provider.connect?.() || await provider.request?.({ method: "connect" });
      return normalizeAddress(response?.accounts || response);
    },
  },
  cardano: {
    networkName: "Cardano",
    source: "cardano-injected",
    getProvider: () => {
      const wallets = window.cardano || {};
      return wallets.lace || wallets.nami || wallets.eternl || wallets.flint || wallets.yoroi || Object.values(wallets)[0] || null;
    },
    connect: async (provider) => {
      const api = await provider.enable?.();
      const addresses = await api?.getUsedAddresses?.();
      return normalizeAddress(addresses);
    },
  },
  algorand: {
    networkName: "Algorand",
    source: "algorand-injected",
    getProvider: () => window.algorand || window.peraWallet || window.deflyWallet || null,
    connect: async (provider) => {
      const response = await provider.connect?.() || await provider.request?.({ method: "algo_requestAccounts" });
      return normalizeAddress(response?.accounts || response);
    },
  },
  tron: {
    networkName: "Tron",
    source: "tron-injected",
    getProvider: () => window.tronLink || window.tronWeb || null,
    connect: async (provider) => {
      await provider.request?.({ method: "tron_requestAccounts" });
      return normalizeAddress(provider.tronWeb?.defaultAddress?.base58 || window.tronWeb?.defaultAddress?.base58);
    },
  },
  ton: {
    networkName: "TON Network",
    source: "ton-injected",
    getProvider: () => window.tonkeeper || window.ton || window.tonhub || null,
    connect: async (provider) => {
      const response = await provider.connect?.() || await provider.request?.({ method: "ton_requestAccounts" });
      return normalizeAddress(response?.accounts || response);
    },
  },
  xrp: {
    networkName: "XRP Ledger",
    source: "xrp-injected",
    getProvider: () => window.xaman || window.xumm || window.xrpl || null,
    connect: async (provider) => {
      const response = await provider.connect?.() || await provider.request?.({ method: "xrpl_requestAccounts" });
      return normalizeAddress(response?.accounts || response);
    },
  },
};

export function getInjectedSolanaProvider() {
  if (!isBrowser()) return null;
  return window.phantom?.solana || window.solana || null;
}

export async function getConnectedSolanaWallet(provider = getInjectedSolanaProvider()) {
  if (!provider) return null;
  const hasPublicKey = Boolean(normalizeSolanaPublicKey(null, provider));
  if (!hasPublicKey && typeof provider.connect === "function") {
    try {
      await provider.connect({ onlyIfTrusted: true });
    } catch {
      return null;
    }
  }
  const address = normalizeSolanaPublicKey(null, provider);
  if (!address) return null;
  return {
    provider,
    address,
    source: "solana-injected",
    walletType: "solana",
    family: "solana",
    canSign: Boolean(provider.signTransaction || provider.signAndSendTransaction || provider.signMessage || provider.request),
    networkId: "solana",
    networkName: "Solana",
  };
}

export async function connectSolanaWallet(provider = getInjectedSolanaProvider()) {
  if (!provider) {
    throw new Error("Install or unlock a Solana wallet such as Phantom.");
  }
  if (typeof provider.connect === "function") {
    await provider.connect();
  } else if (typeof provider.request === "function") {
    await provider.request({ method: "connect" });
  } else {
    throw new Error("The detected Solana wallet does not expose a connect method.");
  }
  const address = normalizeSolanaPublicKey(null, provider);
  if (!address) {
    throw new Error("Solana wallet did not return a public key.");
  }
  return {
    provider,
    address,
    source: "solana-injected",
    walletType: "solana",
    family: "solana",
    canSign: Boolean(provider.signTransaction || provider.signAndSendTransaction || provider.signMessage || provider.request),
    networkId: "solana",
    networkName: "Solana",
  };
}

export function getInjectedBitcoinProvider() {
  if (!isBrowser()) return null;
  return window.unisat || window.okxwallet?.bitcoin || window.xverse?.bitcoin || window.leatherProvider || null;
}

export async function getConnectedBitcoinWallet(provider = getInjectedBitcoinProvider()) {
  if (!provider) return null;
  const accounts = typeof provider.getAccounts === "function"
    ? await provider.getAccounts().catch(() => [])
    : typeof provider.request === "function"
      ? await provider.request({ method: "getAccounts" }).catch(() => [])
      : [];
  const address = normalizeBitcoinAddress(accounts);
  if (!address) return null;
  return {
    provider,
    address,
    source: "bitcoin-injected",
    walletType: "bitcoin",
    family: "bitcoin",
    canSign: Boolean(provider.signMessage || provider.signPsbt || provider.signTransaction || provider.request),
    networkId: "bitcoin",
    networkName: "Bitcoin",
  };
}

export async function connectBitcoinWallet(provider = getInjectedBitcoinProvider()) {
  if (!provider) {
    throw new Error("Install or unlock a Bitcoin wallet such as UniSat.");
  }
  const accounts = typeof provider.requestAccounts === "function"
    ? await provider.requestAccounts()
    : typeof provider.request === "function"
      ? await provider.request({ method: "requestAccounts" })
      : null;
  const address = normalizeBitcoinAddress(accounts);
  if (!address) {
    throw new Error("Bitcoin wallet did not return an account.");
  }
  return {
    provider,
    address,
    source: "bitcoin-injected",
    walletType: "bitcoin",
    family: "bitcoin",
    canSign: Boolean(provider.signMessage || provider.signPsbt || provider.signTransaction || provider.request),
    networkId: "bitcoin",
    networkName: "Bitcoin",
  };
}

export function getInjectedNonEvmProvider(networkId) {
  if (!isBrowser()) return null;
  return GENERIC_NON_EVM_WALLETS[networkId]?.getProvider?.() || null;
}

export async function getConnectedNonEvmWallet(networkId, provider = getInjectedNonEvmProvider(networkId)) {
  if (!provider || !GENERIC_NON_EVM_WALLETS[networkId]) return null;
  return null;
}

export async function connectNonEvmWallet(networkId, provider = getInjectedNonEvmProvider(networkId)) {
  const definition = GENERIC_NON_EVM_WALLETS[networkId];
  if (!definition) {
    throw new Error("This network wallet is not configured.");
  }
  if (!provider) {
    throw new Error(`Install or unlock a ${definition.networkName} wallet.`);
  }
  const address = normalizeAddress(await definition.connect(provider));
  if (!address) {
    throw new Error(`${definition.networkName} wallet did not return an account.`);
  }
  return {
    provider,
    address,
    source: definition.source,
    walletType: networkId,
    family: networkId,
    canSign: walletProviderReady(provider),
    networkId,
    networkName: definition.networkName,
  };
}

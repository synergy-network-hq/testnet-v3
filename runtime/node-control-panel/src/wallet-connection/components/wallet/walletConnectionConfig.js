export const DEFAULT_WALLET_CONNECTION_CONFIG = {
  brand: {
    label: "RELAY",
    ariaLabel: "Relay",
    logoSrc: "/relay-icon.png",
    bannerSrc: "/relay-banner.png",
  },
  copy: {
    homeTitle: "Connect Wallet",
    homeSubtitle: "Choose your network to get started",
  },
  securityNote: {
    title: "Your funds stay secure",
    body: "We never access your funds.",
  },
  lanes: {
    synergy: {
      enabled: true,
      title: "Synergy Network",
      subtitle: "Relay native network",
      iconSrc: "",
    },
    evm: {
      enabled: true,
      title: "EVM Networks",
      subtitle: "Ethereum & EVM-compatible chains",
      flowTitle: "Connect to EVM Networks",
      iconSrc: "",
    },
    nonEvm: {
      enabled: true,
      title: "Non-EVM Networks",
      subtitle: "Solana swaps live; other wallets",
      flowTitle: "Connect to Non-EVM Networks",
      iconSrc: "",
    },
  },
};

function mergeSection(defaultValue, overrideValue) {
  if (!overrideValue) return { ...defaultValue };
  return { ...defaultValue, ...overrideValue };
}

export function createWalletConnectionConfig(overrides = {}) {
  const lanes = Object.fromEntries(
    Object.entries(DEFAULT_WALLET_CONNECTION_CONFIG.lanes).map(([key, defaultLane]) => [
      key,
      mergeSection(defaultLane, overrides.lanes?.[key]),
    ]),
  );

  Object.entries(overrides.enabledLanes || {}).forEach(([key, enabled]) => {
    if (lanes[key]) lanes[key] = { ...lanes[key], enabled: Boolean(enabled) };
  });

  return {
    ...DEFAULT_WALLET_CONNECTION_CONFIG,
    ...overrides,
    brand: mergeSection(DEFAULT_WALLET_CONNECTION_CONFIG.brand, overrides.brand),
    copy: mergeSection(DEFAULT_WALLET_CONNECTION_CONFIG.copy, overrides.copy),
    securityNote: mergeSection(DEFAULT_WALLET_CONNECTION_CONFIG.securityNote, overrides.securityNote),
    lanes,
  };
}

export const relayWalletConnectionConfig = createWalletConnectionConfig();

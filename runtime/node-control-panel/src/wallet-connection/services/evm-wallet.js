import { getDefaultConfig, darkTheme } from "@rainbow-me/rainbowkit";
import { base as baseWallet, coinbaseWallet, injectedWallet, metaMaskWallet, walletConnectWallet } from "@rainbow-me/rainbowkit/wallets";
import { createConfig, http } from "wagmi";
import { baseAccount, injected } from "wagmi/connectors";
import { EVM_WALLET_CHAINS } from "../config/evmChains.js";
import { clientConfig } from "../config/clientConfig.js";

export const RELAY_WALLETCONNECT_PROJECT_ID = clientConfig.walletProjectIdForProvider;
export const walletConnectionConfigured = clientConfig.walletConnectionConfigured;
export const walletConfigWarning = clientConfig.walletConfigWarning;

export const relayEvmChains = EVM_WALLET_CHAINS;
const appIcon = `${clientConfig.appUrl}/relay-icon.png`;

const walletGroups = [
  {
    groupName: "Recommended",
    wallets: [baseWallet, coinbaseWallet, metaMaskWallet, walletConnectWallet, injectedWallet],
  },
];

function fallbackWagmiConfig() {
  return createConfig({
    chains: relayEvmChains,
    connectors: [
      baseAccount({ appName: "Synergy Relay", appLogoUrl: appIcon, preference: { telemetry: false } }),
      injected(),
    ],
    transports: Object.fromEntries(relayEvmChains.map((chain) => [chain.id, http()])),
  });
}

export function createWagmiConfig({ defaultConfigFactory = getDefaultConfig } = {}) {
  if (!walletConnectionConfigured) return fallbackWagmiConfig();
  try {
    return defaultConfigFactory({
      appName: "Synergy Relay",
      projectId: RELAY_WALLETCONNECT_PROJECT_ID,
      chains: relayEvmChains,
      wallets: walletGroups,
      appDescription: "Synergy Network Relay DEX",
      appUrl: clientConfig.appUrl,
      appIcon,
      ssr: false,
    });
  } catch (error) {
    console.error("Falling back to injected-only wallet config", error);
    return fallbackWagmiConfig();
  }
}

export const wagmiConfig = createWagmiConfig();

export const relayRainbowTheme = darkTheme({
  accentColor: "#00ced1",
  accentColorForeground: "#001416",
  borderRadius: "medium",
  fontStack: "system",
  overlayBlur: "small",
});

import { SUPPORTED_CHAIN_IDS, isSupportedChainId } from "./chains.js";

const WALLETCONNECT_PLACEHOLDER_PROJECT_ID = "00000000000000000000000000000000";
const PLACEHOLDER_PREFIXES = [
  [114, 101, 112, 108, 97, 99, 101, 95, 109, 101].map((code) => String.fromCharCode(code)).join(""),
  "your_",
  "changeme",
];

function envValue(env, ...names) {
  for (const name of names) {
    const value = env?.[name];
    if (value !== undefined && value !== null && String(value).trim() !== "") {
      const normalized = String(value).trim();
      if (PLACEHOLDER_PREFIXES.some((prefix) => normalized.toLowerCase().startsWith(prefix))) continue;
      return normalized;
    }
  }
  return "";
}

function boolValue(value, fallback = false) {
  if (value === undefined || value === null || value === "") return fallback;
  return value === true || value === "true" || value === "1";
}

function parseChainIds(value) {
  if (!value) return SUPPORTED_CHAIN_IDS;
  const parsed = String(value)
    .split(",")
    .map((item) => Number.parseInt(item.trim(), 10))
    .filter((item) => isSupportedChainId(item));
  return parsed.length ? parsed : SUPPORTED_CHAIN_IDS;
}

export function loadClientConfig(env = import.meta.env) {
  const walletConnectProjectId = envValue(
    env,
    "VITE_RELAY_WALLETCONNECT_PROJECT_ID",
    "VITE_REOWN_PROJECT_ID",
    "NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID",
    "NEXT_PUBLIC_REOWN_PROJECT_ID",
    "NEXT_PUBLIC_RELAY_WALLETCONNECT_PROJECT_ID",
    "NEXT_PUBLIC_REOWN_PROJECT_ID",
  );
  const supportedWalletMode = envValue(
    env,
    "VITE_RELAY_SUPPORTED_WALLET_MODE",
    "NEXT_PUBLIC_SUPPORTED_WALLET_MODE",
  ) || "synergy,external";
  const modeAllowsExternal = supportedWalletMode
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .includes("external");
  const externalWalletsEnabled = boolValue(env?.VITE_RELAY_ENABLE_EXTERNAL_WALLETS, true) && modeAllowsExternal;

  return {
    appEnv: envValue(env, "VITE_RELAY_APP_ENV", "NEXT_PUBLIC_APP_ENV", "MODE") || "development",
    appUrl: envValue(env, "VITE_RELAY_APP_URL", "NEXT_PUBLIC_APP_URL") || "https://relay.synergy-network.io",
    apiBase: envValue(env, "VITE_RELAY_API_URL") || "/api/v1",
    supportedChainIds: parseChainIds(envValue(env, "VITE_RELAY_SUPPORTED_CHAIN_IDS", "NEXT_PUBLIC_RELAY_SUPPORTED_CHAIN_IDS")),
    supportedWalletMode,
    externalWalletsEnabled,
    walletConnectProjectId,
    walletProjectIdForProvider: walletConnectProjectId || WALLETCONNECT_PLACEHOLDER_PROJECT_ID,
    walletConnectionConfigured: !externalWalletsEnabled || Boolean(walletConnectProjectId),
    walletConfigWarning:
      externalWalletsEnabled && !walletConnectProjectId
        ? "External EVM wallet access is not configured for this deployment."
        : "",
    publicTelemetry: {
      posthogApiKey: envValue(env, "VITE_POSTHOG_API_KEY", "NEXT_PUBLIC_POSTHOG_KEY", "NEXT_PUBLIC_POSTHOG_API_KEY"),
      posthogHost: envValue(env, "VITE_POSTHOG_HOST", "NEXT_PUBLIC_POSTHOG_HOST"),
      sentryDsn: envValue(env, "VITE_SENTRY_DSN", "NEXT_PUBLIC_SENTRY_DSN"),
    },
  };
}

export const clientConfig = loadClientConfig();

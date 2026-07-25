import QRCode from "qrcode";

export const SYNERGY_TESTNET = Object.freeze({
  key: "testnet",
  displayName: "Synergy Testnet",
  slug: "synergy-testnet",
  chainIdDecimal: 1264,
  chainIdHex: "0x4f0",
  rpcUrl: "https://testnet-rpc.synergy-network.io",
});

const DEFAULT_CREATE_PATH = "/sessions";
const DEFAULT_POLL_PATH = "/sessions/{sessionId}";
const HOSTED_RELAY_PAIRING_URL = "https://relay.synergy-network.io/api/wallet-pairing";
const HOSTED_RELAY_HOSTS = new Set(["relay.synergy-network.io"]);
const DEFAULT_SCOPES = ["read:identity", "read:address", "sign:transaction", "send:transaction", "wallet:getCapabilities"];
const REQUESTED_METHODS = ["synergy_getChainId", "synergy_signTransaction", "synergy_sendTransaction"];

function envValue(env, key) {
  return typeof env?.[key] === "string" ? env[key].trim() : "";
}

function hostedPairingUrl(locationLike = globalThis.location) {
  const hostname = String(locationLike?.hostname || "").toLowerCase();
  return HOSTED_RELAY_HOSTS.has(hostname) ? HOSTED_RELAY_PAIRING_URL : "";
}

function joinPairingUrl(baseUrl, path) {
  return new URL(path.replace(/^\//, ""), baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`).toString();
}

function pairingErrorMessage(message) {
  const text = String(message || "").trim();
  if (!text) return "";
  if (/origin is not allowed/i.test(text) || /relay wallet pairing/i.test(text)) {
    return "Mobile Synergy Wallet pairing is not available from this app origin.";
  }
  return text
    .replace(/\bRelay wallet pairing\b/gi, "mobile Synergy Wallet pairing")
    .replace(/\bRelay requires\b/g, "Synergy Testnet requires");
}

async function parseJsonResponse(response) {
  if (!response?.ok) {
    const payload = await response?.json?.().catch(() => null);
    throw new Error(pairingErrorMessage(payload?.error || payload?.message) || `Synergy Wallet pairing HTTP ${response?.status || "error"}`);
  }
  return response.json();
}

function extractAccount(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return extractAccount(value[0]);
  return (
    value?.synergyAddress ||
    value?.account ||
    value?.address ||
    value?.walletAddress ||
    value?.accountsByChain?.[SYNERGY_TESTNET.chainIdHex] ||
    value?.accountsByChain?.[SYNERGY_TESTNET.chainIdDecimal] ||
    value?.session?.account ||
    value?.session?.address ||
    value?.wallet?.address ||
    ""
  );
}

function extractSynId(value) {
  return value?.synId || value?.syn_id || value?.session?.synId || value?.wallet?.synId || "";
}

function extractChainId(value) {
  return value?.chainId ?? value?.chain_id ?? value?.network?.chainId ?? value?.session?.chainId ?? null;
}

export function chainIdToDecimal(value) {
  if (typeof value === "number" && Number.isFinite(value)) return Math.trunc(value);
  if (typeof value === "bigint") return Number(value);
  if (typeof value !== "string") return null;

  const text = value.trim().toLowerCase();
  if (!text) return null;
  if (text.startsWith("0x")) {
    const parsed = Number.parseInt(text, 16);
    return Number.isFinite(parsed) ? parsed : null;
  }
  if (!/^\d+$/.test(text)) return null;
  const parsed = Number.parseInt(text, 10);
  return Number.isFinite(parsed) ? parsed : null;
}

export function isCurrentTestnetChain(value) {
  return chainIdToDecimal(value) === SYNERGY_TESTNET.chainIdDecimal;
}

function providerRequest(provider, method, params = []) {
  if (!provider) throw new Error("Synergy Wallet provider is not available.");
  if (typeof provider.request === "function") {
    return provider.request({ method, params });
  }
  if (typeof provider.send === "function") {
    return provider.send(method, params);
  }
  throw new Error("Synergy Wallet provider does not expose a request method.");
}

export function getInjectedSynergyProvider() {
  if (typeof window === "undefined") return null;
  return window.synergy || window.SynergyWallet || window.synergyWallet || null;
}

export function providerCanSign(provider = getInjectedSynergyProvider()) {
  return Boolean(
    provider &&
      (typeof provider.signTransaction === "function" ||
        typeof provider.sendTransaction === "function" ||
        typeof provider.request === "function")
  );
}

async function requestOptional(provider, methods) {
  for (const method of methods) {
    try {
      if (method.type === "fn" && typeof provider?.[method.name] === "function") {
        return await provider[method.name](...(method.params || []));
      }
      if (method.type === "request") {
        return await providerRequest(provider, method.name, method.params || []);
      }
    } catch {
      // Try the next supported Synergy Wallet method.
    }
  }
  return null;
}

export async function getConnectedSynergyWallet(provider = getInjectedSynergyProvider()) {
  if (!provider) return null;

  const accountsResult = await requestOptional(provider, [
    { type: "request", name: "synergy_accounts" },
    { type: "request", name: "eth_accounts" },
  ]);
  const address = extractAccount(accountsResult);
  if (!address) return null;

  const chainResult = await requestOptional(provider, [
    { type: "fn", name: "getChainId" },
    { type: "request", name: "synergy_chainId" },
    { type: "request", name: "synergy_getChainId" },
    { type: "request", name: "eth_chainId" },
  ]);

  return {
    address,
    chainId: chainIdToDecimal(chainResult),
    chainIdHex: isCurrentTestnetChain(chainResult) ? SYNERGY_TESTNET.chainIdHex : null,
    synId: extractSynId(accountsResult),
    source: "injected",
    canSign: providerCanSign(provider),
    provider,
  };
}

export async function connectInjectedWallet(provider = getInjectedSynergyProvider()) {
  if (!provider) {
    throw new Error("Install or unlock Synergy Wallet to connect an in-browser wallet provider.");
  }

  let accountsResult = null;
  try {
    accountsResult =
      typeof provider.requestAccounts === "function"
        ? await provider.requestAccounts()
        : await providerRequest(provider, "synergy_requestAccounts");
  } catch {
    accountsResult = await providerRequest(provider, "synergy_accounts");
  }

  const address = extractAccount(accountsResult);
  if (!address) throw new Error("Synergy Wallet did not return a wallet address.");

  let chainResult = null;
  try {
    chainResult =
      typeof provider.getChainId === "function" ? await provider.getChainId() : await providerRequest(provider, "synergy_chainId");
  } catch {
    chainResult = await providerRequest(provider, "synergy_getChainId");
  }
  if (!isCurrentTestnetChain(chainResult)) {
    throw new Error(`Synergy Wallet is on chain ${chainResult || "unknown"}; Synergy Testnet requires ${SYNERGY_TESTNET.chainIdHex}.`);
  }

  return {
    address,
    chainId: chainIdToDecimal(chainResult),
    chainIdHex: SYNERGY_TESTNET.chainIdHex,
    synId: extractSynId(accountsResult),
    source: "injected",
    canSign: true,
    provider,
  };
}

export function normalizeSignedEnvelope(result) {
  if (!result) return null;
  if (result.signature || result.signerPublicKey || result.signedBy) return result;
  if (result.signedEnvelope) return normalizeSignedEnvelope(result.signedEnvelope);
  if (result.transaction) return normalizeSignedEnvelope(result.transaction);
  if (result.envelope) return normalizeSignedEnvelope(result.envelope);
  if (result.rawTransaction || result.signedTransaction) return result;
  return null;
}

export async function signEnvelope(envelope, provider = getInjectedSynergyProvider()) {
  if (!provider) throw new Error("Synergy Wallet provider is required for transaction signing.");
  const result =
    typeof provider.signTransaction === "function"
      ? await provider.signTransaction(envelope)
      : await providerRequest(provider, "synergy_signTransaction", [envelope]);
  const signed = normalizeSignedEnvelope(result);
  if (!signed) throw new Error("Synergy Wallet did not return a signed transaction envelope.");
  return signed;
}

export async function sendEnvelopeViaWallet(envelope, provider = getInjectedSynergyProvider()) {
  if (!provider) throw new Error("Synergy Wallet provider is required to send a transaction.");
  if (typeof provider.sendTransaction === "function") {
    return provider.sendTransaction(envelope);
  }
  return providerRequest(provider, "synergy_sendTransaction", [envelope]);
}

export async function signMessage(message, address, provider = getInjectedSynergyProvider()) {
  if (!provider) throw new Error("Synergy Wallet provider is required for message signing.");
  if (typeof provider.signMessage === "function") return provider.signMessage(message, address);
  return providerRequest(provider, "synergy_signMessage", address ? [message, address] : [message]);
}

export function getWalletPairingConfig(env = import.meta.env) {
  const pairingUrl =
    envValue(env, "VITE_RELAY_WALLET_PAIRING_RELAY_URL") ||
    envValue(env, "VITE_SYNERGY_WALLET_PAIRING_RELAY_URL") ||
    hostedPairingUrl();

  if (!pairingUrl) {
    return {
      ok: false,
      message: "Synergy Wallet mobile pairing is unavailable on this origin.",
    };
  }

  return {
    ok: true,
    pairingUrl,
    createPath: envValue(env, "VITE_RELAY_WALLET_PAIRING_CREATE_PATH") || DEFAULT_CREATE_PATH,
    pollPath: envValue(env, "VITE_RELAY_WALLET_PAIRING_POLL_PATH") || DEFAULT_POLL_PATH,
  };
}

export function buildSynergyWalletQrPayload({
  sessionId,
  nonce,
  relayUrl,
  origin,
  expiresAt,
  network = SYNERGY_TESTNET,
  appName = "Synergy Wallet",
  iconUrl = `${origin.replace(/\/+$/, "")}/wallet-icon.png`,
} = {}) {
  const url = new URL("synergywallet://connect");
  url.searchParams.set("session", sessionId);
  url.searchParams.set("nonce", nonce || sessionId);
  url.searchParams.set("origin", origin);
  url.searchParams.set("relay", relayUrl.replace(/\/+$/, ""));
  url.searchParams.set("scopes", DEFAULT_SCOPES.join(","));
  url.searchParams.set("chains", network.slug);
  url.searchParams.set("methods", REQUESTED_METHODS.join(","));
  url.searchParams.set("name", appName);
  url.searchParams.set("icon", iconUrl);
  if (expiresAt) url.searchParams.set("expires", expiresAt);
  return url.toString();
}

export async function createWalletPairingSession({
  config,
  fetchImpl = globalThis.fetch,
  origin = globalThis.location?.origin || "https://relay.synergy-network.io",
  route = globalThis.location?.href || "https://relay.synergy-network.io/",
  network = SYNERGY_TESTNET,
  appName = "Synergy Wallet",
  iconUrl = `${origin.replace(/\/+$/, "")}/wallet-icon.png`,
} = {}) {
  if (!config?.ok) throw new Error(config?.message || "Synergy Wallet mobile pairing configuration is missing.");
  if (typeof fetchImpl !== "function") throw new Error("Synergy Wallet mobile pairing requires fetch support.");

  const response = await fetchImpl(joinPairingUrl(config.pairingUrl, config.createPath), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      app: {
        name: appName,
        route,
        origin,
        iconUrl,
      },
      intent: "connect",
      network: {
        key: network.key,
        displayName: network.displayName,
        slug: network.slug,
        chainIdDecimal: network.chainIdDecimal,
        chainIdHex: network.chainIdHex,
        rpcUrl: network.rpcUrl,
      },
      requestedScopes: DEFAULT_SCOPES,
      requestedChains: [network.slug],
      requestedMethods: REQUESTED_METHODS,
    }),
  });
  const payload = await parseJsonResponse(response);
  const sessionId = payload.sessionId || payload.id || payload.session?.id || "";
  const expiresAt = payload.expiresAt || payload.session?.expiresAt || null;
  const nonce = payload.nonce || payload.session?.nonce || sessionId;
  const pollUrl =
    payload.pollUrl ||
    payload.session?.pollUrl ||
    joinPairingUrl(config.pairingUrl, config.pollPath.replace("{sessionId}", encodeURIComponent(sessionId)));
  const relayUrl = payload.relayUrl || payload.relay_url || payload.session?.relayUrl || config.pairingUrl;
  const qrPayload =
    payload.qrPayload ||
    payload.uri ||
    payload.deepLink ||
    payload.session?.qrPayload ||
    buildSynergyWalletQrPayload({ sessionId, nonce, relayUrl, origin, expiresAt, network, appName, iconUrl });

  if (!sessionId || !qrPayload) {
    throw new Error("Synergy Wallet pairing did not return a sessionId and QR payload.");
  }

  return { sessionId, nonce, qrPayload, pollUrl, relayUrl, expiresAt };
}

export async function pollWalletPairingSession({ session, fetchImpl = globalThis.fetch } = {}) {
  if (!session?.pollUrl) throw new Error("Synergy Wallet pairing session is missing a poll URL.");
  if (typeof fetchImpl !== "function") throw new Error("Synergy Wallet mobile pairing requires fetch support.");

  const response = await fetchImpl(session.pollUrl, {
    method: "GET",
    headers: { Accept: "application/json" },
  });
  const payload = await parseJsonResponse(response);
  return normalizeWalletApproval(payload);
}

function walletActionUrl(session, suffix = "") {
  const sessionId = session?.sessionId || session?.id || "";
  const relayUrl = session?.relayUrl || session?.relay_url || "";
  if (!sessionId || !relayUrl) throw new Error("Synergy Wallet mobile action requires an approved relay session.");
  const path = `/sessions/${encodeURIComponent(sessionId)}/requests${suffix}`;
  return joinPairingUrl(relayUrl, path);
}

function normalizeWalletAction(payload = {}, session) {
  const requestId = payload.requestId || payload.id || payload.request?.requestId || payload.request?.id || "";
  const status = String(payload.status || payload.state || payload.request?.status || "pending").toLowerCase();
  return {
    ...payload,
    requestId,
    status,
    pollUrl: payload.pollUrl || payload.request?.pollUrl || walletActionUrl(session, `/${encodeURIComponent(requestId)}`),
  };
}

export async function createWalletActionRequest({
  session,
  method,
  params = [],
  label = "",
  summary = "",
  metadata = {},
  fetchImpl = globalThis.fetch,
} = {}) {
  if (typeof fetchImpl !== "function") throw new Error("Synergy Wallet mobile action requires fetch support.");
  if (!method) throw new Error("Synergy Wallet mobile action requires a method.");
  const response = await fetchImpl(walletActionUrl(session), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ method, params, label, summary, metadata }),
  });
  const payload = await parseJsonResponse(response);
  return normalizeWalletAction(payload.request || payload, session);
}

export async function pollWalletActionRequest({ action, fetchImpl = globalThis.fetch } = {}) {
  if (!action?.pollUrl) throw new Error("Synergy Wallet mobile action is missing a poll URL.");
  if (typeof fetchImpl !== "function") throw new Error("Synergy Wallet mobile action requires fetch support.");
  const response = await fetchImpl(action.pollUrl, {
    method: "GET",
    headers: { Accept: "application/json" },
  });
  const payload = await parseJsonResponse(response);
  return payload.request || payload;
}

export function normalizeWalletApproval(payload = {}) {
  const rawStatus = String(payload.status || payload.state || payload.session?.status || "pending").toLowerCase();
  const account = extractAccount(payload);
  const chainId = extractChainId(payload) ?? SYNERGY_TESTNET.chainIdHex;

  if (["approved", "connected", "complete", "completed"].includes(rawStatus)) {
    if (!account) {
      return { status: "error", connected: false, error: "Synergy Wallet approved the session without an address." };
    }
    if (!isCurrentTestnetChain(chainId)) {
      return {
        status: "network-mismatch",
        connected: false,
        account,
        chainId,
        error: `Synergy Wallet approved chain ${chainId || "unknown"}; Synergy Testnet requires ${SYNERGY_TESTNET.chainIdHex}.`,
      };
    }
    return {
      status: "approved",
      connected: true,
      account,
      address: account,
      chainId: chainIdToDecimal(chainId),
      chainIdHex: SYNERGY_TESTNET.chainIdHex,
      synId: extractSynId(payload),
      sessionId: payload.sessionId || payload.id || payload.session?.id || "",
      source: "mobile-pairing",
      canSign: providerCanSign(),
    };
  }

  if (["rejected", "denied", "cancelled", "canceled"].includes(rawStatus)) {
    return {
      status: "rejected",
      connected: false,
      error: payload.error?.message || payload.message || "Connection was rejected in Synergy Wallet.",
    };
  }

  if (["expired", "timeout", "timed_out"].includes(rawStatus)) {
    return {
      status: "expired",
      connected: false,
      error: payload.error?.message || payload.message || "Synergy Wallet connection request expired.",
    };
  }

  if (["error", "failed"].includes(rawStatus)) {
    return {
      status: "error",
      connected: false,
      error: payload.error?.message || payload.message || "Synergy Wallet pairing returned an error.",
    };
  }

  return {
    status: "pending",
    connected: false,
    expiresAt: payload.expiresAt || payload.session?.expiresAt || null,
  };
}

export function qrToDataUrl(payload) {
  return QRCode.toDataURL(payload, {
    margin: 1,
    width: 300,
    color: {
      dark: "#071013",
      light: "#f2feff",
    },
  });
}

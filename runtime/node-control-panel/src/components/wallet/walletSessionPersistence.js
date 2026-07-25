export const CONTROL_PANEL_WALLET_SESSION_STORAGE_KEY = 'synergy:node-control-panel:wallet-session:v1';

export function withWalletNetworkDefaults(wallet, { chainId, chainIdHex } = {}) {
  if (!wallet || typeof wallet !== 'object') return null;
  return {
    ...wallet,
    chainId: wallet.chainId ?? chainId,
    chainIdHex: wallet.chainIdHex ?? chainIdHex,
  };
}

function readStorage(storage, key) {
  if (!storage) return null;
  try {
    return storage.getItem(key);
  } catch {
    return null;
  }
}

function writeStorage(storage, key, value) {
  if (!storage) return false;
  try {
    storage.setItem(key, value);
    return true;
  } catch {
    return false;
  }
}

function removeStorage(storage, key) {
  if (!storage) return;
  try {
    storage.removeItem(key);
  } catch {
    // Storage availability must not block wallet operations.
  }
}

function normalizeStoredSession(value, now = Date.now()) {
  const session = value?.session;
  const wallet = value?.wallet;
  if (!wallet?.address || !session?.sessionId || !session?.pollUrl || !session?.relayUrl) return null;
  if (session.expiresAt && Number.isFinite(Date.parse(session.expiresAt)) && Date.parse(session.expiresAt) <= now) {
    return null;
  }
  return {
    wallet: {
      address: wallet.address,
      chainId: wallet.chainId,
      chainIdHex: wallet.chainIdHex,
      synId: wallet.synId || null,
    },
    session: {
      sessionId: session.sessionId,
      nonce: session.nonce || session.sessionId,
      pollUrl: session.pollUrl,
      relayUrl: session.relayUrl,
      expiresAt: session.expiresAt || null,
    },
  };
}

export function readPersistedWalletSession({ storage, legacyStorage, now = Date.now() } = {}) {
  const raw = readStorage(storage, CONTROL_PANEL_WALLET_SESSION_STORAGE_KEY);
  const legacyRaw = raw ? null : readStorage(legacyStorage, CONTROL_PANEL_WALLET_SESSION_STORAGE_KEY);
  const value = raw || legacyRaw;
  if (!value) return null;

  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    removeStorage(storage, CONTROL_PANEL_WALLET_SESSION_STORAGE_KEY);
    removeStorage(legacyStorage, CONTROL_PANEL_WALLET_SESSION_STORAGE_KEY);
    return null;
  }

  const normalized = normalizeStoredSession(parsed, now);
  if (!normalized) {
    removeStorage(storage, CONTROL_PANEL_WALLET_SESSION_STORAGE_KEY);
    removeStorage(legacyStorage, CONTROL_PANEL_WALLET_SESSION_STORAGE_KEY);
    return null;
  }

  if (legacyRaw && !raw) {
    writeStorage(storage, CONTROL_PANEL_WALLET_SESSION_STORAGE_KEY, value);
    removeStorage(legacyStorage, CONTROL_PANEL_WALLET_SESSION_STORAGE_KEY);
  }
  return normalized;
}

export function persistWalletSession({ storage, wallet, session } = {}) {
  if (!wallet?.address || !session?.sessionId || !session?.pollUrl || !session?.relayUrl) return false;
  return writeStorage(
    storage,
    CONTROL_PANEL_WALLET_SESSION_STORAGE_KEY,
    JSON.stringify({
      wallet: {
        address: wallet.address,
        chainId: wallet.chainId,
        chainIdHex: wallet.chainIdHex,
        synId: wallet.synId || null,
      },
      session: {
        sessionId: session.sessionId,
        nonce: session.nonce || session.sessionId,
        pollUrl: session.pollUrl,
        relayUrl: session.relayUrl,
        expiresAt: session.expiresAt || null,
      },
      persistedAt: new Date().toISOString(),
    }),
  );
}

export function clearPersistedWalletSession({ storage, legacyStorage } = {}) {
  removeStorage(storage, CONTROL_PANEL_WALLET_SESSION_STORAGE_KEY);
  removeStorage(legacyStorage, CONTROL_PANEL_WALLET_SESSION_STORAGE_KEY);
}

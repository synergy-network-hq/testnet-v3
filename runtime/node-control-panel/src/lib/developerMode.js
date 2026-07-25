import { useEffect, useState } from 'react';

const DEVELOPER_MODE_STORAGE_KEY = 'synergy:testnet:developer-mode:v1';
const DEVELOPER_MODE_CHANGE_EVENT = 'synergy:testnet:developer-mode-change';

function getLocalStorage() {
  if (typeof window === 'undefined') {
    return null;
  }

  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

function normalizeDeveloperMode(value) {
  if (typeof value === 'boolean') {
    return value;
  }

  const normalized = String(value ?? '').trim().toLowerCase();
  return normalized === 'true' || normalized === '1' || normalized === 'yes' || normalized === 'on';
}

export function readStoredDeveloperMode() {
  const storage = getLocalStorage();
  if (!storage) {
    return false;
  }

  try {
    return normalizeDeveloperMode(storage.getItem(DEVELOPER_MODE_STORAGE_KEY));
  } catch {
    return false;
  }
}

export function writeStoredDeveloperMode(enabled) {
  const normalized = Boolean(enabled);
  const storage = getLocalStorage();

  if (storage) {
    try {
      storage.setItem(DEVELOPER_MODE_STORAGE_KEY, normalized ? 'true' : 'false');
    } catch {
      // Ignore storage errors and still update current-page listeners.
    }
  }

  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(DEVELOPER_MODE_CHANGE_EVENT, {
      detail: { enabled: normalized },
    }));
  }

  return normalized;
}

export function useDeveloperMode() {
  const [developerModeEnabled, setDeveloperModeEnabled] = useState(() => readStoredDeveloperMode());

  useEffect(() => {
    if (typeof window === 'undefined') {
      return undefined;
    }

    const syncFromStorage = () => {
      setDeveloperModeEnabled(readStoredDeveloperMode());
    };

    const handleStorage = (event) => {
      if (!event || event.key == null || event.key === DEVELOPER_MODE_STORAGE_KEY) {
        syncFromStorage();
      }
    };

    const handleChange = (event) => {
      if (typeof event?.detail?.enabled === 'boolean') {
        setDeveloperModeEnabled(event.detail.enabled);
        return;
      }

      syncFromStorage();
    };

    window.addEventListener('storage', handleStorage);
    window.addEventListener(DEVELOPER_MODE_CHANGE_EVENT, handleChange);

    return () => {
      window.removeEventListener('storage', handleStorage);
      window.removeEventListener(DEVELOPER_MODE_CHANGE_EVENT, handleChange);
    };
  }, []);

  const updateDeveloperMode = (nextValue) => {
    const resolved = typeof nextValue === 'function'
      ? nextValue(developerModeEnabled)
      : nextValue;
    const normalized = writeStoredDeveloperMode(resolved);
    setDeveloperModeEnabled(normalized);
    return normalized;
  };

  return [developerModeEnabled, updateDeveloperMode];
}

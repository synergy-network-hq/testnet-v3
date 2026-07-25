import { useEffect, useState } from 'react';
import {
  modeLabel as profileModeLabel,
  normalizePanelViewMode,
} from '../components/control-panel/viewProfiles';

const VIEW_MODE_STORAGE_KEY = 'synergy:testnet:view-mode:v2';
const LEGACY_VIEW_MODE_STORAGE_KEY = 'synergy:testnet:view-mode:v1';
const VIEW_MODE_EVENT = 'synergy:testnet:view-mode-change';

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

function normalizeViewMode(value) {
  return normalizePanelViewMode(value);
}

export function readStoredViewMode() {
  const storage = getLocalStorage();
  if (!storage) {
    return 'basic';
  }

  try {
    const current = storage.getItem(VIEW_MODE_STORAGE_KEY);
    if (current) {
      return normalizeViewMode(current);
    }
    return normalizeViewMode(storage.getItem(LEGACY_VIEW_MODE_STORAGE_KEY));
  } catch {
    return 'basic';
  }
}

export function writeStoredViewMode(value) {
  const normalized = normalizeViewMode(value);
  const storage = getLocalStorage();

  if (storage) {
    try {
      storage.setItem(VIEW_MODE_STORAGE_KEY, normalized);
      storage.removeItem(LEGACY_VIEW_MODE_STORAGE_KEY);
    } catch {
      // Keep dispatch behavior even if storage throws.
    }
  }

  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(VIEW_MODE_EVENT, {
      detail: { mode: normalized },
    }));
  }

  return normalized;
}

export function usePanelViewMode() {
  const [viewMode, setViewMode] = useState(() => readStoredViewMode());

  useEffect(() => {
    if (typeof window === 'undefined') {
      return undefined;
    }

    const sync = () => {
      setViewMode(readStoredViewMode());
    };

    const handleStorage = (event) => {
      if (!event || event.key == null || event.key === VIEW_MODE_STORAGE_KEY) {
        sync();
      }
    };

    const handleChange = (event) => {
      if (event?.detail?.mode) {
        setViewMode(normalizeViewMode(event.detail.mode));
        return;
      }

      sync();
    };

    window.addEventListener('storage', handleStorage);
    window.addEventListener(VIEW_MODE_EVENT, handleChange);

    return () => {
      window.removeEventListener('storage', handleStorage);
      window.removeEventListener(VIEW_MODE_EVENT, handleChange);
    };
  }, []);

  const updateViewMode = (nextValue) => {
    const resolved = typeof nextValue === 'function'
      ? nextValue(viewMode)
      : nextValue;
    const normalized = writeStoredViewMode(resolved);
    setViewMode(normalized);
    return normalized;
  };

  return [viewMode, updateViewMode];
}

export function modeLabel(viewMode) {
  return profileModeLabel(normalizeViewMode(viewMode));
}

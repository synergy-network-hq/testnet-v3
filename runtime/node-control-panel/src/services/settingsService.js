import { checkForUpdate, downloadAndInstallUpdate } from '../lib/appUpdater';
import { invoke, openExternal } from '../lib/desktopClient';

export const defaultControlPanelSettings = {
  autoStartNode: false,
  checkUpdatesAutomatically: true,
  desktopNotifications: true,
  darkTheme: true,
  language: 'English',
  alertEmail: '',
  webhookUrl: '',
  criticalAlerts: true,
  dailySummary: false,
  encryptedStorage: true,
  passwordLock: false,
  sessionTimeout: '15 minutes',
  snapshotLocation: '',
  logDirectory: '',
  dataDirectory: '',
  logRetention: '30 days',
  lockPasswordHash: '',
  lockPasswordSalt: '',
};

function getBridge() {
  if (typeof window !== 'undefined' && window.synergyDesktop) {
    return window.synergyDesktop;
  }
  return null;
}

function requireBridge() {
  const bridge = getBridge();
  if (!bridge?.getControlPanelSettings || !bridge?.updateControlPanelSettings) {
    throw new Error('Electron desktop settings bridge is required.');
  }
  return bridge;
}

function normalizeSettings(value = {}) {
  return { ...defaultControlPanelSettings, ...(value || {}) };
}

function parseTimeoutMinutes(value) {
  const text = String(value || '').trim();
  const match = text.match(/^(\d+)/);
  return match ? Number(match[1]) : 15;
}

function validateEmail(value) {
  const text = String(value || '').trim();
  if (!text) return true;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(text);
}

function validateWebhook(value) {
  const text = String(value || '').trim();
  if (!text) return true;
  try {
    const url = new URL(text);
    return url.protocol === 'https:' || url.protocol === 'http:';
  } catch {
    return false;
  }
}

async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function randomSalt() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function notifyDesktop(title, body) {
  const bridge = getBridge();
  if (bridge?.showNotification) {
    return bridge.showNotification({ title, body });
  }
  if (typeof Notification === 'undefined') {
    throw new Error('Desktop notifications are unavailable in this renderer.');
  }
  if (Notification.permission === 'default') {
    await Notification.requestPermission();
  }
  if (Notification.permission !== 'granted') {
    throw new Error('Desktop notification permission was denied.');
  }
  new Notification(title, { body });
  return { shown: true };
}

export function sessionTimeoutMs(settings) {
  return parseTimeoutMinutes(settings?.sessionTimeout) * 60 * 1000;
}

export const settingsService = {
  async getSettings() {
    const bridge = requireBridge();
    return normalizeSettings(await bridge.getControlPanelSettings());
  },

  async updateSettings(patch) {
    const nextPatch = { ...(patch || {}) };
    if ('alertEmail' in nextPatch && !validateEmail(nextPatch.alertEmail)) {
      throw new Error('Alert email must be a valid email address.');
    }
    if ('webhookUrl' in nextPatch && !validateWebhook(nextPatch.webhookUrl)) {
      throw new Error('Webhook URL must be http:// or https://.');
    }
    const bridge = requireBridge();
    return normalizeSettings(await bridge.updateControlPanelSettings(nextPatch));
  },

  async setLockPassword(password) {
    const text = String(password || '');
    if (text.length < 8) {
      throw new Error('Lock password must be at least 8 characters.');
    }
    const lockPasswordSalt = randomSalt();
    const lockPasswordHash = await sha256Hex(`${lockPasswordSalt}:${text}`);
    return this.updateSettings({ lockPasswordHash, lockPasswordSalt, passwordLock: true });
  },

  async verifyLockPassword(settings, password) {
    if (!settings?.lockPasswordHash || !settings?.lockPasswordSalt) {
      return false;
    }
    const hash = await sha256Hex(`${settings.lockPasswordSalt}:${String(password || '')}`);
    return hash === settings.lockPasswordHash;
  },

  async validatePath(pathValue) {
    const path = String(pathValue || '').trim();
    if (!path) {
      return { ok: false, message: 'Path is required.' };
    }
    return invoke('testnet_validate_path', { path });
  },

  async checkForUpdates() {
    return checkForUpdate();
  },

  async installUpdate() {
    return downloadAndInstallUpdate();
  },

  async sendTestNotifications(settings) {
    const result = { desktop: null, webhook: null, email: null };
    if (settings.desktopNotifications) {
      result.desktop = await notifyDesktop(
        'Synergy Node Control Panel',
        'Desktop notification channel verified.',
      );
    }
    if (settings.webhookUrl) {
      const response = await fetch(settings.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source: 'synergy-node-control-panel',
          event: 'notification.test',
          generatedAt: new Date().toISOString(),
        }),
      });
      if (!response.ok) {
        throw new Error(`Webhook test failed with HTTP ${response.status}.`);
      }
      result.webhook = { ok: true, status: response.status };
    }
    if (settings.alertEmail) {
      const subject = encodeURIComponent('Synergy Node Control Panel notification test');
      const body = encodeURIComponent('This verifies the configured alert email destination.');
      await openExternal(`mailto:${encodeURIComponent(settings.alertEmail)}?subject=${subject}&body=${body}`);
      result.email = { opened: true };
    }
    return result;
  },
};

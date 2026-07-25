import { getVersion } from './desktopClient';

function getBridge() {
  if (typeof window !== 'undefined' && window.synergyDesktop) {
    return window.synergyDesktop;
  }
  return null;
}

function hasNativeUpdater() {
  const bridge = getBridge();
  return !!(bridge?.checkForUpdate && bridge?.downloadUpdate && bridge?.installUpdate);
}

/**
 * Relaunch (restart) the application immediately.
 */
export async function relaunchApp() {
  const bridge = getBridge();
  if (bridge?.relaunch) {
    await bridge.relaunch();
  }
}

/**
 * Check if an update is available.
 * Returns { available: boolean, version?: string, currentVersion?: string, error?: string }
 */
export async function checkForUpdate() {
  try {
    if (hasNativeUpdater()) {
      try {
        const bridge = getBridge();
        const result = await bridge.checkForUpdate();
        const updateInfo = result?.updateInfo;
        if (updateInfo?.version) {
          const currentVersion = await getVersion();
          const isNewer = compareVersions(updateInfo.version, currentVersion) > 0;
          return {
            available: isNewer,
            version: updateInfo.version,
            currentVersion,
          };
        }
        // Native updater returned no version info — fall through to GitHub API
      } catch {
        // Native updater threw (e.g. no latest.yml published yet) — fall through
      }
    }

    // Fallback: check GitHub releases API directly
    return await checkForPublishedUpdate();
  } catch (error) {
    return { available: false, error: normalizeUpdateError(error) };
  }
}

/**
 * Download and install an available update.
 * Returns { status: string, message: string }
 */
export async function downloadAndInstallUpdate(version = '') {
  try {
    if (hasNativeUpdater()) {
      const bridge = getBridge();
      let targetVersion = String(version || '').trim();
      if (!targetVersion) {
        const update = await checkForUpdate();
        if (!update?.available || !update.version) {
          return {
            status: update?.error ? 'error' : 'up-to-date',
            message: update?.error || 'You are running the latest published version.',
          };
        }
        targetVersion = update.version;
      }
      const result = await bridge.downloadUpdate({ version: targetVersion });
      if (result?.manualInstall) {
        return {
          status: 'manual-install',
          version: result.version || targetVersion,
          url: result.url,
          message: 'The notarized macOS installer opened in your browser. Open the DMG and replace the app in Applications.',
        };
      }
      return {
        status: 'downloading',
        message: 'Downloading update in the background. The app will restart automatically when ready.',
      };
    }

    return {
      status: 'error',
      message: 'Native updater is not bundled in this build.',
    };
  } catch (error) {
    return {
      status: 'error',
      message: normalizeUpdateError(error),
    };
  }
}

/**
 * Quit and install the downloaded update.
 */
export async function installDownloadedUpdate(version = '') {
  if (hasNativeUpdater()) {
    const bridge = getBridge();
    return bridge.installUpdate({ version });
  }
  return null;
}

/**
 * Subscribe to updater events from the main process.
 * Returns an unsubscribe function.
 */
export function onUpdaterEvent(eventName, callback) {
  const bridge = getBridge();
  if (bridge?.onUpdaterEvent) {
    return bridge.onUpdaterEvent(`updater:${eventName}`, callback);
  }
  return () => {};
}

/**
 * Legacy combined check-and-install function (kept for compatibility).
 */
export async function checkAndInstallAppUpdate() {
  return downloadAndInstallUpdate();
}

// ── Internal helpers ──

const RELEASES_API_LATEST = 'https://api.github.com/repos/synergy-network-hq/synergy-node-control-panel-releases/releases/latest';

function parseVersionParts(value) {
  const normalized = String(value || '').trim().replace(/^v/i, '');
  return normalized.split('.').map((part) => Number.parseInt(part, 10) || 0);
}

function compareVersions(left, right) {
  const leftParts = parseVersionParts(left);
  const rightParts = parseVersionParts(right);
  const maxLength = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < maxLength; index += 1) {
    const a = leftParts[index] || 0;
    const b = rightParts[index] || 0;
    if (a > b) return 1;
    if (a < b) return -1;
  }
  return 0;
}

async function checkForPublishedUpdate() {
  const currentVersion = await getVersion();
  const response = await fetch(RELEASES_API_LATEST, {
    headers: { Accept: 'application/vnd.github+json' },
  });

  if (!response.ok) {
    throw new Error(`GitHub release lookup failed with status ${response.status}`);
  }

  const release = await response.json();
  const latestVersion = String(release?.tag_name || '').replace(/^v/i, '');
  if (!latestVersion) {
    throw new Error('Latest GitHub release does not contain a version tag.');
  }

  if (compareVersions(latestVersion, currentVersion) <= 0) {
    return { available: false };
  }

  return { available: true, version: latestVersion, currentVersion };
}

function normalizeUpdateError(error) {
  const text = String(error?.message ?? error ?? '').trim();
  const lower = text.toLowerCase();

  if (lower.includes('no published versions') || lower.includes('cannot find channel')) {
    return 'No published auto-update package is available for this platform yet.';
  }

  if (lower.includes('network') || lower.includes('timed out') || lower.includes('timeout')) {
    return 'Update check failed due to network/timeout. Verify internet access.';
  }

  if (lower.includes('rate limit') || lower.includes('api rate limit')) {
    return 'Update check hit the GitHub rate limit. Try again shortly.';
  }

  if (lower.includes('cannot update while running') && lower.includes('disk image')) {
    return 'Move the app into Applications, launch it from Applications, then run the update again.';
  }

  if (lower.includes('code signature') || lower.includes('signature') || lower.includes('signed bundle')) {
    return 'This build is not signed correctly for native auto-update. Install a signed release build and try again.';
  }

  if (lower.includes('cannot find appimage') || lower.includes('appimageupdat') || lower.includes('deb package')) {
    return 'This Linux install type does not support native in-app updates. Install the latest packaged release for your platform.';
  }

  if (lower.includes('404') || lower.includes('not found')) {
    return 'No update metadata found. A new release may not have been published yet.';
  }

  return `Update check failed: ${text || 'unknown error'}`;
}

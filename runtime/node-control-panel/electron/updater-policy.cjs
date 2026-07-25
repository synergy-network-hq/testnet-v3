const RELEASES_DOWNLOAD_BASE = 'https://github.com/synergy-network-hq/synergy-node-control-panel-releases/releases/download';

function normalizeReleaseVersion(value) {
  const normalized = String(value || '').trim().replace(/^v/i, '');
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(normalized)) {
    return null;
  }
  return normalized;
}

function usesNativeInstaller(platform) {
  return platform !== 'darwin';
}

function macDmgReleaseUrl(version, arch = 'arm64') {
  const normalizedVersion = normalizeReleaseVersion(version);
  if (!normalizedVersion) {
    throw new Error('A valid published update version is required to open the macOS installer.');
  }

  const normalizedArch = arch === 'x64' ? 'x64' : 'arm64';
  return `${RELEASES_DOWNLOAD_BASE}/v${normalizedVersion}/Synergy.Node.Control.Panel-${normalizedVersion}-${normalizedArch}.dmg`;
}

module.exports = {
  macDmgReleaseUrl,
  normalizeReleaseVersion,
  usesNativeInstaller,
};

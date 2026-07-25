const assert = require('node:assert/strict');
const {
  macDmgReleaseUrl,
  normalizeReleaseVersion,
  usesNativeInstaller,
} = require('../../electron/updater-policy.cjs');

assert.equal(normalizeReleaseVersion('v19.0.3'), '19.0.3');
assert.equal(normalizeReleaseVersion('19.0.3-rc.1'), '19.0.3-rc.1');
assert.equal(normalizeReleaseVersion('../../latest'), null);
assert.equal(normalizeReleaseVersion('19.0'), null);

assert.equal(usesNativeInstaller('darwin'), false);
assert.equal(usesNativeInstaller('linux'), true);
assert.equal(usesNativeInstaller('win32'), true);

assert.equal(
  macDmgReleaseUrl('v19.0.3', 'arm64'),
  'https://github.com/synergy-network-hq/synergy-node-control-panel-releases/releases/download/v19.0.3/Synergy.Node.Control.Panel-19.0.3-arm64.dmg',
);
assert.equal(
  macDmgReleaseUrl('19.0.3', 'x64'),
  'https://github.com/synergy-network-hq/synergy-node-control-panel-releases/releases/download/v19.0.3/Synergy.Node.Control.Panel-19.0.3-x64.dmg',
);
assert.throws(() => macDmgReleaseUrl('not-a-version'), /valid published update version/);

console.log('macOS updater policy tests passed');

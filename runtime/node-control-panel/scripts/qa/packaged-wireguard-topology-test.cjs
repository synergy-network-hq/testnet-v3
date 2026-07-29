const assert = require('node:assert/strict');
const test = require('node:test');

const {
  activatePackagedWireguardConfig,
  canonicalPackagedWireguardPeers,
  validatePackagedWireguardConfig,
} = require('../../electron/onboarding/innernet.cjs');

const LOCAL_IP = '10.70.10.1';

function packageData(peerIps) {
  return {
    available: true,
    vpnIp: `${LOCAL_IP}/16`,
    wireguardPrivateKey: 'test-private-key',
    wireguardConfig: [
      '[Interface]',
      `Address = ${LOCAL_IP}/16`,
      'PrivateKey = test-private-key',
      '',
      ...peerIps.flatMap((peer, index) => [
        '[Peer]',
        `PublicKey = test-public-key-${index}`,
        `AllowedIPs = ${peer}/32`,
        '',
      ]),
    ].join('\n'),
  };
}

test('a packaged validator configuration contains every other canonical Testnet-v3 participant', () => {
  const peers = canonicalPackagedWireguardPeers(LOCAL_IP);
  assert.equal(peers.length, 24);
  const expected = [
    '10.70.0.1',
    ...Array.from({ length: 20 }, (_, index) => `10.70.10.${index + 2}`),
    '10.70.20.1',
    '10.70.20.2',
    '10.70.20.3',
  ];
  assert.deepEqual(new Set(peers), new Set(expected));
  assert.doesNotThrow(() => validatePackagedWireguardConfig(packageData(peers)));
});

test('a packaged validator configuration rejects a partial mesh even when it has many peers', () => {
  const partial = canonicalPackagedWireguardPeers(LOCAL_IP).filter((peer) => peer !== '10.70.20.3');
  assert.throws(
    () => validatePackagedWireguardConfig(packageData(partial)),
    (error) => error?.code === 'PACKAGED_WIREGUARD_INVALID',
  );
});

test('packaged activation retires a conflicting Innernet service before starting the static mesh', async () => {
  const calls = [];
  const now = Math.floor(Date.now() / 1_000);
  const executor = {
    mode: 'remote',
    async writeFile(filePath) {
      calls.push(['writeFile', filePath]);
    },
    async removeFile(filePath) {
      calls.push(['removeFile', filePath]);
    },
    async run(command, args) {
      calls.push(['run', command, args]);
      if (command === 'wg' && args.join(' ') === 'pubkey') return { stdout: 'test-public-key\n' };
      if (command === 'ip') return { stdout: `6: sy-vpn    inet ${LOCAL_IP}/16 scope global sy-vpn\n` };
      throw new Error(`unexpected unprivileged command: ${command} ${args.join(' ')}`);
    },
    async runElevated(command, args) {
      calls.push(['runElevated', command, args]);
      if (command === '/bin/sh') return { stdout: '' };
      if (command === 'mkdir' || command === 'install' || command === 'wg-quick') return { stdout: '' };
      if (command === 'systemctl' && args.join(' ') === 'enable wg-quick@sy-vpn.service') return { stdout: '' };
      if (command === 'wg' && args.join(' ') === 'show interfaces') return { stdout: 'sy-vpn\n' };
      if (command === 'wg' && args.join(' ') === 'show sy-vpn dump') {
        return { stdout: `private\tpublic\t51820\t0\npeer\t(none)\t198.51.100.1:51820\t10.70.0.1/32\t${now}\t0\t0\t25\n` };
      }
      throw new Error(`unexpected elevated command: ${command} ${args.join(' ')}`);
    },
  };
  const result = await activatePackagedWireguardConfig(executor, {
    ...packageData(canonicalPackagedWireguardPeers(LOCAL_IP)),
    wireguardPublicKey: 'test-public-key',
  });
  assert.equal(result.handshakeConfirmed, true);
  const retirement = calls.find(([kind, command]) => kind === 'runElevated' && command === '/bin/sh');
  assert.match(retirement[2][1], /disable --now synergy-innernet-refresh\.timer/);
  assert.match(retirement[2][1], /disable --now synergy-innernet\.service/);
  assert.equal(calls.some(([, command, args]) => command === 'wg-quick' && args.join(' ') === 'up sy-vpn'), true);
});

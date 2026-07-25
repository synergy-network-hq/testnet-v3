import assert from 'node:assert/strict';
import test from 'node:test';

import { normalizeAccountSnapshot } from '../../src/wallet-connection/lib/accountSnapshot.js';
import { withWalletNetworkDefaults } from '../../src/components/wallet/walletSessionPersistence.js';
import { createWagmiConfig } from '../../src/wallet-connection/services/evm-wallet.js';

test('normalizes a transient null Wagmi account before chainId access', () => {
  const account = normalizeAccountSnapshot(null);

  assert.equal(account.chainId, undefined);
  assert.equal(account.address, undefined);
  assert.equal(account.isConnected, false);
});

test('preserves a connected Wagmi account snapshot', () => {
  const connected = { address: '0x1234', chainId: 1264, isConnected: true };

  assert.equal(normalizeAccountSnapshot(connected), connected);
});

test('does not dereference an absent Synergy wallet while persistence mounts', () => {
  assert.equal(withWalletNetworkDefaults(null, { chainId: 1264, chainIdHex: '0x4f0' }), null);
});

test('adds Synergy network defaults to a wallet before persistence', () => {
  assert.deepEqual(
    withWalletNetworkDefaults({ address: 'syn1operator' }, { chainId: 1264, chainIdHex: '0x4f0' }),
    { address: 'syn1operator', chainId: 1264, chainIdHex: '0x4f0' },
  );
});

test('falls back to injected-only wallet config when default wallet bootstrap throws', () => {
  const config = createWagmiConfig({
    defaultConfigFactory: () => {
      throw new TypeError("Cannot read properties of null (reading 'chainId')");
    },
  });

  assert.ok(config);
  assert.equal(typeof config.subscribe, 'function');
});

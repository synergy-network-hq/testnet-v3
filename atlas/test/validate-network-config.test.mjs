import assert from 'node:assert/strict';
import test from 'node:test';
import { validateNetworkConfig } from '../scripts/validate-network-config.mjs';

const digest = 'a'.repeat(64);
const baseConfig = () => ({
  schema_version: 1,
  chain_id: 1266,
  chain_incarnation: 4,
  network_id: 'synergy-testnet-v3',
  genesis_hash: digest,
  network_magic: '1a2b3c4d',
  finalization: { status: 'final', approval_sha256: digest, release_sha256: digest },
  endpoints: { rpc: 'https://rpc.example.test', api: 'https://api.example.test', websocket: 'wss://ws.example.test' },
  token_metadata: { source_url: 'https://metadata.example.test/tokens.json', sha256: digest },
  validator_registry: { source_url: 'https://metadata.example.test/validators.json', sha256: digest },
  contracts: { source_url: 'https://metadata.example.test/contracts.json', sha256: digest },
  fee_reward: { source_url: 'https://metadata.example.test/economics.json', sha256: digest },
  posy_etdag: { source_url: 'https://metadata.example.test/consensus.json', sha256: digest, target_block_time_ms: 2000 },
});

test('accepts a complete final Testnet-v3 configuration', () => {
  const config = validateNetworkConfig(baseConfig());
  assert.equal(config.chain_id, 1266);
  assert.equal(config.chain_incarnation, 4);
  assert.equal(config.network_id, 'synergy-testnet-v3');
  assert.match(config.manifest_sha256, /^[a-f0-9]{64}$/);
});

test('fails closed when finalization is not final', () => {
  const config = baseConfig();
  config.finalization.status = 'candidate';
  assert.throws(() => validateNetworkConfig(config), /finalization\.status/);
});

test('fails closed on a non-Testnet-v3 chain identity', () => {
  const config = baseConfig();
  config.chain_id = 1265;
  assert.throws(() => validateNetworkConfig(config), /chain_id/);
});

test('fails closed on a stale chain incarnation', () => {
  const config = baseConfig();
  config.chain_incarnation = 3;
  assert.throws(() => validateNetworkConfig(config), /chain_incarnation/);
});

test('fails closed without a secure websocket endpoint', () => {
  const config = baseConfig();
  config.endpoints.websocket = 'ws://ws.example.test';
  assert.throws(() => validateNetworkConfig(config), /websocket/);
});

import assert from 'node:assert/strict';
import test from 'node:test';
import { preflightLiveRpc } from '../scripts/preflight-live-rpc.mjs';

const digest = 'b'.repeat(64);
const config = {
  chain_id: 1266,
  chain_incarnation: 4,
  network_id: 'synergy-testnet-v3',
  genesis_hash: digest,
  endpoints: { rpc: 'https://rpc.example.test' },
};

function successfulRpcFetch(overrides = {}) {
  return async (_url, request) => {
    const { method } = JSON.parse(request.body);
    const result = method === 'synergy_chainId'
      ? { chain_id: 1266, chain_incarnation: 4, network_id: 'synergy-testnet-v3', genesis_hash: digest, ...overrides }
      : { method };
    return { ok: true, status: 200, json: async () => ({ jsonrpc: '2.0', result }) };
  };
}

test('accepts an RPC that matches final Testnet-v3 identity and sources', async () => {
  const result = await preflightLiveRpc(config, successfulRpcFetch());
  assert.equal(result.identity.chainId, 1266);
  assert.equal(result.identity.chainIncarnation, 4);
  assert.equal(result.identity.networkId, 'synergy-testnet-v3');
  assert.equal(result.identity.genesisHash, digest);
});

test('rejects an RPC from an old chain incarnation', async () => {
  await assert.rejects(
    () => preflightLiveRpc(config, successfulRpcFetch({ chain_incarnation: 3 })),
    /chain incarnation/,
  );
});

test('rejects an RPC with a different genesis hash', async () => {
  await assert.rejects(
    () => preflightLiveRpc(config, successfulRpcFetch({ genesis_hash: 'c'.repeat(64) })),
    /genesis hash/,
  );
});

test('rejects a malformed RPC response', async () => {
  const fetchImpl = async () => ({ ok: true, status: 200, json: async () => ({ jsonrpc: '2.0' }) });
  await assert.rejects(() => preflightLiveRpc(config, fetchImpl), /no result/);
});

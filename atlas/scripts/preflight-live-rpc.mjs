import { pathToFileURL } from 'node:url';
import { readAndValidateConfig } from './validate-network-config.mjs';

function fail(message) {
  throw new Error(`Atlas Testnet-v3 RPC preflight failed: ${message}`);
}

function record(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

async function rpcCall(endpoint, method, fetchImpl) {
  const response = await fetchImpl(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: method, method, params: [] }),
  });
  if (!response.ok) fail(`${method} returned HTTP ${response.status}`);
  const body = await response.json();
  if (body?.error) fail(`${method} returned ${body.error.message || 'an RPC error'}`);
  if (!Object.prototype.hasOwnProperty.call(body || {}, 'result')) fail(`${method} returned no result`);
  return body.result;
}

function identityFrom(result) {
  const root = record(result);
  const identity = record(root.identity);
  const source = Object.keys(identity).length ? identity : root;
  return {
    chainId: source.chain_id ?? source.chainId,
    chainIncarnation: source.chain_incarnation ?? source.chainIncarnation,
    networkId: source.network_id ?? source.networkId,
    genesisHash: source.genesis_hash ?? source.genesisHash,
  };
}

export async function preflightLiveRpc(config, fetchImpl = fetch) {
  const identity = identityFrom(await rpcCall(config.endpoints.rpc, 'synergy_chainId', fetchImpl));
  if (identity.chainId !== config.chain_id) fail(`RPC chain ID ${String(identity.chainId)} does not match ${config.chain_id}`);
  if (identity.chainIncarnation !== config.chain_incarnation) fail(`RPC chain incarnation ${String(identity.chainIncarnation)} does not match ${config.chain_incarnation}`);
  if (identity.networkId !== config.network_id) fail(`RPC network ID ${String(identity.networkId)} does not match ${config.network_id}`);
  if (identity.genesisHash !== config.genesis_hash) fail('RPC genesis hash does not match the final network manifest');

  const [finalizedHead, validators, feeSchedule, etdag, tokens] = await Promise.all([
    rpcCall(config.endpoints.rpc, 'synergy_getFinalizedHead', fetchImpl),
    rpcCall(config.endpoints.rpc, 'synergy_getValidatorSetSnapshot', fetchImpl),
    rpcCall(config.endpoints.rpc, 'synergy_getFeeSchedule', fetchImpl),
    rpcCall(config.endpoints.rpc, 'synergy_getEtdagStatus', fetchImpl),
    rpcCall(config.endpoints.rpc, 'synergy_stsGetTokens', fetchImpl),
  ]);

  return { identity, finalizedHead, validators, feeSchedule, etdag, tokens };
}

async function main() {
  const path = process.argv[2];
  if (!path) fail('usage: preflight-live-rpc.mjs <final-network.json>');
  const config = await readAndValidateConfig(path);
  const result = await preflightLiveRpc(config);
  process.stdout.write(`${JSON.stringify({ identity: result.identity, preflight: 'passed' })}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}

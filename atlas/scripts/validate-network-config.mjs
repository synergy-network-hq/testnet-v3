import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const HEX_64 = /^[a-f0-9]{64}$/;
const HEX_8 = /^[a-f0-9]{8}$/;
const REQUIRED_SECTION_NAMES = ['token_metadata', 'validator_registry', 'contracts', 'fee_reward', 'posy_etdag'];

function fail(message) {
  throw new Error(`Invalid Atlas Testnet-v3 network configuration: ${message}`);
}

function asObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  return value;
}

function requiredUrl(value, label, protocol) {
  if (typeof value !== 'string' || value.length === 0) fail(`${label} is required`);
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail(`${label} must be a URL`);
  }
  if (protocol && parsed.protocol !== protocol) fail(`${label} must use ${protocol}`);
  if (!protocol && !['http:', 'https:'].includes(parsed.protocol)) fail(`${label} must use HTTP or HTTPS`);
  return parsed.toString();
}

function requiredDigest(value, label) {
  if (typeof value !== 'string' || !HEX_64.test(value)) fail(`${label} must be a lowercase SHA-256 digest`);
  return value;
}

export function validateNetworkConfig(config) {
  const input = asObject(config, 'configuration');
  if (input.schema_version !== 1) fail('schema_version must be 1');
  if (input.chain_id !== 1266) fail('chain_id must be 1266');
  if (input.chain_incarnation !== 4) fail('chain_incarnation must be 4');
  if (input.network_id !== 'synergy-testnet-v3') fail('network_id must be synergy-testnet-v3');
  if (!HEX_64.test(input.genesis_hash || '')) fail('genesis_hash must be a lowercase 32-byte hash');
  if (!HEX_8.test(input.network_magic || '')) fail('network_magic must be a lowercase 4-byte value');

  const finalization = asObject(input.finalization, 'finalization');
  if (finalization.status !== 'final') fail('finalization.status must be final');
  requiredDigest(finalization.approval_sha256, 'finalization.approval_sha256');
  requiredDigest(finalization.release_sha256, 'finalization.release_sha256');

  const endpoints = asObject(input.endpoints, 'endpoints');
  const normalizedEndpoints = {
    rpc: requiredUrl(endpoints.rpc, 'endpoints.rpc'),
    api: requiredUrl(endpoints.api, 'endpoints.api'),
    websocket: requiredUrl(endpoints.websocket, 'endpoints.websocket', 'wss:'),
  };

  for (const name of REQUIRED_SECTION_NAMES) {
    const section = asObject(input[name], name);
    requiredUrl(section.source_url, `${name}.source_url`);
    requiredDigest(section.sha256, `${name}.sha256`);
  }
  if (!Number.isInteger(input.posy_etdag.target_block_time_ms) || input.posy_etdag.target_block_time_ms <= 0) {
    fail('posy_etdag.target_block_time_ms must be a positive integer');
  }

  return {
    ...input,
    endpoints: normalizedEndpoints,
    manifest_sha256: createHash('sha256').update(JSON.stringify(input)).digest('hex'),
  };
}

export async function readAndValidateConfig(path) {
  let parsed;
  try {
    parsed = JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    fail(`cannot read ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
  return validateNetworkConfig(parsed);
}

async function main() {
  const path = process.argv[2];
  if (!path) fail('usage: validate-network-config.mjs <network.json>');
  const config = await readAndValidateConfig(path);
  process.stdout.write(`${JSON.stringify({
    chain_id: config.chain_id,
    chain_incarnation: config.chain_incarnation,
    network_id: config.network_id,
    genesis_hash: config.genesis_hash,
    network_magic: config.network_magic,
    manifest_sha256: config.manifest_sha256,
  })}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}

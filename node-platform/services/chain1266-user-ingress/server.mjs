import http from 'node:http';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

// Supplied by a verified deployment context; never learned from the upstream being checked.
export function validateNetworkContext(context) {
  if (!context || !Number.isSafeInteger(context.chain_id) || context.chain_id <= 0
      || typeof context.network_id !== 'string' || !context.network_id.trim()
      || !/^[a-f0-9]{64}$/.test(context.genesis_hash)
      || !Number.isSafeInteger(context.chain_incarnation) || context.chain_incarnation < 0) {
    throw new Error('Explicit authenticated network context required.');
  }
  return Object.freeze({ ...context });
}
const MAX_BODY_BYTES = 256 * 1024;
const MAX_IN_FLIGHT = 32;

function reply(response, status, payload) {
  response.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  response.end(JSON.stringify(payload));
}

function rpcError(id, code, message) {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

function chainId(value) {
  if (typeof value === 'number') return value;
  if (typeof value !== 'string') return NaN;
  return value.startsWith('0x') ? Number.parseInt(value.slice(2), 16) : Number(value);
}

export function validateEnvelope(body, context) {
  context = validateNetworkContext(context);
  if (!body || typeof body !== 'object' || Array.isArray(body) || body.jsonrpc !== '2.0'
      || body.method !== 'synergy_submitAegisTransaction' || !Array.isArray(body.params)
      || body.params.length !== 1) return 'Only one signed Aegis transaction is accepted.';
  const envelope = body.params[0];
  const tx = envelope?.transaction;
  if (!tx || typeof tx !== 'object' || Array.isArray(tx) || !envelope.public_key || !envelope.lifecycle_record) {
    return 'Signed Aegis envelope is incomplete.';
  }
  if (chainId(tx.chain_id) !== context.chain_id || tx.network_id !== context.network_id) {
    return 'Transaction does not target the selected chain and network.';
  }
  if (tx.aegis_pq_signature?.algorithm !== 'mldsa87'
      || envelope.public_key?.algorithm !== 'mldsa87'
      || !Array.isArray(tx.aegis_pq_signature?.signature_bytes)
      || tx.aegis_pq_signature.signature_bytes.length === 0) {
    return 'A user transaction requires an ML-DSA-87 signature.';
  }
  if (typeof tx.sender_uma_or_account !== 'string' || !tx.sender_uma_or_account.startsWith('syn')) {
    return 'Transaction sender is missing.';
  }
  return null;
}

async function readBody(request) {
  let bytes = 0;
  const chunks = [];
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > MAX_BODY_BYTES) throw new Error('request_too_large');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

export async function verifyAuthority(upstream, context, fetchImpl = globalThis.fetch) {
  const expected = validateNetworkContext(context);
  const response = await fetchImpl(upstream, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 'ingress-chain-check', method: 'synergy_getChainId', params: [] }),
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw new Error('Authority chain probe failed.');
  const data = await response.json();
  const actual = data.chain_context;
  if (chainId(data.result) !== expected.chain_id || chainId(actual?.chain_id) !== expected.chain_id
      || actual?.genesis_hash !== expected.genesis_hash || actual?.chain_incarnation !== expected.chain_incarnation) {
    throw new Error('Authority differs from the authenticated selected network.');
  }
  return true;
}

export function createIngressServer({ upstream, networkContext, fetchImpl = globalThis.fetch, enabled = false } = {}) {
  const context = validateNetworkContext(networkContext);
  if (!upstream) throw new Error('An explicit authority RPC URL is required.');
  const target = new URL(upstream);
  if (target.username || target.password || (target.protocol !== 'https:'
      && !(target.protocol === 'http:' && ['127.0.0.1', '::1', 'localhost'].includes(target.hostname)))) {
    throw new Error('Authority RPC must use HTTPS or loopback HTTP.');
  }
  let inFlight = 0;
  return http.createServer(async (request, response) => {
    if (request.method === 'GET' && request.url === '/healthz') {
      const ready = enabled && await verifyAuthority(target, context, fetchImpl).catch(() => false);
      reply(response, ready ? 200 : 503, { ready, chainId: context.chain_id });
      return;
    }
    if (!enabled || request.method !== 'POST' || request.url !== '/') {
      reply(response, 404, rpcError(null, -32601, 'User ingress is not enabled for this route.'));
      return;
    }
    if (inFlight >= MAX_IN_FLIGHT) {
      reply(response, 503, rpcError(null, -32005, 'User ingress is busy.'));
      return;
    }
    inFlight++;
    let body;
    try {
      body = await readBody(request);
      const problem = validateEnvelope(body, context);
      if (problem) { reply(response, 400, rpcError(body?.id, -32602, problem)); return; }
      // The authority verifies identity binding, signature, nonce, fee, balance and execution.
      // An ingress acknowledgement is never treated as a finalized receipt.
      await verifyAuthority(target, context, fetchImpl);
      const upstreamResponse = await fetchImpl(target, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body), signal: AbortSignal.timeout(15000),
      });
      if (!upstreamResponse.ok) throw new Error('Authority rejected the upstream request.');
      const result = await upstreamResponse.json();
      if (result.id !== body.id || result.jsonrpc !== '2.0'
          || (!result.result && !result.error)) throw new Error('Authority returned an invalid JSON-RPC response.');
      reply(response, 200, result);
    } catch (error) {
      const status = error.message === 'request_too_large' ? 413 : error instanceof SyntaxError ? 400 : 502;
      reply(response, status, rpcError(body?.id, status === 413 ? -32006 : -32000,
        status === 413 ? 'Signed transaction exceeds the ingress size limit.' : 'User ingress could not verify or reach the authority.'));
    } finally {
      inFlight--;
    }
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.env.SYNERGY_USER_INGRESS_ENABLED !== '1') {
    throw new Error('Set SYNERGY_USER_INGRESS_ENABLED=1 only after authority and wallet qualification.');
  }
  const bytes = readFileSync(process.env.SYNERGY_INGRESS_NETWORK_CONTEXT);
  const expectedHash = process.env.SYNERGY_INGRESS_CONTEXT_SHA256;
  if (!/^[a-f0-9]{64}$/.test(expectedHash || '') || createHash('sha256').update(bytes).digest('hex') !== expectedHash) {
    throw new Error('Authenticated deployment context hash mismatch.');
  }
  const server = createIngressServer({ upstream: process.env.SYNERGY_AUTHORITY_RPC,
    networkContext: JSON.parse(bytes), enabled: true });
  server.listen(Number(process.env.SYNERGY_USER_INGRESS_PORT || 8793), '127.0.0.1');
}

import test from 'node:test';
import assert from 'node:assert/strict';
import { createIngressServer, validateNetworkContext, validateEnvelope, verifyAuthority } from '../server.mjs';

const GENESIS_HASH = '2272fe2b48c6e2019b27223f61ba8d8a82b58656fe9daab50c81f224a301ca74';
const networkContext = { chain_id: 1266, network_id: 'synergy-testnet-v3', genesis_hash: GENESIS_HASH, chain_incarnation: 5 };
const validate = body => validateEnvelope(body, networkContext);
const envelope = {
  jsonrpc: '2.0', id: 7, method: 'synergy_submitAegisTransaction',
  params: [{
    transaction: {
      chain_id: 1266, network_id: 'synergy-testnet-v3', sender_uma_or_account: 'synw1testaccount',
      aegis_pq_signature: { algorithm: 'mldsa87', signature_bytes: [1, 2, 3] },
    },
    public_key: { algorithm: 'mldsa87', key_bytes: [1] },
    lifecycle_record: { roles: ['Transaction'] },
  }],
};

const authorityReply = (body) => body.method === 'synergy_getChainId'
  ? { jsonrpc: '2.0', id: body.id, result: '0x4f2', chain_context: { chain_id: 1266, chain_incarnation: 5, genesis_hash: GENESIS_HASH } }
  : { jsonrpc: '2.0', id: body.id, result: { success: true, mempool_status: 'queued', tx_hash: 'syntxn-test' } };

test('ingress rejects plaintext, wrong-chain and FN-DSA user carriers', () => {
  assert.match(validate({ ...envelope, method: 'synergy_sendTransaction' }), /Only one/);
  assert.match(validate({ ...envelope, params: [{ ...envelope.params[0], transaction: { ...envelope.params[0].transaction, chain_id: 1264 } }] }), /selected chain/);
  assert.match(validate({ ...envelope, params: [{ ...envelope.params[0], transaction: { ...envelope.params[0].transaction, aegis_pq_signature: { algorithm: 'fndsa', signature_bytes: [1] } } }] }), /ML-DSA-87/);
});

test('authority probe requires the exact active Genesis and incarnation', async () => {
  const fetchImpl = async (_, options) => ({ ok: true, json: async () => authorityReply(JSON.parse(options.body)) });
  assert.equal(await verifyAuthority('http://127.0.0.1:9999/', networkContext, fetchImpl), true);
  await assert.rejects(verifyAuthority('http://127.0.0.1:9999/', networkContext, async (_, options) => ({
    ok: true, json: async () => ({ ...authorityReply(JSON.parse(options.body)), chain_context: { chain_id: 1266, chain_incarnation: 5, genesis_hash: 'wrong' } }),
  })), /authenticated selected network/);
});

test('disabled service remains closed; enabled service forwards only after chain probe', async () => {
  const calls = [];
  const fetchImpl = async (_, options) => {
    const body = JSON.parse(options.body);
    calls.push(body.method);
    return { ok: true, json: async () => authorityReply(body) };
  };
  const server = createIngressServer({ upstream: 'http://127.0.0.1:9999/', networkContext, fetchImpl, enabled: true });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const url = `http://127.0.0.1:${server.address().port}/`;
    const post = body => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    assert.equal((await post({ ...envelope, method: 'synergy_sendTransaction' })).status, 400);
    assert.deepEqual(calls, []);
    const result = await (await post(envelope)).json();
    assert.equal(result.result.tx_hash, 'syntxn-test');
    assert.deepEqual(calls, ['synergy_getChainId', 'synergy_submitAegisTransaction']);
  } finally { await new Promise(resolve => server.close(resolve)); }
  const disabled = createIngressServer({ upstream: 'http://127.0.0.1:9999/', networkContext });
  await new Promise(resolve => disabled.listen(0, '127.0.0.1', resolve));
  try {
    const url = `http://127.0.0.1:${disabled.address().port}`;
    assert.equal((await fetch(`${url}/healthz`)).status, 503);
    assert.equal((await fetch(url + '/', { method: 'POST', body: JSON.stringify(envelope) })).status, 404);
  } finally { await new Promise(resolve => disabled.close(resolve)); }
});

test('network selection is explicit and never inferred from a transaction', () => {
  assert.throws(() => validateNetworkContext(undefined), /authenticated network context/);
  for (const chain_id of [1266, 9001, 9002]) {
    const selected = { ...networkContext, chain_id, network_id: `network-${chain_id}` };
    const body = structuredClone(envelope);
    body.params[0].transaction.chain_id = chain_id;
    body.params[0].transaction.network_id = selected.network_id;
    assert.equal(validateEnvelope(body, selected), null);
    assert.match(validateEnvelope(body, { ...selected, chain_id: chain_id + 1 }), /selected chain/);
  }
});

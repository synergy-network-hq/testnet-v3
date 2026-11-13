import assert from 'node:assert/strict';
import test from 'node:test';

import { Contract, QuantumVMClient, QuantumVMSDK } from '../src/sdk';
import { FalconKeypair, MlDsaKeypair, MlKemKeypair } from '../src/keys';
import { Transaction } from '../src/tx';

type RpcRequest = {
  url: string;
  payload: {
    jsonrpc: string;
    method: string;
    params: unknown[];
    id: number;
  };
};

type MockResponse = {
  result: unknown;
  error?: {
    code: number;
    message: string;
  };
  ok?: boolean;
  status?: number;
  statusText?: string;
};

function installFetchMock(responses: MockResponse[]) {
  const captured: RpcRequest[] = [];
  const originalFetch = globalThis.fetch;
  let index = 0;

  (globalThis as Record<string, unknown>).fetch = async (
    url: string,
    init: RequestInit
  ) => {
    const body = JSON.parse(String(init.body));
    captured.push({
      url,
      payload: body
    });

    const response = responses[index];
    index += 1;
    return {
      ok: response?.ok ?? true,
      status: response?.status ?? 200,
      statusText: response?.statusText ?? 'OK',
      json: async () =>
        response?.error
          ? { jsonrpc: '2.0', id: body.id, error: response.error }
          : { jsonrpc: '2.0', id: body.id, result: response?.result ?? null }
    };
  };

  return {
    captured,
    restore: () => {
      (globalThis as Record<string, unknown>).fetch = originalFetch;
    }
  };
}

test('Contract deploy/call emit expected JSON-RPC envelopes', async () => {
  const mock = installFetchMock([{ result: '0xcontract' }, { result: { ok: true } }]);
  try {
    const client = new QuantumVMClient('http://localhost:8545');
    const contract = new Contract(client, [{ name: 'run' }], '0xdeadbeef');

    const deployResult = await contract.deploy('0xabc', 500_000);
    const callResult = await contract.call('run', ['arg1']);

    assert.equal(deployResult, '0xcontract');
    assert.deepEqual(callResult, { ok: true });
    assert.equal(mock.captured.length, 2);

    assert.equal(mock.captured[0].url, 'http://localhost:8545');
    assert.equal(mock.captured[0].payload.method, 'contract_deploy');
    assert.deepEqual(mock.captured[0].payload.params, ['0xabc', '0xdeadbeef', 500_000]);

    assert.equal(mock.captured[1].payload.method, 'contract_call');
    assert.deepEqual(mock.captured[1].payload.params, ['run', ['arg1']]);
    assert.equal(mock.captured[1].payload.id, 2);
  } finally {
    mock.restore();
  }
});

test('QuantumVMSDK tx/balance/block RPC calls are end-to-end well-formed', async () => {
  const mock = installFetchMock([
    { result: '0xtxhash' },
    { result: '42' },
    { result: 777 }
  ]);

  try {
    const sdk = new QuantumVMSDK('http://localhost:8545');
    const tx = new Transaction(
      '0xfrom',
      '0xto',
      1000n,
      5,
      21000,
      new Uint8Array([1, 2, 3]),
      1700000000
    );
    tx.setSignature(new Uint8Array([9, 8, 7]));

    const txHash = await sdk.sendTransaction(tx);
    const balance = await sdk.getBalance('0xfrom');
    const block = await sdk.getBlockNumber();

    assert.equal(txHash, '0xtxhash');
    assert.equal(balance, '42');
    assert.equal(block, 777);
    assert.equal(mock.captured.length, 3);

    const sent = mock.captured[0].payload;
    assert.equal(sent.method, 'tx_sendRaw');
    assert.equal(Array.isArray(sent.params), true);
    assert.equal(Array.isArray(sent.params[0] as unknown[]), true);
    assert.deepEqual(sent.params[1], [9, 8, 7]);

    assert.equal(mock.captured[1].payload.method, 'get_balance');
    assert.deepEqual(mock.captured[1].payload.params, ['0xfrom']);

    assert.equal(mock.captured[2].payload.method, 'get_blockNumber');
    assert.deepEqual(mock.captured[2].payload.params, []);
  } finally {
    mock.restore();
  }
});

test('QuantumVMClient rejects JSON-RPC and HTTP failures', async () => {
  const rpcError = installFetchMock([
    { result: null, error: { code: -32000, message: 'execution reverted' } }
  ]);
  try {
    const client = new QuantumVMClient('http://localhost:8545');
    await assert.rejects(
      () => client.send('contract_call', []),
      /QuantumVM RPC -32000: execution reverted/
    );
  } finally {
    rpcError.restore();
  }

  const httpError = installFetchMock([
    { result: null, ok: false, status: 503, statusText: 'Service Unavailable' }
  ]);
  try {
    const client = new QuantumVMClient('http://localhost:8545');
    await assert.rejects(
      () => client.send('get_blockNumber', []),
      /QuantumVM RPC HTTP 503: Service Unavailable/
    );
  } finally {
    httpError.restore();
  }
});

test('ML-KEM key API uses a real FIPS 203 backend', async () => {
  const keypair = await MlKemKeypair.generate();
  const sealed = keypair.encapsulate();
  const opened = keypair.decapsulate(sealed.ct);

  assert.equal(keypair.variant, 'ML-KEM-768');
  assert.equal(keypair.publicKey.length, 1184);
  assert.equal(keypair.secretKey.length, 2400);
  assert.equal(sealed.ct.length, 1088);
  assert.equal(sealed.ss.length, 32);
  assert.deepEqual(opened, sealed.ss);
});

test('ML-DSA key API uses a real FIPS 204 backend', async () => {
  const keypair = await MlDsaKeypair.generate();
  const message = new TextEncoder().encode('synq-fips-204');
  const signature = keypair.sign(message);

  assert.equal(keypair.variant, 'ML-DSA-65');
  assert.equal(keypair.publicKey.length, 1952);
  assert.equal(keypair.secretKey.length, 4032);
  assert.equal(signature.length, 3309);
  assert.equal(keypair.verify(message, signature), true);

  const tampered = new Uint8Array(message);
  tampered[0] ^= 1;
  assert.equal(keypair.verify(tampered, signature), false);
});

test('Falcon key API uses a real Falcon backend', async () => {
  const keypair = await FalconKeypair.generate();
  const message = new TextEncoder().encode('synq-falcon');
  const signature = keypair.sign(message);

  assert.equal(keypair.variant, 'Falcon-512');
  assert.equal(keypair.publicKey.length, 897);
  assert.equal(keypair.secretKey.length, 1281);
  assert.equal(keypair.verify(message, signature), true);
});

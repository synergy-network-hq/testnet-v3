// sdk/src/sdk.ts

import { DilithiumKeypair, ECDSAKeypair, KyberKeypair } from './keys';
import { Transaction } from './tx';

export class QuantumVMClient {
  rpcUrl: string;

  constructor(rpcUrl: string) {
    this.rpcUrl = rpcUrl;
  }

  async send(method: string, params: any[]): Promise<any> {
    const body = {
      jsonrpc: '2.0',
      method,
      params,
      id: 1
    };
    const res = await fetch(this.rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const json = await res.json();
    return json.result;
  }
}

export class Contract {
  abi: any;
  bytecode: string;
  client: QuantumVMClient;

  constructor(client: QuantumVMClient, abi: any, bytecode: string) {
    this.abi = abi;
    this.bytecode = bytecode;
    this.client = client;
  }

  async deploy(from: string, gas: number): Promise<string> {
    return this.client.send('contract_deploy', [from, this.bytecode, gas]);
  }

  async call(method: string, args: any[]): Promise<any> {
    return this.client.send('contract_call', [method, args]);
  }
}

export class QuantumVMSDK {
  client: QuantumVMClient;

  constructor(rpcUrl: string) {
    this.client = new QuantumVMClient(rpcUrl);
  }

  async generateDilithiumKeypair(): Promise<DilithiumKeypair> {
    return DilithiumKeypair.generate();
  }

  generateECDSAKeypair(): ECDSAKeypair {
    return ECDSAKeypair.generate();
  }

  async generateKyberKeypair(): Promise<KyberKeypair> {
    return KyberKeypair.generate();
  }

  async sendTransaction(tx: Transaction): Promise<string> {
    const raw = tx.serialize();
    return this.client.send('tx_sendRaw', [Array.from(raw), Array.from(tx.signature)]);
  }

  async getBalance(address: string): Promise<string> {
    return this.client.send('get_balance', [address]);
  }

  async getBlockNumber(): Promise<number> {
    return this.client.send('get_blockNumber', []);
  }
}



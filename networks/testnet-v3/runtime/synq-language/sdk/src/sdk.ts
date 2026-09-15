import type {
  ECDSAKeypair,
  FalconKeypair,
  MlDsaKeypair,
  MlDsaVariant,
  MlKemKeypair,
  MlKemVariant,
  FalconVariant
} from './keys';
import { Transaction } from './tx';

type JsonRpcSuccess = {
  jsonrpc: '2.0';
  id: number | string | null;
  result: unknown;
};

type JsonRpcFailure = {
  jsonrpc: '2.0';
  id: number | string | null;
  error: {
    code: number;
    message: string;
    data?: unknown;
  };
};

type JsonRpcResponse = JsonRpcSuccess | JsonRpcFailure;

export class QuantumVMClient {
  rpcUrl: string;
  private nextId: number;

  constructor(rpcUrl: string) {
    this.rpcUrl = rpcUrl;
    this.nextId = 1;
  }

  async send(method: string, params: any[]): Promise<any> {
    const id = this.nextId;
    this.nextId += 1;

    const body = {
      jsonrpc: '2.0',
      method,
      params,
      id
    };
    const res = await fetch(this.rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (!res.ok) {
      throw new Error(`QuantumVM RPC HTTP ${res.status}: ${res.statusText}`);
    }

    const json = (await res.json()) as JsonRpcResponse;
    if ('error' in json) {
      throw new Error(`QuantumVM RPC ${json.error.code}: ${json.error.message}`);
    }

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

  async generateMlDsaKeypair(variant: MlDsaVariant = 'ML-DSA-65'): Promise<MlDsaKeypair> {
    const { MlDsaKeypair } = await import('./keys');
    return MlDsaKeypair.generate(variant);
  }

  async generateECDSAKeypair(): Promise<ECDSAKeypair> {
    const { ECDSAKeypair } = await import('./keys');
    return ECDSAKeypair.generate();
  }

  async generateMlKemKeypair(variant: MlKemVariant = 'ML-KEM-768'): Promise<MlKemKeypair> {
    const { MlKemKeypair } = await import('./keys');
    return MlKemKeypair.generate(variant);
  }

  async generateFalconKeypair(variant: FalconVariant = 'Falcon-512'): Promise<FalconKeypair> {
    const { FalconKeypair } = await import('./keys');
    return FalconKeypair.generate(variant);
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

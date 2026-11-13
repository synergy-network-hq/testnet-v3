// sdk/src/tx.ts

import { encodeBase58 } from './encoding';

export class Transaction {
  from: string;
  to: string;
  amount: bigint;
  nonce: number;
  gasLimit: number;
  data: Uint8Array;
  timestamp: number;
  signature: Uint8Array;

  constructor(
    from: string,
    to: string,
    amount: bigint,
    nonce: number,
    gasLimit: number,
    data: Uint8Array,
    timestamp: number
  ) {
    this.from = from;
    this.to = to;
    this.amount = amount;
    this.nonce = nonce;
    this.gasLimit = gasLimit;
    this.data = data;
    this.timestamp = timestamp;
    this.signature = new Uint8Array();
  }

  serialize(): Uint8Array {
    const enc = new TextEncoder();
    const payload = JSON.stringify({
      from: this.from,
      to: this.to,
      amount: this.amount.toString(),
      nonce: this.nonce,
      gasLimit: this.gasLimit,
      data: Array.from(this.data),
      timestamp: this.timestamp
    });
    return enc.encode(payload);
  }

  async hash(): Promise<string> {
    const data = this.serialize();
    const input = data.buffer.slice(
      data.byteOffset,
      data.byteOffset + data.byteLength
    ) as ArrayBuffer;
    const hashBuffer = await crypto.subtle.digest('SHA-256', input);
    return encodeBase58(new Uint8Array(hashBuffer));
  }

  setSignature(sig: Uint8Array) {
    this.signature = sig;
  }
}

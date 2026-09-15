// sdk/src/keys.ts

import nacl from 'tweetnacl';
import * as Kyber from './crypto/kyber';
import * as dilithium from '@openquantum/dilithium';
import bs58 from 'bs58';

export class DilithiumKeypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;

  constructor(publicKey: Uint8Array, secretKey: Uint8Array) {
    this.publicKey = publicKey;
    this.secretKey = secretKey;
  }

  static async generate(): Promise<DilithiumKeypair> {
    const { publicKey, secretKey } = await dilithium.keyPair();
    return new DilithiumKeypair(publicKey, secretKey);
  }

  sign(message: Uint8Array): Uint8Array {
    return dilithium.sign(message, this.secretKey);
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    return dilithium.verify(message, signature, this.publicKey);
  }

  toBase58(): string {
    return bs58.encode(this.publicKey);
  }
}

export class KyberKeypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;

  constructor(publicKey: Uint8Array, secretKey: Uint8Array) {
    this.publicKey = publicKey;
    this.secretKey = secretKey;
  }

  static async generate(): Promise<KyberKeypair> {
    const { publicKey, secretKey } = await Kyber.keyPair();
    return new KyberKeypair(publicKey, secretKey);
  }

  encapsulate(): { ct: Uint8Array; ss: Uint8Array } {
    return Kyber.encapsulate(this.publicKey);
  }

  decapsulate(ct: Uint8Array): Uint8Array {
    return Kyber.decapsulate(ct, this.secretKey);
  }
}

export class ECDSAKeypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;

  constructor(publicKey: Uint8Array, secretKey: Uint8Array) {
    this.publicKey = publicKey;
    this.secretKey = secretKey;
  }

  static generate(): ECDSAKeypair {
    const key = nacl.sign.keyPair();
    return new ECDSAKeypair(key.publicKey, key.secretKey);
  }

  sign(message: Uint8Array): Uint8Array {
    return nacl.sign.detached(message, this.secretKey);
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    return nacl.sign.detached.verify(message, signature, this.publicKey);
  }
}

export class HybridMultiSig {
  dilithium: DilithiumKeypair;
  falcon: any;

  constructor(dilithium: DilithiumKeypair, falcon: any) {
    this.dilithium = dilithium;
    this.falcon = falcon;
  }

  async sign(message: Uint8Array): Promise<{ d: Uint8Array; f: Uint8Array }> {
    return {
      d: await this.dilithium.sign(message),
      f: await this.falcon.sign(message)
    };
  }

  async verify(message: Uint8Array, sig: { d: Uint8Array; f: Uint8Array }): Promise<boolean> {
    return (
      this.dilithium.verify(message, sig.d) &&
      this.falcon.verify(message, sig.f)
    );
  }
}

export function base58Encode(data: Uint8Array): string {
  return bs58.encode(data);
}

export function base58Decode(encoded: string): Uint8Array {
  return bs58.decode(encoded);
}

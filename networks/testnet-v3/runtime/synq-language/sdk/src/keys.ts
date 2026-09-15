import nacl from 'tweetnacl';
import { falcon1024, falcon512 } from '@noble/post-quantum/falcon.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem1024, ml_kem512, ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { decodeBase58, encodeBase58 } from './encoding';

export type MlDsaVariant = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';
export type MlKemVariant = 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024';
export type FalconVariant = 'Falcon-512' | 'Falcon-1024';

type SigningBackend = {
  keygen: () => { publicKey: Uint8Array; secretKey: Uint8Array };
  sign: (message: Uint8Array, secretKey: Uint8Array) => Uint8Array;
  verify: (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) => boolean;
};

type KemBackend = {
  keygen: () => { publicKey: Uint8Array; secretKey: Uint8Array };
  encapsulate: (publicKey: Uint8Array) => { cipherText: Uint8Array; sharedSecret: Uint8Array };
  decapsulate: (cipherText: Uint8Array, secretKey: Uint8Array) => Uint8Array;
};

function mldsaBackend(variant: MlDsaVariant): SigningBackend {
  switch (variant) {
    case 'ML-DSA-44':
      return ml_dsa44;
    case 'ML-DSA-65':
      return ml_dsa65;
    case 'ML-DSA-87':
      return ml_dsa87;
  }
}

function mlkemBackend(variant: MlKemVariant): KemBackend {
  switch (variant) {
    case 'ML-KEM-512':
      return ml_kem512;
    case 'ML-KEM-768':
      return ml_kem768;
    case 'ML-KEM-1024':
      return ml_kem1024;
  }
}

function falconBackend(variant: FalconVariant): SigningBackend {
  switch (variant) {
    case 'Falcon-512':
      return falcon512;
    case 'Falcon-1024':
      return falcon1024;
  }
}

export class MlDsaKeypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  variant: MlDsaVariant;

  constructor(publicKey: Uint8Array, secretKey: Uint8Array, variant: MlDsaVariant = 'ML-DSA-65') {
    this.publicKey = publicKey;
    this.secretKey = secretKey;
    this.variant = variant;
  }

  static async generate(variant: MlDsaVariant = 'ML-DSA-65'): Promise<MlDsaKeypair> {
    const keypair = mldsaBackend(variant).keygen();
    return new MlDsaKeypair(keypair.publicKey, keypair.secretKey, variant);
  }

  sign(message: Uint8Array): Uint8Array {
    return mldsaBackend(this.variant).sign(message, this.secretKey);
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    return mldsaBackend(this.variant).verify(signature, message, this.publicKey);
  }

  toBase58(): string {
    return encodeBase58(this.publicKey);
  }
}

export class MlKemKeypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  variant: MlKemVariant;

  constructor(publicKey: Uint8Array, secretKey: Uint8Array, variant: MlKemVariant = 'ML-KEM-768') {
    this.publicKey = publicKey;
    this.secretKey = secretKey;
    this.variant = variant;
  }

  static async generate(variant: MlKemVariant = 'ML-KEM-768'): Promise<MlKemKeypair> {
    const keypair = mlkemBackend(variant).keygen();
    return new MlKemKeypair(keypair.publicKey, keypair.secretKey, variant);
  }

  encapsulate(): { ct: Uint8Array; ss: Uint8Array } {
    const result = mlkemBackend(this.variant).encapsulate(this.publicKey);
    return { ct: result.cipherText, ss: result.sharedSecret };
  }

  decapsulate(ct: Uint8Array): Uint8Array {
    return mlkemBackend(this.variant).decapsulate(ct, this.secretKey);
  }
}

export class FalconKeypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  variant: FalconVariant;

  constructor(publicKey: Uint8Array, secretKey: Uint8Array, variant: FalconVariant = 'Falcon-512') {
    this.publicKey = publicKey;
    this.secretKey = secretKey;
    this.variant = variant;
  }

  static async generate(variant: FalconVariant = 'Falcon-512'): Promise<FalconKeypair> {
    const keypair = falconBackend(variant).keygen();
    return new FalconKeypair(keypair.publicKey, keypair.secretKey, variant);
  }

  sign(message: Uint8Array): Uint8Array {
    return falconBackend(this.variant).sign(message, this.secretKey);
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    return falconBackend(this.variant).verify(signature, message, this.publicKey);
  }

  toBase58(): string {
    return encodeBase58(this.publicKey);
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
  mldsa: MlDsaKeypair;
  falcon: FalconKeypair;

  constructor(mldsa: MlDsaKeypair, falcon: FalconKeypair) {
    this.mldsa = mldsa;
    this.falcon = falcon;
  }

  async sign(message: Uint8Array): Promise<{ mldsa: Uint8Array; falcon: Uint8Array }> {
    return {
      mldsa: await this.mldsa.sign(message),
      falcon: await this.falcon.sign(message)
    };
  }

  async verify(
    message: Uint8Array,
    sig: { mldsa: Uint8Array; falcon: Uint8Array }
  ): Promise<boolean> {
    return (
      this.mldsa.verify(message, sig.mldsa) &&
      this.falcon.verify(message, sig.falcon)
    );
  }
}

export function base58Encode(data: Uint8Array): string {
  return encodeBase58(data);
}

export function base58Decode(encoded: string): Uint8Array {
  return decodeBase58(encoded);
}

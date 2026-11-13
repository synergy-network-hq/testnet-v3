import { ml_kem1024, ml_kem512, ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import type { MlKemVariant } from '../keys';

function backend(variant: MlKemVariant) {
  switch (variant) {
    case 'ML-KEM-512':
      return ml_kem512;
    case 'ML-KEM-768':
      return ml_kem768;
    case 'ML-KEM-1024':
      return ml_kem1024;
  }
}

export function keyPair(
  variant: MlKemVariant = 'ML-KEM-768'
): { publicKey: Uint8Array; secretKey: Uint8Array } {
  return backend(variant).keygen();
}

export function encapsulate(
  publicKey: Uint8Array,
  variant: MlKemVariant = 'ML-KEM-768'
): { ct: Uint8Array; ss: Uint8Array } {
  const result = backend(variant).encapsulate(publicKey);
  return { ct: result.cipherText, ss: result.sharedSecret };
}

export function decapsulate(
  ciphertext: Uint8Array,
  secretKey: Uint8Array,
  variant: MlKemVariant = 'ML-KEM-768'
): Uint8Array {
  return backend(variant).decapsulate(ciphertext, secretKey);
}

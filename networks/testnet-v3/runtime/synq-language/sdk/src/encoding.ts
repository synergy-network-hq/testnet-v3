import bs58 from 'bs58';

export function encodeBase58(data: Uint8Array): string {
  return bs58.encode(data);
}

export function decodeBase58(encoded: string): Uint8Array {
  return bs58.decode(encoded);
}

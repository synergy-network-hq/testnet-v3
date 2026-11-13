// sdk/src/crypto/kyber.ts
export function generateKyberKeypair(): { publicKey: Uint8Array, privateKey: Uint8Array } {
	throw new Error("Not implemented");
}

export function kyberEncapsulate(pk: Uint8Array): { ciphertext: Uint8Array, sharedSecret: Uint8Array } {
	throw new Error("Not implemented");
}

export function kyberDecapsulate(ct: Uint8Array, sk: Uint8Array): Uint8Array {
	throw new Error("Not implemented");
}

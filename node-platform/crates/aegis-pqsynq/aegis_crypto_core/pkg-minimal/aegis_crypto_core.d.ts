/* tslint:disable */
/* eslint-disable */
/**
 * Generate a new ML-DSA keypair using the NIST reference implementation
 */
export function nist_mldsa_keygen(variant: string): Promise<NistMldsaKeyPair>;
/**
 * Sign a message using the NIST reference ML-DSA implementation
 */
export function nist_mldsa_sign(variant: string, secret_key: Uint8Array, message: Uint8Array): Promise<Uint8Array>;
/**
 * Verify a signature using the NIST reference ML-DSA implementation
 */
export function nist_mldsa_verify(variant: string, public_key: Uint8Array, signature: Uint8Array, message: Uint8Array): Promise<boolean>;
/**
 * Get information about the supported ML-DSA variants
 */
export function nist_mldsa_variants(): any;
/**
 * Generate a new ML-KEM keypair using the NIST reference implementation
 */
export function nist_mlkem_keygen(variant: string): Promise<NistMlkemKeyPair>;
/**
 * Encapsulate a shared secret using the NIST reference ML-KEM implementation
 */
export function nist_mlkem_encapsulate(variant: string, public_key: Uint8Array): Promise<NistMlkemEncapsulated>;
/**
 * Decapsulate a shared secret using the NIST reference ML-KEM implementation
 */
export function nist_mlkem_decapsulate(variant: string, secret_key: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
/**
 * Get information about the supported ML-KEM variants
 */
export function nist_mlkem_variants(): any;
export function sha3_256_hash(data: Uint8Array): Uint8Array;
export function sha3_256_hash_hex(data: Uint8Array): string;
export function sha3_256_hash_base64(data: Uint8Array): string;
export function sha3_512_hash(data: Uint8Array): Uint8Array;
export function sha3_512_hash_hex(data: Uint8Array): string;
export function sha3_512_hash_base64(data: Uint8Array): string;
export function blake3_hash(data: Uint8Array): Uint8Array;
export function blake3_hash_hex(data: Uint8Array): string;
export function blake3_hash_base64(data: Uint8Array): string;
export function hex_to_bytes(hex_string: string): Uint8Array;
export function bytes_to_hex(bytes: Uint8Array): string;
export function sha3_256(data: Uint8Array): Uint8Array;
export function sha3_256_hex(data: Uint8Array): string;
export function sha3_256_base64(data: Uint8Array): string;
export function sha3_512(data: Uint8Array): Uint8Array;
export function sha3_512_hex(data: Uint8Array): string;
export function sha3_512_base64(data: Uint8Array): string;
export function blake3(data: Uint8Array): Uint8Array;
export function blake3_hex(data: Uint8Array): string;
export function blake3_base64(data: Uint8Array): string;
export function nistMlkemKeygen(variant: string): Promise<NistMlkemKeyPair>;
export function nistMlkemEncapsulate(variant: string, public_key: Uint8Array): Promise<NistMlkemEncapsulated>;
export function nistMlkemDecapsulate(variant: string, secret_key: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
export function nistMlkemVariants(): any;
export function nistMldsaKeygen(variant: string): Promise<NistMldsaKeyPair>;
export function nistMldsaSign(variant: string, secret_key: Uint8Array, message: Uint8Array): Promise<Uint8Array>;
export function nistMldsaVerify(variant: string, public_key: Uint8Array, signature: Uint8Array, message: Uint8Array): Promise<boolean>;
export function nistMldsaVariants(): any;
export function initWasmLoader(): any;
export function loadMlkemModules(): Promise<any>;
export function loadMldsaModules(): Promise<any>;
export function isWasmSupported(): boolean;
export function getWasmInfo(): any;
export function hexToBytes(hex_str: string): Uint8Array;
export function bytesToHex(bytes: Uint8Array): string;
/**
 * Initialize the WASM loader with default paths
 */
export function init_wasm_loader(): WasmLoaderJs;
/**
 * Load ML-KEM WASM modules
 */
export function load_mlkem_modules(): Promise<any>;
/**
 * Load ML-DSA WASM modules
 */
export function load_mldsa_modules(): Promise<any>;
/**
 * Check if WASM is supported in the current environment
 */
export function is_wasm_supported(): boolean;
/**
 * Get WASM environment information
 */
export function get_wasm_info(): any;
/**
 * Represents an ML-DSA key pair (public and secret keys).
 */
export class NistMldsaKeyPair {
  private constructor();
  free(): void;
  /**
   * Returns the length of the public key in bytes.
   */
  public_key_length(): number;
  /**
   * Returns the length of the secret key in bytes.
   */
  secret_key_length(): number;
  /**
   * Returns the public key as bytes.
   */
  readonly public_key: Uint8Array;
  /**
   * Returns the secret key as bytes.
   */
  readonly secret_key: Uint8Array;
}
/**
 * Represents an ML-KEM encapsulated shared secret.
 */
export class NistMlkemEncapsulated {
  private constructor();
  free(): void;
  /**
   * Returns the length of the ciphertext in bytes.
   */
  ciphertext_length(): number;
  /**
   * Returns the length of the shared secret in bytes.
   */
  shared_secret_length(): number;
  /**
   * Returns the ciphertext as bytes.
   */
  readonly ciphertext: Uint8Array;
  /**
   * Returns the shared secret as bytes.
   */
  readonly shared_secret: Uint8Array;
}
/**
 * Represents an ML-KEM key pair (public and secret keys).
 */
export class NistMlkemKeyPair {
  private constructor();
  free(): void;
  /**
   * Returns the length of the public key in bytes.
   */
  public_key_length(): number;
  /**
   * Returns the length of the secret key in bytes.
   */
  secret_key_length(): number;
  /**
   * Returns the public key as bytes.
   */
  readonly public_key: Uint8Array;
  /**
   * Returns the secret key as bytes.
   */
  readonly secret_key: Uint8Array;
}
/**
 * JavaScript bindings for the WASM loader
 */
export class WasmLoaderJs {
  free(): void;
  /**
   * Create a new WASM loader
   */
  constructor(base_path: string);
  /**
   * Load a WASM module
   */
  load_module(filename: string): Promise<any>;
  /**
   * Get or load a module
   */
  get_or_load_module(filename: string): Promise<any>;
  /**
   * Preload multiple modules
   */
  preload_modules(filenames: any): Promise<void>;
  /**
   * Get cache statistics
   */
  cache_stats(): any;
  /**
   * Clear the cache
   */
  clear_cache(): void;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_nistmldsakeypair_free: (a: number, b: number) => void;
  readonly nistmldsakeypair_public_key: (a: number) => [number, number];
  readonly nistmldsakeypair_secret_key: (a: number) => [number, number];
  readonly nistmldsakeypair_public_key_length: (a: number) => number;
  readonly nistmldsakeypair_secret_key_length: (a: number) => number;
  readonly nist_mldsa_keygen: (a: number, b: number) => any;
  readonly nist_mldsa_sign: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
  readonly nist_mldsa_verify: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => any;
  readonly nist_mldsa_variants: () => any;
  readonly __wbg_nistmlkemkeypair_free: (a: number, b: number) => void;
  readonly nistmlkemkeypair_public_key: (a: number) => [number, number];
  readonly nistmlkemkeypair_secret_key: (a: number) => [number, number];
  readonly __wbg_nistmlkemencapsulated_free: (a: number, b: number) => void;
  readonly nistmlkemencapsulated_ciphertext: (a: number) => [number, number];
  readonly nistmlkemencapsulated_shared_secret: (a: number) => [number, number];
  readonly nistmlkemencapsulated_ciphertext_length: (a: number) => number;
  readonly nistmlkemencapsulated_shared_secret_length: (a: number) => number;
  readonly nist_mlkem_keygen: (a: number, b: number) => any;
  readonly nist_mlkem_encapsulate: (a: number, b: number, c: number, d: number) => any;
  readonly nist_mlkem_decapsulate: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
  readonly nist_mlkem_variants: () => any;
  readonly nistmlkemkeypair_public_key_length: (a: number) => number;
  readonly nistmlkemkeypair_secret_key_length: (a: number) => number;
  readonly sha3_256_hash: (a: number, b: number) => [number, number];
  readonly sha3_256_hash_hex: (a: number, b: number) => [number, number];
  readonly sha3_256_hash_base64: (a: number, b: number) => [number, number];
  readonly sha3_512_hash: (a: number, b: number) => [number, number];
  readonly sha3_512_hash_hex: (a: number, b: number) => [number, number];
  readonly sha3_512_hash_base64: (a: number, b: number) => [number, number];
  readonly blake3_hash: (a: number, b: number) => [number, number];
  readonly blake3_hash_hex: (a: number, b: number) => [number, number];
  readonly blake3_hash_base64: (a: number, b: number) => [number, number];
  readonly sha3_256: (a: number, b: number) => [number, number];
  readonly sha3_256_hex: (a: number, b: number) => [number, number];
  readonly sha3_256_base64: (a: number, b: number) => [number, number];
  readonly sha3_512: (a: number, b: number) => [number, number];
  readonly sha3_512_hex: (a: number, b: number) => [number, number];
  readonly sha3_512_base64: (a: number, b: number) => [number, number];
  readonly blake3: (a: number, b: number) => [number, number];
  readonly blake3_hex: (a: number, b: number) => [number, number];
  readonly blake3_base64: (a: number, b: number) => [number, number];
  readonly nistMlkemKeygen: (a: number, b: number) => any;
  readonly nistMlkemEncapsulate: (a: number, b: number, c: number, d: number) => any;
  readonly nistMlkemDecapsulate: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
  readonly nistMlkemVariants: () => any;
  readonly nistMldsaKeygen: (a: number, b: number) => any;
  readonly nistMldsaSign: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
  readonly nistMldsaVerify: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => any;
  readonly nistMldsaVariants: () => any;
  readonly initWasmLoader: () => any;
  readonly loadMlkemModules: () => any;
  readonly loadMldsaModules: () => any;
  readonly isWasmSupported: () => number;
  readonly getWasmInfo: () => any;
  readonly hexToBytes: (a: number, b: number) => [number, number, number, number];
  readonly bytesToHex: (a: number, b: number) => [number, number];
  readonly bytes_to_hex: (a: number, b: number) => [number, number];
  readonly hex_to_bytes: (a: number, b: number) => [number, number, number, number];
  readonly __wbg_wasmloaderjs_free: (a: number, b: number) => void;
  readonly wasmloaderjs_new: (a: number, b: number) => number;
  readonly wasmloaderjs_load_module: (a: number, b: number, c: number) => any;
  readonly wasmloaderjs_get_or_load_module: (a: number, b: number, c: number) => any;
  readonly wasmloaderjs_preload_modules: (a: number, b: any) => any;
  readonly wasmloaderjs_cache_stats: (a: number) => any;
  readonly wasmloaderjs_clear_cache: (a: number) => void;
  readonly init_wasm_loader: () => number;
  readonly load_mlkem_modules: () => any;
  readonly load_mldsa_modules: () => any;
  readonly is_wasm_supported: () => number;
  readonly get_wasm_info: () => any;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_2: WebAssembly.Table;
  readonly __wbindgen_export_3: WebAssembly.Table;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly closure93_externref_shim: (a: number, b: number, c: any) => void;
  readonly closure117_externref_shim: (a: number, b: number, c: any, d: any) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput, memory?: WebAssembly.Memory }} module - Passing `SyncInitInput` directly is deprecated.
* @param {WebAssembly.Memory} memory - Deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput, memory?: WebAssembly.Memory } | SyncInitInput, memory?: WebAssembly.Memory): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput>, memory?: WebAssembly.Memory }} module_or_path - Passing `InitInput` directly is deprecated.
* @param {WebAssembly.Memory} memory - Deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput>, memory?: WebAssembly.Memory } | InitInput | Promise<InitInput>, memory?: WebAssembly.Memory): Promise<InitOutput>;

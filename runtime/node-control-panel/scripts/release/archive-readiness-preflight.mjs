#!/usr/bin/env node

import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const DEFAULT_CATALOG_URL = 'https://archive-store.synergynode.xyz/snapshots/latest.json';
export const MAX_AGE_SECONDS = 6 * 60 * 60;
export const MAX_FUTURE_SKEW_SECONDS = 15 * 60;
const CATALOG_SCHEMA = 'synergy-archive-snapshot-catalog-v1';
const SIGNATURE_SCHEMA = 'synergy-aegis-detached-json-signature-v2';
const SIGNATURE_DOMAIN = 'SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1';
const DISTRIBUTION_SIGNATURE_DOMAIN = 'SYNERGY_ARCHIVE_SNAPSHOT_DISTRIBUTION_V1';
const DISTRIBUTION_SCHEMA = 'synergy-archive-snapshot-distribution-v1';
const BINARY_COMPATIBILITY = 'synergy-testnet-v3-validator-pruned-v1';

function requireObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return value;
}

function requirePositiveTimestamp(value, field, label) {
  const timestamp = Number(value?.[field]);
  if (!Number.isSafeInteger(timestamp) || timestamp <= 0) {
    throw new Error(`${label} is missing a positive ${field} timestamp`);
  }
  return timestamp;
}

function requireFresh(timestamp, nowSeconds, label) {
  if (timestamp > nowSeconds + MAX_FUTURE_SKEW_SECONDS) {
    throw new Error(`${label} timestamp is more than ${MAX_FUTURE_SKEW_SECONDS} seconds in the future`);
  }
  if (nowSeconds - timestamp > MAX_AGE_SECONDS) {
    throw new Error(`${label} is older than ${MAX_AGE_SECONDS} seconds`);
  }
}

function requireIdentity(value, expectedGenesisHash, label) {
  if (value.chain_id !== 1264 || value.network_id !== 'synergy-testnet-v3') {
    throw new Error(`${label} is not Synergy Testnet chain 1264 / synergy-testnet-v3`);
  }
  if (String(value.genesis_hash || '').toLowerCase() !== expectedGenesisHash) {
    throw new Error(`${label} genesis hash does not match the bundled Testnet genesis`);
  }
}

export function validateCatalog(catalogValue, expectedGenesisHash, nowSeconds = Math.floor(Date.now() / 1000)) {
  const catalog = requireObject(catalogValue, 'archive catalog');
  const genesisHash = String(expectedGenesisHash || '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(genesisHash)) {
    throw new Error('bundled Testnet genesis hash is missing or invalid');
  }
  if (catalog.schema !== CATALOG_SCHEMA) {
    throw new Error(`archive catalog schema must be ${CATALOG_SCHEMA}`);
  }
  requireIdentity(catalog, genesisHash, 'archive catalog');
  if (catalog.catalog_signature_status !== 'AEGIS_PQC_VERIFIED') {
    throw new Error('archive catalog signature status is not AEGIS_PQC_VERIFIED');
  }
  if (catalog.signature_scheme !== 'aegis-pqc' || catalog.signature_domain !== SIGNATURE_DOMAIN) {
    throw new Error('archive catalog signature scheme or domain is invalid');
  }
  if (!/^[0-9a-f]{64}$/i.test(String(catalog.catalog_content_root || ''))) {
    throw new Error('archive catalog content root is missing or invalid');
  }
  requireFresh(requirePositiveTimestamp(catalog, 'updated_at', 'archive catalog'), nowSeconds, 'archive catalog');

  if (!Array.isArray(catalog.snapshots)) {
    throw new Error('archive catalog snapshots must be an array');
  }
  const candidates = catalog.snapshots.filter((snapshot) =>
    snapshot?.snapshot_class === 'validator-pruned' && snapshot?.status === 'published');
  if (candidates.length === 0) {
    throw new Error('archive catalog has no published validator-pruned snapshot');
  }
  const snapshot = candidates.sort((left, right) => Number(right.height || 0) - Number(left.height || 0))[0];
  requireIdentity(snapshot, genesisHash, 'validator-pruned snapshot');
  if (snapshot.verification_status !== 'green' || snapshot.manifest_signature_status !== 'AEGIS_PQC_VERIFIED') {
    throw new Error('validator-pruned snapshot verification or manifest signature status is not green');
  }
  if (snapshot.producer_role !== 'archive_validator' || snapshot.producer_node_kind !== 'archive-validator') {
    throw new Error('validator-pruned snapshot does not have archive-validator provenance');
  }
  if (snapshot.binary_compatibility !== BINARY_COMPATIBILITY) {
    throw new Error(`validator-pruned snapshot binary compatibility must be ${BINARY_COMPATIBILITY}`);
  }
  if (!Number.isSafeInteger(Number(snapshot.height)) || Number(snapshot.height) <= 0) {
    throw new Error('validator-pruned snapshot height is missing or invalid');
  }
  requireFresh(
    requirePositiveTimestamp(snapshot, 'last_verified_at', 'validator-pruned snapshot'),
    nowSeconds,
    'validator-pruned snapshot',
  );
  for (const field of ['snapshot_url', 'manifest_url', 'manifest_signature_url', 'checksums_url']) {
    const value = String(snapshot[field] || '');
    if (!value.startsWith('https://')) {
      throw new Error(`validator-pruned snapshot ${field} must be an HTTPS URL`);
    }
  }
  return snapshot;
}

export function validateSignatureProof(catalogBytes, signatureValue, authorityValue) {
  const signature = requireObject(signatureValue, 'archive catalog signature');
  const authority = requireObject(authorityValue, 'archive snapshot authority');
  const expectedSigner = String(authority.signer_public_key_sha256 || '').trim().toLowerCase();
  if (authority.schema !== 'synergy-archive-snapshot-authority-v1' || authority.algorithm !== 'ML-DSA-87') {
    throw new Error('archive snapshot authority metadata is unsupported');
  }
  if (!/^[0-9a-f]{64}$/.test(expectedSigner)) {
    throw new Error('archive snapshot authority signer fingerprint is invalid');
  }
  if (signature.schema !== SIGNATURE_SCHEMA || signature.algorithm !== 'ML-DSA-87') {
    throw new Error('archive catalog detached signature schema or algorithm is invalid');
  }
  if (signature.domain !== SIGNATURE_DOMAIN) {
    throw new Error('archive catalog detached signature domain is invalid');
  }
  const payloadHash = createHash('sha256').update(catalogBytes).digest('hex');
  if (signature.payload_sha256 !== payloadHash) {
    throw new Error('archive catalog detached signature payload hash does not match latest.json');
  }
  const publicKey = Buffer.from(String(signature.public_key_base64 || ''), 'base64');
  const signerHash = createHash('sha256').update(publicKey).digest('hex');
  if (signerHash !== expectedSigner) {
    throw new Error('archive catalog signer does not match the pinned archive authority');
  }
  if (signature.key_id !== `mldsa87-sha256:${expectedSigner}` || !signature.signature_base64) {
    throw new Error('archive catalog detached signature key id or signature is invalid');
  }
  return expectedSigner;
}

export function validateDistributionManifest(manifestValue, snapshotValue) {
  const manifest = requireObject(manifestValue, 'archive distribution manifest');
  const snapshot = requireObject(snapshotValue, 'validator-pruned snapshot');
  if (manifest.schema !== DISTRIBUTION_SCHEMA || manifest.distribution_schema !== DISTRIBUTION_SCHEMA) {
    throw new Error(`archive distribution manifest schema must be ${DISTRIBUTION_SCHEMA}`);
  }
  if (manifest.signature_domain !== DISTRIBUTION_SIGNATURE_DOMAIN) {
    throw new Error('archive distribution manifest signature domain is invalid');
  }
  if (manifest.snapshot_id !== snapshot.snapshot_id || Number(manifest.height) !== Number(snapshot.height)) {
    throw new Error('archive distribution manifest identity does not match the selected snapshot');
  }
  if (manifest.archive_filename !== snapshot.archive_filename
      || manifest.archive_sha256 !== snapshot.archive_sha256) {
    throw new Error('archive distribution manifest archive identity does not match the catalog');
  }
  if (!Array.isArray(manifest.chunks) || manifest.chunks.length === 0) {
    throw new Error('archive distribution manifest has no snapshot chunks');
  }
  let totalChunkBytes = 0;
  for (const [index, chunk] of manifest.chunks.entries()) {
    const name = String(chunk?.name || '');
    const size = Number(chunk?.size_bytes);
    if (!name || name.includes('/') || name.includes('\\') || name === '.' || name === '..') {
      throw new Error(`archive distribution chunk ${index} has an unsafe name`);
    }
    if (!Number.isSafeInteger(size) || size <= 0 || !/^[0-9a-f]{64}$/i.test(String(chunk?.sha256 || ''))) {
      throw new Error(`archive distribution chunk ${index} has invalid size or SHA-256`);
    }
    totalChunkBytes += size;
  }
  const compressedSize = Number(snapshot.compressed_size_bytes);
  if (!Number.isSafeInteger(compressedSize) || compressedSize <= 0 || totalChunkBytes !== compressedSize) {
    throw new Error('archive distribution chunk sizes do not match the catalog compressed size');
  }
  return manifest;
}

function readExpectedGenesisHash(path) {
  const genesis = JSON.parse(readFileSync(path, 'utf8'));
  return String(genesis?.integrity?.genesis_hash || '').trim().toLowerCase();
}

async function fetchRequired(url, label) {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(20_000),
    redirect: 'follow',
    headers: {
      accept: 'application/json, application/octet-stream;q=0.9, */*;q=0.8',
      'user-agent': 'Synergy-Node-Control-Panel-Release/19.0 archive-readiness',
    },
  });
  if (!response.ok) {
    const body = (await response.text()).replace(/\s+/g, ' ').trim().slice(0, 240);
    const ray = response.headers.get('cf-ray');
    const detail = [ray ? `cf-ray=${ray}` : '', body].filter(Boolean).join(' ');
    throw new Error(`${label} returned HTTP ${response.status}${detail ? ` (${detail})` : ''}`);
  }
  return Buffer.from(await response.arrayBuffer());
}

function cacheBustedUrl(url, nonce) {
  const requestUrl = new URL(url);
  requestUrl.searchParams.set('consumer_nonce', nonce);
  return requestUrl.toString();
}

async function fetchVerifiedCatalogPair(catalogUrl, authority, attempts = 4) {
  const errors = [];
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const nonce = randomUUID().replaceAll('-', '');
    try {
      const [catalogBytes, signatureBytes] = await Promise.all([
        fetchRequired(cacheBustedUrl(catalogUrl, nonce), 'archive catalog'),
        fetchRequired(cacheBustedUrl(`${catalogUrl}.sig`, nonce), 'archive catalog signature'),
      ]);
      const catalog = JSON.parse(catalogBytes.toString('utf8'));
      const signature = JSON.parse(signatureBytes.toString('utf8'));
      const signerHash = validateSignatureProof(catalogBytes, signature, authority);
      return { catalogBytes, signatureBytes, catalog, signature, signerHash };
    } catch (error) {
      errors.push(`attempt ${attempt}: ${error.message}`);
      if (attempt < attempts) {
        await new Promise((resolve) => setTimeout(resolve, 2_000));
      }
    }
  }
  throw new Error(`archive catalog and detached signature did not converge. ${errors.join('; ')}`);
}

async function requirePublicArtifact(url, label, expectedSize = null) {
  const response = await fetch(url, {
    method: 'HEAD',
    signal: AbortSignal.timeout(20_000),
    redirect: 'follow',
    headers: {
      'user-agent': 'Synergy-Node-Control-Panel-Release/19.0 archive-readiness',
    },
  });
  if (!response.ok) {
    throw new Error(`${label} returned HTTP ${response.status}`);
  }
  if (expectedSize == null) {
    return;
  }
  const contentLength = Number(response.headers.get('content-length'));
  if (!Number.isSafeInteger(contentLength) || contentLength <= 0) {
    throw new Error(`${label} did not report a positive content length`);
  }
  if (contentLength !== expectedSize) {
    throw new Error(`${label} size mismatch: expected ${expectedSize}, received ${contentLength}`);
  }
}

function verifyAegisJson(verifier, domain, inputPath, signaturePath, signerHash, label) {
  const verification = spawnSync(verifier, [
    'verify-json', '--domain', domain,
    '--input', inputPath, '--signature', signaturePath,
    '--expected-signer-sha256', signerHash,
  ], { encoding: 'utf8' });
  if (verification.status !== 0) {
    throw new Error(`${label} Aegis verification failed: ${String(verification.stderr || '').trim()}`);
  }
}

function parseArgs(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (!key?.startsWith('--') || !value) {
      throw new Error('usage: archive-readiness-preflight.mjs --verifier <path> [--catalog-url <url>]');
    }
    options[key.slice(2)] = value;
  }
  return options;
}

export async function runPreflight(options = {}) {
  const catalogUrl = options.catalogUrl || DEFAULT_CATALOG_URL;
  const genesisPath = options.genesisPath || 'testnet/runtime/configs/genesis/genesis.json';
  const authorityPath = options.authorityPath || 'testnet/runtime/configs/archive-snapshot-authority.json';
  const verifier = options.verifier;
  if (!verifier) {
    throw new Error('archive readiness preflight requires the canonical Aegis verifier path');
  }

  const authority = JSON.parse(readFileSync(authorityPath, 'utf8'));
  const {
    catalogBytes,
    signatureBytes,
    catalog,
    signature,
    signerHash,
  } = await fetchVerifiedCatalogPair(catalogUrl, authority);
  const snapshot = validateCatalog(catalog, readExpectedGenesisHash(genesisPath));

  const [manifestBytes, manifestSignatureBytes] = await Promise.all([
    fetchRequired(snapshot.manifest_url, 'archive distribution manifest'),
    fetchRequired(snapshot.manifest_signature_url, 'archive distribution manifest signature'),
  ]);
  const manifest = validateDistributionManifest(
    JSON.parse(manifestBytes.toString('utf8')),
    snapshot,
  );

  const work = mkdtempSync(join(tmpdir(), 'synergy-archive-readiness-'));
  try {
    const catalogPath = join(work, 'latest.json');
    const signaturePath = join(work, 'latest.json.sig');
    const manifestPath = join(work, 'distribution-manifest.json');
    const manifestSignaturePath = join(work, 'distribution-manifest.sig');
    writeFileSync(catalogPath, catalogBytes);
    writeFileSync(signaturePath, signatureBytes);
    writeFileSync(manifestPath, manifestBytes);
    writeFileSync(manifestSignaturePath, manifestSignatureBytes);
    verifyAegisJson(verifier, SIGNATURE_DOMAIN, catalogPath, signaturePath, signerHash, 'archive catalog');
    verifyAegisJson(
      verifier,
      DISTRIBUTION_SIGNATURE_DOMAIN,
      manifestPath,
      manifestSignaturePath,
      signerHash,
      'archive distribution manifest',
    );
  } finally {
    rmSync(work, { recursive: true, force: true });
  }

  const artifactBaseUrl = new URL('.', snapshot.manifest_url);
  await Promise.all([
    requirePublicArtifact(
      snapshot.snapshot_url,
      'archive snapshot payload',
      Number(snapshot.compressed_size_bytes),
    ),
    requirePublicArtifact(snapshot.checksums_url, 'archive snapshot checksums'),
    ...manifest.chunks.map((chunk) => requirePublicArtifact(
      new URL(encodeURIComponent(chunk.name), artifactBaseUrl).toString(),
      `archive snapshot chunk ${chunk.name}`,
      Number(chunk.size_bytes),
    )),
  ]);
  return snapshot;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const args = parseArgs(process.argv.slice(2));
  runPreflight({
    verifier: args.verifier,
    catalogUrl: args['catalog-url'],
    genesisPath: args['genesis-path'],
    authorityPath: args['authority-path'],
  }).then((snapshot) => {
    console.log(`Archive readiness OK: ${snapshot.snapshot_id} at height ${snapshot.height}`);
  }).catch((error) => {
    console.error(`Archive readiness failed: ${error.message}`);
    process.exit(1);
  });
}

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  MAX_AGE_SECONDS,
  validateCatalog,
  validateDistributionManifest,
  validateSignatureProof,
} from '../release/archive-readiness-preflight.mjs';

const genesisHash = 'f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789';
const now = 1_800_000_000;

function catalog() {
  return {
    schema: 'synergy-archive-snapshot-catalog-v1',
    chain_id: 1266,
    network_id: 'synergy-testnet-v3',
    genesis_hash: genesisHash,
    updated_at: now,
    catalog_signature_status: 'AEGIS_PQC_VERIFIED',
    signature_scheme: 'aegis-pqc',
    signature_domain: 'SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1',
    catalog_content_root: 'a'.repeat(64),
    snapshots: [{
      snapshot_id: 'snapshot-000843613-e0a953a8',
      snapshot_class: 'validator-pruned',
      chain_id: 1266,
      network_id: 'synergy-testnet-v3',
      genesis_hash: genesisHash,
      height: 843613,
      status: 'published',
      verification_status: 'green',
      manifest_signature_status: 'AEGIS_PQC_VERIFIED',
      producer_role: 'archive_validator',
      producer_node_kind: 'archive-validator',
      binary_compatibility: 'synergy-testnet-v3-validator-pruned-v1',
      last_verified_at: now,
      snapshot_url: 'https://archive.example/snapshot.tar.zst',
      manifest_url: 'https://archive.example/distribution-manifest.json',
      manifest_signature_url: 'https://archive.example/signature.sig',
      checksums_url: 'https://archive.example/checksums.sha256',
      archive_filename: 'snapshot.validator-pruned.tar.zst',
      archive_sha256: 'c'.repeat(64),
      compressed_size_bytes: 10,
    }],
  };
}

test('accepts a fresh canonical validator-pruned catalog', () => {
  assert.equal(validateCatalog(catalog(), genesisHash, now).height, 843613);
});

test('requires a coherent distribution manifest and complete chunk sizing', () => {
  const snapshot = catalog().snapshots[0];
  const manifest = {
    schema: 'synergy-archive-snapshot-distribution-v1',
    distribution_schema: 'synergy-archive-snapshot-distribution-v1',
    signature_domain: 'SYNERGY_ARCHIVE_SNAPSHOT_DISTRIBUTION_V1',
    snapshot_id: snapshot.snapshot_id,
    height: snapshot.height,
    archive_filename: snapshot.archive_filename,
    archive_sha256: snapshot.archive_sha256,
    chunks: [{ name: 'snapshot.part-000000', size_bytes: 10, sha256: 'd'.repeat(64) }],
  };
  assert.equal(validateDistributionManifest(manifest, snapshot), manifest);

  manifest.chunks[0].name = '../snapshot.part-000000';
  assert.throws(() => validateDistributionManifest(manifest, snapshot), /unsafe name/);
  manifest.chunks[0].name = 'snapshot.part-000000';
  manifest.chunks[0].size_bytes = 9;
  assert.throws(() => validateDistributionManifest(manifest, snapshot), /do not match/);
});

test('rejects stale catalog and snapshot timestamps', () => {
  const staleCatalog = catalog();
  staleCatalog.updated_at = now - MAX_AGE_SECONDS - 1;
  assert.throws(() => validateCatalog(staleCatalog, genesisHash, now), /archive catalog is older/);

  const staleSnapshot = catalog();
  staleSnapshot.snapshots[0].last_verified_at = now - MAX_AGE_SECONDS - 1;
  assert.throws(() => validateCatalog(staleSnapshot, genesisHash, now), /validator-pruned snapshot is older/);
});

test('rejects wrong identity and unverified status', () => {
  const wrongChain = catalog();
  wrongChain.chain_id = 1;
  assert.throws(() => validateCatalog(wrongChain, genesisHash, now), /not Synergy Testnet/);

  const unverified = catalog();
  unverified.snapshots[0].manifest_signature_status = 'UNVERIFIED';
  assert.throws(() => validateCatalog(unverified, genesisHash, now), /status is not green/);
});

test('pins detached signature proof to the archive authority', () => {
  const catalogBytes = Buffer.from(JSON.stringify(catalog()));
  const publicKey = Buffer.from('archive-authority-public-key');
  const signerHash = createHash('sha256').update(publicKey).digest('hex');
  const signature = {
    schema: 'synergy-aegis-detached-json-signature-v2',
    algorithm: 'ML-DSA-87',
    domain: 'SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1',
    payload_sha256: createHash('sha256').update(catalogBytes).digest('hex'),
    key_id: `mldsa87-sha256:${signerHash}`,
    public_key_base64: publicKey.toString('base64').replace(/=+$/, ''),
    signature_base64: 'c2lnbmF0dXJl',
  };
  const authority = {
    schema: 'synergy-archive-snapshot-authority-v1',
    algorithm: 'ML-DSA-87',
    signer_public_key_sha256: signerHash,
  };
  assert.equal(validateSignatureProof(catalogBytes, signature, authority), signerHash);

  authority.signer_public_key_sha256 = 'b'.repeat(64);
  assert.throws(
    () => validateSignatureProof(catalogBytes, signature, authority),
    /does not match the pinned archive authority/,
  );
});

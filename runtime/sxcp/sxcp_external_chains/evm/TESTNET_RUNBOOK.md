# SXCP Sepolia + Amoy Testnet Runbook (Phase 1)

This folder now contains a deployable SXCP EVM stack for:

- Ethereum Sepolia (`11155111`)
- Polygon Amoy (`80002`)

V2 alignment:

- No pooled custody bridge flow.
- Intent commit + threshold attestation verification only.
- Destination execution is consumer-driven via attestation consumption.

## 1) Install

```bash
cd runtime/sxcp/sxcp_external_chains/evm
cp .env.example .env
npm ci
```

Fill `.env` with:

- `SEPOLIA_RPC_URL`
- `AMOY_RPC_URL`
- `DEPLOYER_PRIVATE_KEY`
- `INITIAL_RELAYER_ADDRESSES` (comma-separated)
- `INITIAL_THRESHOLD`
- `PQC_ATTESTATION_BUNDLE_PATH` (verified bundle from the off-chain PQC relayer)

## 2) Deploy Both Chains

```bash
npm run deploy:sepolia
npm run deploy:amoy
```

Deployment outputs are written to:

- `deployments/sepolia.json`
- `deployments/amoy.json`

## 3) Wire Remote Endpoints

```bash
npm run wire:sepolia-to-amoy
npm run wire:amoy-to-sepolia
```

This configures each `SXCPIntentHub` with the other chain as a valid remote endpoint.

## 4) Run Demo Flow

Publish intent on Sepolia:

```bash
npm run demo:publish:sepolia
```

Submit attestation bundle on Amoy:

```bash
npm run demo:attest:on-amoy
```

Runtime artifacts are saved under `runtime/`:

- `latest-intent-sepolia-to-amoy.json`
- `latest-attestation-sepolia-to-amoy.json`

Generate a testnet relayer config artifact from deployment outputs:

```bash
npm run export:testnet-config
```

Output:

- `runtime/testnet-sxcp-relayer-config.json`

## 5) Contracts Deployed in Suite

- `GovernanceModule`
- `WitnessRegistry`
- `SignatureVerifier`
- `FinalityChecker`
- `StateProofValidator`
- `AuditLogger`
- `SXCPIntentHub`

## 6) Test

```bash
npm test
```

The test validates:

- Intent publication
- Threshold commitment and active-relayer validation
- Attestation verification
- Single-use attestation consumption

## PQC bundle input

The attestation script consumes a JSON bundle verified by the off-chain PQC relayer.
It requires `pqcAlgorithmId` (1, 2, or 3), `epochId`, `stateProofRoot`, `digest`,
sorted unique `signers`, and matching nonzero 32-byte `pqcCommitments`.
The script checks the digest against the current intent and destination chain.

The current on-chain verifier checks commitment structure, relayer membership,
ordering, and threshold. Cryptographic PQC signature verification occurs off-chain.
The contract unit tests use explicitly labeled structural fixtures and do not
establish off-chain PQC verification.

Use Node.js 24.15 or later for the Hardhat 3 tooling.

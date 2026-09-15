# Testnet-v3 Service Deployment Contract

The release-config generator emits **prepare-only** artifacts.  It never SSHes,
starts, stops, reloads, enables, or replaces a service.  It also never replaces
an installed `node.toml` or `node.env`: generated configuration must be merged
into the verified service-specific configuration while preserving host-local
identity, key, port, endpoint, storage, and supervision settings.

Every activation plan binds the exact canonical Genesis payload through
`SYNERGY_GENESIS_FILE`, its SHA-256, and its Genesis hash.  A plan must be
discarded if the target unit/plist no longer matches the preflight contract.

## Verified service contract map

| Generated role(s) | Platform | Existing service contract | Prepare artifact | Disposition |
| --- | --- | --- | --- | --- |
| `val1`–`val6` | systemd | `synergy-validator.service`; `/etc/synergy/validator/config.toml` | Genesis-only systemd drop-in | Replace the complete checksum-bound V3 TOML only after inactive-service/port preflight and a recoverable backup; the ML-DSA-65 key is a separate root-only file |
| `relay1`–`relay3` | systemd | `synergy-testnet-relayer.service`; relative `config/node.toml` | Genesis-only systemd drop-in | Re-verify the unit working directory, then replace the complete checksum-bound V3 TOML after inactive-service/port preflight and a recoverable backup |
| `bootnode1` | systemd | `synergy-testnet-bootnode1.service`; its existing bootnode config | Genesis-only systemd drop-in | Manual config merge and explicit activation required |
| `bootnode2` | systemd | Legacy `synergy-testnet-bootnode2.service` remains emergency-held and untouched | New `synergy-testnet-v3-bootnode2.service`, isolated config/state, content-addressed runtime guard | Dedicated V3 template; operator supplies only a verified V3 runtime binary mapping, P2P identity decision, and port preflight |
| `bootnode3` | systemd | Legacy testbeta-named, emergency-held unit remains untouched | New `synergy-testnet-v3-bootnode3.service`, isolated config/state, content-addressed runtime guard | Dedicated V3 template; operator supplies only a verified V3 runtime binary mapping, P2P identity decision, and port preflight |
| `seed1`–`seed3` | systemd | Legacy `synergy-seed-service@seedN.service` remains untouched | New `synergy-testnet-v3-seed@.service`, V3 JSON config, packaged seed source, and hash-verifying guard | Dedicated V3 template; port preflight and explicit activation required |
| `rpc-gateway` | systemd | `synergy-rpc-gateway.service`; existing role-specific config/env | Genesis-only systemd drop-in | Manual config merge and explicit activation required |
| `observer` | systemd | `synergy-observer.service`; existing role-specific config/env | Genesis-only systemd drop-in | Manual config merge and explicit activation required |
| `explorer-indexer` | systemd | Legacy `synergy-node-exp.service` and its OOM-held/missing-config state remain untouched | New `synergy-testnet-v3-explorer-indexer.service`, isolated config/state, content-addressed runtime guard | Dedicated V3 template; operator supplies only a verified V3 runtime binary mapping, P2P identity decision, and port preflight |
| `archive-validator` | launchd | `network.synergy.archive-validator` | Launchd plist environment merge fragment | Merge only `EnvironmentVariables` into the re-verified existing plist; do not replace `ProgramArguments` or load the fragment as a second job |

## Legacy service-remediation P0 set

The generator now records an empty
`deployment.manual_service_remediation_required` list.  It never resolves a
legacy service problem by changing that service: the six former P0 roles have
new V3 service identities, paths, and prepare-only templates.

The legacy `testbeta`, emergency-held, OOM-held, and legacy-seed units must
remain untouched.  They are neither input nor fallback for the dedicated V3
units.

## Dedicated-service activation P0s

The dedicated templates are intentionally not activatable until the following
operator-supplied facts are verified and written into each role's
`activation-plan.json` process:

- Bootnode2, bootnode3, and explorer-indexer require the absolute path and
  SHA-256 of a content-addressed Testnet-v3 runtime binary placed below the
  dedicated V3 binary root.  The package does not guess from a legacy binary.
- Those same three roles require a verified non-validator P2P/private-identity
  import contract, or an explicit approval that an isolated replacement
  identity is correct.  The repository does not prove that mapping.
- Every dedicated role requires a collision-free port preflight.  The plan
  names the required binds; no legacy listener or port configuration is copied.

These are launch gates, not permission to overwrite service configuration or
bypass an existing safety control.

## Mandatory pre-validator support sequence

The generated release tree contains
`support-service-activation-sequence.json`.  It is a checksum-bound,
**offline-only** contract: it neither connects to a host nor starts a service.
It binds chain 1266, `synergy-testnet-v3`, the exact Genesis hash and SHA-256,
and the finalized consensus-parameter root.

Before any validator service may be activated, operators must retain external,
host-collected readiness evidence in this exact order:

1. Bootnodes and seed services
2. Relayers
3. RPC gateway
4. Atlas explorer indexer

Every successor stage requires evidence that all predecessor stages are live
and agree on the canonical chain/network/Genesis binding.  The artifact names
the precise activation plans and the minimum evidence required at each stage;
it does not convert an open listener, a running process, or a generated file
into live-readiness proof.  Each validator activation plan contains a
`support_service_activation_sequence` gate requiring all four completed
support stages and a separately retained external evidence record.

## Generated artifact rules

- Linux uses one immutable Genesis destination and a narrow, new systemd
  drop-in.  The drop-in contains no `ExecStart`, `EnvironmentFile`, user,
  port, key, or enable/start directive. Validators and relayers use a
  full-config replacement contract because their runtime keys are external to
  TOML and startup rejects stale consensus, Genesis, transport, and topology
  bindings.
- The macOS archive uses its service-owned configuration directory and receives
  a syntactically valid plist **merge fragment**.  launchd does not support
  systemd-style drop-ins, so the fragment is not a replacement job.
- Each `activation-plan.json` names the exact service contract, payload hashes,
  manual remediation status, and a mandatory re-verification requirement.
- Every dedicated plan contains a `dedicated_install_map` with the exact
  package-payload-to-absolute-destination mapping.  The operator must copy
  only those new V3 files.  Runtime `runtime.env.example` is deliberately
  non-deployable; it becomes the new runtime environment file only after the
  approved binary path and SHA-256 have been filled in.
- Seed plans identify `dedicated-seed/seed-service.json` as the active config
  consumed by the bundled seed source.  The generated `seedN.toml` is retained
  as a topology audit artifact and must not be substituted for that JSON file.
- The shared seed template installs at
  `/etc/systemd/system/synergy-testnet-v3-seed@.service`; activation, after
  every stated gate has been satisfied, uses its named V3 instance such as
  `synergy-testnet-v3-seed@seed1.service`.
- A missing role contract is a generator failure, not a fallback to a generic
  configuration path.
- Dedicated systemd templates have no `[Install]` section and use isolated
  DynamicUser-owned state directories.  Their hash-verifying guards refuse a
  missing, tampered, or non-V3-root runtime/source/config/Genesis payload.
  Runtime units bind the generated configuration SHA-256 in the unit itself;
  seed units bind the packaged JSON configuration SHA-256 in their guard.

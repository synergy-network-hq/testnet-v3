# Fresh PoSy v3 validator-02..validator-06 launch

This is the production path for the separate Chain-1266 Testnet-v3 chain that
starts from block zero. It does not migrate, import, or read a prior chain.
Fresh PoSy v3 uses chain incarnation 5 and consensus-state schema 5. The P1
incarnation-4 path remains isolated and must not be staged on these hosts.

The commands below intentionally use only `synergy-val2` through
`synergy-val6`. Keep one persistent workbook-backed SSH connection per host;
do not replace those aliases with raw addresses and do not open probe sessions.

## 1. Required final public inputs

Do not proceed until all of these exist and their own validators report final:

- the canonical, execution-complete, governance-approved fresh P3 Genesis;
- the completed 21-validator public ceremony index and completion record;
- the validator VPN public registry;
- one reproducible release build of `synergy-validator-node` with its three
  source-revision build bindings set;
- a Governance Authority signature over the desired-state file.

The no-clobber Genesis sequence is:

1. executed source: `fresh-p3-genesis-with-executed-deployment.json`;
2. prepared authorities: `fresh-p3-genesis-authorities-bound-pre-anchor.json`;
3. governed membership-anchor build and attach;
4. deployable final: `fresh-p3-genesis-final-authority-bound.json`.

Only the fourth file is accepted by the validator bundle renderer. It must
carry the top-level `/etdag_membership_anchor`; neither an executed-only source
nor a pre-anchor candidate is deployable.

The final Genesis must activate exactly `validator-02` through `validator-06`.
`validator-01` and `validator-07` through `validator-21` remain inactive public
Genesis identities; five is an initial set, not a hard-coded network maximum.

## 2. Render public host configurations

Choose a new, nonexistent output directory. The renderer refuses to overwrite
one and does not access custody material.

```bash
P3_RELEASE=/absolute/path/to/new-p3-release
P3_GENESIS="$PWD/launch/posy-v3-genesis-inputs/fresh-p3-genesis-final-authority-bound.json"

python3 scripts/generate-posy-v3-validator-deployment-bundles.py \
  --genesis "$P3_GENESIS" \
  --ceremony-index launch/posy-v3-genesis-inputs/validator-identity-ceremony-index.json \
  --ceremony-completion launch/posy-v3-genesis-inputs/validator-identity-ceremony-completion.json \
  --vpn-registry launch/validator-vpn-public-registry.json \
  --output-root "$P3_RELEASE/validator-public-bundles"
```

The only generated node files are public TOML configurations and their hash
manifest. No encrypted bundle, passphrase, private key, or VPN private key is
copied into this output.

## 3. Build and sign the desired state

Use a release ID/tag pair whose suffixes match, for example
`chain1266-incarnation-5-rc34` and `chain1266-v20.0.0-rc.34`. Supply the exact
full revisions embedded in the release binary.

```bash
build-chain1266-desired-state \
  --release-id chain1266-incarnation-5-rc34 \
  --release-tag chain1266-v20.0.0-rc.34 \
  --testnet-revision 0000000000000000000000000000000000000000 \
  --synq-revision 0000000000000000000000000000000000000000 \
  --aegis-revision 0000000000000000000000000000000000000000 \
  --genesis "$P3_GENESIS" \
  --start-authority launch/TESTNET_V3_CHAIN_START_AUTHORITY.json \
  --artifact validator_node="$P3_RELEASE/bin/synergy-validator-node" \
  --configuration validator-02="$P3_RELEASE/validator-public-bundles/validator-02/config.toml" \
  --configuration validator-03="$P3_RELEASE/validator-public-bundles/validator-03/config.toml" \
  --configuration validator-04="$P3_RELEASE/validator-public-bundles/validator-04/config.toml" \
  --configuration validator-05="$P3_RELEASE/validator-public-bundles/validator-05/config.toml" \
  --configuration validator-06="$P3_RELEASE/validator-public-bundles/validator-06/config.toml" \
  --output "$P3_RELEASE/desired-state.json"
```

Replace the three all-zero revision examples; the builder rejects them unless
they are real full lowercase Git revisions. Sign through the frozen Governance
Authority's interactive encrypted-bundle workflow. Never use the plaintext-key
development signer and never place the passphrase in a command, environment
variable, file, or log.

```bash
sign_chain1266_release_authorization \
  --authorize-desired-state \
  --desired-state "$P3_RELEASE/desired-state.json" \
  --authority-bundle /absolute/path/to/SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY \
  --output "$P3_RELEASE/desired-state.signature.json"

verify-chain1266-release-authorization \
  --desired-state "$P3_RELEASE/desired-state.json" \
  --desired-state-signature "$P3_RELEASE/desired-state.signature.json"
```

Fresh P3 does not use the P1 consensus-activation file. Its only initial
consensus authority is `/consensus/posy_v3_activation` inside the signed,
canonical Genesis.

## 4. Stage each validator without starting it

Stage byte-identical copies of these public release files on all five hosts:

- `/opt/synergy/chain1266/releases/<release>/bin/synergy-validator-node`;
- `/etc/synergy/chain1266/genesis.json`;
- `/etc/synergy/chain1266/desired-state.json`;
- `/etc/synergy/chain1266/desired-state.signature.json`;
- that host's `/etc/synergy/chain1266/validator-NN.toml`.

Install the systemd unit and launcher from `launch/chain1266-systemd/`. Install
only that validator's decrypted ML-DSA-65 consensus key, through the authorized
local custody workflow, at
`/etc/synergy/chain1266/private/validator-NN/mldsa65-consensus.private.key`.
It must be owned by the service account, mode `0600`, correspond to the public
key frozen in Genesis, and never transit through the public bundle directory.

Create `/etc/synergy/chain1266/validator-NN.env` with these public path
bindings (and the private-key *path*, never its contents):

```text
CHAIN1266_ROLE_BINARY=/opt/synergy/chain1266/releases/<release>/bin/synergy-validator-node
CHAIN1266_ROLE_CONFIG=/etc/synergy/chain1266/validator-NN.toml
SYNERGY_PROJECT_ROOT=/var/lib/synergy/validator/chain-1266/incarnation-5
SYNERGY_DATA_PATH=/var/lib/synergy/validator/chain-1266/incarnation-5/data
SYNERGY_GENESIS_FILE=/etc/synergy/chain1266/genesis.json
SYNERGY_DESIRED_STATE_MANIFEST=/etc/synergy/chain1266/desired-state.json
SYNERGY_DESIRED_STATE_MANIFEST_SHA256=<sha256-of-exact-installed-desired-state>
SYNERGY_DESIRED_STATE_SIGNATURE=/etc/synergy/chain1266/desired-state.signature.json
SYNERGY_VALIDATOR_MLDSA65_CONSENSUS_PRIVATE_KEY_FILE=/etc/synergy/chain1266/private/validator-NN/mldsa65-consensus.private.key
```

Do not create or reuse an incarnation-4 state directory. Before staging, the
incarnation-5 project/data directories must either be absent or newly empty.

## 5. Five-host fail-closed preflight

On each already-open persistent SSH connection, load that host's environment
and run the same installed validator executable. This checks the signed desired
state, frozen Governance Authority, Genesis hash/incarnation/schema, active-set
root, exact binary hash, exact node-config hash, source revisions, and isolated
state namespace without opening chain state or networking. It also loads the
host-local ML-DSA-65 key, proves it corresponds to that validator's public key
in Genesis, and then exits; the key itself is never printed.

```bash
set -a
. /etc/synergy/chain1266/validator-NN.env
set +a
"$CHAIN1266_ROLE_BINARY" preflight-release --config "$CHAIN1266_ROLE_CONFIG"
```

Every host must print `CHAIN1266_ROLE_RELEASE_PREFLIGHT_VERIFIED` for the same
release ID. Any mismatch is a stop condition; do not edit a staged file in
place. Correct the release input, regenerate/sign a new desired state, and
restage identical artifacts.

## 6. Start and prove the chain

After all five preflights pass and all five VPN routes can reach the other four
validator transports, start the five instances in one coordinated window:

```bash
sudo systemctl start synergy-chain1266-role@validator-NN.service
```

Success is not `systemctl active`. Confirm all five nodes independently report:

1. the same Genesis hash and chain incarnation 5;
2. the exact active set `validator-02` through `validator-06` and quorum 4;
3. authenticated peers for the other four validators;
4. identical finalized block hashes at increasing heights;
5. at least three consecutive new finalized blocks after the observation
   begins, with no conflicting QC or safety-halt event.

Only after those proofs pass may RPC gateways, relayers, or other consumers be
attached to the fresh chain. Do not erase the single-authority host based only
on process status; preserve it until the fresh-chain proof has been recorded.

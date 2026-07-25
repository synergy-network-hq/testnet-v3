# Testnet Validator Update Workflow

This file is the maintainer guide for validator config changes in the Testnet control panel.

For live node debugging commands, also keep these cheat sheets handy:

- `docs/developer/testnet-validator-debug-cheatsheet-macos.md`
- `docs/developer/testnet-validator-debug-cheatsheet-linux.md`
- `docs/developer/testnet-validator-debug-cheatsheet-windows.md`

The short version:

- Edit the control-panel generators and appliance builders first.
- Regenerate `testnet/runtime/` artifacts from those generators.
- Treat `genesis-nodes/...` copies as exports or legacy mirrors, not the primary source of truth.

## Source Of Truth

The control panel is what creates and repairs validator appliances. The primary edit surface is inside `node-control-panel/`, not inside `genesis-nodes/`.

| File | Role |
| --- | --- |
| `control-service/src/testnet.rs` | Builds the live validator appliance used by the app during `setup_node`, installer import, ceremony import, and appliance repair. If a validator started by the control panel should see a config value, this file usually needs to emit it. |
| `scripts/testnet/render-configs.sh` | Generates the canonical rendered configs under `testnet/runtime/configs/`. Keep this aligned with the installer/runtime config shape so the bundled reference configs match what the control panel deploys. |
| `src/lib/testnetBootstrap.js` | Renderer-side helper that writes bootstrap peer config. Update this when the `peers.toml` structure changes. |
| `scripts/release/build-bundle-prep.sh` | Release prep entry point. Rebuilds deterministic runtime artifacts, validates the committed installer templates, and leaves installer packaging to GitHub Actions. |

## Generated Files

Do not hand-edit these unless you are debugging a one-off local issue and plan to throw the changes away:

- `testnet/runtime/configs/*.toml`
- `testnet/runtime/installers/*`
- `testnet/runtime/installers/*/config/peers.toml`
- `testnet/runtime/installers/*/keys/setup-package.json`

The control panel consumes the generated installer/runtime artifacts above. Editing the generated output without updating the generator guarantees drift on the next rebuild.

## What `genesis-nodes/` Is

`genesis-nodes/` is not the primary control-panel input for validator setup.

Today, the control panel deploys validators from the generated bundles under:

- `testnet/runtime/installers/`

If `genesis-nodes/.../setup-packages/` or related folders are still kept around, treat them as downstream export copies only. The safe rule is:

1. Update the generator inside `node-control-panel/`.
2. Refresh the committed installer assets under `testnet/runtime/installers/`.
3. Sync any legacy `genesis-nodes/` copies from the regenerated control-panel output.

Do not make the same config change independently in both places.

## When A Validator Setting Changes

### Case 1: Existing config key, value change only

Example: changing timeout values, quorum thresholds, peer lists, bootstrap behavior, or startup env.

Update the relevant generators:

1. `control-service/src/testnet.rs`
2. `scripts/testnet/render-configs.sh`
3. `src/lib/testnetBootstrap.js` if `peers.toml` changed
4. Refresh the committed installer assets under `testnet/runtime/installers/`

### Case 2: New config key or renamed config key

If the node binary does not already understand the key, first add support in the core node runtime outside the control panel.

Typical examples from the main repo root:

- `../src/config/mod.rs`
- `../src/p2p/networking.rs`
- `../src/consensus/consensus_algorithm.rs`
- `../src/consensus/dual_quorum.rs`

After the runtime supports the key, wire the same key into the control-panel generators listed above.

If the runtime parser and the control-panel generator are not updated together, the app will ship config that the node either ignores or fails to parse.

## Required Update Checklist

Use this checklist every time validator setup behavior changes.

1. Update `control-service/src/testnet.rs` so live app-created validator appliances use the new values.
2. Update `scripts/testnet/render-configs.sh` so bundled reference configs stay aligned.
3. Update `src/lib/testnetBootstrap.js` if `peers.toml` generation changed.
4. If the key is new, update the core runtime parser/consumer in `../src/...`.
5. Refresh the committed installer assets under `testnet/runtime/installers/`.
6. Verify generated `node.toml`, `peers.toml`, and `setup-package.json`.
7. Rebuild the app bundle if this is a release or installer handoff.
8. Only after regeneration, sync any legacy `genesis-nodes/` package copies that still need to exist.

## Regenerate Artifacts

Run from `node-control-panel/`:

```bash
bash scripts/testnet/render-configs.sh
SKIP_BUNDLED_ASSET_GIT_CLEAN_CHECK=1 npm run build:bundle-prep
```

For a release build:

```bash
SKIP_BUNDLED_ASSET_GIT_CLEAN_CHECK=1 npm run build:bundle-prep
npm run dist:electron
```

## Full Release Procedure

This release path is coordinated across two repos:

1. `testnet/`
2. `node-control-panel/`

The rule is:

- All validator/runtime bundle generation is **manual** and must be completed locally before tagging `node-control-panel`.
- GitHub Actions is **automatic packaging only**. It must not be treated as the place where `testnet/runtime/installers/` gets regenerated.
- The same tag `vX.Y.Z` must exist in both repos before the control-panel release workflow can succeed.

## Manual Vs Automatic

### Manual steps

These steps are run by a maintainer on a workstation:

1. Update runtime code in `testnet/` if the node binary needs new config keys or behavior.
2. Update control-panel generators in `node-control-panel/`.
3. Build or collect the fresh multi-platform `synergy-testnet` binaries.
4. Copy those fresh binaries into both repos' `binaries/` folders as needed.
5. Regenerate `testnet/runtime/configs/`, `testnet/runtime/installers/`, and `testnet/runtime/workspace-manifest.json` locally.
6. Sync all validator setup packages into the legacy `setup-packages` export folders.
7. Verify the generated assets locally.
8. Commit and push both repos.
9. Create and push the matching tags.
10. Watch the GitHub Actions release run until every installer finishes.

### Automatic steps

These steps are performed by GitHub Actions after the control-panel tag is pushed:

1. Check out `node-control-panel` at `vX.Y.Z`.
2. Check out `testnet` at `vX.Y.Z`.
3. Build the current-platform `synergy-testnet` binary for the installer job that is running.
4. Refresh `testnet/runtime/workspace-manifest.json` inside the temporary CI workspace.
5. Build the Electron installer for the current matrix OS.
6. Upload the generated installer files to the releases repo.

### How to trigger the automatic steps

Trigger the release workflow with either of these actions:

```bash
git push origin vX.Y.Z
```

or manually from GitHub:

1. Open `synergy-network-hq/synergy-node-control-panel`.
2. Go to `Actions`.
3. Open `Electron Release Build`.
4. Click `Run workflow`.

## Exact Step-By-Step Release Sequence

### Step 1: Update and verify the runtime repo

Type: `Manual`

Run from `/Users/devpup/Desktop/Testnet/synergy-testnet`:

```bash
cd /Users/devpup/Desktop/Testnet/synergy-testnet

cargo fmt --manifest-path Cargo.toml --all

# Run the focused runtime tests for the code you changed.
# Example tests that were used for the validator mesh stabilization work:
cargo test --manifest-path src/Cargo.toml apply_env_overrides_accepts_mesh_stability_controls -- --exact
cargo test --manifest-path src/Cargo.toml resolve_bootstrap_dial_targets_includes_persistent_peers -- --exact
cargo test --manifest-path src/Cargo.toml test_dual_quorum_consensus -- --exact
cargo test --manifest-path src/Cargo.toml test_dual_quorum_enforces_minimum_validator_count -- --exact
```

If the runtime code did not change for this release, do not create a new runtime commit. Reuse the existing runtime commit and only create the new matching tag later.

### Step 2: Build or collect the runtime binaries

Type: `Manual`

Run from `/Users/devpup/Desktop/Testnet/synergy-testnet`:

```bash
cd /Users/devpup/Desktop/Testnet/synergy-testnet

# Native macOS arm64 build
cargo build --manifest-path src/Cargo.toml --release --bin synergy-testnet
cp target/release/synergy-testnet binaries/synergy-testnet-darwin-arm64
cp target/release/synergy-testnet binaries/synergy-testnet-macos-arm64
chmod +x binaries/synergy-testnet-darwin-arm64 binaries/synergy-testnet-macos-arm64

# Optional cross-builds if the toolchains are available on the current machine
cargo build --manifest-path src/Cargo.toml --release --target x86_64-unknown-linux-gnu --bin synergy-testnet || true
cargo build --manifest-path src/Cargo.toml --release --target x86_64-pc-windows-gnu --bin synergy-testnet || true

# If those cross-builds succeed, refresh the shipped binary files
cp target/x86_64-unknown-linux-gnu/release/synergy-testnet binaries/synergy-testnet-linux-amd64 2>/dev/null || true
cp target/x86_64-pc-windows-gnu/release/synergy-testnet.exe binaries/synergy-testnet-windows-amd64.exe 2>/dev/null || true
chmod +x binaries/synergy-testnet-linux-amd64 2>/dev/null || true
```

If Linux or Windows cross-builds are not available on the workstation, obtain the fresh Linux and Windows binaries from the release builders and copy them into these exact paths:

- `binaries/synergy-testnet-linux-amd64`
- `binaries/synergy-testnet-windows-amd64.exe`

### Step 3: Commit and push the runtime repo if it changed

Type: `Manual`

Run from `/Users/devpup/Desktop/Testnet/synergy-testnet`:

```bash
cd /Users/devpup/Desktop/Testnet/synergy-testnet
git status --short
git push origin main
```

If there are runtime file changes for the release, commit them before the push:

```bash
git add <runtime files>
git commit -m "describe the runtime change"
git push origin main
```

### Step 4: Create and push the runtime tag

Type: `Manual`

Run from `/Users/devpup/Desktop/Testnet/synergy-testnet`:

```bash
cd /Users/devpup/Desktop/Testnet/synergy-testnet
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

### Step 5: Update the control-panel source and release version

Type: `Manual`

Update the control-panel generator code first:

- `control-service/src/testnet.rs`
- `scripts/testnet/render-configs.sh`
- `testnet/runtime/installers/*` bundled installer templates and `keys/setup-package.json`
- `src/lib/testnetBootstrap.js` when `peers.toml` generation changes
- `.github/workflows/release.yml` only when the packaging workflow itself changes

Then bump the release version in the control-panel repo.

Run from `/Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel`:

```bash
cd /Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel

python3 - <<'PY'
import json
from pathlib import Path

path = Path("package.json")
data = json.loads(path.read_text(encoding="utf-8"))
data["version"] = "X.Y.Z"
path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
PY

python3 - <<'PY'
from pathlib import Path
import re

path = Path("control-service/Cargo.toml")
text = path.read_text(encoding="utf-8")
text = re.sub(r'^version = "[^"]+"', 'version = "X.Y.Z"', text, count=1, flags=re.MULTILINE)
path.write_text(text, encoding="utf-8")
PY
```

### Step 6: Sync the fresh runtime binaries into the control panel

Type: `Manual`

Run from `/Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel`:

```bash
cd /Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel

cp ../binaries/synergy-testnet-darwin-arm64 binaries/synergy-testnet-darwin-arm64
cp ../binaries/synergy-testnet-macos-arm64 binaries/synergy-testnet-macos-arm64
cp ../binaries/synergy-testnet-linux-amd64 binaries/synergy-testnet-linux-amd64
cp ../binaries/synergy-testnet-windows-amd64.exe binaries/synergy-testnet-windows-amd64.exe

chmod +x binaries/synergy-testnet-darwin-arm64 binaries/synergy-testnet-macos-arm64 binaries/synergy-testnet-linux-amd64
```

### Step 7: Regenerate the committed bundled validator/runtime assets locally

Type: `Manual`

Run from `/Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel`:

```bash
cd /Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel

bash scripts/testnet/render-configs.sh
SKIP_BUNDLED_ASSET_GIT_CLEAN_CHECK=1 npm run build:bundle-prep
```

What that manual bundle-prep command does:

1. Refreshes `binaries/*.sha256`.
2. Syncs canonical genesis into `testnet/runtime/configs/genesis/genesis.json`.
3. Re-renders `testnet/runtime/configs/*.toml`.
4. Validates the committed `testnet/runtime/installers/*` templates that GitHub Actions will package.
5. Rewrites `testnet/runtime/workspace-manifest.json`.
6. Validates the bundled validator mesh settings.
7. Rebuilds the renderer assets under `dist/`.

The legacy sync command copies:

- `testnet/runtime/installers/GenVal-01/keys/setup-package.json`
- `testnet/runtime/installers/GenVal-02/keys/setup-package.json`
- `testnet/runtime/installers/GenVal-03/keys/setup-package.json`
- `testnet/runtime/installers/GenVal-04/keys/setup-package.json`
- `testnet/runtime/installers/GenVal-05/keys/setup-package.json`

into:

- `$HOME/Desktop/setup-packages`
- `../../genesis-nodes/machine6-macmini-validator1/setup-packages`
- `../../genesis-nodes/machine6-macmini-validator1/setup-packages 2`

with these filenames:

- `validator-1-setup-package.json`
- `validator-2-setup-package.json`
- `validator-3-setup-package.json`
- `validator-4-setup-package.json`
- `validator-5-setup-package.json`

### Step 8: Verify the bundled assets locally

Type: `Manual`

Run from `/Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel`:

```bash
cd /Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel

bash -n scripts/testnet/render-configs.sh
bash -n scripts/release/validate-bundled-assets.sh
bash -n scripts/release.sh

ruby -e 'require "yaml"; YAML.load_file(".github/workflows/release.yml"); puts "yaml-ok"'

cargo test --manifest-path control-service/Cargo.toml setup_node_writes_role_metadata_and_bootstrap_inputs -- --exact
cargo test --manifest-path control-service/Cargo.toml ceremony_import_applies_assigned_validator_ports -- --exact
cargo test --manifest-path control-service/Cargo.toml repair_workspace_config_restores_ceremony_validator_ports_from_base_slot -- --exact
```

Then inspect these generated files directly:

- `binaries/synergy-testnet-*.sha256`
- `testnet/runtime/installers/GenVal-01/config/node.toml`
- `testnet/runtime/installers/GenVal-01/config/peers.toml`
- `testnet/runtime/installers/GenVal-01/keys/setup-package.json`
- `testnet/runtime/workspace-manifest.json`
- `$HOME/Desktop/setup-packages/validator-1-setup-package.json`
- `$HOME/Desktop/setup-packages/validator-5-setup-package.json`
- `../../genesis-nodes/machine6-macmini-validator1/setup-packages/validator-1-setup-package.json`
- `../../genesis-nodes/machine6-macmini-validator1/setup-packages/validator-5-setup-package.json`

### Step 9: Optional local macOS installer smoke build

Type: `Manual`

Run from `/Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel`:

```bash
cd /Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel
SKIP_BUNDLED_ASSET_GIT_CLEAN_CHECK=1 npm run build:bundle-prep
npm run dist:electron
```

This is optional, but useful before tagging when you want a local macOS packaging sanity check.

### Step 10: Commit and push the control-panel repo

Type: `Manual`

Run from `/Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel`:

```bash
cd /Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel

git status --short
git add .github/workflows/release.yml
git add control-service/Cargo.toml
git add docs/developer/testnet-validator-update-workflow.md
git add package.json
git add scripts/testnet/sync-legacy-setup-packages.sh
git add scripts/testnet/render-configs.sh
git add scripts/release/validate-bundled-assets.sh
git add testnet/runtime/configs
git add testnet/runtime/installers
git add testnet/runtime/workspace-manifest.json
git commit -m "describe the control-panel release change"
git push origin main
```

### Step 11: Create and push the control-panel tag

Type: `Manual`

Run from `/Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel`:

```bash
cd /Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

That push is the normal trigger for the automatic installer build workflow.

### Step 12: GitHub Actions packages and publishes the installers

Type: `Automatic`

Trigger:

```bash
git push origin vX.Y.Z
```

Automatic behavior:

1. GitHub Actions starts `Electron Release Build`.
2. The workflow checks out `node-control-panel`.
3. The workflow checks out `testnet` at the same tag.
4. Each matrix job builds the current-platform runtime binary.
5. Each matrix job refreshes `testnet/runtime/workspace-manifest.json` inside the temporary CI workspace.
6. Each matrix job builds the Electron installer for its OS.
7. Each matrix job uploads the installer files to `synergy-network-hq/synergy-node-control-panel-releases`.

CI does **not** regenerate `testnet/runtime/installers/`.

### Step 13: Watch the release run until all installers finish

Type: `Manual`

From any authenticated shell:

```bash
gh run list --repo synergy-network-hq/synergy-node-control-panel --limit 5
gh run view <run-id> --repo synergy-network-hq/synergy-node-control-panel
gh run watch <run-id> --repo synergy-network-hq/synergy-node-control-panel
```

To inspect job logs for a failing run:

```bash
gh run view <run-id> --repo synergy-network-hq/synergy-node-control-panel --log
gh run view <run-id> --repo synergy-network-hq/synergy-node-control-panel --job <job-id> --log
```

Do not consider the release complete until the macOS, Linux, and Windows installer jobs all show `success`.

## Single-Source Rule

If a validator setting is supposed to affect nodes created by the control panel, the control-panel code must be treated as authoritative.

Generated runtime assets are outputs.
`genesis-nodes/` copies are mirrors.
The edit surface is the generator code.

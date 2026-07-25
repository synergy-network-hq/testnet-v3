# Release Pipeline Setup Guide

## Overview

The Synergy Node Control Panel uses a GitHub Actions pipeline to build
installers for macOS Apple Silicon and Linux amd64 and publish them to a
**public releases repository** so that:

1. **New machines** can download the installer for their OS from the releases page
2. **Existing installations** can auto-update via the "Check for Updates" button

```
Source repo                              Public releases repo
(synergy-node-control-panel)             (synergy-node-control-panel-releases)
        │                                        │
        │  push tag v2.0.2                       │
        ├──────────────────►  GitHub Actions      │
        │                     builds supported    │
        │                     platforms           │
        │                            │            │
        │                            ▼            │
        │                     Publishes to  ──────►  Installers + latest*.yml
        │                                         │  available for download
```

---

## One-Time Setup Steps

### 1. Add secrets to the PRIVATE source repo

Go to **https://github.com/synergy-network-hq/synergy-node-control-panel/settings/secrets/actions**
and add these repository secrets:

#### `CSC_LINK`

Path, URL, or base64 value for the code-signing certificate consumed by
`electron-builder`. This is used for macOS signing and notarized release
builds.

#### `CSC_KEY_PASSWORD`

Password for the code-signing certificate referenced by `CSC_LINK`.

#### `APPLE_ID`

Apple developer account email used by the macOS notarization step.

#### `APPLE_APP_SPECIFIC_PASSWORD`

App-specific password for the Apple ID above.

#### `APPLE_TEAM_ID`

Apple team identifier used by the macOS signing/notarization workflow.

#### `RELEASES_REPO_TOKEN`

A GitHub **Personal Access Token** (classic) with `repo` scope, so the
workflow in the private repo can publish releases to the public repo.

To create one:
1. Go to https://github.com/settings/tokens/new
2. Note: "Synergy release publishing"
3. Scopes: check `repo` (full control of private repositories)
4. Generate token
5. Copy and save as `RELEASES_REPO_TOKEN` secret

### 2. Initialize the public releases repo

The releases repo at `synergy-network-hq/synergy-node-control-panel-releases`
should be **public** and can start empty. The first release build will
create the initial release automatically.

Optionally add a README:

```markdown
# Synergy Node Control Panel — Releases

Download the latest installer for your platform from the
[Releases page](../../releases).

## Platforms

| Platform | File |
|----------|------|
| macOS (Apple Silicon) | `.dmg` or `.zip` |
| Linux (x86_64) | `.deb` or `.AppImage` |

## Auto-Update

If you already have the control panel installed, click **Check for Updates**
in the top-right corner of the app. It will automatically detect and install
new versions.
```

---

## How to Cut a Release

### Option A: Use the release script (recommended)

```bash
./scripts/release.sh 2.0.2
```

This bumps the version everywhere, commits, tags, and pushes.

### Option B: Manual steps

```bash
# 1. Bump version in: package.json, control-service/Cargo.toml,
#    electron-builder.yml, electron/main.cjs, src/components/Layout.jsx
# 2. Commit
git add -A && git commit -m "chore: bump version to 2.0.2"
# 3. Tag
git tag -a v2.0.2 -m "Release v2.0.2"
# 4. Push (triggers the build)
git push origin main && git push origin v2.0.2
```

### Option C: Validation build without publishing

Go to **Actions** -> **Electron Release Build** -> **Run workflow**. An optional
`testnet_runtime_ref` can select a trusted runtime ref. A manual dispatch builds
and validates artifacts but does not publish a release; publication is tag-only.

---

## How Updates Work

1. The app uses `electron-updater` to check the platform update metadata from
   the releases repo and can fall back to the GitHub Releases API
2. `latest.yml` and `latest-linux.yml` contain the latest version and installer
   metadata for the supported platforms
3. If a newer version exists, the button changes to **Update Available**
4. Clicking it downloads and installs the update, then restarts the app
5. Update bundles are signed with the minisign keypair — the app
   verifies the signature before installing

### Update endpoint

```
https://github.com/synergy-network-hq/synergy-node-control-panel-releases/releases/latest/download/latest.yml
```

Linux clients use the corresponding `latest-linux.yml` asset from the most
recent release.

---

## Signing Key Info

| Key | Value |
|-----|-------|
| Algorithm | Ed25519 (minisign format) |
| macOS signing certificate | GitHub secret `CSC_LINK` |
| macOS signing certificate password | GitHub secret `CSC_KEY_PASSWORD` |
| macOS Apple ID | GitHub secret `APPLE_ID` |
| macOS app password | GitHub secret `APPLE_APP_SPECIFIC_PASSWORD` |
| macOS team ID | GitHub secret `APPLE_TEAM_ID` |

If the private key is ever compromised, generate a new keypair, update
all three updater secrets, and release a new version. All machines will
need to manually update one last time (since the old key signed that build).

# Synergy Node Control Panel v18 UI Architecture

Version `18.0.0` rebuilds the control panel around six primary screens:

- Overview
- Setup Node
- Validator
- Monitoring
- Logs
- Settings

The renderer mounts `ControlPanelV18` inside the existing `ControlPanelProvider`, so live testnet state, selected-node state, polling, and control-service access remain centralized.

## Component Model

The v18 frontend adds these reusable surfaces in `src/components/control-panel-v18/ControlPanelV18.jsx`:

- App shell, sidebar, top status controls, and bottom status bar
- Page headers
- Cards and metric cards
- Status pills and icon buttons
- Copy buttons
- Stepper
- Confirmation modal
- Toasts
- Log viewer and filters
- Settings inputs and toggles

The stylesheet lives in `src/styles/controlPanelV18.css` and uses explicit v18 design tokens for background, cards, borders, text, green, purple, warning, error, info, radius, and glow.

## Synergy-only wallet policy

The control panel copies the master wallet connection component from:

`/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnet/synergy-wallet-connection`

The local copy is under `src/wallet-connection`. The control-panel integration layer is:

- `src/components/wallet/SynergyWalletConnection.jsx`
- `src/components/wallet/synergyOnlyWalletConnectionConfig.js`

The control panel config enables only the Synergy lane:

- `synergy: true`
- `evm: false`
- `nonEvm: false`

EVM and non-EVM wallet families are not rendered in the control panel modal and cannot be used for validator onboarding. The control panel also passes the official node control panel banner into the modal via `brand.bannerSrc`.

## Validator Onboarding Flow

Setup Node uses this fixed order. The renderer cannot advance through a
prerequisite by treating a partial action as success:

1. Welcome
2. Choose Node Role
3. Validator Identity and encrypted backup
4. Wallet and bonded stake
5. Device, secure network, and synchronization
6. Launch and activation observation

The identity screen supports this computer or a saved SSH target. A remote
target can use an NCP-managed SSH key, an existing private key, or a one-time
password bootstrap that installs an NCP-managed public key and immediately
forgets the password. The temporary password is never stored in the target
registry. Validator identity keys are generated and encrypted on the selected
machine; the renderer receives public node metadata only.

## 50,000 SNRG Requirement

The required validator stake is `50,000 SNRG`, defined in `src/services/validatorEligibilityService.js`.

The data model tracks:

- wallet address
- SNRG balance
- required stake
- active stake amount
- pending stake amount
- missing stake amount
- eligibility status
- boolean eligibility
- stake transaction hash
- validator slot id
- last verified timestamp
- error message

If the backend staking API is unavailable or fails to return verified on-chain eligibility, the adapter fails closed and blocks onboarding.

## Service Adapters

Frontend service adapters keep backend calls out of page components:

- `src/services/nodeService.js`
- `src/services/validatorEligibilityService.js`
- `src/services/validatorProvisioningService.js`
- `src/services/settingsService.js`

The preload surface exposes a typed `onboarding` namespace for target
management, connection tests, device checks, identity creation, backups,
owner/stake verification, secure-network enrollment, snapshot operations,
normal sync, launch, and status. The Electron main process owns SSH,
subprocesses, temporary files, coordinator calls, Innernet installation, and
remote sidecar verification.

Remote commands run through the signed `synergy-control` sidecar. The main
process detects the remote platform, verifies the packaged sidecar SHA-256,
uploads it to the target only when needed, verifies the remote checksum, sends
JSON requests over SSH stdin into a mode-0600 temporary file, and deletes that
file after the command. The release workflow bundles the Linux sidecar for
remote validator targets.

## Validator VPN Autonomous Enrollment

The provisioning checklist explicitly represents validator VPN onboarding:

- validator certificate requested
- validator certificate issued
- validator VPN credentials generated
- validator VPN configuration installed
- validator VPN tunnel verified
- validator-only peer configuration received
- validator-only peer configuration installed

Activation remains blocked until backend enrollment returns a valid validator VPN result. The intended backend integration points are represented in `validatorProvisioningService`.

The coordinator, not the renderer or a validator host, owns peer topology. A
mesh result is accepted only after a coordinator-issued invite is redeemed,
the latest configuration generation has propagated to every expected
validator, and an Innernet/WireGuard handshake is observed.

## Sync Choice

Fast sync downloads an archive-validator-produced snapshot and verifies its
catalog, manifest, signature, chain identity, checksums, and archive contents
before replacing any local chain data. Normal sync starts peer-based
synchronization without downloading or applying a snapshot. It never silently
falls back to snapshot mutation; activation remains gated on live canonical
head and onboarding evidence in either mode.

## Future Node Types

Only Validator Node is selectable in v18. Committee Node, Archive Validator, Relayer, and Oracle are visible as coming-later cards and are disabled.

To enable a future type:

1. Add backend provisioning support.
2. Add eligibility requirements for that role.
3. Enable the card in `SetupStepContent`.
4. Add role-specific checks to the provisioning adapter.
5. Add tests for disabled and enabled states.

## Windows Installer Pause

Windows installer build logic is preserved but commented out in:

- `.github/workflows/release.yml`
- `electron-builder.yml`
- `scripts/release/build-bundle-prep.sh`
- `scripts/testnet/verify-node-installers.sh`

Re-enable those blocks together when Windows support resumes.

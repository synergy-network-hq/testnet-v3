# Synergy Token System

## Protocol And Token Standards Reference

**Network scope:** Synergy testnet

**Chain ID:** `1264`

**STS payload version:** `synergy-sts-v1`

**Native fee asset:** SNRG

This document is the protocol reference for the Synergy Token System (STS). It explains what each standard represents, the rules that the network enforces, and how wallets, applications, and Atlas should interpret STS objects. It is intentionally separate from the [STS CLI Guide](STS_CLI_GUIDE.md), which explains installation and command usage.

STS is native runtime state. A token, collection, multi-asset item, or credential is created by a signed Synergy transaction carrying an STS payload; it is not deployed as a user smart contract. The network validates the payload, applies the state transition atomically, records events, and charges the transaction fee in native SNRG.

## Contents

1. [System Model](#system-model)
2. [Native SNRG And Non-Native Addresses](#native-snrg-and-non-native-addresses)
3. [Standards At A Glance](#standards-at-a-glance)
4. [Shared Protocol Rules](#shared-protocol-rules)
5. [Authorities, Disclosure, And Lifecycle](#authorities-disclosure-and-lifecycle)
6. [Metadata And Token Images](#metadata-and-token-images)
7. [B1 Basic Fungible Tokens](#b1-basic-fungible-tokens)
8. [B2 Managed Fungible Tokens](#b2-managed-fungible-tokens)
9. [B3 Policy Fungible Tokens](#b3-policy-fungible-tokens)
10. [NF1 Standard NFTs](#nf1-standard-nfts)
11. [NF2 Controlled NFTs](#nf2-controlled-nfts)
12. [MA Multi-Asset Collections](#ma-multi-asset-collections)
13. [ID Credentials](#id-credentials)
14. [Security And Anti-Impersonation Rules](#security-and-anti-impersonation-rules)
15. [Transaction, API, And Explorer Model](#transaction-api-and-explorer-model)
16. [Issuer And Integrator Checklist](#issuer-and-integrator-checklist)
17. [Reference Tables](#reference-tables)

## System Model

### Native state, not token contracts

STS is the protocol-owned asset ledger for Synergy. The runtime owns the token registry, balances, collection state, authority checks, policy evaluation, event records, and deterministic object identifiers. A creator signs an STS operation, but no user-deployed contract address is created.

This distinction is important:

| Concept | STS meaning |
| --- | --- |
| Token address | A deterministic Bech32m object identifier for a non-native STS asset. It is not a contract address and cannot sign transactions. |
| Wallet address | A signable Synergy account controlled by a key. Wallets pay fees and authorize STS operations. |
| STS payload | Versioned transaction data prefixed by `synergy-sts-v1:` and included in a signed Synergy transaction. |
| Authority | A wallet address granted a narrowly defined protocol permission, such as mint, burn, or metadata authority. |
| Atlas record | An indexed presentation of finalized STS state. Atlas does not create canonical token state. |

### Deterministic object identity

Every non-native STS object is assigned a deterministic identifier at creation. The derivation uses a domain-separated SHA3-256 construction that includes the testnet chain ID and the object-specific creation inputs. This makes the identifier predictable before submission, unique to the creation context, and independent of a user-managed contract deployment.

The derivation domains are distinct for fungible tokens, NFT collections, NFT instances, multi-asset collections, and credential records. For example, a fungible token derivation includes the creator, creator nonce, class, metadata commitment, and creation timestamp. An NFT instance derivation includes its collection, serial number, metadata commitment, class, and mint time.

An STS object ID is an identifier only. It must never be treated as a private-key address, an approval target that can sign, or proof of ownership without consulting finalized STS state.

### State transition lifecycle

1. A creator prepares an STS payload for one operation.
2. The creator reviews the operation, expected object ID where applicable, authorities, supply rules, metadata commitments, and fee estimate.
3. A wallet signs the carrier transaction on chain ID `1264`.
4. The network validates the transaction and the STS operation together. Invalid operations do not partially mutate token state.
5. After finalization, STS state, events, and balances are queryable through the STS RPC API and indexable by Atlas.

The [STS CLI Guide](STS_CLI_GUIDE.md) describes the review, signing, and submission workflow. The [STS RPC API](STS_RPC_API.md) describes the read-only RPC methods.

## Native SNRG And Non-Native Addresses

### Native SNRG

SNRG is the native Synergy asset and the only gas and transaction-fee asset in this STS implementation. It is not an STS object and has no canonical token address.

Native asset responses therefore use:

```json
{
  "symbol": "SNRG",
  "token_address": null,
  "gas_asset": true
}
```

For legacy or string-only integrations, the protocol reserves this compatibility placeholder:

```text
00000000000000000000000000000000000000000
```

The 41-zero value is **not** an address, token contract, STS object ID, wallet, or signing target. New software should preserve `null` for native SNRG and use the placeholder only when a string value is technically unavoidable.

### Non-native assets

Every user-created STS asset has a real deterministic object address. For fungible standards, `token_id` and `token_address` are the same Bech32m object ID:

| Standard | Object prefix | Example shape |
| --- | --- | --- |
| B1 basic fungible | `synb1` | `synb1...` |
| B2 managed fungible | `synb2` | `synb2...` |
| B3 policy fungible | `synb3` | `synb3...` |
| NF1 standard NFT | `synn1` | `synn1...` |
| NF2 controlled NFT | `synn2` | `synn2...` |
| MA multi-asset collection | `synj` | `synj...` |
| ID credential | `synk` | `synk...` |

An application must identify a non-native token by its object address, not only by its display name or symbol. Names and symbols are user-facing labels; object addresses are the canonical identifiers.

## Standards At A Glance

| Standard | Wire class | Primary model | Transfer model | Typical use |
| --- | --- | --- | --- | --- |
| B1 | `b1` | Simple fungible supply and balances | Open, ordinary transfer | Community token, points, simple currency |
| B2 | `b2` | Fungible asset with disclosed administrative controls | Open unless a runtime control blocks it | Regulated, operational, or recovery-sensitive assets |
| B3 | `b3` | Fungible asset with bounded policy templates | Policy-aware transfer | Fee-bearing, capped-wallet, vesting, or snapshot use cases |
| NF1 | `nf1` | Standard NFT collection and unique instances | Collection or instance transfer rules | Collectibles, tickets, unique records |
| NF2 | `nf2` | Controlled NFT collection and unique instances | Can require issuer control or approval | Credentials, access passes, controlled entitlements |
| MA | `ma` | One collection containing multiple item types | Per-item transfer policy | Games, catalogs, inventory, memberships |
| ID | `id` | Credential schemas and non-transferable records | Never transferable | Attestations, identity, compliance, eligibility |

Choose the narrowest standard that matches the required behavior. A token should not advertise or enable more authority than the asset actually needs.

## Shared Protocol Rules

### Network binding

STS payloads are valid only when all of the following match:

- Payload version is `1`.
- Payload chain ID is `1264`.
- Payload network is `testnet`.
- The enclosing Synergy transaction is validly authorized by the sender wallet.

The runtime rejects an STS payload with a mismatched network or chain ID. Tools and services must not substitute a legacy chain ID or silently retarget an STS payload.

### Amounts, decimals, and time

- Amounts and supplies are integer base units represented as unsigned 128-bit values. Floating-point values are never part of STS consensus data.
- An amount in a transfer, mint, or burn must be greater than zero.
- Fungible and multi-asset decimal precision is bounded from `0` through `9`.
- A timestamp is Unix time in seconds and is bounded to a protocol-safe range.
- Implementations must use checked arithmetic. Supply overflow, underflow, and insufficient balances are rejected.

User interfaces may display decimal formatting, but they must convert values to exact base units before signing. For a token with `9` decimals, `1.25` displays as `1,250,000,000` base units.

### Names and symbols

Token identity rules are consensus checks, not just UI conventions:

- Name: non-empty ASCII, at most 64 characters.
- Symbol: 2 to 12 ASCII characters, uppercase letters and digits only, beginning with an uppercase letter.
- User-created names and symbols may not impersonate native SNRG or Synergy branding. Names containing `SNRG` or `SYNERGY`, and symbols containing `SNRG`, are reserved and rejected.

The runtime also rejects duplicate fungible symbols. Applications should still present the object address and creator to users, because symbol uniqueness alone is not a substitute for identity verification across all asset classes.

### Metadata commitments

Metadata may include an external URI, a SHA3-256 content hash, or both. The hash format is strict: 64 lowercase hexadecimal characters, without `0x`.

Accepted external URI schemes are:

- `https://`
- `ipfs://`
- `ar://`

URIs must be at most 512 characters and cannot contain whitespace, control characters, or backslashes. Storing the hash allows clients to retrieve content and verify that it matches the creator's committed bytes.

### Atomicity and event history

Each valid STS operation produces an all-or-nothing state transition. Batch multi-asset operations validate their input set as a single operation; an invalid item, duplicate item ID, or failed balance check prevents the whole batch from applying.

Finalized state changes are accompanied by STS events. Indexers and applications should use finalized events and canonical state reads rather than inferring state from unconfirmed client-side intent.

## Authorities, Disclosure, And Lifecycle

### Authority set

STS models operational privileges as explicit authority fields. Depending on the standard, these can include:

| Authority | Purpose |
| --- | --- |
| `mint_authority` | Authorizes issuance where minting is enabled. |
| `burn_authority` | Authorizes administrative destruction where supported. |
| `freeze_authority` | Authorizes account or asset freeze controls where supported. |
| `metadata_authority` | Authorizes supported metadata updates. |
| `transfer_authority` | Authorizes controlled transfer flows where supported. |
| `compliance_authority` | Identifies the compliance controller for standards that expose it. |
| `issuer_authority` | Identifies the issuer for controlled NFTs and credentials. |
| `upgrade_authority` | Identifies a declared upgrade controller where the standard exposes one. |

Authorities are wallet references. A missing authority means that privilege is unavailable or has been renounced; no wallet can recover it through an STS shortcut. An authority does not grant every other authority, and it does not override the standard's own validation rules.

### Supply lifecycle

Fungible supply starts with `initial_supply`. A creator may set a `max_supply` cap and may set or omit mint authority. The network rejects minting that would exceed an established cap or otherwise overflow supply.

To create a fixed-supply asset, issue the full intended supply at creation and do not retain mint authority. To create a capped but mintable asset, set `max_supply` and disclose the mint authority. A wallet or explorer should show these choices prominently because they materially affect holder risk.

### Control disclosure

Controls are not hidden implementation details. A B2 or B3 issuer must select the appropriate standard and publish the applicable flags, policies, authorities, and supply terms in metadata and explorer-visible state. A user interface should not call a token "immutable," "uncensored," or "fixed supply" when the finalized STS definition says otherwise.

## Metadata And Token Images

### Metadata is integrity data

Metadata may contain descriptive fields such as name, description, external URLs, attributes, issuer contact details, and policy explanation. The network stores the URI and optional content hash, not a trust judgment about the referenced material.

Consumers should:

1. Retrieve metadata only through an allowed URI scheme.
2. Verify the returned bytes against the on-chain SHA3-256 hash when one is supplied.
3. Treat a missing hash as lower-integrity external metadata.
4. Display the asset address, creator, authorities, policies, and verification state alongside human-readable metadata.

The CLI guide contains a full metadata-file template and hashing workflow. This reference defines the consensus requirements rather than prescribing a particular JSON layout.

### Token image rules

A fungible token image requires **both** an image URI and an image SHA3-256 hash. The URI follows the same allowed schemes as metadata, with an additional safety rule: SVG image URIs are rejected. This avoids active-content and rendering ambiguity in explorer and wallet surfaces.

For fungible tokens, image lifecycle is intentionally one-way:

| Creation condition | Result |
| --- | --- |
| URI and hash supplied at token creation | Image is stored and locked. |
| No image supplied at token creation | Creator may set one image later. |
| Creator sets the omitted image later | Image is stored and locked. |
| An image is already present or locked | Any later replacement is rejected. |
| Caller is not the creator | The post-create image operation is rejected. |

The post-create operation is `SetFungibleImage`. Atlas exposes the same creator-authenticated fallback from the token detail view when the creator omitted an image at creation. It does not let a creator replace an existing image. NFT and multi-asset collection images are currently supplied at collection creation; their per-instance descriptive media should be committed through the relevant metadata URI and hash.

### Metadata mutability boundary

Metadata mutability is explicit in asset state. The current operation surface provides NFT instance metadata updates only where the instance is marked mutable and the caller has the required authority. Fungible-definition metadata is not an arbitrary post-create editing path in the current protocol slice. A one-time fungible image set is deliberately narrower than general metadata editing.

## B1 Basic Fungible Tokens

### Purpose

B1 is the simple fungible token standard. It is the appropriate choice for a token whose core behavior is supply, balances, minting when retained, burning, and normal transfers without privileged transfer controls or policy templates.

**Wire class:** `b1`

**Object prefix:** `synb1`

### What B1 supports

- Deterministic non-native token address.
- Initial supply, optional supply cap, and optional mint authority.
- Mint, burn, and transfer operations.
- Metadata URI/hash and one-time fungible image lifecycle.
- Finalized balances, events, and registry visibility.

### What B1 deliberately prohibits

B1 requires the default, empty control flag set. It cannot opt into freeze, pause, clawback, denylist, allowlist, metadata-update, or transfer-approval flags. It cannot attach B3 policy templates.

This restriction gives a straightforward compatibility signal: a B1 holder is not subject to a B2 management control or a B3 policy template. It does not remove normal protocol protections such as invalid-amount checks, supply-cap enforcement, or transaction-fee requirements.

### Appropriate use cases

- Simple community, loyalty, or utility balances.
- Fixed-supply or transparently capped assets.
- Application points that do not need an issuer-controlled transfer workflow.

### Holder-facing disclosures

At minimum, a B1 issuer should disclose initial supply, maximum supply or the absence of a cap, mint authority status, decimals, metadata commitment, and creator identity. A B1 token is still a user-created asset; `synb1` does not itself imply endorsement, verification, or value.

## B2 Managed Fungible Tokens

### Purpose

B2 is a fungible standard for assets that need disclosed, protocol-visible administrative controls. It is appropriate only when the issuer has a concrete operational reason to retain those controls.

**Wire class:** `b2`

**Object prefix:** `synb2`

### Control flags

B2 can declare the following flags in its definition:

| Flag | Meaning |
| --- | --- |
| `can_freeze` | The asset may use account freeze and thaw controls. |
| `can_pause` | The asset may use global pause and unpause controls. |
| `can_clawback` | The asset may use the supported clawback operation. |
| `can_denylist` | The definition discloses a denylist control model. |
| `can_allowlist` | The definition discloses an allowlist control model. |
| `can_update_metadata` | The definition discloses metadata-update authority. |
| `requires_transfer_approval` | The definition discloses a transfer-approval model. |

The current STS transaction namespace directly exposes freeze/thaw, pause/unpause, and clawback operations for the managed fungible lifecycle. Allowlist, denylist, metadata-update, and transfer-approval flags are still valuable disclosure fields, but an integrator must not present a flag as an available mutation endpoint unless that endpoint exists in the released protocol surface it is connected to.

### Enforced controls

When the relevant flag and authority are present:

- A frozen account cannot make the affected outgoing transfer.
- A globally paused token rejects transfers.
- A clawback requires an authorized caller and an enabled clawback flag.

The explorer or wallet presentation must surface these controls before a user acquires or transfers the asset. Hiding a B2 control state is a misleading integration.

### Appropriate use cases

- Operational assets with explicit recovery requirements.
- Issuer-managed balances where legally or contractually required controls are disclosed.
- Systems where temporary pause or account-level containment is a documented necessity.

### Design discipline

Do not choose B2 merely to keep optional control over holders. Each enabled flag increases the trust assumptions of the token. Prefer B1 when no privileged control is genuinely required, and renounce unneeded authorities rather than leaving inactive keys exposed.

## B3 Policy Fungible Tokens

### Purpose

B3 is a fungible token standard for bounded, declared policy behavior. Policy templates are protocol data with consensus validation; they are not arbitrary executable code.

**Wire class:** `b3`

**Object prefix:** `synb3`

### B3 control boundary

B3 cannot enable `can_freeze`, `can_pause`, or `can_clawback`. Those are B2 managed controls. A B3 issuer uses supported policy templates instead of embedding unconstrained issuer logic.

### Current supported policy templates

| Template | Fields | Enforced behavior or purpose |
| --- | --- | --- |
| `transfer_fee_v1` | `fee_bps`, `recipient` | Collects a transfer fee to the declared recipient. Fee is capped at 1,000 basis points, or 10%. |
| `snapshot_v1` | None | Enables the protocol snapshot operation for the token. |
| `vesting_v1` | `start_at`, `cliff_at`, `end_at` | Records a validated vesting schedule with ordered timestamps. |
| `max_wallet_v1` | `max_balance` | Enforces a non-zero maximum wallet balance. |

The runtime rejects unsupported template names, transfer fees above 10%, blank fee recipients, invalid vesting time ordering, and zero max-wallet values. A B3 policy set is fixed by the creation payload in the current surface; it should be disclosed as part of the asset identity.

### Transfer fee semantics

`transfer_fee_v1` uses basis points. The fee calculation is integer base-unit arithmetic:

```text
fee = amount * fee_bps / 10,000
```

The fee recipient is part of the finalized token definition. Wallets should show the fee rate, fee recipient, and the expected net amount before the sender approves a transfer. The 10% consensus cap prevents extreme transfer-tax configurations, but a lower fee can still be material to users.

### Appropriate use cases

- Protocol or ecosystem assets with a disclosed transfer fee.
- Tokens needing a verifiable snapshot history.
- A constrained distribution with a maximum balance rule.
- Assets whose holder documentation includes a fixed vesting schedule.

### Important limitation

B3 does not turn every business rule into a token policy. Its safety comes from supporting a small, explicit template set. An application requiring arbitrary code execution must not claim that B3 supplies that behavior.

## NF1 Standard NFTs

### Purpose

NF1 is the standard NFT model: a collection is created first, then it mints unique instances with deterministic serial numbers and ownership state.

**Wire class:** `nf1`

**Object prefix:** `synn1`

### Collection state

An NF1 collection records:

- Collection address, creator, name, and symbol.
- Metadata and optional collection image commitments.
- Collection, mint, and metadata authorities.
- Optional royalty basis points and recipient.
- Collection verification status.
- Default transferability and issuer-approval requirement.
- The next serial number to issue.

Royalty fields are canonical collection metadata. They describe the issuer's stated royalty terms, but integrators must not claim universal secondary-sale royalty enforcement unless the relevant marketplace transfer path explicitly implements it.

### Instance state

Each NFT instance records its `synn1` object ID, collection, serial number, owner, metadata commitment, lifecycle status, and applicable transfer settings. The protocol supports mint, transfer, burn, freeze, thaw, metadata update where permitted, and collection verification operations.

### Appropriate use cases

- Standard collectibles and digital art.
- Tickets or access objects that do not need issuer-controlled approval at every transfer.
- Unique records with metadata that users can inspect through a committed URI and hash.

## NF2 Controlled NFTs

### Purpose

NF2 is an NFT model for issuer-controlled or lifecycle-sensitive unique assets. It retains the collection-and-instance structure of NF1 while adding controls relevant to credentials, passes, entitlements, and other assets that cannot be treated as unrestricted collectibles.

**Wire class:** `nf2`

**Object prefix:** `synn2`

### Controlled lifecycle

NF2 instances can carry and enforce:

- Transferability settings.
- Issuer-approval requirements.
- Expiration timestamp.
- Freeze and thaw state.
- Revocation state and revocation time.
- One-time use state and use time.
- Issuer and transfer authority references.

An inactive instance, including a burned, frozen, revoked, or expired instance, cannot be treated as an ordinary transferable asset. Applications should check finalized state at the time of use rather than relying on cached ownership alone.

### Appropriate use cases

- Tickets that can be used once.
- Access passes with expiration.
- Issuer-approved memberships.
- Revocable certificates or regulated unique assets.

### Presentation requirements

A wallet or Atlas view should visually distinguish NF2 from a normal collectible and show the current transferability, approval rule, expiry, frozen state, revocation state, and used state. Displaying an NF2 as an unrestricted NFT would conceal material protocol restrictions.

## MA Multi-Asset Collections

### Purpose

MA is a collection standard for applications that need multiple related item types under one deterministic collection address. A collection can define fungible, non-fungible, and semi-fungible items without deploying a separate token contract for each item.

**Wire class:** `ma`

**Object prefix:** `synj`

### Collection and item model

The collection carries its creator, name, symbol, metadata, optional image, and declared authorities. Each item is identified by a non-zero numeric `item_id` within the collection and carries its own type, name, symbol, decimals, metadata, supply information, mint and burn authorities, and transfer policy.

| Item type | Meaning |
| --- | --- |
| `fungible` | Multiple interchangeable units, optionally with decimal precision. |
| `non_fungible` | A unique item. Its amount must be `1`, and an owner cannot hold more than one unit of the same item ID. |
| `semi_fungible` | Multiple units of a defined item that are distinct from other item IDs. |

### Transfer policies

| Policy | Behavior |
| --- | --- |
| `open` | Holder transfers are allowed subject to normal balance and authority validation. |
| `non_transferable` | Transfers are rejected. |
| `authority_only` | Transfer requires the applicable authority. |

### Batch operations

MA supports batch mint, transfer, and burn. A batch:

- Must contain at least one and no more than 128 item entries.
- Cannot repeat an item ID.
- Requires every item ID and amount to be valid.
- Is validated atomically as one STS operation.

This lets an application move a coherent inventory set without leaving partially applied state when a single item fails validation.

### Appropriate use cases

- Game inventories and crafting materials.
- Event packages, catalogs, and memberships.
- A collection containing currency, unique items, and limited-edition items together.
- Enterprise or application inventory with different transfer policies per item.

## ID Credentials

### Purpose

ID is the credential standard. It stores issuer-controlled attestations and status information, not a tradable token balance.

**Wire class:** `id`

**Object prefix:** `synk`

### Schema and record model

An issuer first creates an active credential schema. A schema includes an issuer, a lowercase identifier such as `kyc-basic-v1`, a name, an optional description hash, and a required schema hash.

The issuer can then issue a credential record. A record includes:

- Deterministic credential ID.
- Issuer.
- Optional raw subject address.
- Required `subject_commitment`.
- Schema ID.
- Credential content hash.
- Issued time and optional expiration.
- Current status and status-change timestamps.

Credential status is one of `active`, `suspended`, `revoked`, or `expired`.

### Non-transferability and privacy

Credentials are explicitly non-transferable. They must not appear as a wallet asset balance or be offered for sale, transfer, or collateral use.

For privacy, applications should prefer `subject_commitment` when displaying or indexing a credential. Raw subject addresses should be used only when the application has a valid reason and the subject understands the disclosure. The credential data itself belongs off-chain; STS stores integrity commitments and lifecycle state, not raw identity documents.

### Status checks

Relying parties should query finalized credential status at the point of verification. A previously active credential may become suspended, revoked, or expired. A hash match alone is insufficient without a current status check.

### Appropriate use cases

- Eligibility attestations.
- Compliance or enrollment records.
- Validator, participant, or organization credentials.
- Revocable, privacy-aware proof references.

## Security And Anti-Impersonation Rules

### Protocol-level protections

STS includes consensus checks designed to prevent unsafe asset definitions and misleading integration patterns:

| Protection | Protocol behavior |
| --- | --- |
| Native impersonation prevention | User-created names/symbols using reserved SNRG or Synergy identity are rejected. |
| Deterministic non-native addresses | Every user-created asset receives a canonical object identifier rather than a blank or arbitrary address. |
| Native address separation | SNRG has `token_address: null`; the 41-zero placeholder is compatibility-only. |
| Strict identity validation | Names, symbols, decimals, timestamps, amounts, metadata hashes, and URI schemes are bounded and validated. |
| Supply safety | Zero-value mutation, overflow, cap violations, and insufficient balances are rejected. |
| Authority enforcement | Privileged actions require the configured authority; absent authority is treated as renounced. |
| Policy containment | B1 disallows controls and policies; B3 allows a fixed template set and caps transfer fees at 10%. |
| Image integrity | Images require a URI and hash, reject SVG, and lock after the first set. |
| Credential safety | Credentials are non-transferable and have explicit active, suspended, revoked, and expired states. |
| Atomic execution | Invalid STS operations do not leave partial state changes. |

### What the protocol cannot prove

No token standard can prove that an issuer is trustworthy, that off-chain metadata is truthful, that a project will retain liquidity, or that an asset has economic value. The object address, creator wallet, authority configuration, supply, policy flags, metadata hash, and Atlas verification status are evidence users can inspect; they are not endorsements.

Wallets, exchanges, and explorers should use a layered model:

1. Resolve canonical STS state by object address.
2. Show the creator and all live authorities.
3. Show supply cap, mint status, controls, policies, and image lock state.
4. Verify external metadata and media hashes when supplied.
5. Clearly distinguish protocol identity from an application-level verification badge.

### Unsafe integration practices to avoid

- Never treat the 41-zero native placeholder as a token or wallet address.
- Never display a symbol without a canonical STS object address and creator context.
- Never hide B2 flags, B3 policies, supply authority, or NF2 lifecycle restrictions.
- Never permit a UI to imply that a token image can be changed after its first set.
- Never store or display raw credential content as if it were on-chain STS data.
- Never submit an STS payload constructed for a chain other than `1264`.
- Never interpret an unfinalized client artifact as successful issuance.

## Transaction, API, And Explorer Model

### STS write path

STS mutations are made by a signed Synergy transaction containing a `synergy-sts-v1:` payload. The network uses the sender wallet to authorize the carrier transaction, enforces STS rules for the embedded operation, and charges native SNRG fees once.

The dedicated `synergy-sts` CLI can build, decode, estimate, sign, and submit these artifacts. It is a client tool, not an independent ledger and not a privileged issuer service. See the [STS CLI Guide](STS_CLI_GUIDE.md) for installation and payload examples.

### Fees and gas

The runtime assigns an STS gas estimate based on the operation. The transaction fee is based on the selected gas limit and gas price, and is paid in native SNRG by the submitting wallet. A client must estimate conservatively and confirm the wallet has sufficient native balance before submission.

Asset transfers, minting, burns, and control operations do not cause the token itself to become a gas asset. Native SNRG remains the fee asset for every STS standard.

### Read APIs

The STS RPC namespace is read-only and exposes finalized records for:

- Native SNRG and fungible token definitions, balances, and events.
- NFT collections, instances, ownership, and collection membership.
- Multi-asset collections, items, and balances.
- Credential schemas, records, subjects, and verification status.

Use the [STS RPC API](STS_RPC_API.md) for exact methods, request shapes, and response fields. Read clients should prefer finalized STS responses over legacy token-manager methods.

### Atlas discovery

Atlas indexes finalized STS state and materializes newly created non-native assets into its token registry. A valid finalized creation is therefore discoverable without a separate manual token-list submission.

For a fungible token that was created without an image, Atlas can authenticate the creator wallet and offer the one-time image set flow. Atlas must enforce the same creator-only and already-locked checks as the runtime. Explorer surfaces should fetch canonical state rather than trust user-provided display data.

Asset-specific presentation can evolve over time. Integrators should rely on STS object identifiers and RPC state, not on a particular Explorer page layout or assumed UI treatment of every standard.

## Issuer And Integrator Checklist

### Before issuing

- Select the narrowest STS standard that satisfies the actual asset requirement.
- Confirm the target is testnet chain ID `1264`.
- Choose a unique, non-impersonating name and symbol.
- Express all supply values in exact base units and choose `0` through `9` decimals.
- Decide whether mint authority should exist, and set a maximum supply when appropriate.
- Minimize authorities and controls; disclose each retained authority.
- Prepare metadata on `https://`, IPFS, or Arweave and calculate a lowercase SHA3-256 hash.
- Prepare a safe raster token image if using one. Supply both URI and hash at creation whenever possible.
- Review the expected deterministic object address before signing.

### Before presenting an asset to users

- Resolve canonical STS state by object address.
- Show the class, creator, supply, decimals, mint status, authority set, and verified state.
- For B2, show every enabled control flag.
- For B3, show every policy template, the fee recipient and fee rate where present, and max-wallet rules.
- For NFTs, show transferability, issuer approval, expiry, freeze, revocation, and use state when applicable.
- For credentials, show only an appropriate privacy-preserving status view and never treat the record as a transferable asset.
- Verify metadata and image hashes before representing external media as authenticated.

### During ongoing operation

- Query finalized state before relying on a balance, credential, or NFT lifecycle status.
- Retain secure records of authority ownership and perform authority actions from the intended wallet only.
- Do not promise controls or policy behavior beyond what the current STS operation surface enforces.
- Keep application verification badges separate from the protocol's `verified` state and document the criteria for any additional badge.

## Reference Tables

### Standard prefixes and operations

| Standard | Prefix | Create | Lifecycle operations |
| --- | --- | --- | --- |
| B1 | `synb1` | Create fungible | Mint, burn, transfer, one-time image set |
| B2 | `synb2` | Create fungible | B1 operations plus freeze, thaw, pause, unpause, and clawback when enabled |
| B3 | `synb3` | Create fungible | Mint, burn, transfer, supported policy behavior, snapshot where enabled, one-time image set |
| NF1 | `synn1` | Create collection | Mint, transfer, burn, freeze, thaw, permitted metadata update, verify collection |
| NF2 | `synn2` | Create collection | NF1 operations plus revoke and one-time use lifecycle state |
| MA | `synj` | Create collection and items | Mint, batch mint, transfer, batch transfer, burn, batch burn |
| ID | `synk` | Create credential schema | Issue, revoke, suspend, restore, expire, verify status |

The exact availability of an operation is still subject to class, configured flags or policies, asset state, and authority validation.

### Common rejection conditions

| Condition | Result |
| --- | --- |
| Wrong chain ID, wrong network, or invalid STS payload version | `InvalidNetwork` or payload validation failure |
| Missing or wrong privileged authority | `Unauthorized`, `InvalidAuthority`, or `AuthorityRenounced` |
| Transfer while paused or frozen | `TokenPaused` or `AccountFrozen` |
| Invalid name, symbol, URI, image, metadata hash, decimals, or timestamp | Validation failure such as `InvalidMetadata`, `InvalidImage`, `InvalidMetadataHash`, `InvalidDecimals`, or `InvalidTimestamp` |
| Native SNRG or Synergy impersonation attempt | `ReservedTokenIdentity` |
| Supply overflow, cap breach, insufficient balance, or zero amount | `SupplyOverflow`, `InsufficientBalance`, or `InvalidAmount` |
| Unsupported policy or class/control combination | `PolicyNotEnabled` or `InvalidTokenClass` |
| Second fungible image set | `ImageAlreadySet` |
| Transfer attempt for a credential or non-transferable MA item | `NonTransferableAsset` |

### Canonical documents

- [STS CLI Guide](STS_CLI_GUIDE.md): installation, command syntax, signing, submission, metadata template, and payload examples.
- [STS RPC API](STS_RPC_API.md): finalized-state RPC methods and responses.
- [STS Implementation Map](STS_IMPLEMENTATION_MAP.md): runtime, CLI, indexer, and integration implementation details.

## Scope Note

This reference describes the current native STS testnet implementation on chain ID `1264`. It is a technical description of protocol behavior, not investment advice, a listing guarantee, or a substitute for independent security review. Applications that custody funds, make eligibility decisions, or serve regulated users should perform their own security, compliance, privacy, and operational review before relying on an STS asset.

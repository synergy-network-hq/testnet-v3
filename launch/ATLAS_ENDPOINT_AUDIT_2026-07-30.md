# Atlas Testnet-v3 endpoint audit

Verified: **2026-07-30 12:03 UTC**

## Outcome

The deployed Atlas API is reachable, but Atlas is not feature-complete or
transport-stable enough to call fixed.

- All 34 explicitly registered read-only GET routes on the direct API behaved
  according to their deployed contracts.
- The two generated Swagger representations also work on the direct API.
- The Pages worker successfully proxied the implemented `/api/v1/*`,
  `/healthz`, and `/readyz` routes during this audit.
- The Pages worker does not proxy `/version`, `/docs/json`, or `/docs/yaml`;
  those paths return the Atlas SPA HTML instead of their direct-API content.
- Twenty-six GET contracts referenced by the current Atlas UI are not
  registered. Every one returned HTTP 404 from both the Pages proxy and direct
  API.
- A fresh 400-request soak over the ten polled snapshot routes returned 400
  HTTP 200 responses. No HTTP 400 recurred during that soak.
- The origin log nevertheless proves 460 genuine Chrome-origin HTTP 400
  responses on those same ten paths between 10:33:08 and 11:17:38 UTC:
  exactly 46 failures per route.
- Nginx still requires an Authenticated Origin Pull client certificate while
  Cloudflare currently reports zone AOP disabled and no hostname associations.
  The configuration mismatch remains an intermittent-failure risk.
- CORS is also misbound: preflight requests from the canonical Atlas origin
  receive `Access-Control-Allow-Origin:
  https://testnet-explorer.synergy-network.io`.
- The denomination converter and gas tools are present only in the dirty local
  Atlas checkout. They are absent from the live JavaScript bundle and have not
  been deployed.
- Atlas still reports height 0 because the public RPC is height 0. The six
  validators are advancing independently; relayer observer rejection is the
  downstream chain-data blocker.

No state-changing API, wallet-pairing creation, authentication, deployment, or
origin configuration was performed during this audit.

## Audited deployments

| Surface | URL |
|---|---|
| Canonical Pages site and same-origin proxy | `https://testnet-atlas.synergy-network.io` |
| Direct Atlas API | `https://testnet-atlas-api.synergy-network.io` |
| Public RPC source | `https://testnet-core-rpc.synergy-network.io` |

The active backend release on `ssh synergy-index` is:

```text
/opt/synergy/testnet-v3/atlas/releases/v20.0.0-atlas-v3-hotfix-c78c9574406d
```

The public site currently presents the Testnet-v3 activation landing page to
an unauthenticated browser. A Playwright load produced no console errors and no
Atlas data requests; it requested only the staff-session state plus static and
Cloudflare resources. The mass browser API failures were verified from the
origin access log rather than reproduced through an authenticated staff
session.

## Implemented GET route matrix

`200` means a valid read returned JSON. `404 data` means the route exists and
correctly rejected a well-formed identifier for which the height-0 index has no
record. `HTML mismatch` means the Pages worker served the SPA instead of the
direct backend representation.

| Route | Pages proxy | Direct API | Finding |
|---|---:|---:|---|
| `/healthz` | 200 | 200 | Healthy |
| `/readyz` | 200 | 200 | Healthy at RPC/indexed height 0 |
| `/version` | HTML mismatch | 200 | Worker does not proxy route |
| `/api/v1/wallet-pairing/healthz` | 200 | 200 | Healthy |
| `/api/v1/wallet-pairing` | 200 | 200 | Healthy |
| `/api/v1/wallet-pairing/sessions/:sessionId` | 404 data | 404 data | Route exists; valid session not created because that requires POST |
| `/api/v1/wallet/assertions/session` | 200 | 200 | Correctly reports disconnected without cookie |
| `/api/v1/entities/:entityType/:entityId/tags` | 200 | 200 | Valid validator public tags returned |
| `/api/v1/network/summary` | 200 | 200 | Chain 1266, latest block 0, six validators |
| `/api/v1/network/accounts` | 200 | 200 | Genesis allocation inventory returned |
| `/api/v1/dag/status` | 200 | 200 | Empty committed DAG at public height 0 |
| `/api/v1/dag/frontier` | 200 | 200 | Empty frontier |
| `/api/v1/dag/vertices` | 200 | 200 | Empty list |
| `/api/v1/dag/topology` | 200 | 200 | Empty topology |
| `/api/v1/blocks` | 200 | 200 | Genesis block returned |
| `/api/v1/blocks/:id` | 200 | 200 | Genesis block 0 returned |
| `/api/v1/txs` | 200 | 200 | Empty list |
| `/api/v1/txs/:hash` | 404 data | 404 data | Route exists; no indexed transaction |
| `/api/v1/synids` | 200 | 200 | Empty list |
| `/api/v1/synids/:synId` | 404 data | 404 data | Route exists; no indexed mapping |
| `/api/v1/address/:address` | 200 | 200 | Canonical validator address returned |
| `/api/v1/validators` | 200 | 200 | Six validators returned |
| `/api/v1/validators/:address/profile` | 200 | 200 | No profile; edit correctly requires wallet |
| `/api/v1/validators/:address/synergy-score` | 200 | 200 | Score returned |
| `/api/v1/validators/:address/score-history` | 200 | 200 | Empty history |
| `/api/v1/epochs/:epoch/validator-scorecards` | 200 | 200 | Empty epoch-0 scorecards |
| `/api/v1/validators/:address/rewards` | 200 | 200 | Zero totals |
| `/api/v1/validators/:address/reward-settlements` | 200 | 200 | Empty list |
| `/api/v1/validators/:address` | 200 | 200 | Validator detail returned |
| `/api/v1/token/SNRG/holders` | 200 | 200 | Route exists; holder list empty |
| `/api/v1/tokens` | 200 | 200 | Native SNRG record returned |
| `/api/v1/wallets/:address/token-balances` | 200 | 200 | Empty token balance list |
| `/api/v1/contracts` | 200 | 200 | Empty registry |
| `/api/v1/contracts/:address` | 404 data | 404 data | Route exists; canonical genesis contract is not indexed |
| `/docs/json` | HTML mismatch | 200 | Direct OpenAPI JSON exists; worker does not proxy it |
| `/docs/yaml` | HTML mismatch | 200 | Direct OpenAPI YAML exists; worker does not proxy it |

The direct API therefore passed all 36 checks: 34 explicit GET routes plus two
generated Swagger representations. The Pages proxy passed all implemented API
reads but has three path-routing gaps.

## Missing frontend-required contracts

All 26 paths below returned HTTP 404 from both public surfaces:

### Consensus cluster and epoch entities

```text
GET /api/v1/clusters
GET /api/v1/clusters/:id
GET /api/v1/clusters/:id/history
GET /api/v1/epochs
GET /api/v1/epochs/:number
GET /api/v1/epochs/:number/history
```

The specialized
`GET /api/v1/epochs/:epoch/validator-scorecards` route exists, but it is not an
epoch directory/detail contract. The UI's `Backend blocked` and
`REQUIRED CONTRACT GET /clusters` messages are therefore accurate.

### Range metrics and histories

```text
GET /api/v1/metrics/network-activity
GET /api/v1/metrics/blocks
GET /api/v1/metrics/throughput
GET /api/v1/metrics/indexer-lag
GET /api/v1/metrics/accounts
GET /api/v1/metrics/contracts
GET /api/v1/metrics/contracts/:address
GET /api/v1/tokens/:id/history
GET /api/v1/validators/:address/history?metric=score
GET /api/v1/accounts/:address/balance-history
GET /api/v1/contracts/:address/activity
```

The `Historical endpoint required` messages are not false alarms: these
range/history contracts do not exist. The dirty local frontend derives several
charts from current snapshots and a client-side observation buffer, but that is
not a substitute for durable server history and is not deployed.

### Status, discovery, and detailed entity contracts

```text
GET /api/v1/status/components
GET /api/v1/status/incidents
GET /api/v1/search
GET /api/v1/openapi.json
GET /api/v1/tokens/:id/holders
GET /api/v1/tokens/:id/transfers
GET /api/v1/tokens/:id/transactions
GET /api/v1/validators/:address/events
GET /api/v1/dag/vertices/:vertexId
```

The holder path has a naming mismatch: the deployed backend exposes singular
`/api/v1/token/SNRG/holders`, while the frontend's general token-detail contract
expects plural `/api/v1/tokens/:id/holders`.

OpenAPI is available directly at `/docs/json` and `/docs/yaml`, but not at the
UI-referenced `/api/v1/openapi.json`, and the Pages worker does not proxy
`/docs/*`.

## HTTP 400 investigation

The live origin access log contains 460 browser failures across the exact ten
SPA snapshot routes:

| Route | Browser HTTP 400 count |
|---|---:|
| `/api/v1/network/summary` | 46 |
| `/api/v1/blocks?page=1&limit=25` | 46 |
| `/api/v1/txs?page=1&limit=25` | 46 |
| `/api/v1/validators?page=1&limit=100` | 46 |
| `/api/v1/tokens` | 46 |
| `/api/v1/contracts?page=1&limit=100` | 46 |
| `/api/v1/network/accounts` | 46 |
| `/api/v1/dag/status` | 46 |
| `/api/v1/dag/frontier` | 46 |
| `/api/v1/dag/topology?limit=300` | 46 |

The failing requests have the authenticated Atlas site's referrers and a Chrome
150 user agent. They occurred between 10:33:08 and 11:17:38 UTC. These are not
the expected 404s from missing routes.

A fresh 400-request test at approximately 12:01 UTC sent 20 cycles to all ten
paths through both the Pages proxy and direct API:

```text
Pages proxy: 200 / 200 requests returned HTTP 200
Direct API:  200 / 200 requests returned HTTP 200
Latency:     69–584 ms, 151 ms average
```

The current success does not eliminate the recurrence risk because the
transport configuration remains contradictory:

```text
Nginx:
  ssl_client_certificate ...cloudflare-authenticated-origin-pull-ca.pem
  ssl_verify_client on

Cloudflare zone synergy-network.io:
  Authenticated Origin Pulls enabled = false
  hostname associations = []
```

Before Atlas is declared stable, Cloudflare and Nginx must use one consistent
AOP policy and the same checks must pass from multiple Cloudflare edges after
cache/config propagation.

## CORS mismatch

An OPTIONS preflight from:

```text
Origin: https://testnet-atlas.synergy-network.io
```

to both public Atlas surfaces returned HTTP 204 but advertised:

```text
Access-Control-Allow-Origin: https://testnet-explorer.synergy-network.io
```

Relative same-origin requests through the Pages worker are not blocked by CORS,
but direct API calls from the canonical Atlas site are. The backend CORS allow
origin must include the canonical Atlas hostname or intentionally support both
canonical explorer hostnames.

## Missing gas and denomination tools

The live JavaScript bundle contains routes for blocks, validators, clusters,
and epochs, but no `/gas` or `/converter` route strings. The live site therefore
cannot expose the tools.

The uncommitted local checkout is:

```text
/Volumes/xcode/Synergy-Network-Projects/network-websites/atlas-v3
```

It contains:

```text
src/pages/GasPage.tsx
src/pages/ConverterPage.tsx
src/components/GasPanel.tsx
src/components/DenominationConverter.tsx
src/lib/gas.ts
src/lib/denominations.ts
```

That local work previously passed 66 tests, lint, and a production build. It
must still be reviewed with the other dirty Atlas changes, committed, pushed,
and deployed. The gas tools derive fee information from the existing
transaction feed; the denomination converter is client-side. Their absence is
a deployment/source-state problem, not a missing API blocker.

## Required completion work

1. Resolve the Cloudflare AOP/Nginx mismatch and repeat the multi-edge soak.
2. Correct CORS for the canonical Atlas hostname.
3. Extend the Pages worker proxy allowlist to `/version` and `/docs/*`, or
   intentionally expose the canonical OpenAPI path under `/api/v1`.
4. Implement the cluster, epoch, history/metrics, status, search, and detailed
   entity contracts, or explicitly remove features that claim those contracts.
5. Index the nine genesis contracts so canonical contract detail reads do not
   return data-level 404.
6. Review and deploy the existing gas/converter frontend work without
   overwriting unrelated dirty Atlas changes.
7. Repair relayer observer propagation; then prove RPC, indexer, block,
   transaction, DAG, and Atlas heights advance together.


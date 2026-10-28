# Hardhat compatibility with patched Zod

GHSA-mrhx-c7xc-m3w5 is fixed in Zod 4.6.6 and later. Hardhat 3.21.0 and
its plugins still request Zod 3, whose array parser has no compatible patched
release. This kit overrides Zod to 4.6.7 and adapts four installed runtime files
to the current record, function-validation, and error-reporting APIs.

`scripts/prepare-dependencies.js` applies the reviewed replacements in
`zod4-compat.json`. Exact package versions and before/after SHA-256 hashes
make application fail closed when an upstream dependency changes. Repeated
application is safe. No Zod 3 compatibility entry point is used.

Normal installs run this through `postinstall`. When installing with
`--ignore-scripts`, run `npm run postinstall` before using Hardhat.
CI does this explicitly, audits the complete dependency graph, and runs the
contract and compatibility regression tests.

Remove these patches when Hardhat and its plugins support patched Zod directly.
Upgrades to the pinned packages require reviewing the manifest and rerunning
the complete EVM test suite.

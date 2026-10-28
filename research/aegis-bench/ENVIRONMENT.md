# Frozen environment

The primary local environment ID is `macmini-m2-macos26.5.2-rust1.97.1-aarch64-20260814`.

The machine is a non-virtualized Apple M2 Mac mini (`Mac14,3`) with four performance and four efficiency cores, 8 GiB RAM, macOS 26.5.2 build 25F84, and AC power with low-power mode disabled. The Rust target is `aarch64-apple-darwin`; Rust 1.97.1 uses LLVM 22.1.6 and Apple clang 21.0.0 supplies the native C compiler.

The harness is compiled in the explicitly declared release profile: `opt-level=3`, no debug info, symbols stripped, LTO disabled, 16 code-generation units, unwinding panics. The target exposes the AArch64 NEON feature, but the production `synergy-testnet` dependency enables Aegis features `mlkem,mldsa,fndsa,security` and does **not** enable Aegis's `neon` feature. The measured Aegis ML-DSA/FN-DSA native implementation is therefore its clean portable path, not the optional AArch64-specific path.

The runtime subtree is byte-clean at Git commit `9d3ab807a08ef4cf1077dbc23213e2314ce37c87`. The wider working tree contains pre-existing unrelated changes and release artifacts; those are preserved and are not benchmark inputs. Hashes of the exact PQC abstraction, Aegis wrapper, lockfile, harness, binary, raw inputs, and derived outputs are retained in the evidence package.

The Aegis consensus domain is bound through `SYNERGY_GENESIS_FILE` to the RC30 Chain 1266 incarnation-4 Genesis with SHA-256 `ee554c197a878cbfdaf7d470a0274ab2859a7a0c14c87e425908a69c6fbb51cf`. A missing or mismatched Genesis fails the run closed.

The repository consolidation left workspace manifests pointing to a missing sibling `synq-language`. The build uses a non-overwriting symlink from `/Volumes/xcode/Synergy-Network/01-Core-Protocol/synq-language` to the commit-bound `runtime/synq-language`. No tracked manifest or production source is changed by that shim.

CPU frequency, temperature, calibrated energy, and hardware performance counters are `NOT_MEASURED`. Peak resident set size is captured with `getrusage`; it is a process high-water mark, not per-operation incremental allocation. CPU time is process user-plus-system time and can include bounded Aegis verification worker activity.

An earlier post-build diagnostic snapshot was rejected because compilation and swap activity were elevated. The accepted publication run remained an interactive desktop measurement: one-minute load averages were 2.55 before build, 4.16 immediately after build/before measurement, and 2.89 after measurement on eight logical cores. Those snapshots are checksummed with the run. The results are a development-host baseline rather than a quiet bare-metal cycle measurement.

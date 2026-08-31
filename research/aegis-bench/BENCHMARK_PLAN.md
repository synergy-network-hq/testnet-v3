# Benchmark plan and execution record

The plan follows the attachment’s phase order and preserves the distinction between completed, derived, and unavailable evidence.

| Phase | Scope | Completion evidence |
|---|---|---|
| 1. Reconnaissance | Algorithms, dependencies, call paths, current consensus mode, deployment and safety boundary | `SOURCE_RECONNAISSANCE.md`, `algorithm-inventory.csv`, `ALGORITHM_MATRIX.md` |
| 2. Microbenchmark harness | Direct primitives, PQCManager, Aegis wrapper, lifecycle, cold start, negative paths | `src/`, locked research manifest, diagnostic runs |
| 3. Protocol harness | Public and typed transactions, P2P handshake, coordinated assignment/block/commit, exact frames | Primary publication protocol CSV |
| 4. Safe controlled load | Local bounded verification pool with worker counts 1/2/4 | Three independent load run directories |
| 5. Passive live observation | One authorized, non-mutating RPC-gateway snapshot | `results/live-observation-20260814.json` |
| 6. Analysis and derivation | Statistics, plots, transaction/block bytes, validator formulas | `analyze.py`, `report.py`, `results/publication/` |
| 7. Publication package | Tables, results, limitations, provenance, requirement audit | Markdown deliverables in this directory |

No production source, consensus parameter, validator configuration, chain state, firewall, or credential was changed. The only non-repository layout action was the documented, non-overwriting symlink needed by retained workspace path dependencies.

The safe local plan is complete. Node TPS/finality and multi-node resource experiments were not replaced with smaller synthetic claims; their missing prerequisites and exact status are recorded in `NOT_MEASURED.md`.

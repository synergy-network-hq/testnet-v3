# SynQ Security Audit Manual

> This manual is security process documentation, not an implementation-status
> source. AIVM execution tasks live in
> `../../synergy-aivm/docs/readiness/SMART_CONTRACT_PRODUCTION_READINESS.md`.

Version: 1.0
Last Updated: 2026-02-09
Audience: New SynQ auditors, internal security engineers, third-party audit partners

---

## 1. Document Purpose

This manual is the full step-by-step operating playbook for performing security audits on SynQ contracts in the current repository state.

This is not a high-level checklist. It is an execution manual that tells a new auditor exactly what to do, in what order, with what tooling, and with what acceptance criteria.

Use this document together with:

- Audit policy: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/audits/procedures/Audit-Procedure.md`
- Report template: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/audits/templates/Audit-Report-Template.md`

---

## 2. Non-Negotiable Audit Principles

1. Source-of-truth is implementation plus tests, not marketing prose.
2. If behavior is ambiguous, you treat it as risk until proven otherwise.
3. Every critical claim must be reproducible from a pinned commit.
4. No unresolved Critical/High issues at certification sign-off.
5. No “trust me” assertions from project authors are accepted without evidence.

---

## 3. SynQ-Specific Reality You Must Internalize

Before auditing contracts, understand this operational truth:

- SynQ grammar surface is broader than current proven runtime semantics.
- Some constructs parse but are only partially lowered/executed.
- PQ operations are integrated, but name-based lowering and runtime assumptions matter.

This means your audit has two layers:

1. Contract logic audit
2. Toolchain semantic audit for the subset used by the contract

If you skip layer 2, your audit can be technically neat and practically wrong.

---

## 4. Required Inputs Before Audit Start

Collect and freeze all of the following:

1. Contract source files in scope
2. Exact git commit hash for audit target
3. SynQ workspace commit hash
4. Compiler and VM commit hashes (if split)
5. Rust toolchain version
6. Build/test command list used by project team
7. Declared PQ algorithms used by contract
8. Threat model assumptions from project team
9. Expected invariants from business owner
10. Intended deployment conditions

Do not start analysis before this freeze. Scope drift creates fake confidence.

---

## 5. Auditor Environment Setup (Step-by-Step)

## 5.1 Clone and Pin

```bash
git clone <repo-url>
cd /Users/devpup/Desktop/Synergy/synergy-components/synq-language
git checkout <audit-commit-hash>
```

## 5.2 Validate Toolchain

```bash
rustc --version
cargo --version
```

Record both in report appendix.

## 5.3 Baseline Build

```bash
cargo build --workspace
```

If this fails, audit status is blocked until reproducible baseline exists.

## 5.4 Baseline Tests

```bash
cargo test --workspace --all-targets
cargo test -p compiler --test integration_test
cargo test -p quantumvm --test integration_test
```

Capture raw command output into audit evidence logs.

## 5.5 PQ Substrate Validation

```bash
bash aegis-pqsynq/pqsynq/scripts/run_tests.sh
```

If this script fails, contracts relying on PQ behavior are not certifiable.

## 5.6 Dependency Security Pass

```bash
cargo audit
```

Record CVEs and warnings. Warnings still require explicit risk disposition.

---

## 6. Audit Workflow (Phase-by-Phase)

Each phase has objective, actions, outputs, and exit criteria.

## Phase 0: Intake and Scope Lock

Objective:

- Define exactly what will be audited and what will not.

Actions:

1. Enumerate in-scope files with absolute paths.
2. Enumerate out-of-scope components explicitly.
3. Record commit hash and branch.
4. Freeze scope document.

Outputs:

- Scope table in audit report
- Commit hash evidence

Exit criteria:

- Scope approved by both auditor lead and project owner

## Phase 1: Contract Inventory and Risk Ranking

Objective:

- Prioritize audit effort where impact is highest.

Actions:

1. List all entry points (`@public` and externally intended functions).
2. Mark high-impact functions:
   - fund movement
   - key rotation
   - governance control
   - emergency paths
3. Mark PQ-critical paths:
   - signature verification
   - decapsulation
   - auth gating via `require_pqc`

Outputs:

- Attack-surface inventory
- Priority matrix

Exit criteria:

- Every externally callable path has a risk priority class

## Phase 2: Threat Modeling

Objective:

- Define attacker capabilities before code review bias sets in.

Actions:

1. Define actors:
   - external attacker
   - malicious privileged actor
   - compromised key holder
   - griefing participant
2. Define assets:
   - funds
   - governance control
   - key material
   - service availability
3. Define attack goals:
   - unauthorized action
   - replay
   - denial of service
   - state corruption
4. Define trust boundaries:
   - on-chain contract logic
   - off-chain signing flow
   - VM/compiler assumptions

Outputs:

- Threat model table tied to specific contract functions

Exit criteria:

- Every high-impact function maps to at least one adversarial scenario

## Phase 3: Static Contract Logic Review

Objective:

- Identify business logic and access-control vulnerabilities.

Actions:

1. Review access control for each external function.
2. Review state transitions for invariants.
3. Validate preconditions, postconditions, and error paths.
4. Check for inconsistent authorization model across code paths.
5. Check for bypasses in emergency/admin flows.

Outputs:

- Preliminary finding set (logic/security)

Exit criteria:

- No entry point left unreviewed

## Phase 4: SynQ Language and Compiler Semantics Review

Objective:

- Ensure contract intent matches emitted behavior.

Actions:

1. Parse contract with current parser.
2. Compile contract to `.synq` bytecode.
3. Validate expected opcodes exist in code section.
4. Identify any syntax constructs used by contract that are known partial in current implementation.
5. Flag features that parse but do not lower with stable semantics.

Commands:

```bash
cargo run -p cli -- compile --path /absolute/path/to/contract.synq
```

For bytecode inspection, either:

- use a custom disassembler harness, or
- inspect code section in Rust test harness similar to `compiler/tests/integration_test.rs`.

Outputs:

- Semantic conformance note per critical function

Exit criteria:

- Auditor can prove critical logic is represented in emitted bytecode

## Phase 5: VM Runtime Behavior Review

Objective:

- Verify runtime execution and error behavior under normal and adversarial inputs.

Actions:

1. Execute compiled bytecode in VM.
2. Validate success-path outputs and stack effects.
3. Validate failure-path outputs and error types.
4. Check out-of-gas behavior for expensive PQ paths.
5. Validate VM handles malformed inputs without undefined behavior.

Commands:

```bash
cargo run -p cli -- run --path /absolute/path/to/contract.compiled.synq
cargo test -p quantumvm --test integration_test
```

Outputs:

- Runtime behavior evidence with pass/fail expectations

Exit criteria:

- Critical paths have explicit success and failure execution evidence

## Phase 6: PQC Correctness and Misuse-Resistance Review

Objective:

- Ensure cryptographic usage is safe and context-bound.

Actions:

1. Confirm intended algorithms and levels are used.
2. Confirm signature verification is bound to message context (domain separation).
3. Confirm decapsulation paths handle invalid ciphertext/key combinations safely.
4. Confirm no secret key material is exposed in logs or persisted paths.
5. Confirm key rotation logic cannot be bypassed.

Commands:

```bash
cargo test -p aegis-pqsynq --all-features --test nist_vector_replay_tests
bash aegis-pqsynq/pqsynq/scripts/generate_compliance_report.sh
```

Outputs:

- PQ correctness evidence references
- Misuse-resistance findings

Exit criteria:

- No unresolved cryptographic misuse finding in critical paths

## Phase 7: Gas and Denial-of-Service Review

Objective:

- Determine whether attackers can force expensive execution or state bloat.

Actions:

1. Identify loops and unbounded input handling.
2. Identify expensive PQ operations on attacker-controlled data.
3. Check transaction-level PQ gas limits against worst-case inputs.
4. Check repeated verification/decap patterns for griefing vectors.

VM references:

- default total gas and PQ gas caps in `vm/src/vm.rs`
- dynamic PQ cost formulas in opcode handlers

Outputs:

- DoS risk findings with exploit conditions

Exit criteria:

- High-confidence statement on DoS posture for in-scope contracts

## Phase 8: Negative Testing and Adversarial Scenarios

Objective:

- Prove exploitability or resistance with reproducible tests.

Actions:

For each critical path, add at minimum:

1. Wrong signature test
2. Tampered message test
3. Wrong key test
4. Malformed bytes input test
5. Boundary size input test
6. Out-of-gas scenario test

Outputs:

- Reproducible test artifacts per high-risk finding

Exit criteria:

- Every high/critical hypothesis has either exploit repro or disproving evidence

## Phase 9: Findings Classification and Report Draft

Objective:

- Produce a precise, defensible finding set.

Actions:

1. Classify findings by severity:
   - Critical
   - High
   - Medium
   - Low
   - Informational
2. For each finding include:
   - affected file/function
   - exploit preconditions
   - impact
   - reproduction steps
   - remediation recommendation
3. Populate report template.

Template:

`/Users/devpup/Desktop/Synergy/synergy-components/synq-language/audits/templates/Audit-Report-Template.md`

Outputs:

- Draft audit report

Exit criteria:

- Every finding is reproducible and severity-justified

## Phase 10: Remediation Verification

Objective:

- Ensure fixes actually solve problems without introducing regressions.

Actions:

1. Verify each fix against original exploit scenario.
2. Re-run relevant test suites.
3. Re-run full baseline checks.
4. Update finding status.

Commands:

```bash
cargo test --workspace --all-targets
bash aegis-pqsynq/pqsynq/scripts/run_tests.sh
cargo audit
```

Outputs:

- Remediation verification section in report

Exit criteria:

- No unresolved Critical/High findings for certification

## Phase 11: Final Determination and Sign-Off

Objective:

- Issue an explicit, accountable audit outcome.

Actions:

1. Record certification decision.
2. Record open residual risks (if any).
3. Record assumptions and limitations.
4. Sign auditor attestation.

Outputs:

- Final signed report

Exit criteria:

- Report complete, evidence linked, decision explicit

---

## 7. SynQ Contract Auditor Checklist (Detailed)

Use this line-by-line checklist during review.

## 7.1 Authorization and Privilege

- Are all privileged functions gated?
- Can privilege checks be bypassed through alternate code paths?
- Are key-rotation functions themselves protected?
- Are emergency paths as strict as normal paths?

## 7.2 Signature and Message Binding

- Is signed payload domain-separated?
- Is signed payload bound to contract, chain, and function intent?
- Is replay prevention present (nonce/counter/one-time marker)?
- Are wrong-key and wrong-message paths tested?

## 7.3 PQ Function Name and Lowering Integrity

- Do PQ calls use codegen-recognized prefixes?
- Does compiled bytecode actually contain expected PQ opcodes?
- Is algorithm variant implied by function name what team expects?

## 7.4 State Integrity

- Are invariants explicit and preserved on all branches?
- Are partial updates possible before failure/revert?
- Are assignment targets semantically what author intended in current compiler?

## 7.5 Input Validation

- Are lengths and formats validated before expensive operations?
- Are byte payloads attacker-controlled without limits?
- Are zero/default/sentinel values blocked where unsafe?

## 7.6 Error Handling and Fail-Safe Behavior

- Do failure paths fail closed?
- Is fallback logic safe and deterministic?
- Are runtime errors surfaced in a controlled way?

## 7.7 Gas and DoS

- Can attacker force repeated expensive PQ operations?
- Are loops bounded?
- Is maximum input size constrained for PQ operations?
- Does contract rely on unrealistic gas assumptions?

## 7.8 Toolchain Assumption Safety

- Are contracts using features known to be partial in parser/codegen/VM?
- Is there test evidence for every critical semantic branch?
- Are old aspirational examples being mistaken for production-safe patterns?

---

## 8. High-Risk SynQ Anti-Patterns

These are recurring audit failures to detect early.

1. CamelCase PQ call names that do not trigger current opcode lowering.
2. Assuming `docs/examples/` contracts are production-ready without compile/runtime proof.
3. Using parser-supported syntax that has partial codegen/runtime semantics.
4. Missing domain separation in signed messages.
5. Missing replay protection around signed authorizations.
6. Unbounded byte input passed into expensive PQ operations.
7. Weakly tested fallback/revert paths in `require_pqc` blocks.
8. Governance key updates without robust multi-step authorization.

---

## 9. Minimum Evidence Package for a Credible Audit

A valid SynQ audit deliverable must include:

1. Scope lock with commit hash
2. Environment/toolchain versions
3. Baseline command outputs
4. Contract compile and runtime evidence
5. Bytecode opcode evidence for critical functions
6. Negative tests for high-risk scenarios
7. Full findings list with severities and remediation guidance
8. Remediation verification notes
9. Final decision and residual risk register

If any item is missing, audit quality is below standard.

---

## 10. Sample Command Pack (Copy/Paste)

Run from:

`/Users/devpup/Desktop/Synergy/synergy-components/synq-language`

```bash
# Baseline
cargo build --workspace
cargo test --workspace --all-targets

# Compiler and VM integration
cargo test -p compiler --test integration_test
cargo test -p quantumvm --test integration_test

# Compile and run a target contract
cargo run -p cli -- compile --path /absolute/path/to/target.synq
cargo run -p cli -- run --path /absolute/path/to/target.compiled.synq

# PQ substrate validation
bash aegis-pqsynq/pqsynq/scripts/run_tests.sh

# PQ compliance artifacts
bash aegis-pqsynq/pqsynq/scripts/generate_compliance_report.sh

# Dependency security
cargo audit
```

---

## 11. Findings Writing Standard

Each finding must be written so another engineer can reproduce it without contacting you.

Required fields:

1. Finding ID
2. Severity
3. Affected files/functions
4. Preconditions
5. Exploit sequence
6. Impact statement
7. Reproduction steps
8. Recommended fix
9. Retest method

No vague language. No “might be risky” filler.

---

## 12. Auditor Ethics and Independence

1. Disclose conflicts immediately.
2. Do not accept outcome-contingent compensation.
3. Do not suppress unresolved high-impact issues.
4. Do not issue “partial pass” language that hides unresolved critical risk.

If independence is compromised, stop and escalate.

---

## 13. Final Practical Advice for New Auditors

A good SynQ audit is not just contract review. It is contract review plus implementation-path verification.

If you remember one rule, remember this one:

- Never certify logic you did not verify in emitted bytecode and runtime behavior.

That rule alone prevents most early-language audit failures.

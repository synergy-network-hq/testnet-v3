# SynQ File Tree

```markdown
SynQ/
✅├── README.md                          # Project overview, dev guide
├── LICENSE                            # (Recommended: MIT or Apache 2.0)
│
├── docs/                              # Human-facing documentation
✅│   ├── Language_Specification.md
✅│   ├── Gas_Model.md
✅│   ├── VM_Specification.md
│   ├── Developer_Manual.md
✅│   └── QuantumDAO_Example.md
│
├── specs/                             # Raw design docs and drafts
✅│   ├── quantumscript.dsl              # Core DSL definition
✅│   ├── vm.opcodes                     # QuantumVM opcode table
│   ├── gas.table                      # PQC operation gas costs
✅│   └── checklist.md                   # Full roadmap + milestone tracking
│
├── compiler/                          # SynQ compiler (JS or Rust)
│   ├── src/
│   │   ├── lexer.ts
│   │   ├── parser.ts
│   │   ├── ast.ts
│   │   ├── typechecker.ts
│   │   ├── bytecode_generator.ts
│   │   └── index.ts
│   └── tests/
│       ├── dao.qs
│       └── dao.bytecode
│
├── vm/                                # QuantumVM bytecode interpreter
│   ├── src/
│   │   ├── memory.rs
│   │   ├── opcode.rs
│   │   ├── executor.rs
│   │   ├── gas.rs
│   │   └── main.rs
│   └── tests/
│       ├── unit/
│       └── integration/
│
├── sdk/                               # JS SDK for keygen, tx build, verify
│   ├── src/
│   │   ├── keys.ts
│   │   ├── tx.ts
│   │   ├── crypto/
│   │   │   ├── dilithium.ts
│   │   │   ├── kyber.ts
│   │   │   └── falcon.ts
│   │   └── index.ts
│   └── examples/
│       └── deploy_dao.ts
│
├── examples/                          # End-to-end contract examples
│   ├── quantumdao.qs
│   ├── vote.qs
│   └── wallet.qs
│
└── testnet/                           # Testnet configs, accounts, test tools
    ├── genesis.json
    ├── pq_accounts.json
    ├── deploy_script.ts
    └── node_config.toml
```

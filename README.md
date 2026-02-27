# DevMatrix — Deterministic Software Compilation for AI-Generated Systems

**Governance is not documented. It is compiled.**

---

## What DevMatrix Is

DevMatrix is a **software compiler**.

It transforms system specifications into **production-grade software**
with **deterministic outputs**, **compile-time governance**, and
**cryptographically verifiable evidence**.

Same input → same system.  
If not, the build **fails**.

DevMatrix exists to solve a problem that AI tooling has not:
**unpredictable systems caused by architectures without invariants**.

Models can be probabilistic.  
**Architecture cannot.**

It is a **compiler** that produces:

- Complete backend (Python/FastAPI)
- Generated tests (pytest)
- Infrastructure (Docker, migrations)
- Cryptographic evidence of reproducibility
- Frontend generation (React/Next.js)  *in development*

---

## What DevMatrix Is NOT

DevMatrix is **not**:

- an AI coding assistant  
- an agent framework  
- prompt engineering  
- runtime AI governance  
- probabilistic code generation  

DevMatrix does not "suggest" software.
It **compiles** systems.

---

## Relationship to Models

DevMatrix is model-agnostic infrastructure designed to sit downstream of reasoning models, turning their outputs into deterministic, verifiable, and auditable systems. Models produce candidate specifications and decisions; DevMatrix deterministically compiles, verifies, and governs the resulting systems.

---

## What DevMatrix Guarantees

DevMatrix provides guarantees that are normally expected from compilers,
not AI systems:

- **Deterministic builds**  
  The same specification produces **byte-identical output**.

- **Compile-time governance**  
  Security, access control, and behavioral constraints are enforced
  during compilation, not documented after the fact.

- **Replayable decision graphs**  
  Every structural decision can be replayed, inspected, and verified.

- **Cryptographic provenance**  
  Generated artifacts include signed manifests, hashes, and
  reproducibility proofs.

- **Fail-closed behavior**
  If determinism or invariants cannot be guaranteed, the build fails.

- **Platform provenance**
  Platform provenance is sealed explicitly, never as a build side-effect.
  Sealing is a governance decision that validates completeness, quality gates,
  and determinism before emitting evidence.

If a system cannot be rebuilt exactly,  
**it is not governed**.

Governance that cannot be replayed is not governance.

---

## Failure Mode

DevMatrix is fail-closed.

If determinism, invariants, or provenance
cannot be guaranteed,
the build fails.

Silent degradation is not allowed.

---

## Why This Exists

AI systems fail in production not because models drift,
but because the **architecture around them has no invariants**.

Common failure modes across industries:

- Rules that shift between contexts  
- No enforced boundaries  
- No deterministic decision structure  
- No way to replay or verify outcomes  
- Governance that exists only in documentation  

DevMatrix addresses this by moving governance
**from policy and runtime into compilation itself**.

---

## Proof: Deterministic Compilation

This repository contains **public, cryptographically verifiable evidence**
that DevMatrix produces deterministic systems.

Included:

- A real system specification
- Multiple independent compilation runs
- Identical output hashes
- Signed build manifests
- Verification scripts

### Verify It Yourself

**Key guarantee**: Same specification → same system → same SHA-256 hash.

---

## Quick Links

| Document | Description |
|----------|-------------|
| [PAPER_EN.md](PAPER_EN.md) | Technical paper (English - canonical) |
| [EVIDENCE_EN.md](EVIDENCE_EN.md) | Reproducibility evidence (English) |
| [HOW_TO_VERIFY.md](HOW_TO_VERIFY.md) | Verification instructions |
| [REPRODUCIBILITY_SPEC.md](REPRODUCIBILITY_SPEC.md) | Canonical hash algorithm definitions |
| [SEALING.md](SEALING.md) | Platform provenance sealing protocol |
| [GOLDEN_PACK_INDEX.md](GOLDEN_PACK_INDEX.md) | Verification in 10 minutes |
| [PLATFORM_VERIFICATION.md](PLATFORM_VERIFICATION.md) | Platform-scale verification model |
| [PAPER.md](PAPER.md) | Technical paper (Spanish) |
| [EVIDENCE.md](EVIDENCE.md) | Reproducibility evidence (Spanish) |

---

## Evidence Summary

### Platform-Scale Evidence (February 2026)

| Platform | Modules | Tests | Pass Rate | Grade | Gates | Seal |
|----------|---------|-------|-----------|-------|-------|------|
| HIP (Healthcare) | 12 | 2,391 | 100.0% | A+ (100.0%) | 594/594 | G_SEAL PASS |

12/12 modules Grade A. 0 gate failures. 0 test failures. Per-module breakdown in [EVIDENCE_EN.md](EVIDENCE_EN.md).

HIP is a real-world healthcare platform currently being deployed to production in Argentina for multiple clinical laboratory companies.

Full details: [EVIDENCE_EN.md](EVIDENCE_EN.md) | [GOLDEN_PACK_INDEX.md](GOLDEN_PACK_INDEX.md)

### Evidence Timeline (Deterministic Builds)

This repository exposes **verifiable evidence snapshots** of DevMatrix builds.
Each snapshot corresponds to a sealed compilation run and can be independently
validated without access to proprietary implementation.

| Build ID | Date (UTC) | Scope | Tests (Pass/Fail/Blocked) | IR Nodes | IR Edges | Cross-Svc | HTTP Deps | Seal |
|----------|------------|-------|---------------------------|----------|----------|-----------|-----------|------|
| HIP | 2026-02-26 | Platform (12 modules) | 2,391 (2,248/0/12) | ~6,390 | ~7,622 | 91 | 19 | G_SEAL PASS |

**Column definitions**: IR Nodes/Edges = structural graph size of the compiled IR. Cross-Svc = cross-service FK dependencies resolved at compile time. HTTP Deps = inter-service HTTP dependencies.

Full details: [EVIDENCE_EN.md](EVIDENCE_EN.md) | [PLATFORM_VERIFICATION.md](PLATFORM_VERIFICATION.md)

---

## Verify It Yourself

```bash
# Quick verification — compare two independent compilations
python verify_fingerprint.py \
  -f fingerprints/20260226_modular_hip_test_20260221_103259_0fe80102.json \
  --compare fingerprints/20260227_modular_hip_test_20260221_103259_0fe80102.json
```

If DevMatrix is non-deterministic, one of these must occur:
- Same spec → different `spec_hash`
- Same `spec_hash` → different `code_bundle_hash`

**Current status**: 0 hash variations observed.

See [HOW_TO_VERIFY.md](HOW_TO_VERIFY.md) for detailed instructions.

---

## What Makes This Different

| Aspect | Copilots | Agents | DevMatrix |
|--------|----------|--------|-----------|
| Output | Lines of code | Varies | Complete systems |
| Determinism | No | No | **Yes** |
| Verifiable | No | No | **Yes** |
| Tests | No | Sometimes | **Generated + executed** |
| Reproducible | No | No | **Same hash** |

---

## Files in This Package

```
├── README.md                          # This file
├── PAPER_EN.md                        # Technical paper (English - canonical)
├── PAPER.md                           # Technical paper (Spanish)
├── EVIDENCE_EN.md                     # Evidence (English)
├── EVIDENCE.md                        # Evidence (Spanish)
├── HOW_TO_VERIFY.md                   # Verification guide
├── REPRODUCIBILITY_SPEC.md            # Canonical hash algorithm definitions
├── SEALING.md                         # Platform sealing protocol
├── GOLDEN_PACK_INDEX.md               # Quick verification table
├── PLATFORM_VERIFICATION.md           # Platform-scale verification model
├── verify_fingerprint.py              # Verification script (reference implementation)
├── LICENSE                            # CC-BY 4.0 (docs) + MIT (script)
├── CITATION.cff                       # Citation metadata
├── examples/
│   ├── build_fingerprint_example.json   # Single-module fingerprint
│   ├── platform_provenance_sealed.json  # 12-module platform example
│   └── seal_manifest_example.json       # G_SEAL validation example
└── fingerprints/
    ├── 20260221_modular_hip_test_..._a57210ff.json
    ├── 20260226_modular_hip_test_..._0d1cc2ed.json
    ├── 20260226_modular_hip_test_..._5ac138f8.json
    ├── 20260226_modular_hip_test_..._0fe80102.json
    └── 20260227_modular_hip_test_..._0fe80102.json
```

---

## What You Will NOT See Here (By Design)

This repository contains evidence, not implementation. Proprietary components — including
IR schemas (~390 types), compilation passes (42), emitter source, gate logic, and
LLM prompt architecture — are excluded by design.

Details available under NDA.

---

## Public Evidence vs NDA-Only Artifacts

This repository intentionally contains only verification artifacts and documentation required for independent technical evaluation.

### Included (Public)
- Sealed platform provenance examples
- Build fingerprints and verification script
- Gate results and QA summaries
- Reproducibility specification and hash algorithms
- SEAL process documentation and Golden Pack verification

### Excluded (NDA Required)
- Internal IR schemas and pass implementations
- Compiler pipeline source code
- Domain-specific generation templates
- Prompting logic and repair strategies
- Runtime orchestration internals

This separation is deliberate and designed to allow independent verification without exposing proprietary compiler internals.

**To request NDA access**: [aeghysels@devmatrix.dev](mailto:aeghysels@devmatrix.dev)

---

## Citation

If you reference this work:

```bibtex
@misc{ghysels2026devmatrix,
  author = {Ghysels, Ariel Eduardo},
  title = {DevMatrix: A Specification-to-System Compiler},
  year = {2026},
  url = {https://devmatrix.dev/}
}
```

See [CITATION.cff](CITATION.cff) for full citation metadata.

---

## License

- **Documentation**: CC-BY 4.0
- **Verification script**: MIT
- **DevMatrix software**: Proprietary (not included)

---

## Intended Audience

DevMatrix is built for:

- Principal / Staff / Distinguished Engineers
- AI governance and reliability teams
- Regulated and high-risk industries
- Organizations that require auditability, replayability, and proof

It is not optimized for tutorials, demos, or casual experimentation.

## Status

DevMatrix is an active compiler system with:

- Deterministic IR
- Invariant-driven compilation
- Unified testing and verification
- Cryptographic build provenance

This repository is intentionally minimal and evidence-focused.

## Final Note

If your AI-generated system cannot be rebuilt
byte-for-byte from the same input,

then you cannot prove how it behaves,
why it behaves that way,
or how a decision was made.

That is not governance.

DevMatrix exists to eliminate that class of failure.

## Contact

**Ariel Eduardo Ghysels**
**aeghysels@devmatrix.dev**

- [https://devmatrix.dev/](https://devmatrix.dev/)
- [LinkedIn](https://www.linkedin.com/in/ariel-ghysels-52469198/)
- [X @builddevmatrix](https://x.com/builddevmatrix)
- Supervised verification sessions available
- Access to compilations under NDA

---

*This is not a demo. This is evidence.*

*Evidence = cryptographic fingerprints + reproducible build hashing, not screenshots.*

*Last updated: February 26, 2026*

---

**Intellectual Property Notice**

DevMatrix™ and the underlying compilation technology are protected intellectual property.
The concepts and evidence presented in this repository are disclosed for research and evaluation purposes.
The DevMatrix compiler core is proprietary. US Patent Pending. EU registration filed.

**Not affiliated with** any other product, service, or entity named "DevMatrix". The canonical domain is [devmatrix.dev](https://devmatrix.dev/).

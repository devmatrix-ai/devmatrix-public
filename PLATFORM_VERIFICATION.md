# Platform Verification

This document describes how platform-scale determinism is verified in DevMatrix.

---

## Scope

The same deterministic guarantees demonstrated for single-module compilation
apply to full platforms composed of multiple services.

A platform compilation produces a **single sealed IR graph** where all modules
are compiled in one pass. Cross-service dependencies (foreign keys, HTTP calls)
are resolved at compile time, not at runtime.

---

## Verification Model

| Property | Single-Module | Platform |
|----------|---------------|----------|
| Deterministic output | Yes | Yes |
| Cryptographic fingerprint | `build_fingerprint.json` | `platform_provenance.json` |
| Seal governance | — | G_SEAL (4 checks) |
| IR graph | Per-module | Unified across all services |
| Cross-service resolution | N/A | Compile-time FK + HTTP |

**Key invariant**: Re-execution with identical input specification produces
identical `build_id`, identical IR graph metrics, and identical `deterministic_seed`.

---

## Evidence Artifacts

Each platform compilation produces:

| Artifact | Purpose |
|----------|---------|
| `build_fingerprint.json` (per module) | Per-module cryptographic hashes |
| `platform_provenance.json` | Aggregate hashes and seal status |
| `seal_manifest.json` | G_SEAL validation details |
| `PLATFORM_QA_REPORT.md` | Aggregated test results |
| `PLATFORM_GRAPH_COUNTING_CONTRACT.md` | IR graph structural metrics |

---

## IR Graph Metrics

The compiled IR graph exposes structural properties that are **deterministic
invariants** — they cannot vary between executions with the same specification.

| Metric | Description |
|--------|-------------|
| IR Nodes | Total nodes in the compiled graph (entities, attributes, endpoints, schemas, fields, test cases) |
| IR Edges | Total edges connecting nodes (relationships, dependencies, references) |
| Cross-Service FK Dependencies | Foreign key relationships that span service boundaries |
| HTTP Dependencies | Inter-service HTTP call dependencies resolved at compile time |

These metrics are derived from the canonical IR and are included in the
`PLATFORM_GRAPH_COUNTING_CONTRACT.md` evidence artifact.

---

## Falsification Conditions

If platform-scale determinism is broken, one of the following must occur:

| Test | Expected if Non-Deterministic |
|------|-------------------------------|
| Same modules → different `build_id` | Seal is non-deterministic |
| Same modules → different IR graph metrics | Graph construction varies |
| Same modules → different `deterministic_seed` | Pipeline state varies |
| Seal succeeds with missing module | Completeness check is broken |
| Seal succeeds with failing gates | Gate enforcement is broken |

---

## Relationship to Single-Module Verification

Platform verification is a **superset** of single-module verification:

1. Each module is independently verifiable via `build_fingerprint.json`
2. The platform seal aggregates all module fingerprints into a single `deterministic_seed`
3. IR graph metrics provide structural verification beyond hash comparison

No proprietary compilation passes or heuristics are required to verify these properties.

---

## Contact

For independent platform verification:

**Ariel Eduardo Ghysels** — [aeghysels@devmatrix.dev](mailto:aeghysels@devmatrix.dev)
- [https://devmatrix.dev/](https://devmatrix.dev/) | [LinkedIn](https://www.linkedin.com/in/ariel-ghysels-52469198/) | [X @builddevmatrix](https://x.com/builddevmatrix)
- Supervised verification sessions available
- Access to compilations under NDA

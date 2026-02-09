# SEALING.md — Platform Provenance Sealing Protocol

> Platform Sealing Protocol | Public Reference

---

## What Is Sealing?

Sealing is the explicit, governance-controlled step that produces **platform-level provenance** after all modules have been compiled.

```
compile → per-module artifacts (build_fingerprint.json, gate_results.json)
seal    → platform provenance  (evidence_pack/)
```

**Compilation emits code. Sealing emits evidence.**

---

## Design Constraints

| Constraint | Rationale |
|-----------|-----------|
| **Seal is never automatic** | Sealing is a governance decision, not a build side-effect. There is no auto-seal flag. |
| **Idempotence is absolute** | Same modules on disk → same seal output. Same hashes. Same build ID. No timestamps in hash inputs. |
| **Fail-closed** | If any module is missing, any gate fails, or git is dirty in release mode — seal refuses. |

---

## Seal Verification (G_SEAL)

Before emitting provenance, the sealer runs four validation checks:

| Check | What It Verifies | Failure Mode |
|-------|-----------------|--------------|
| **Completeness** | All modules declared in manifest exist on disk | Hard fail — missing module listed |
| **Gate Results** | Every module passes all quality gates (34/34) | Hard fail — failing modules listed |
| **Version Consistency** | Pipeline version identical across all modules | Warning (non-release) or fail (release) |
| **Git State** | Clean working tree, valid commit | Fail in release mode; warning otherwise |

---

## What Sealing Produces

All seal artifacts are written to a single directory: `evidence_pack/`

| Artifact | Content |
|----------|---------|
| `build_provenance.json` | Aggregate hashes, build ID, deterministic seed, per-module fingerprints, git state |
| `platform_provenance.json` | Platform-level build identity with per-module summary |
| `REPLAY.md` | Human-readable reproduction instructions with expected hashes |
| `seal_manifest.json` | G_SEAL validation results, artifact inventory, sealed module list |
| `evidence_pack.json` | Augmented with seal provenance (sealed_at, build_id, g_seal_passed) |

Pre-existing compilation artifacts (`merkle_proof.json`, `gate_results.json`, `source_map.json`) remain in the same directory.

---

## Deterministic Guarantees

| Property | Mechanism |
|----------|-----------|
| **Build ID** | `sha256(agg_ir_hash[:16] + agg_output_hash[:16])[:16]` — derived from content, not time |
| **Aggregate IR Hash** | `sha256(sorted per-module ir_structural_hash values)` |
| **Aggregate Output Hash** | `sha256(sorted per-module code_bundle_hash values)` |
| **Deterministic Seed** | `sha256(agg_ir \| agg_output \| pipeline_version \| python_version)` |

Running `seal` twice on identical module artifacts produces **byte-for-byte identical** provenance. Timestamps appear only in metadata fields and are excluded from hash inputs.

---

## Usage

```bash
# Compile all modules
devmatrix run -m manifest.yaml -o output/ --force -y

# Seal platform provenance (explicit governance step)
devmatrix seal -m manifest.yaml -o output/

# Release mode (requires clean git)
devmatrix seal -m manifest.yaml -o output/ --release

# Assert expected module count
devmatrix seal -m manifest.yaml -o output/ --expect-modules 12
```

---

## Verification Protocol

```bash
# First seal
devmatrix seal -m manifest.yaml -o output/
cp output/evidence_pack/seal_manifest.json /tmp/seal_manifest_1.json

# Second seal (same inputs)
devmatrix seal -m manifest.yaml -o output/

# Verify idempotence (order-normalized)
diff <(jq -S . /tmp/seal_manifest_1.json) <(jq -S . output/evidence_pack/seal_manifest.json)

# Alternative: hash-based idempotence check
sha256sum /tmp/seal_manifest_1.json output/evidence_pack/seal_manifest.json
```

**Falsification condition**: If running seal twice on identical modules produces different `build_id` or `deterministic_seed`, sealing is broken.

---

## Relationship to Compilation

```
┌─────────────────────────────────────────────────┐
│ devmatrix run (compilation)                     │
│                                                 │
│  spec.yaml → IR → passes → emitters → code     │
│                                                 │
│  Per-module output:                             │
│    hip_*/build_fingerprint.json                 │
│    hip_*/gate_results.json                      │
│    hip_*/source code + tests + infra            │
│                                                 │
│  ⚠ No platform provenance emitted              │
│  "Output is UNSEALED"                           │
└─────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│ devmatrix seal (governance decision)            │
│                                                 │
│  Reads:  hip_*/build_fingerprint.json           │
│          hip_*/gate_results.json                │
│          manifest.yaml                          │
│                                                 │
│  Validates: G_SEAL (completeness, gates,        │
│             version, git)                       │
│                                                 │
│  Writes:  evidence_pack/                        │
│           ├── build_provenance.json             │
│           ├── platform_provenance.json          │
│           ├── REPLAY.md                         │
│           ├── seal_manifest.json                │
│           └── evidence_pack.json (augmented)    │
│                                                 │
│  ✅ Platform provenance sealed                  │
└─────────────────────────────────────────────────┘
```

---

*This document describes the public sealing protocol. Internal compiler passes, IR schemas, and emitter internals are proprietary and subject to NDA.*

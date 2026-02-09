# DD Readiness Checklist — Pre-NDA Verification

> 8 binary checks. Each is PASS or FAIL. Each links to verifiable evidence.

---

## Checklist

| # | Check | Status | Evidence | How to Verify |
|---|-------|--------|----------|---------------|
| 1 | **Deterministic compilation** | PASS | `build_fingerprint.json` per module | Compile same spec twice → identical `code_bundle_hash` |
| 2 | **Platform seal (G_SEAL)** | PASS | `evidence_pack/seal_manifest.json` | `g_seal.passed == true`, all 4 checks pass |
| 3 | **Module completeness** | PASS | `seal_manifest.json` → `g_seal.checks.completeness` | `expected == found == 12`, `missing == []` |
| 4 | **Gate enforcement (34/34)** | PASS | `hip_*/gate_results.json` per module | `passed == true` in all 12 modules |
| 5 | **Idempotent seal** | PASS | Run `devmatrix seal` twice | `build_id` and `deterministic_seed` identical |
| 6 | **Fail-closed on missing module** | PASS | Remove fingerprint → re-seal | Seal refuses with specific error |
| 7 | **Fail-closed on dirty release** | PASS | `devmatrix seal --release` on dirty git | Seal refuses with governance error |
| 8 | **Reproducible build** | PASS | `evidence_pack/REPLAY.md` | Instructions + expected hashes for independent replay |

---

## Evidence Paths

All evidence is machine-readable JSON. No manual interpretation required.

```
output/
├── hip_admin/
│   ├── build_fingerprint.json    ← Check 1 (determinism)
│   └── gate_results.json         ← Check 4 (gates)
├── hip_billing/
│   ├── build_fingerprint.json
│   └── gate_results.json
├── ... (12 modules)
│
└── evidence_pack/
    ├── seal_manifest.json        ← Checks 2, 3, 5, 6, 7
    ├── build_provenance.json     ← Aggregate hashes + build metadata
    ├── platform_provenance.json  ← Platform identity
    ├── REPLAY.md                 ← Check 8 (reproducibility)
    ├── evidence_pack.json        ← Compilation + seal evidence
    └── merkle_proof.json         ← Cryptographic artifact tree
```

---

## Verification Commands

```bash
# Check 1: Deterministic compilation
devmatrix run -m manifest.yaml -o output_a/ --force -y
devmatrix run -m manifest.yaml -o output_b/ --force -y
diff <(jq -S .code_bundle_hash output_a/hip_core/build_fingerprint.json) \
     <(jq -S .code_bundle_hash output_b/hip_core/build_fingerprint.json)
# Expected: no diff

# Check 2-3: Platform seal
devmatrix seal -m manifest.yaml -o output/
jq '.g_seal.passed, .g_seal.checks.completeness' output/evidence_pack/seal_manifest.json
# Expected: true, {"passed": true, "expected": 12, "found": 12, "missing": []}

# Check 4: Gate enforcement
for m in output/hip_*/gate_results.json; do
  echo "$(basename $(dirname $m)): $(jq .passed $m)"
done
# Expected: all true

# Check 5: Idempotent seal
ID1=$(jq -r '.provenance_summary.build_id' output/evidence_pack/seal_manifest.json)
devmatrix seal -m manifest.yaml -o output/
ID2=$(jq -r '.provenance_summary.build_id' output/evidence_pack/seal_manifest.json)
[ "$ID1" = "$ID2" ] && echo "PASS: Idempotent" || echo "FAIL"

# Check 6: Fail-closed on missing module
mv output/hip_core/build_fingerprint.json /tmp/
devmatrix seal -m manifest.yaml -o output/
# Expected: ❌ Seal FAILED: Missing modules: ['hip_core']
mv /tmp/build_fingerprint.json output/hip_core/

# Check 7: Fail-closed on dirty release
devmatrix seal -m manifest.yaml -o output/ --release
# Expected: ❌ Seal FAILED (if git dirty)

# Check 8: Reproducibility
cat output/evidence_pack/REPLAY.md
# Contains: exact git commit, commands, expected hashes
```

---

## What You Will NOT See Here (By Design)

| Proprietary Component | Why It's Excluded |
|----------------------|-------------------|
| IR schemas and types (~390 types) | Core IP — the type system IS the compiler |
| Compilation passes (42 passes) | Sequencing and transformation logic |
| Emitter source code | Code generation templates and strategies |
| Gate implementation logic | Quality enforcement internals |
| LLM prompt architecture | Specification-to-IR translation |
| Behavior model and action aliases | Semantic action classification system |

These components are available under NDA for supervised evaluation.

---

## What This Checklist Enables

A champion inside an evaluating organization can say:

> "We verified 8 binary checks independently. The evidence is machine-readable JSON with cryptographic hashes. Platform provenance is sealed with a governance-controlled command that refuses incomplete builds. This is audit-grade infrastructure, not a demo."

---

## Security & Threat Modeling

DevMatrix performs compile-time security analysis and enforcement based on structural signals derived from the IR (e.g. authentication requirements, authorization scopes, data sensitivity, state transitions, external boundaries).

Threat models represent structural coverage and enforcement intent, not penetration testing or runtime exploit validation. Security artifacts describe what is enforced by the compiler and gates, not claims of absolute security correctness.

---

*Pre-NDA document. All checks reference publicly verifiable evidence. Proprietary components available under NDA.*

*Note: All claims in this checklist are backed by verifiable artifacts included in this repository or reproducible via the provided verification steps. No claims rely on trust or undocumented behavior.*

# Golden Pack Index — Verification in 10 Minutes

> Pre-NDA verification table. Every test is independently reproducible.

---

## Quick Reference

| # | What to Verify | Command | Time | Expected Output |
|---|---------------|---------|------|-----------------|
| 1 | **Platform seal** | `devmatrix seal -m manifest.yaml -o output/` | <5s | `✅ Seal complete`, 12/12 modules, all artifacts in `evidence_pack/` |
| 2 | **Completeness enforcement** | Remove any `hip_*/build_fingerprint.json`, re-seal | <5s | `❌ Seal FAILED: Missing modules: ['hip_xxx']` |
| 3 | **Idempotence** | Run seal twice, compare `build_id` + `deterministic_seed` | <10s | Identical values both runs |
| 4 | **Release governance** | `devmatrix seal ... --release` on dirty git | <5s | `❌ Seal FAILED: Cannot seal in release mode with dirty git` |
| 5 | **Gate enforcement** | Manually fail a gate in `gate_results.json`, re-seal | <5s | `❌ Seal FAILED: Gate failures: ['hip_xxx']` |
| 6 | **Fingerprint verification** | `python verify_fingerprint.py -f build_fingerprint.json` | <3s | `VERIFIED: All hashes match` |
| 7 | **Deterministic compilation** | Compile same spec twice, compare `code_bundle_hash` | <30s | Identical hashes (byte-for-byte) |
| 8 | **Module-level provenance** | Inspect any `hip_*/build_fingerprint.json` | <3s | 5 cryptographic hashes present: spec, ir_canonical, ir_semantic, ir_structural, code_bundle |

---

## Artifact Inventory

### Per-Module (emitted by compilation)

| Artifact | Location | Content |
|----------|----------|---------|
| `build_fingerprint.json` | `hip_*/` | 5 cryptographic hashes + build metadata |
| `gate_results.json` | `hip_*/` | ~50 gate pass/fail results with evidence |
| `source_map.json` | `hip_*/` | File → IR traceability |
| `uts_evidence.json` | `hip_*/` | Unit test simulation evidence |
| `threat_model.json` | `hip_*/` | Structural threat coverage (not penetration testing) |

### Platform (emitted by seal)

| Artifact | Location | Content |
|----------|----------|---------|
| `build_provenance.json` | `evidence_pack/` | Aggregate hashes, build ID, deterministic seed |
| `platform_provenance.json` | `evidence_pack/` | Platform identity + per-module summary |
| `REPLAY.md` | `evidence_pack/` | Reproduction instructions with expected hashes |
| `seal_manifest.json` | `evidence_pack/` | G_SEAL results, artifact list, sealed modules |
| `evidence_pack.json` | `evidence_pack/` | Compilation evidence + seal augmentation |
| `merkle_proof.json` | `evidence_pack/` | Merkle tree of all generated artifacts |

---

## Seal Manifest Example (Real Output)

```json
{
  "schema_version": "1.0.0",
  "manifest_name": "HIP",
  "release_mode": false,
  "g_seal": {
    "passed": true,
    "checks": {
      "completeness": { "passed": true, "expected": 12, "found": 12, "missing": [] },
      "gates":        { "passed": true, "modules_checked": 12, "failing_modules": [] },
      "version_consistency": { "passed": true, "pipeline_version": "60bc51c51" },
      "git_state":    { "passed": true, "dirty": true }
    }
  },
  "provenance_summary": {
    "build_id": "modular-20260226_142414-2f3639c8",
    "aggregate_ir_hash": "3ee8b2589f7cf244...6f",
    "aggregate_output_hash": "8b99cc65c84f3401...73",
    "deterministic_seed": "c441af276334fc00...32",
    "total_modules": 12,
    "pipeline_version": "60bc51c51"
  },
  "sealed_modules": [
    "hip_admin", "hip_billing", "hip_core", "hip_crm",
    "hip_finance", "hip_insurance", "hip_lis", "hip_logistics",
    "hip_marketplace", "hip_patient", "hip_scheduling", "hip_training"
  ]
}
```

---

## Platform Provenance Example (Real Output)

```json
{
  "folder_name": "HIP_TEST_20260221_103259",
  "platform": {
    "build_id": "modular-20260226_142414-2f3639c8",
    "output_hash": "8a4ca548b75187c3c92e3bd9b59f6e459b9a3ee9fd1b65a1271538c81f2fa9e6",
    "deterministic": true,
    "total_modules": 12
  },
  "modules": [
    { "module_id": "hip_admin",   "deterministic": true },
    { "module_id": "hip_billing", "deterministic": true },
    { "module_id": "hip_core",    "deterministic": true },
    "..."
  ]
}
```

---

## What This Proves

| Property | Evidence |
|----------|---------|
| **Not scaffolding** | 12 modules, 34 gates each, per-module cryptographic fingerprints |
| **Not pre-computed** | Deterministic seed changes with any input change; same inputs = same output |
| **Audit-grade** | G_SEAL refuses incomplete or failing builds; all evidence machine-verifiable |
| **Reproducible** | REPLAY.md contains exact commands + expected hashes for independent replay |

---

*This index describes publicly verifiable evidence. Compiler internals, IR schemas, and emitter source are proprietary.*

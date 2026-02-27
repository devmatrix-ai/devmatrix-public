# DevMatrix - Deterministic Evidence Pack

This repository contains **cryptographically verifiable proof**
that DevMatrix produces deterministic, replayable software systems.

This is not a demo.
This is evidence.

---

## Claim

**The same system specification, compiled multiple times,
produces byte-identical software.**

If this claim fails, DevMatrix is incorrect.

---

## What Is Included

This evidence pack contains:

- Real system specifications (input)
- Build fingerprints from independent compilation runs
- Deterministic hashes for specs, IR, and generated code
- Verification scripts and reproducibility spec

No trust is required.
Everything can be independently verified.

---

## Evidence Structure

```
fingerprints/
├── 20260221_modular_hip_test_..._a57210ff.json
├── 20260226_modular_hip_test_..._0d1cc2ed.json
├── 20260226_modular_hip_test_..._5ac138f8.json
├── 20260226_modular_hip_test_..._0fe80102.json
└── 20260227_modular_hip_test_..._0fe80102.json
examples/
├── build_fingerprint_example.json
├── platform_provenance_sealed.json
└── seal_manifest_example.json
verify_fingerprint.py
REPRODUCIBILITY_SPEC.md
```

Each fingerprint was produced from the **same input specification** for that run.

---

## Evidence Summary (This Repo)

The `fingerprints/` directory contains multiple independent compilation fingerprints from the HIP Healthcare Platform. The determinism check is the fact that compilations from the same specification produce byte-identical hashes across independent runs.

See [EVIDENCE_EN.md](EVIDENCE_EN.md) for complete platform-scale evidence.

---

## Verification

### Quick determinism check (recommended)

```bash
python verify_fingerprint.py \
  -f fingerprints/20260226_modular_hip_test_20260221_103259_0fe80102.json \
  --compare fingerprints/20260227_modular_hip_test_20260221_103259_0fe80102.json
```

**Expected result**: all compared hashes are `IDENTICAL`.

### What the script compares

The script compares:

- `spec_hash`
- `code_bundle_hash`
- `ir_canonical_hash`
- `ir_semantic_hash`
- `ir_structural_hash`

If any mismatch is found, determinism is broken.

---

## What This Proves

This evidence demonstrates that:

- Compilation is deterministic
- Decisions are replayable
- Governance invariants are enforced at compile time
- Outputs are verifiable and auditable

This is the minimum requirement for
trustworthy AI-generated systems.

---

## Important Note

If a system cannot be rebuilt exactly from the same input,
it cannot be reliably governed.

Documentation is not governance.
Runtime checks are not governance.

Compilation is.

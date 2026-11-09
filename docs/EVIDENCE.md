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
fingerprints/                     production evidence, signed by a production key
verify_fingerprint.py
keys.json
docs/REPRODUCIBILITY_SPEC.md
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
  -f fingerprints/5fc1882a-0d3e-4bf0-b6a5-c5ba69820e5f/5fc1882a-0d3e-4bf0-b6a5-c5ba69820e5f.json \
  --compare fingerprints/ae86be9a-cb25-4178-9bb1-39bc0aacd0d3/ae86be9a-cb25-4178-9bb1-39bc0aacd0d3.json
```

Two separate compiler runs of the same specification (different
`compiler_run_id` and `compile_attempt_id`), each signed with the production
key: both signatures verify and the five hashes both runs record are identical
(see [HOW_TO_VERIFY.md](../HOW_TO_VERIFY.md#verifying-the-signature)).

**Expected result**: both signatures verify and every compared hash is `IDENTICAL` (`Hashes compared by path: 5, identical: 5`).

### What the script compares

The script compares every hash the two fingerprints record, by its path in the
fingerprint: each field whose name ends in `_hash`, at any depth (for example
`spec_hash`, `code_bundle_hash`, `ir_semantic_hash`, `ir_structural_hash`,
`ir_hashes.spec_hash` or `modules.<module>.code_bundle_hash`, depending on the
fingerprint's schema version).

If any compared hash differs, determinism is broken. A hash recorded by only
one of the two fingerprints fails too, and so do two fingerprints that record
no hash at all: an absent hash is never reported as identical.

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

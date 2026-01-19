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
├── 20260110_flowdesk_spec_complete_a4846466.json
├── 20260110_crm_spec_complete_722342d9.json
├── 20260110_argencool_crm_722342d9.json
└── 20260110_healthcare_professional_advanc_956a1da0.json
examples/
└── build_fingerprint_example.json
verify_fingerprint.py
REPRODUCIBILITY_SPEC.md
```

Each fingerprint was produced from the **same input specification** for that run.

---

## Evidence Summary (This Repo)

| Spec | Fingerprint | `spec_hash` | `code_bundle_hash` | `ir_canonical_hash` |
|------|-------------|-------------|-------------------|---------------------|
| FLOWDESK | `fingerprints/20260110_flowdesk_spec_complete_a4846466.json` | `51852a112e025db9…` | `9a9d280d7be8b23a…` | `69aabad140e1eb21…` |
| ArgenCool CRM (run A) | `fingerprints/20260110_crm_spec_complete_722342d9.json` | `25ecacbfce72fead…` | `7ab063f6817728da…` | `44b6c92b8853011c…` |
| ArgenCool CRM (run B) | `fingerprints/20260110_argencool_crm_722342d9.json` | `25ecacbfce72fead…` | `7ab063f6817728da…` | `44b6c92b8853011c…` |
| MediCloud | `fingerprints/20260110_healthcare_professional_advanc_956a1da0.json` | `d6c0b58bdbb7e966…` | `78e98509a105e5e7…` | `4203fa99f3cf1871…` |

The determinism check is the fact that the ArgenCool CRM runs are byte-identical (same hashes across independent runs).

---

## Verification

### Quick determinism check (recommended)

```bash
python verify_fingerprint.py \
  -f fingerprints/20260110_crm_spec_complete_722342d9.json \
  --compare fingerprints/20260110_argencool_crm_722342d9.json
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

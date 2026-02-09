# How to Verify DevMatrix Builds

This document explains how to independently verify DevMatrix compilation evidence.

---

## Quick Verification

### Using the verification script (authoritative method)

> **The `verify_fingerprint.py` script is the canonical reference implementation.**
> Shell commands below are illustrative only. For guaranteed correctness, always use the Python script.

```bash
# Verify spec and output against fingerprint
python verify_fingerprint.py \
  --fingerprint build_fingerprint.json \
  --spec original_spec.md \
  --output generated/

# Compare two fingerprints (from different runs)
python verify_fingerprint.py \
  --fingerprint fingerprint1.json \
  --compare fingerprint2.json
```

### Manual spec_hash verification

```bash
# Linux
sha256sum original_spec.md

# macOS
shasum -a 256 original_spec.md

# Windows PowerShell
Get-FileHash -Algorithm SHA256 original_spec.md
```

The output must match `spec_hash` in the fingerprint.

**Note**: Manual verification of `code_bundle_hash` requires the script due to the canonical stream format. See [REPRODUCIBILITY_SPEC.md](REPRODUCIBILITY_SPEC.md) for the exact algorithm.

---

## Understanding the Fingerprint

Each DevMatrix compilation produces a `build_fingerprint.json`:

```json
{
  "build_id": "61c051e66e545856",
  "build_timestamp": "2026-01-05T01:42:53.428709+00:00",
  "spec_hash": "51852a112e025db90685dcc997ccadca99fc5bee...",
  "code_bundle_hash": "94dc63a1162c6516426b9de92d199582a82b1a43...",
  "ir_canonical_hash": "414ea2de3a0ebe2b651214778eaa33dac688f804...",
  "ir_semantic_hash": "5ca05d9cedcb90ef81c23faff5d858f6954166a2...",
  "ir_structural_hash": "ff44e5acc42d6ce0c7b745e53d6cd7a2f614ec90..."
}
```

### Hash Definitions

| Hash | What It Verifies |
|------|------------------|
| `spec_hash` | Input specification has not changed |
| `code_bundle_hash` | Generated code is byte-for-byte identical |
| `ir_canonical_hash` | Internal representation is identical |
| `ir_semantic_hash` | Captured semantics are identical |
| `ir_structural_hash` | System structure is identical |

**Important**: `build_timestamp` is for auditing only. It is NOT part of any hash calculation.

---

## Understanding the Platform Fingerprint

For platform-scale compilations (multiple modules sealed together), the provenance includes aggregate hashes:

```json
{
  "build_id": "532effc61fabcad3",
  "aggregate_ir_hash": "3a9925b169b54079...e3",
  "aggregate_output_hash": "bf22f63e7f794355...10",
  "deterministic_seed": "67dcbe6c565b7da7...f9",
  "total_modules": 12,
  "g_seal_passed": true
}
```

| Hash | What It Verifies |
|------|------------------|
| `aggregate_ir_hash` | Combined IR of all modules is identical |
| `aggregate_output_hash` | Combined generated code of all modules is identical |
| `deterministic_seed` | Full pipeline state (IR + output + versions) is identical |
| `build_id` | Derived from content hashes — same modules → same build_id |

See [SEALING.md](SEALING.md) for the sealing protocol and [REPRODUCIBILITY_SPEC.md](REPRODUCIBILITY_SPEC.md) for hash algorithms.

---

## Cross-Platform Support

The verification script (`verify_fingerprint.py`) works on:
- Linux
- macOS
- Windows

Requirements: Python 3.9+ with standard library only (no external dependencies).

**Recommendation**: The Python verifier is cross-platform and recommended on all operating systems, including Windows where shell-based hash verification differs from Unix systems.

### Platform-specific notes

| Platform | sha256 command | Script works? |
|----------|----------------|---------------|
| Linux | `sha256sum` | Yes |
| macOS | `shasum -a 256` | Yes |
| Windows | `Get-FileHash -Algorithm SHA256` | Yes |

---

## Falsification Tests

If DevMatrix is **non-deterministic**, one of these must occur:

| Test | Expected Failure |
|------|------------------|
| Same spec → different `spec_hash` | Hash algorithm broken |
| Same `spec_hash` → different `code_bundle_hash` | Transformation is stochastic |
| Same `spec_hash` → different `ir_canonical_hash` | IR construction varies |
| Repeated runs → different test results | Runtime leakage |

**Challenge**: Run the same spec through DevMatrix N times. If ANY hash differs, the determinism claim is false.

---

## Verification Script Usage

### Installation

No installation required. The script uses Python standard library only.

```bash
# Download
curl -O https://raw.githubusercontent.com/devmatrix-ai/devmatrix-public/main/verify_fingerprint.py

# Or clone the repository
git clone https://github.com/devmatrix-ai/devmatrix-public.git
```

### Commands

```bash
# Full verification against files
python verify_fingerprint.py -f build_fingerprint.json -s spec.md -o generated/

# Spec hash only
python verify_fingerprint.py -f build_fingerprint.json -s spec.md

# Code bundle hash only
python verify_fingerprint.py -f build_fingerprint.json -o generated/

# Compare two fingerprints (determinism test)
python verify_fingerprint.py -f fingerprint1.json --compare fingerprint2.json
```

### Expected output

```
============================================================
DevMatrix Build Fingerprint Verification
============================================================

Fingerprint: build_fingerprint.json
Build ID: 61c051e66e545856
Timestamp: 2026-01-05T01:42:53.428709+00:00

[OK] spec_hash matches: 51852a112e025db9...
[OK] code_bundle_hash matches: 94dc63a1162c6516...

============================================================
VERIFICATION PASSED
All hashes match. This build is reproducible.
```

---

## Access to Build Artifacts

Build fingerprints and specifications are available:

- **Public**: Example fingerprint in this repository (`examples/`)
- **Full access**: Contact author for supervised verification sessions (NDA required)

**Contact**: Ariel Eduardo Ghysels — [aeghysels@devmatrix.dev](mailto:aeghysels@devmatrix.dev) | [https://devmatrix.dev/](https://devmatrix.dev/) | [LinkedIn](https://www.linkedin.com/in/ariel-ghysels-52469198/) | [X @builddevmatrix](https://x.com/builddevmatrix)

---

## Platform Seal Verification

For platform-scale compilations, the sealing step produces platform-level provenance:

```bash
# Seal platform provenance (explicit governance step)
devmatrix seal -m manifest.yaml -o output/

# Verify idempotence
devmatrix seal -m manifest.yaml -o output/
# Run twice on identical modules → build_id and deterministic_seed must be identical

# Verify completeness enforcement
mv output/hip_core/build_fingerprint.json /tmp/
devmatrix seal -m manifest.yaml -o output/
# Expected: Seal refuses with specific missing module error
mv /tmp/build_fingerprint.json output/hip_core/

# Verify release governance
devmatrix seal -m manifest.yaml -o output/ --release
# Expected: Seal refuses if git working tree is dirty
```

**What seal validates (G_SEAL)**:

| Check | Failure Mode |
|-------|-------------|
| Completeness | Missing module → hard fail |
| Gate Results | Any module with failing gates → hard fail |
| Version Consistency | Pipeline version mismatch → fail (release) or warning |
| Git State | Dirty working tree → fail (release) or warning |

See [GOLDEN_PACK_INDEX.md](GOLDEN_PACK_INDEX.md) for the full 10-minute verification table.

---

## Technical Reference

For the exact hash algorithms and canonical formats, see:
- [REPRODUCIBILITY_SPEC.md](REPRODUCIBILITY_SPEC.md) - Canonical hash definitions
- [verify_fingerprint.py](verify_fingerprint.py) - Reference implementation (MIT licensed)

---

## Platform Builds

Platform builds follow the same verification principles as single-module builds.
Verification is performed against the sealed platform IR and its associated `build_id`.

For platform-scale evidence, the IR graph metrics (nodes, edges, cross-service
dependencies) are structural invariants that must remain identical across
re-executions with the same specification.

See [PLATFORM_VERIFICATION.md](PLATFORM_VERIFICATION.md) for the full verification model.

---

## Notes

- All hashes use SHA-256 (64 hexadecimal characters)
- Timestamps are for auditing only (not part of determinism)
- Build ID is derived from content hashes
- IR hashes prove semantic equivalence even if file order differs
- The script excludes `__pycache__/`, `node_modules/`, `.git/`, and `*.pyc` files

# How to Verify DevMatrix Builds

This document explains how to independently verify DevMatrix compilation evidence.

---

## Quick Verification

### Using the verification script (recommended)

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

## Cross-Platform Support

The verification script (`verify_fingerprint.py`) works on:
- Linux
- macOS
- Windows

Requirements: Python 3.9+ with standard library only (no external dependencies).

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
curl -O https://raw.githubusercontent.com/arielghysels/devmatrix-paper/main/verify_fingerprint.py

# Or clone the repository
git clone https://github.com/arielghysels/devmatrix-paper.git
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

**Contact**: Ariel Eduardo Ghysels

---

## Technical Reference

For the exact hash algorithms and canonical formats, see:
- [REPRODUCIBILITY_SPEC.md](REPRODUCIBILITY_SPEC.md) - Canonical hash definitions
- [verify_fingerprint.py](verify_fingerprint.py) - Reference implementation (MIT licensed)

---

## Notes

- All hashes use SHA-256 (64 hexadecimal characters)
- Timestamps are for auditing only (not part of determinism)
- Build ID is derived from content hashes
- IR hashes prove semantic equivalence even if file order differs
- The script excludes `__pycache__/`, `node_modules/`, `.git/`, and `*.pyc` files

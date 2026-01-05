# How to Verify DevMatrix Builds

This document explains how to independently verify DevMatrix compilation evidence.

---

## Quick Verification (3 Commands)

```bash
# 1. Read the build fingerprint
cat build_fingerprint.json | jq '.spec_hash, .code_bundle_hash'

# 2. Verify spec hash (SHA-256 of input specification)
sha256sum original_spec.md
# Output must match spec_hash in fingerprint

# 3. Verify code bundle hash (SHA-256 of generated code)
find generated/ -type f -exec sha256sum {} \; | sort | sha256sum
# Output must match code_bundle_hash in fingerprint
```

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

---

## Verification Script

Use the provided `verify_fingerprint.py`:

```bash
python verify_fingerprint.py \
  --fingerprint build_fingerprint.json \
  --spec original_spec.md \
  --output generated/
```

Expected output:
```
Verifying DevMatrix build fingerprint...

[OK] spec_hash matches: 51852a112e025db90685dcc997ccadca99fc5bee...
[OK] code_bundle_hash matches: 94dc63a1162c6516426b9de92d199582a82b1a43...

VERIFICATION PASSED
All hashes match. This build is reproducible.
```

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

## Supervised Verification

For independent verification with access to the full system:

**Contact**: Ariel Eduardo Ghysels
- Supervised compilation sessions available
- Access under NDA

---

## Example Verification Session

```bash
$ # Step 1: Obtain fingerprint from a published build
$ curl -O https://example.com/builds/flowdesk/build_fingerprint.json

$ # Step 2: Verify the spec hash
$ sha256sum flowdesk-spec.md
51852a112e025db90685dcc997ccadca99fc5bee...  flowdesk-spec.md
# MATCHES spec_hash in fingerprint ✓

$ # Step 3: If you have access to DevMatrix, recompile
$ devmatrix compile flowdesk-spec.md --output recompiled/

$ # Step 4: Compare fingerprints
$ diff build_fingerprint.json recompiled/build_fingerprint.json
# No output = identical = deterministic ✓
```

---

## Notes

- All hashes use SHA-256
- Timestamps are for auditing only (not part of determinism)
- Build ID is derived from content hashes
- IR hashes prove semantic equivalence even if file order differs

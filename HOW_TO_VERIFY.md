# How to Verify DevMatrix Builds

This document explains how to independently verify DevMatrix compilation evidence.

---

## Quick Verification

### Using the verification script (authoritative method)

> **The `verify_fingerprint.py` script is the canonical reference implementation.**
> Shell commands below are illustrative only. For guaranteed correctness, always use the Python script.

```bash
# Verify spec and output against the fingerprint of an unsigned build
python verify_fingerprint.py \
  --fingerprint build_fingerprint.json --allow-unsigned \
  --spec original_spec.md \
  --output generated/

# Compare two published evidence files: every hash both record, by path
# (their signatures are checked too)
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

**Note**: Manual verification of `code_bundle_hash` requires the script due to the canonical stream format. See [REPRODUCIBILITY_SPEC.md](docs/REPRODUCIBILITY_SPEC.md) for the exact algorithm.

---

## Verifying the Signature

Every evidence file in this repository carries a `signature` beside its `fingerprint`:

```json
"signature": {
  "algorithm": "Ed25519",
  "key_id": "dm-prod-2026-01",
  "public_key": "<base64, 32 bytes>",
  "signature": "<base64, 64 bytes>",
  "signed_at": "2026-10-06T13:03:14.317248+00:00",
  "signed_payload_hash": "sha256:<hex>"
}
```

What is signed is the `fingerprint` object serialized as JSON with sorted keys, no whitespace, UTF-8 (`json.dumps(fingerprint, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`). `signed_payload_hash` is the SHA-256 of those same bytes.

A public key inside the file proves nothing by itself: anyone can sign with their own key and paste it there. The keys DevMatrix signs with are published in [`keys.json`](keys.json), each with its `key_id`, `class` and validity window. `verify_fingerprint.py` runs the signature check on every file it reads, and passes only when all of these hold:

1. `signed_payload_hash` is the SHA-256 of the canonical fingerprint;
2. `key_id` and the inline `public_key` are one entry of `keys.json`;
3. `signed_at` falls inside that entry's window;
4. the Ed25519 signature verifies over the canonical fingerprint with that key;
5. the key's class is `production`.

```bash
python verify_fingerprint.py -f fingerprints/<evidence>.json --compare fingerprints/<evidence>.json
```

```
[OK] signature: Ed25519, key 'dm-prod-2026-01' (production), signed 2026-10-06T13:03:14.317248+00:00
```

A failed check prints a `[FAIL] signature: ...` line and the script exits non-zero.

Notes:

- **`signed_at` is claimed, not signed.** It sits beside the signature, outside the signed fingerprint. The window check catches evidence that names a time its key was not in use, but it cannot stop someone who holds a retired private key from signing new evidence and claiming a time inside that key's window. A retired key that leaked would have to be withdrawn from `keys.json`.
- **Where the keys come from.** `keys.json` lives in this repository with the evidence. Its `anchor` field says whether a key was also published somewhere independent of it; a key whose anchor is not independent prints a `[NOTE]`.
- **Production keys only.** `keys.json` lists production keys only. A signature by a key of any other class fails with `NOT a production key`, and no option accepts it.
- **Unsigned fingerprints.** A flat `build_fingerprint.json` carries no signature, and fails unless you pass `--allow-unsigned`; then only its hashes are checked.
- **Tests.** `python -m unittest discover -s tests` runs the checks on every evidence file in this repository, plus the tampering cases: a changed signature, payload, key, key id or time.

---

## Verifying a Published Attestation

A build's attestation is published to this repository's `attestations/` directory as a signed evidence file whose `fingerprint` is a **published attestation**: digests, counts, module identifiers and closed-set statuses only. `verify_fingerprint.py` checks its signature as above, and then checks the document against the closed schema it names in `schema`:

| Schema | Who ran the tests |
|--------|-------------------|
| `published-attestation/2` | `run_by` is `devmatrix` or `client`, and `seal_class` is `sealed` or `self_attested`. The only valid pairs are `devmatrix` with `sealed` (DevMatrix ran the tests) and `client` with `self_attested` (the client ran them on its own machine). |
| `published-attestation/1` | Not stated. A `/1` document carries neither key, and the verifier reports none. |

The check fails when:

- the schema is not one of these, is misspelled, or is missing from a document that states who ran the tests or a seal class;
- a key is missing or undeclared, at any level, except inside `identity` and `merkle.sub_roots`: those two are checked for form only, as non-empty bounded objects of sha256 digests under bounded lower-case names, not against a fixed list of names;
- a value is not of its declared form: a sha256 digest, a module identifier, a job identifier (a UUID), a bounded count or list, or one of a closed set;
- a module's determinism status is not `VERIFIED`, `NOT_VERIFIED` or `DRIFT`, or a cause appears with any status other than `NOT_VERIFIED`, or is missing on it (the cause is checked as a bounded lower-case name, not against a fixed list);
- in `/2`, the seal class does not go with who ran the tests.

```
[OK] signature: Ed25519, key 'dm-prod-2026-01' (production), signed ...
[OK] attestation: published-attestation/2; tests run by client, seal self_attested
```

A valid signature over a document that fails these checks still fails verification: the signature proves who published the document, and the schema check proves the document says only what this schema allows.

---

## Understanding the Fingerprint

Each DevMatrix compilation produces a `build_fingerprint.json`:

```json
{
  "build_id": "modular-20260226_142414-2f3639c8",
  "build_timestamp": "2026-02-26T17:26:34.130735+00:00",
  "spec_hash": "22ab4591608c37f10685dcc997ccadca99fc5bee...",
  "code_bundle_hash": "0fe801020d46e15f426b9de92d199582a82b1a43...",
  "ir_canonical_hash": "feffbdc9b4c8bba3b8ee197486c5abcded94ec10...",
  "ir_semantic_hash": "fb0eb96841b302cb5cd944556b1fc1df86057296...",
  "ir_structural_hash": "a87e6a4113d7ae8ba8678c7619b3eb8e318d68b9..."
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

For platform-scale compilations (multiple modules sealed together), the provenance includes aggregate hashes (key names illustrative):

```json
{
  "build_id": "modular-20260226_142414-2f3639c8",
  "aggregate_ir_hash": "3ee8b2589f7cf244...6f",
  "aggregate_output_hash": "8b99cc65c84f34d0...73",
  "deterministic_seed": "c441af276334fc00...32",
  "total_modules": 12,
  "seal_passed": true
}
```

| Hash | What It Verifies |
|------|------------------|
| `aggregate_ir_hash` | Combined IR of all modules is identical |
| `aggregate_output_hash` | Combined generated code of all modules is identical |
| `deterministic_seed` | Full pipeline state (IR + output + versions) is identical |
| `build_id` | Derived from content hashes — same modules → same build_id |

See [SEALING.md](docs/SEALING.md) for the sealing protocol and [REPRODUCIBILITY_SPEC.md](docs/REPRODUCIBILITY_SPEC.md) for hash algorithms.

---

## Cross-Platform Support

The verification script (`verify_fingerprint.py`) works on:
- Linux
- macOS
- Windows

Requirements: Python 3.9+. The hash checks use the standard library only; the signature check needs the `cryptography` package (`pip install cryptography`).

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

The hash checks need nothing beyond Python. The signature check needs `cryptography`; without it the script fails with `signature NOT verified`, it never skips the check.

```bash
pip install cryptography
```

```bash
# Clone the repository
git clone https://github.com/devmatrix-ai/devmatrix-public.git
```

### Commands

```bash
# Full verification against files
python verify_fingerprint.py -f build_fingerprint.json --allow-unsigned -s spec.md -o generated/

# Spec hash only
python verify_fingerprint.py -f build_fingerprint.json --allow-unsigned -s spec.md

# Code bundle hash only
python verify_fingerprint.py -f build_fingerprint.json --allow-unsigned -o generated/

# Compare two fingerprints (determinism test)
python verify_fingerprint.py -f fingerprint1.json --compare fingerprint2.json
# (flat, unsigned build_fingerprint.json files: add --allow-unsigned)
```

### Expected output

```
============================================================
DevMatrix Build Fingerprint Verification
============================================================

Fingerprint: build_fingerprint.json
Build ID: modular-20260226_142414-2f3639c8
Timestamp: 2026-02-26T17:26:34.130735+00:00

[WARN] UNSIGNED: signature not verified (--allow-unsigned); hashes only
[OK] spec_hash matches: 22ab4591608c37f1...
[OK] code_bundle_hash matches: 0fe801020d46e15f...

============================================================
VERIFICATION PASSED
Every check above passed.
```

---

## Access to Build Artifacts

Build fingerprints and specifications are available:

- **Public**: the production evidence in `fingerprints/`
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

**What the seal validates**:

| Check | Failure Mode |
|-------|-------------|
| Completeness | Missing module → hard fail |
| Quality Checks | Any module with a failing quality check → hard fail |
| Version Consistency | Compiler version mismatch → fail (release) or warning |
| Git State | Dirty working tree → fail (release) or warning |

See [GOLDEN_PACK_INDEX.md](docs/GOLDEN_PACK_INDEX.md) for the full 10-minute verification table.

---

## Technical Reference

For the exact hash algorithms and canonical formats, see:
- [REPRODUCIBILITY_SPEC.md](docs/REPRODUCIBILITY_SPEC.md) - Canonical hash definitions
- [verify_fingerprint.py](verify_fingerprint.py) - Reference implementation (MIT licensed)

---

## Platform Builds

Platform builds follow the same verification principles as single-module builds.
Verification is performed against the sealed platform IR and its associated `build_id`.

For platform-scale evidence, the graph metrics (cross-service foreign-key and HTTP
dependencies) are structural invariants that must remain identical across
re-executions with the same specification.

See [PLATFORM_VERIFICATION.md](docs/PLATFORM_VERIFICATION.md) for the full verification model.

---

## Notes

- All hashes use SHA-256 (64 hexadecimal characters)
- Timestamps are for auditing only (not part of determinism)
- Build ID is derived from content hashes
- IR hashes prove semantic equivalence even if file order differs
- The script excludes `__pycache__/`, `node_modules/`, `.git/`, and `*.pyc` files

# DevMatrix Reproducibility Specification

This document defines the canonical algorithms for cryptographic fingerprinting in DevMatrix builds.

---

## 1. Hash Algorithm

All hashes use **SHA-256** (256-bit output, 64 hexadecimal characters).

---

## 2. spec_hash

**Purpose**: Verify the input specification has not changed.

**Algorithm**:
```
spec_hash = SHA256(file_bytes)
```

**Input**: Raw bytes of the specification file (UTF-8 encoded markdown).

**Canonical form**: No normalization. Byte-for-byte hash of the file as stored.

---

## 3. code_bundle_hash

**Purpose**: Verify the generated code is byte-for-byte identical.

**Algorithm**:
```python
def code_bundle_hash(directory: Path) -> str:
    sha256 = hashlib.sha256()

    # 1. List all files recursively
    files = list(directory.rglob("*"))

    # 2. Filter to files only (exclude directories)
    files = [f for f in files if f.is_file()]

    # 3. Sort lexicographically by relative path (Unix-style separators)
    files = sorted(files, key=lambda f: str(f.relative_to(directory)).replace("\\", "/"))

    # 4. For each file, hash: relative_path + newline + file_hash + newline
    for filepath in files:
        rel_path = str(filepath.relative_to(directory)).replace("\\", "/")
        file_hash = sha256_file(filepath)

        sha256.update(rel_path.encode("utf-8"))
        sha256.update(b"\n")
        sha256.update(file_hash.encode("utf-8"))
        sha256.update(b"\n")

    return sha256.hexdigest()
```

**Canonical stream format**:
```
<relative_path_1>\n<sha256_of_file_1>\n<relative_path_2>\n<sha256_of_file_2>\n...
```

**Critical details**:
- Paths use Unix-style separators (`/`) regardless of OS
- Paths are relative to the output directory root
- Files are sorted lexicographically by path
- Each entry is delimited by newline (`\n`, 0x0A)
- Empty directories are ignored
- Hidden files (starting with `.`) are included

**Excluded from hash**:
- `__pycache__/` directories
- `node_modules/` directories
- `.git/` directories
- `*.pyc` files
- Build timestamps embedded in files (DevMatrix does not embed these)

---

## 4. IR Hashes

### 4.1 ir_canonical_hash

**Purpose**: Verify the internal representation is identical.

**Algorithm**: SHA-256 of the canonical JSON serialization of the IR.

**Canonical JSON rules**:
- Keys sorted alphabetically at all levels
- No whitespace (compact format)
- UTF-8 encoding
- Numbers without trailing zeros
- Null values included explicitly

### 4.2 ir_semantic_hash

**Purpose**: Verify semantic content regardless of structural variations.

**Algorithm**: SHA-256 of semantic-normalized IR (order-independent for collections).

### 4.3 ir_structural_hash

**Purpose**: Verify system structure (entities, relationships, endpoints).

**Algorithm**: SHA-256 of structural elements only (excludes implementation details).

---

## 5. build_fingerprint.json Schema

```json
{
  "build_id": "string (16 hex chars, derived from content hashes)",
  "build_timestamp": "string (ISO 8601 with timezone)",
  "spec_hash": "string (64 hex chars)",
  "code_bundle_hash": "string (64 hex chars)",
  "ir_canonical_hash": "string (64 hex chars)",
  "ir_semantic_hash": "string (64 hex chars)",
  "ir_structural_hash": "string (64 hex chars)"
}
```

**Note**: `build_timestamp` is for auditing only and is NOT part of any hash calculation. Same inputs at different times produce identical hashes.

---

## 6. Verification Process

### Using the verification script (recommended)

```bash
python verify_fingerprint.py \
  --fingerprint build_fingerprint.json \
  --spec original_spec.md \
  --output generated/
```

### Manual verification (cross-platform)

**Step 1: Verify spec_hash**
```bash
# Linux/macOS
sha256sum original_spec.md

# macOS alternative
shasum -a 256 original_spec.md

# Windows PowerShell
Get-FileHash -Algorithm SHA256 original_spec.md
```

**Step 2: Verify code_bundle_hash**

Due to the canonical stream format, manual verification requires the script. The script is the reference implementation.

---

## 7. Determinism Guarantees

If DevMatrix is deterministic, then:

| Property | Guarantee |
|----------|-----------|
| `spec_hash(A) = spec_hash(B)` | Specifications A and B are byte-identical |
| `code_bundle_hash(A) = code_bundle_hash(B)` | Generated code A and B are byte-identical |
| `ir_canonical_hash(A) = ir_canonical_hash(B)` | Internal representations are identical |

**Contrapositive (falsification)**:
- Different `code_bundle_hash` from same `spec_hash` → non-deterministic transformation
- Different `ir_canonical_hash` from same `spec_hash` → non-deterministic IR construction

---

## 8. Security Considerations

### What this scheme verifies
- Byte-level reproducibility of generated code
- Semantic equivalence of internal representations
- Input specification integrity

### What this scheme does NOT verify
- Correctness of the generated code (covered by tests)
- Security of the generated code (covered by security tests)
- Runtime behavior equivalence (covered by behavioral tests)
- Absence of malicious modifications to DevMatrix itself

### Threat model assumptions
- The verifier has access to the original specification
- The verifier can run the verification script
- SHA-256 is collision-resistant (standard cryptographic assumption)
- The verification script has not been tampered with (verify via code review)

---

## 9. Reference Implementation

The canonical implementation is `verify_fingerprint.py` in this repository, licensed under MIT for unrestricted use.

---

## 10. Platform Seal Hashes

For platform-scale compilations (multiple modules sealed together), aggregate hashes are computed as follows:

### 10.1 Aggregate IR Hash

```
aggregate_ir_hash = SHA256(sorted per-module ir_structural_hash values, concatenated)
```

All `ir_structural_hash` values from individual module fingerprints are sorted lexicographically and concatenated into a single string, then hashed with SHA-256.

### 10.2 Aggregate Output Hash

```
aggregate_output_hash = SHA256(sorted per-module code_bundle_hash values, concatenated)
```

Same algorithm as aggregate IR hash, applied to `code_bundle_hash` values.

### 10.3 Deterministic Seed

```
deterministic_seed = SHA256(aggregate_ir_hash | aggregate_output_hash | pipeline_version | python_version)
```

The pipe (`|`) represents string concatenation. The deterministic seed captures the full pipeline state.

### 10.4 Platform Build ID

```
build_id = SHA256(aggregate_ir_hash[:16] + aggregate_output_hash[:16])[:16]
```

The build ID is a 16-character hex string derived from the first 16 characters of each aggregate hash.

### 10.5 Timestamp Exclusion

Timestamps appear only in metadata fields (`build_timestamp`, `seal_timestamp`). They are **never** included in hash inputs. Same modules at different times produce identical hashes.

---

*Version 2.0 | February 2026*

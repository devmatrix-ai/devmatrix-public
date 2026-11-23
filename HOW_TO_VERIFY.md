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

A public key inside the file proves nothing by itself: anyone can sign with their own key and paste it there. The keys DevMatrix signs with are published in [`keys.json`](keys.json), a `devmatrix-keys/1` document: each key has a `kid` (the SHA-256 of its public key), its `key_id`, `purpose`, `class`, `status` and validity window (`created_at` to `expires_at`). One `key_id` once named two keys, so a key is found by its `key_id` and its public key together. `verify_fingerprint.py` runs the signature check on every file it reads, and passes only when all of these hold:

1. `signed_payload_hash` is the SHA-256 of the canonical fingerprint;
2. `key_id` and the inline `public_key` are one entry of `keys.json`, an `evidence-signing` key that is not `revoked`;
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
- **Where the keys come from.** `keys.json` lives in this repository with the evidence. DevMatrix also publishes every key it signs with, without sign-in, at <https://devmatrix.dev/.well-known/devmatrix-keys.json>, in the same format; compare the key the verifier names with the one listed there. A `retired` key still verifies what it signed inside its window; a `revoked` key never verifies.
- **Refreshing `keys.json`.** `python refresh_keys.py --check` reads the published document and says whether `keys.json` is a copy of it; without `--check` it writes the copy. It reads over https only, verifying the certificate, through no proxy, within one deadline for the whole read and a size limit, and refuses a redirect. It refuses a document whose `kid` is not the SHA-256 of its public key, a key that is not a production Ed25519 key, a purpose (`evidence-signing`, `seal-signing`) with other than one `active` key, and any change that drops a key `keys.json` lists, rewrites one, moves a status back, changes an `expires_at` once set, or changes a `status_since` without a forward status move (or to an earlier date): a retired key still verifies what it signed, so no key is ever removed and no window is reopened or widened, and a key that leaked can still be revoked. `keys.json` is replaced in one step. `--from <file>` reads a saved copy instead.
- **Production keys only.** `keys.json` lists production keys only. A signature by a key of any other class fails with `NOT a production key`, and no option accepts it.
- **A keys file holds one class of key.** A file that mixes classes is refused. A file whose keys are not production keys must add a `label` (a short name that claims neither production nor a pass); without one it is refused by name. Evidence that verifies against such a file ends with `<label> — not a production attestation` and exit code 3, never `VERIFICATION PASSED` and never 0: a keys file anyone can write can never produce a pass. A production keys file carries no label.
- **Unsigned fingerprints.** A flat `build_fingerprint.json` carries no signature, and fails unless you pass `--allow-unsigned`; then only its hashes are checked.
- **Tests.** `python -m unittest discover -s tests` runs the checks on every evidence file in this repository, plus the tampering cases: a changed signature, payload, key, key id or time.

---

## Verifying a Published Attestation

A build's attestation is published to this repository's `attestations/` directory as a signed evidence file whose `fingerprint` is a **published attestation**: digests, counts, module identifiers and closed-set statuses only. `verify_fingerprint.py` checks its signature as above, and then checks the document against the closed schema it names in `schema`:

| Schema | Who ran the tests |
|--------|-------------------|
| `published-attestation/3` | As in `/2`. `/3` also states the build's spec identity: `identity.platform_spec_hash` (the SHA-256 of the platform source), `identity.service_spec_hashes` (each module's source hash) and `identity.service_spec_hashes_sha256`, the digest of that map, which the verifier recomputes. Its `attestation_sha256` is the SHA-256 of the delivered attestation file's bytes, the digest a seal signs. |
| `published-attestation/2` | `run_by` is `devmatrix` or `client`, and `seal_class` is `sealed` or `self_attested`. The only valid pairs are `devmatrix` with `sealed` (DevMatrix ran the tests) and `client` with `self_attested` (the client ran them on its own machine). |
| `published-attestation/1` | Not stated. A `/1` document carries neither key, and the verifier reports none. |

The check fails when:

- the schema is not one of these, is misspelled, or is missing from a document that states who ran the tests or a seal class;
- a key is missing or undeclared, at any level. In `/1` and `/2`, `identity` and `merkle.sub_roots` are checked for form only, as non-empty bounded objects of sha256 digests under bounded lower-case names; in `/3` both are closed sets of names;
- a value is not of its declared form: a sha256 digest, a module identifier, a job identifier (a UUID), a bounded count or list, or one of a closed set;
- a module's determinism status is not `VERIFIED`, `NOT_VERIFIED` or `DRIFT`, or a cause appears with any status other than `NOT_VERIFIED`, or is missing on it (in `/1` and `/2` the cause is checked as a bounded lower-case name; in `/3` it is one of `not_measured_yet`, `gate_did_not_run`, `no_baseline`, `in_build_unmeasured`, `gate_row_absent_from_ledger`);
- in `/2` and `/3`, the seal class does not go with who ran the tests;
- in `/3`, the module map is not the one `service_spec_hashes_sha256` names.

```
[OK] signature: Ed25519, key 'dm-prod-2026-01' (production), signed ...
[OK] attestation: published-attestation/2; tests run by client, seal self_attested
```

A valid signature over a document that fails these checks still fails verification: the signature proves who published the document, and the schema check proves the document says only what this schema allows.

---

## Binding Your Download to the Seal and the Published Attestation

A build's download carries its fingerprint attestation, `verification/<run>/fingerprint_attestation.json`. A platform seal signs that file's SHA-256 for each service, and the published attestation states the same SHA-256 as `attestation_sha256`. One command checks that the three name one build:

```
python verify_fingerprint.py --seal <unzipped seal bundle> \
  --attestation <service>=<download>/verification/<run>/fingerprint_attestation.json \
  --published attestations/<job>.json
```

It passes only when all of these hold:

1. the seal statement's signature verifies with the key `keys.json` publishes for the statement's `key_id` as a production `seal-signing` key whose window holds `sealed_at`; the key inside the bundle proves nothing by itself;
2. the published attestation's signature verifies as above, and it is a `published-attestation/3` document (`/1` and `/2` state the digest of another serialization, so they cannot be bound to the file);
3. the SHA-256 of the delivered file is the `document_sha256` the seal signed for the service, and the published `attestation_sha256`;
4. the file's `reproducible_sha256` is the digest of its reproducible block, and the seal and the published attestation state the same one;
5. the file's platform spec hash and its hash for the service are the seal's `platform.spec_hash` and the service's `spec_hash`;
6. who ran the tests, read from the file's platform verdict, is who the seal says measured the build: `devmatrix` with a seal measured by `devmatrix`, `client` with a `self_attested` one. A `seal-statement/2` does not state who measured the build, so it is refused, with what to do: re-seal the platform (a new seal is `seal-statement/3` or later) and verify the new seal;
7. from `seal-statement/5` on, every service of the seal states the lowest grade it was sealed at (`seal_floor`, which is `A`), a grade at it or above (DevMatrix's, or the client's when the client ran the tests) and every test that failed, by name, each once and in order; for a build the client tested, those are exactly the tests that did not pass. The grade and each failed test are printed;
7b. from `seal-statement/6` on, every service also states its tests not judged: each by name, once and in order, none of them also failed, and their total (`not_judged_count`) is those names plus every tier the run did not reach, by its count. A grade of A+ beside a test not judged fails. A build the client tested states its own count in its grade (`listed_not_judged`) and names as many; when its grade was given before that count existed the count is null, and the seal prints «This seal does not state how many tests were not judged.», never 0, names none, and bears no A+. A statement of a version the verifier does not know fails;
7c. from `seal-statement/7` on, every service also states the build it seals (`compilation_id`), what its grade rests on (`basis`: `compile`, `qa_run` for a QA run on DevMatrix, or `client_run`) and its tests proven not applicable. `compile` and `qa_run` are measured by `devmatrix`, `client_run` is `self_attested`; one seal never mixes them, and a self-attested seal is one build: a mixture fails. A `qa_run` service names its run (`qa_run`: id, attempt, report version and SHA-256, when it finished, its letter, score and counts, and the emitted suite's failed tests); every other basis names none. The count of tests proven not applicable (`proven_not_applicable_count`) names as many tests, each `<module>::<test>`, with the digest of the proof rows (`proof_rows_sha256`) and of the tests each module collected (`collected_node_ids_sha256`). It is null only where the measurement predates proofs (a `qa-run-report/1`, or a client run), and the seal then prints «This seal does not state its tests proven not applicable.» and bears no A+. A build sealed on its compile states none. These are checked on the signed statement, after its signature: a failure says the signed statement is refused by its content. A `qa_run` service states its fingerprint attestation like every other and binds the same way: its build was delivered with its tests deferred to the QA run (`NOT_RUN`, `runtime_phase_deferred_to_qa_run`), read as tests deferred to a QA run. From `seal-statement/7` who ran the tests is checked against the basis: `compile` with `devmatrix`; `qa_run` with deferred; `client_run` with `client`, or deferred when a build awaiting its QA run was run by the client instead. Anything else fails, and a deferred build sealed by an earlier statement fails. No published attestation version states a deferred build, so `--published` with such a build fails with what to do (bind it without `--published`);
8. the published attestation is exactly what the file is published as: every field is recomputed from the file (its digest, identity, Merkle commitment, modules, determinism, gate verdict, counts, coverage, certificate, who ran the tests and the seal class that goes with them) and compared, and every field that differs is named.

Every check that can run does: the `[OK]` lines say what was verified and the `[FAIL]` lines what was not. A published `published-attestation/1` or `/2` is refused with what to do (republish the build's attestation, which is published as `/3`), and the file is still bound to the seal.

`--evidence <folder>` checks the seal's evidence bundle (unzipped) against a `seal-statement/7`: the QA run report each `qa_run` service rests on (`qa-runs/<compilation_id>/report.json`: its SHA-256 is `report_sha256`, and its run, attempt, build, outcome, grade, score, counts, the number of modules it measured, failed tests, emitted suite failures, tests not run and finish time are the seal's; from `qa-run-report/2` its modules' collected digests and proof rows are the seal's) and each service's proof rows (`proofs/<compilation_id>.json`: its SHA-256 is `proof_rows_sha256`, written in the seal's serialization, each row once in order, the witnessed rows exactly the tests proven not applicable and every other one named not judged). The manifest must name exactly the files held, by digest and size, and be of this seal. The folder is untrusted: a link (file or folder) is refused and never followed, a name an evidence bundle never holds is refused, a report or proof file is at most 4 MiB, any other file at most 1 MiB, and the whole at most 1 MiB plus 8 MiB per sealed service. Each check is named in an `[OK]` or `[FAIL]` line. Without `--evidence`, a `seal-statement/7` service that rests on a QA run or states proofs prints `[NOT CHECKED] … QA run report and proof rows not checked: no evidence given (--evidence)`.

`--verdict-json <file>` writes the verdict of the binding as JSON besides the printed one: `verdict` (`VERIFIED` exactly when no check failed), `reason_classes` (the sorted classes of the failed checks, one per failure) and `key_class` (the class of the keys it was reached with; a verdict reached with keys that are not production keys is never a production attestation, whatever it says). The printed verdict and the exit status are the same with or without it.

`--published` is optional: without it, the file is bound to the seal alone. Name several `--attestation` options to bind every service of a seal; a published attestation is one build's, so it goes with exactly one.

### A published platform seal

`python verify_fingerprint.py -f platform-seals/<seal>.json` verifies the publication signature of a published platform seal and the closed schema it names. `published-platform-seal/1` is the record of a `seal-statement/3` or `/4` seal; `published-platform-seal/2` is the record of a `seal-statement/5` seal, where every service states the floor it was sealed at (`seal_floor`), its grade at or above it, and how many of its tests failed (`failed`; for a build the client tested, every test that did not pass). `published-platform-seal/3` is the record of a `seal-statement/6` seal: as `/2`, and every service states how many of its tests were not judged (`not_judged`); the signed statement names them. A null count is printed as «This seal does not state how many tests were not judged.», never 0, and a grade of A+ beside a count above 0 or null fails. `published-platform-seal/4` is the record of a `seal-statement/7` seal: as `/3`, and every service states what its grade rests on (`basis`) and how many of its tests were proven not applicable (`proven_not_applicable`, or null: «This seal does not state its tests proven not applicable.»); a basis its measurer does not measure, a count beside `compile`, an A+ beside a null count, or a self-attested record of more than one build fails. The record carries no platform or service name. The seal key it names must be a `seal-signing` key `keys.json` publishes, whose window holds `sealed_at`. A holder of the seal statement checks that its SHA-256 is the record's `statement_sha256`.

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

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
key: both signatures verify and every value both runs record is identical, except
when each run happened and its own identifiers
(see [HOW_TO_VERIFY.md](../HOW_TO_VERIFY.md#verifying-the-signature)).

**Expected result**: both signatures verify and every compared value is identical (`Compared by the build fingerprint (no schema named) table: 22 values, identical: 22`).

### What the script compares

The script compares the two documents by a table declared for their schema.
Every field the schema carries is compared at any depth, lists included: a
published attestation's modules are matched by name and each module's
emission digest is compared, and the leaves of its Merkle commitment are
compared in order, since their order is part of the commitment. The only
fields not compared are the ones that name the run itself: when it happened,
its job and its own identifiers, the signature over a delivered attestation,
and a published attestation's `attestation_sha256` (the digest of the whole
delivered file, which carries the job). Each is printed as `[--] <path>: not
compared (<reason>)`. A delivered `fingerprint-attestation/2` is compared by
its own table. Of the paths it lists as not covered, only the spec copy a run
files under its job (`specification/<job_id>/<module>`) is read without that
job; every other path is compared as written, and a path listed twice counts
twice.

If any compared value differs, the two builds are not the same and the
difference is named by its path. A value recorded by only one of the two
documents fails, a field the table does not name fails, two documents of
different schemas fail, a schema with no table fails with `update the
verifier`, and comparing no value at all fails: nothing is compared in part,
and an absent value is never reported as identical.

Two builds are compared only as a determinism pair: they must share their
identity inputs (the specification, the compiler toolchain and, from
`published-attestation/4` and `fingerprint-attestation/3` on, the runtime
key). Otherwise the comparison is refused with `not a determinism pair`,
naming every input that differs. The language the build emitted for and the modules it emitted are
part of the reproducible identity: two builds that reproduced state the
same ones. The digest of a delivered `/3`'s build inputs record names the
build's own job and is not compared. Whether two builds reproduced is decided by
their reproducible block alone (identity, Merkle commitment, modules and its
digest), printed as its own `determinism` line. The fields a run attests
(determinism statuses, gate verdict, counts, who ran the tests) may depend on
the build's history. From `/4` and `/3` on, each document states its
`regression_baseline`, the input its regression gate ruled against, with the
SHA-256 of that input (`digest`). The gate verdict is compared only when both
documents state the same digest; otherwise it is listed as `not comparable:
the builds ruled against different baselines`, and the builds are still a
determinism pair. The rest of the attested fields are compared. Documents of
earlier versions state no baseline: their attested fields are compared, and
when only those differ the output says the documents predate the regression
baseline, so the difference is not evidence of a determinism break.

A delivered attestation checked with `-f` is checked against its own table and
its own signature: the SHA-256 of its JSON (keys sorted, default separators)
without its signature, without the fields that say when or in which run it
was made, and without the sections that record the build's history
(`convergence_metrics`, `convergence_curve`, `convergence_narrative`,
`convergence_proof`, `learning_impact`, `learning_snapshot`,
`build_identity`), at any depth, signed with Ed25519 by a published production `evidence-signing`
key. Compared with `--compare`, the comparison decides the verdict, and each
document's signature is stated apart: an unsigned one is compared only with
`--allow-unsigned` (without it the run fails, naming it), and one that is
unsigned or does not verify is printed as `[NOTE] ... NOT verified`, never as verified, and the verdict line
then reads `COMPARISON PASSED (N of M delivered attestations NOT verified)`,
not `VERIFICATION PASSED`.

Earlier versions of the verifier compared only the fields whose name ends
in `_hash` outside lists: on a published attestation, its identity hashes and
its gate verdict hash. An `identical` from such a verifier does not cover the
per-module emission digests or the Merkle commitment.

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

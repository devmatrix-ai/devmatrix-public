# Changelog

## 2026-11-09 — Repository reorganised

- The repository history was restarted. The previous history is preserved
  under the tag `legacy/main-2026-11-09`, so every link that pins an earlier
  commit keeps resolving.
- `fingerprints/` holds production evidence only, and `keys.json` lists
  production keys only. The signed evidence that remains is unchanged.
- The paper, the evidence write-up, the reproducibility specification and the
  sealing protocol moved to `docs/`.
- Added `SECURITY.md`, `CONTRIBUTING.md` and a read-only workflow that runs the
  tests and verifies every production evidence file on each push.

## Verifier

- **`--compare` compares every field of the schema, lists included.** Two
  documents are compared by a table declared for their schema: every field is
  compared or named as not compared with its reason (only when the run
  happened, its job and its own identifiers, the signature over a delivered
  attestation, and `attestation_sha256`, the digest of the whole delivered
  file, which carries the job), modules are matched by name,
  the Merkle leaves in order, and every difference is named by its path. The
  delivered `fingerprint-attestation/2` has its own table. A
  field the table does not know, two schemas, a schema with no table (`update
  the verifier`) or nothing compared fails. Earlier versions compared only
  the fields whose name ends in `_hash` outside lists — on a published
  attestation, the identity hashes and the gate verdict hash, 5 to 6 fields —
  so an `identical` from an earlier verifier did not cover each module's
  emission digest nor the Merkle commitment.
- **A comparison is of a determinism pair.** Two builds whose specification,
  toolchain or (from `/4` and `/3` on) runtime differ are refused with `not a
  determinism pair`, naming every input that differs. Whether they reproduced
  is decided by the reproducible block alone, printed as its own
  `determinism` line. The fields a run attests are compared only when both
  documents ran from the same determinism reference state; otherwise they are
  listed as not comparable. Documents that state no reference state predate
  it: when only their attested fields differ, the output says so, and that
  this is not evidence of a determinism break.
- **`published-attestation/4` and `fingerprint-attestation/3`.** Both state
  the runtime key the build ran for and its determinism reference state
  (`absent`, `candidate`, `promoted`). A delivered `/3` is published as `/4`
  and binds to its seal as `/2` did to `/3`.
- **A delivered attestation is checked by its own signature.** With `-f`, a
  `fingerprint-attestation/2` or `/3` is checked against its closed table, its
  reproducible digest and its Ed25519 signature by a published production
  `evidence-signing` key; it was refused as an unknown attestation schema.
  With `--compare`, the comparison decides and each document's signature is
  stated apart; an unsigned one is compared only with `--allow-unsigned`
  and is said to be unsigned.
- **Python 3.10.** The guide said 3.9; the verifier has needed 3.10 since its
  type annotations were written.

- **A self-attested seal-statement/4 states its share.** Each service its
  client tested states a whole share from 1 to 100%, counts that hold, enough
  tests passed to meet that share, and every test that did not pass named once,
  in order; a seal below its share fails.
- **`refresh_keys.py` names itself.** It asks for the published keys as
  `devmatrix-refresh-keys`, not the default Python client name the server
  refuses; a 401 or 403 now says the server refused this client and to save
  the document with a browser and run with `--from`.
- **Proof rows that are not the rows the seal states fail as proofs.** Once
  the proof rows file matches its digest, a file that is not JSON, not in the
  seal's serialization, or not sorted distinct rows fails with the proofs
  class, as the bundled verifier reads it.
- **A QA run report or proof rows file may be up to 8 MiB** (it was 4 MiB):
  the proof rows name each row's module, so they can outgrow their report.
- **Origin is checked against the keys this repository ships.** With no
  `--keys`, only the keys in `keys.json` are trusted, and a seal whose key it
  does not publish is not verified; `--keys` stays as an override. A seal
  bundle's own `verify.py` is a quick integrity check, not a check of origin.
- **Shared seal vectors.** `conformance/seal-verifier-vectors/` holds signed
  seals with their downloads and evidence, each with the verdict, reason
  classes and key class the bundled verifier gives it; the set's digest is
  pinned and this verifier must give every vector the same verdict. A vector
  the bundled verifier runs without a keys file is run here with the keys
  this repository ships, and must be refused on its key, never verified.
- **Evidence and seal keys, as the bundled verifier reads them.** Proofs the
  seal states that the proof rows do not show fail as proofs; a manifest entry
  that is not a file named by its path, or a file the manifest does not name
  (other than the manifest, verify.py and VERIFY.md), is refused evidence; a
  seal sealed at or after its key retired (status_since) is refused, as is a
  retired seal key that states no retirement instant.
- **A QA run report's modules state the tests they collected.** Each module
  of a qa-run-report/2 emitted suite states its collected test ids, strictly
  ordered or null, and their digest (the JSON array sorted by code point, no
  whitespace, UTF-8); a digest that is not theirs fails as tampered evidence.
- **A seal-statement/4 states who measured it coherently.** What DevMatrix
  measured states its score, and each such service its grade and no client
  grade; what the client measured states no DevMatrix score or grade, and each
  such service exactly the fields of its client grade and at least one run.
- **The verdict as a file, by reason class.** `--verdict-json <file>` (with
  `--seal`) also writes `{"verdict": "VERIFIED" | "FAILED", "reason_classes":
  [...], "key_class": ...}`: every failed check names one class (signature,
  key, unknown_version, statement_version, basis_measurer, mixture, runner,
  qa_run_binding, proofs, grade_floor, not_judged, evidence_tampered,
  evidence_refused, evidence_absent, attestation_digest, attestation_identity,
  published_deferred), so two verifiers can be compared over the same signed
  seals by verdict and class, never by wording. It is additive: the printed
  verdict and the exit status do not change. The file says FAILED from the
  start of a run until its verdict is reached, so a run that stops early never
  leaves an earlier verdict there. A delivered or published attestation nested
  too deep, which stopped with a traceback, and a seal key file that is not a
  public key, are now refused by name.
- **A seal states what its grade rests on.** `seal-statement/7` is read:
  every sealed service names its build, rests on its compile, a QA run on
  DevMatrix (named by its run and its report's SHA-256) or the client's run,
  and states its tests proven not applicable, or prints «This seal does not
  state its tests proven not applicable.» A seal that mixes builds measured by
  DevMatrix with self-attested ones, or is self-attested over more than one
  build, fails. `--evidence` checks the seal's evidence bundle: the QA run
  report and the proof rows against the digests and the grade the seal signed.
  The folder is read as untrusted (no link followed, only known names, each
  bounded). Without it, what was not checked is printed. A build sealed on a
  QA run binds to its delivered attestation, which states its tests deferred
  to that run, and a client-run seal may rest on such a build when the client
  ran it instead; who ran the tests is checked against what the grade rests on. `published-platform-seal/4`
  carries each service's basis and its count of tests proven not applicable.
  `seal-statement/2` to `/6` and `published-platform-seal/1` to `/3` are read
  as before.
- **A seal that states its tests not judged verifies.** `seal-statement/6`
  is read: every sealed service names its tests not judged and counts them
  with every tier the run did not reach; a grade of A+ beside one fails. A
  grade given before that count existed states none, and the seal says «This
  seal does not state how many tests were not judged.», never 0, with no A+.
  `published-platform-seal/3`, its public record, carries the count only (the
  signed statement names the tests). `seal-statement/2` to `/5` and
  `published-platform-seal/1` and `/2` are read as before.
- **A build awaiting its QA run is read as not sealable.** A published
  fingerprint may state `completed_awaiting_qa`; a passed seal beside it fails.
- **A seal taken at the grade floor verifies.** `seal-statement/5` is read:
  every sealed service states the lowest grade it was sealed at (`A`), a grade
  at it or above and every failed test by name, and each is printed. A grade
  below the floor, a floor other than `A`, or failed tests not named once and
  in order (for a build the client tested, not exactly the tests that did not
  pass) fail. `seal-statement/2` to `/4` are read as before.
- **A published platform seal is checked against its closed schema.**
  `published-platform-seal/1` (the record of a `seal-statement/3` or `/4`
  seal) and `published-platform-seal/2` (of a `seal-statement/5` seal: floor,
  grade at or above it, failed count) are verified with `-f`; the seal key
  each names must be a published `seal-signing` key. Before, such a record was
  refused as an unknown attestation schema.
- **A published fingerprint is checked against its one schema.**
  `published-fingerprint/2` is verified against its closed set of keys and
  carries no `code_bundle_hash` (the delivered code is sealed per module in the
  export manifest). `published-fingerprint/1` was never published and is
  refused by name; any other fingerprint schema is refused as unknown. Before,
  a published fingerprint was refused as an unknown attestation schema.
- **Every value of a published fingerprint is of its declared form.** An
  outcome is `true`, `false` or `null` (a `"yes"` fails), a digest is a sha256
  hex digest, a closed set is closed, and the nested objects (Merkle
  commitment, determinism, seal, customer checks, complexity) carry exactly
  their declared keys, each of its declared form.
- **`keys.json` is refreshed from the published keys by one command.**
  `refresh_keys.py` reads the `devmatrix-keys/1` document DevMatrix publishes
  (https, certificate verified, no redirect), checks it with the verifier's own
  reader, and writes it unchanged only when it can replace `keys.json`: every
  key production Ed25519, one active key per purpose, and no key dropped,
  rewritten or moved back in status. `--check` reports drift without writing.
- **The published attestation is the delivered file's, and its runner the
  seal's.** With `--published`, the published attestation must be exactly what
  the delivered file is published as: every field is recomputed and each one
  that differs is named. Who ran the tests, read from the file, must be who the
  seal says measured the build; a `seal-statement/2` states no measurer and is
  refused with what to do (re-seal). Every check runs and the output says what
  was and was not verified; a published `/1` or `/2` is refused with what to do
  (republish), and the file is still bound to the seal.
- **One build, three documents.** `--seal <bundle> --attestation <service>=<file>
  [--published <file>]` binds a download's fingerprint attestation to the
  platform seal and the published attestation: the file's SHA-256 is the one
  the seal signed and the published `attestation_sha256`, the reproducible
  digest is one value in all three, and the file names the specs the seal
  names. The seal key must be a production `seal-signing` key in `keys.json`.
- **`published-attestation/3`.** States the platform's and each module's spec
  hash, with the module map's digest recomputed; named Merkle sub-roots and
  NOT_VERIFIED causes are closed sets. Its `attestation_sha256` is the digest
  of the delivered file's bytes. `/1` and `/2` still verify.
- **Published attestations.** A signed document that names an attestation
  schema is checked against that closed schema. `published-attestation/2`
  states who ran the build's tests (`run_by`) and the seal class
  (`seal_class`); only `devmatrix` with `sealed` and `client` with
  `self_attested` are accepted. `published-attestation/1` states neither, and
  none is inferred. An unknown or misspelled schema fails.
- **Signatures.** Every evidence file's Ed25519 signature is checked against
  `keys.json`: the key id and the inline key must be one published entry, the
  claimed signing time must fall inside that key's window, and the key must be
  a production key. A key of any other class is refused, and no option
  accepts it.
- **Comparison by path** (replaced: see the first entry, on `--compare`).
  `--compare` compared every hash field at any depth of the two signed
  fingerprints outside lists. A hash recorded by one side only failed, and two
  fingerprints that recorded no hash failed.
- An unsigned flat fingerprint fails unless `--allow-unsigned` is passed.
  Without the `cryptography` package the signature check fails; it is never
  skipped.

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

- **A self-attested seal-statement/4 states its share.** Each service its
  client tested states a whole share from 1 to 100%, counts that hold, enough
  tests passed to meet that share, and every test that did not pass named once,
  in order; a seal below its share fails.
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
- **Comparison by path.** `--compare` compares every hash field at any depth of
  the two signed fingerprints. A hash recorded by one side only fails, and two
  fingerprints that record no hash fail.
- An unsigned flat fingerprint fails unless `--allow-unsigned` is passed.
  Without the `cryptography` package the signature check fails; it is never
  skipped.

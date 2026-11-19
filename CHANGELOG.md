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

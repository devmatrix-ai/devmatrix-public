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

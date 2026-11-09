# Security

## Reporting a problem

Report privately to [aeghysels@devmatrix.dev](mailto:aeghysels@devmatrix.dev),
not in a public issue, when you find:

- a way to make `verify_fingerprint.py` pass a file that was forged, altered,
  or signed by a key that is not a published production key;
- a reason to believe a DevMatrix signing key was exposed;
- evidence in this repository that does not verify.

Include the command, the full output and, if you can, the file that shows it.
You will get an acknowledgement, and a fix or a withdrawal of the affected key
or evidence is published here and recorded in [CHANGELOG.md](CHANGELOG.md).

## What the verifier relies on

- **The keys in `keys.json`.** They live in this repository with the evidence.
  Each key's `anchor` says whether it was also published somewhere independent
  of this repository; until it is, a passing check shows that the evidence
  matches the keys published here, not that the keys are DevMatrix's. Compare
  `keys.json` with the keys DevMatrix publishes elsewhere before you rely on it.
- **The signing time is claimed, not signed.** `signed_at` sits outside the
  signed payload. A key's validity window bounds the time a signature may
  claim; it does not protect against a retired private key that leaked. A key
  known to be exposed is removed from `keys.json` and its evidence withdrawn.
- **The `cryptography` package.** Without it the signature check fails; it is
  never skipped. Install it from a source you trust.

## Supported versions

Only the verifier on the default branch is maintained.

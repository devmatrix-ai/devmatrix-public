<div align="center">

<img src="assets/logo-readme.png" alt="DevMatrix" width="320" />

# DevMatrix — public evidence

**Define the system. DevMatrix compiles it. Check the build yourself.**

[Website](https://devmatrix.dev) ·
[How it works](https://devmatrix.dev/docs/pipeline) ·
[DMX reference](https://devmatrix.dev/docs/dmx-reference) ·
[Builds](https://devmatrix.dev/builds) ·
[Pricing](https://devmatrix.dev/pricing) ·
[Request beta access](https://devmatrix.dev/request-beta)

</div>

---

## What this repository is

[DevMatrix](https://devmatrix.dev) is a compiler for complete systems: a
specification goes in, and production code, tests, migrations, infrastructure
and evidence come out. The same specification compiles to the same artifacts,
every run. If that cannot be guaranteed, the build fails.

This repository holds the **evidence** DevMatrix publishes about its builds,
and the **tool to check it** without trusting DevMatrix:

- signed build fingerprints and attestations, in [`fingerprints/`](fingerprints);
- the public keys that sign them, in [`keys.json`](keys.json);
- the verifier, [`verify_fingerprint.py`](verify_fingerprint.py) (MIT), and its tests.

The compiler itself is proprietary and is not here.

---

## Verify a build in 3 steps

You need Python 3.10 or later and a clone of this repository.

**1. Install the one dependency** (it checks the Ed25519 signatures):

```bash
pip install cryptography
```

**2. Pick an evidence file.** Each file in `fingerprints/` is one build,
signed by a DevMatrix production key. These two are two separate runs of the
compiler on the same specification:

```
fingerprints/5fc1882a-0d3e-4bf0-b6a5-c5ba69820e5f/5fc1882a-0d3e-4bf0-b6a5-c5ba69820e5f.json
fingerprints/ae86be9a-cb25-4178-9bb1-39bc0aacd0d3/ae86be9a-cb25-4178-9bb1-39bc0aacd0d3.json
```

**3. Run the verifier:**

```bash
python verify_fingerprint.py \
  -f fingerprints/5fc1882a-0d3e-4bf0-b6a5-c5ba69820e5f/5fc1882a-0d3e-4bf0-b6a5-c5ba69820e5f.json \
  --compare fingerprints/ae86be9a-cb25-4178-9bb1-39bc0aacd0d3/ae86be9a-cb25-4178-9bb1-39bc0aacd0d3.json
```

It ends with `VERIFICATION PASSED` and exit code 0 only when both signatures
verify against a production key in `keys.json` and every hash the two builds
record is identical:

```
[OK] signature: Ed25519, key 'dm-prod-2026-01' (production), signed 2026-10-06T13:03:14.317248+00:00
...
Hashes compared by path: 5, identical: 5
[OK] code_bundle_hash: IDENTICAL (e94b30ea389c9658...)
...
VERIFICATION PASSED
```

Anything it cannot prove prints `[FAIL]` and exits non-zero; nothing is
skipped. To check a single file, leave out `--compare`. The full guide,
including attestations and every failure case, is
[HOW_TO_VERIFY.md](HOW_TO_VERIFY.md).

---

## What a passing check proves, and what it does not

**It proves:**

- the evidence file was signed by the key published in `keys.json` under its
  `key_id`, and has not been changed since;
- the key is a **production** key, and the time the signature claims falls
  inside that key's validity window;
- with `--compare`, that the two builds recorded the same hash for every field
  either of them records (a hash recorded by one build only fails).

**It does not prove:**

- that the keys are DevMatrix's beyond this repository: `keys.json` lives here
  with the evidence, and each key's `anchor` says whether it was also published
  somewhere else. A key that was not prints a `[NOTE]`;
- the signing time: `signed_at` is claimed by the signer and is not covered by
  the signature;
- anything about code you cannot see: the hashes are compared, the generated
  code is not published here.

---

## Keys

| Key | Class | Status |
|-----|-------|--------|
| `dm-prod-2026-01` (`iKkD…`) | production | current |
| `dm-prod-2026-01` (`d3K5…`) | production | retired, window closed |

Only evidence signed by a production key is accepted. A signature by a key of
any other class is refused, and no option accepts it.

---

## Repository layout

```
README.md                  this page
HOW_TO_VERIFY.md           the full verification guide
verify_fingerprint.py      the verifier (MIT)
keys.json                  the public signing keys
tests/                     the verifier's tests, run on every evidence file
fingerprints/              production evidence only
docs/                      the technical paper, the evidence write-up, the
                           reproducibility specification and the sealing protocol
assets/                    the logo
```

Run the tests from the repository root:

```bash
python -m unittest discover -s tests
```

They check every evidence file in the repository against `keys.json`, and that
`fingerprints/` holds production evidence only.

---

## Read more

| Document | What it covers |
|----------|----------------|
| [HOW_TO_VERIFY.md](HOW_TO_VERIFY.md) | Every check the verifier runs, and how to run it |
| [docs/PAPER_EN.md](docs/PAPER_EN.md) · [ES](docs/PAPER.md) | Technical paper |
| [docs/EVIDENCE_EN.md](docs/EVIDENCE_EN.md) · [ES](docs/EVIDENCE.md) | The evidence, platform by platform |
| [docs/REPRODUCIBILITY_SPEC.md](docs/REPRODUCIBILITY_SPEC.md) | How each hash is computed |
| [docs/SEALING.md](docs/SEALING.md) | How a platform build is sealed |
| [docs/PLATFORM_VERIFICATION.md](docs/PLATFORM_VERIFICATION.md) | Verifying a multi-module platform |
| [docs/GOLDEN_PACK_INDEX.md](docs/GOLDEN_PACK_INDEX.md) | The evidence in ten minutes |
| [CHANGELOG.md](CHANGELOG.md) | What changed in this repository |
| [SECURITY.md](SECURITY.md) | Reporting a problem with the verifier, a key or the evidence |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to report a verification result |

---

## License and citation

- Documentation: CC BY 4.0. Verifier: MIT. See [LICENSE](LICENSE).
- The DevMatrix compiler is proprietary and is not included. US patent pending;
  EU registration filed.
- To cite this work, see [CITATION.cff](CITATION.cff).

**Contact:** Ariel Eduardo Ghysels — [aeghysels@devmatrix.dev](mailto:aeghysels@devmatrix.dev) ·
[devmatrix.dev](https://devmatrix.dev) ·
[LinkedIn](https://www.linkedin.com/in/ariel-ghysels-52469198/) ·
[X @builddevmatrix](https://x.com/builddevmatrix)

DevMatrix™ is not affiliated with any other product, service or entity named
"DevMatrix". The canonical domain is [devmatrix.dev](https://devmatrix.dev).

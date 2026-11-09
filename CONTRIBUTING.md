# Contributing

This repository publishes evidence and the tool that checks it. The evidence
files are signed by DevMatrix: they are not edited, and pull requests that
change them cannot be accepted, because any change breaks their signature.

## What helps

- **A verification result that disagrees with the documentation.** Open an
  issue with the command you ran, the full output, your Python version and
  your `cryptography` version.
- **A case the verifier accepts and should not, or refuses and should not.**
  Open an issue with a minimal evidence file that shows it. If it is a way to
  make a forged or altered file pass, do not open a public issue: follow
  [SECURITY.md](SECURITY.md).
- **Corrections to the documentation** in `README.md`, `HOW_TO_VERIFY.md` or
  `docs/`.

## Changing the verifier

Changes to `verify_fingerprint.py` come with tests in `tests/` that fail
without the change. Run the suite from the repository root before opening a
pull request:

```bash
pip install cryptography
python -m unittest discover -s tests
```

The verifier stays dependency-light (the standard library plus
`cryptography`) and fails, never skips, on anything it cannot prove.

## License

By contributing you agree that documentation changes are licensed under
CC BY 4.0 and changes to the verifier under MIT, as described in
[LICENSE](LICENSE).

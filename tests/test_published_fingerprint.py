"""A published fingerprint is verified against the one schema ever published.

``published-fingerprint/2`` is the public projection of a build's fingerprint
record. It carries no ``code_bundle_hash``: the delivered code never reproduced
it, and each module's delivered code is sealed in the export manifest instead.
``published-fingerprint/1`` was never published, so it is refused by name and
nothing reads it; every other schema is refused as unknown.

Run from the repository root: python -m unittest discover -s tests
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import verify_fingerprint as vf  # noqa: E402
from test_published_attestation import _KEYS, _signed  # noqa: E402


def _fingerprint() -> dict:
    return {
        "schema": "published-fingerprint/2",
        "source_record_digest": "b" * 64,
        "build_id": "build-1",
        "job_id": "0b2f6c55-7f9e-4c1a-9a63-1f0a7e2c4d11",
        "spec_hash": "c" * 64,
        "compile_status": "succeeded",
        "merkle_root": {"root_hash": "d" * 64, "leaf_count": 3},
        "determinism": {"deterministic": True},
        "passed": True,
        "seal": {"passed": True},
    }


class AValidFingerprint(unittest.TestCase):
    def test_v2_without_the_code_bundle_hash(self) -> None:
        self.assertEqual(vf.check_published_fingerprint(_fingerprint()), ["[OK] fingerprint: published-fingerprint/2"])

    def test_v2_with_only_its_required_keys(self) -> None:
        minimal = {"schema": "published-fingerprint/2", "source_record_digest": "b" * 64}
        self.assertEqual(vf.check_published_fingerprint(minimal), ["[OK] fingerprint: published-fingerprint/2"])


class ARefusedFingerprint(unittest.TestCase):
    def _refused(self, document: dict, reason: str) -> None:
        with self.assertRaises(vf.AttestationRefused) as refused:
            vf.check_published_fingerprint(document)
        self.assertIn(reason, str(refused.exception))

    def test_v1_is_refused_as_never_published(self) -> None:
        document = dict(_fingerprint(), schema="published-fingerprint/1", code_bundle_hash="e" * 64)
        self._refused(document, "'published-fingerprint/1' was never published")

    def test_v2_that_carries_the_code_bundle_hash(self) -> None:
        self._refused(dict(_fingerprint(), code_bundle_hash="e" * 64), "carries no code_bundle_hash")

    def test_an_unknown_fingerprint_schema(self) -> None:
        self._refused(dict(_fingerprint(), schema="published-fingerprint/3"), "unknown fingerprint schema")

    def test_an_undeclared_key(self) -> None:
        self._refused(dict(_fingerprint(), source_code="x"), "undeclared keys ['source_code']")

    def test_a_missing_source_record_digest(self) -> None:
        document = _fingerprint()
        del document["source_record_digest"]
        self._refused(document, "lacks ['source_record_digest']")

    def test_a_source_record_digest_that_is_not_a_digest(self) -> None:
        self._refused(dict(_fingerprint(), source_record_digest="sha256:" + "b" * 64), "is not a sha256 digest")


class TheCommandLine(unittest.TestCase):
    def _run(self, payload: dict) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmp:
            keys = Path(tmp) / "keys.json"
            keys.write_text(json.dumps({"schema_id": vf.KEYS_SCHEMA_ID, "keys": _KEYS}), encoding="utf-8")
            evidence = Path(tmp) / "fingerprint.json"
            evidence.write_text(json.dumps(_signed(payload)), encoding="utf-8")
            command = [sys.executable, str(ROOT / "verify_fingerprint.py"), "-f", str(evidence),
                       "--keys", str(keys)]
            return subprocess.run(command, capture_output=True, text=True, check=False)

    def test_a_signed_v2_passes_as_a_fingerprint_not_an_attestation(self) -> None:
        result = self._run(_fingerprint())
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("[OK] fingerprint: published-fingerprint/2", result.stdout)
        self.assertNotIn("attestation schema", result.stdout)

    def test_a_signed_v1_fails_although_its_signature_verifies(self) -> None:
        result = self._run(dict(_fingerprint(), schema="published-fingerprint/1", code_bundle_hash="e" * 64))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("[OK] signature", result.stdout)
        self.assertIn("was never published", result.stdout)


if __name__ == "__main__":
    unittest.main()

"""A published attestation is verified against the closed schema it names.

``published-attestation/2`` states who ran the build's tests and the seal
class, and only the pairs devmatrix/sealed and client/self_attested are
valid. ``published-attestation/1`` states neither, and none is read into it.
Every other schema fails, and so does a document that is not exactly its schema.

The documents here are built in the test and signed with a key made for the
test, so keys.json is not touched.

Run from the repository root: python -m unittest discover -s tests
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import verify_fingerprint as vf  # noqa: E402

_DIGEST = "sha256:" + "a" * 64
_KEY = Ed25519PrivateKey.generate()
_PUBLIC = base64.b64encode(
    _KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
).decode()
_KEY_ID = "test-key"
_KEYS = [{
    "key_id": _KEY_ID,
    "algorithm": "Ed25519",
    "public_key": _PUBLIC,
    "class": "production",
    "valid_from": "2026-01-01T00:00:00+00:00",
    "valid_until": None,
    "anchor": "independent: made for this test",
}]


def _attestation_v1() -> dict:
    return {
        "schema": "published-attestation/1",
        "job_id": "0b2f6c55-7f9e-4c1a-9a63-1f0a7e2c4d11",
        "attestation_sha256": _DIGEST,
        "reproducible_sha256": _DIGEST,
        "identity": {"spec_hash": _DIGEST, "other_link": _DIGEST},
        "merkle": {
            "nested_root": _DIGEST,
            "sub_roots": {"root_a": _DIGEST, "root_b": _DIGEST},
            "emit_root": _DIGEST,
            "emit_leaf_sha256": [_DIGEST, _DIGEST],
        },
        "modules": [{"module": "orders", "emission_sha256": _DIGEST}],
        "determinism": [
            {"module": "orders", "status": "VERIFIED"},
            {"module": "billing", "status": "NOT_VERIFIED", "cause": "some_cause"},
        ],
        "terminal_gate_verdict_hash": _DIGEST,
        "not_tested_count": 0,
        "coverage": {"delivered_files": 10, "covered": 10},
        "certificate_fingerprint": _DIGEST,
    }


def _attestation_v2(run_by: str = "devmatrix", seal_class: str = "sealed") -> dict:
    return dict(_attestation_v1(), schema="published-attestation/2", run_by=run_by, seal_class=seal_class)


def _signed(payload: dict) -> dict:
    canonical = vf.canonical_payload(payload)
    return {
        "evidence_version": "1.0.0",
        "fingerprint": payload,
        "published_at": "2026-11-09T10:00:00+00:00",
        "signature": {
            "algorithm": "Ed25519",
            "key_id": _KEY_ID,
            "public_key": _PUBLIC,
            "signature": base64.b64encode(_KEY.sign(canonical)).decode(),
            "signed_at": "2026-11-09T10:00:00+00:00",
            "signed_payload_hash": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        },
    }


class AValidAttestation(unittest.TestCase):
    def test_v2_tested_by_devmatrix_and_sealed(self) -> None:
        lines = vf.check_published_attestation(_attestation_v2("devmatrix", "sealed"))
        self.assertIn("tests run by devmatrix, seal sealed", lines[0])

    def test_v2_tested_by_the_client_and_self_attested(self) -> None:
        lines = vf.check_published_attestation(_attestation_v2("client", "self_attested"))
        self.assertIn("tests run by client, seal self_attested", lines[0])

    def test_v1_states_no_runner_and_none_is_read_into_it(self) -> None:
        lines = vf.check_published_attestation(_attestation_v1())
        self.assertIn("who ran the tests is not stated", lines[0])
        self.assertNotIn("sealed", " ".join(lines))

    def test_its_signature_verifies(self) -> None:
        passed, lines = vf.verify_signature(_signed(_attestation_v2()), _KEYS)
        self.assertTrue(passed, lines)


class ARefusedAttestation(unittest.TestCase):
    def _refused(self, document: dict, reason: str) -> None:
        with self.assertRaises(vf.AttestationRefused) as raised:
            vf.check_published_attestation(document)
        self.assertIn(reason, str(raised.exception))

    def test_tests_run_by_the_client_published_as_sealed(self) -> None:
        self._refused(_attestation_v2("client", "sealed"), "does not go with tests run by 'client'")

    def test_tests_run_by_devmatrix_published_as_self_attested(self) -> None:
        self._refused(_attestation_v2("devmatrix", "self_attested"), "does not go with tests run by 'devmatrix'")

    def test_v2_without_who_ran_the_tests(self) -> None:
        document = _attestation_v2()
        del document["run_by"]
        self._refused(document, "lacks ['run_by']")

    def test_v1_that_states_a_runner(self) -> None:
        document = dict(_attestation_v1(), run_by="devmatrix", seal_class="sealed")
        self._refused(document, "undeclared keys ['run_by', 'seal_class']")

    def test_an_unknown_runner_or_seal_class(self) -> None:
        self._refused(_attestation_v2("someone", "sealed"), "attestation.run_by")
        self._refused(_attestation_v2("devmatrix", "gold"), "attestation.seal_class")

    def test_an_unknown_schema(self) -> None:
        self._refused(dict(_attestation_v2(), schema="published-attestation/3"), "unknown attestation schema")

    def test_an_undeclared_key_at_any_level(self) -> None:
        self._refused(dict(_attestation_v2(), source_code="x"), "undeclared keys ['source_code']")
        document = _attestation_v2()
        document["coverage"]["paths"] = ["src/app.py"]
        self._refused(document, "attestation.coverage: carries undeclared keys ['paths']")

    def test_a_value_that_is_not_a_digest(self) -> None:
        document = _attestation_v2()
        document["merkle"]["emit_leaf_sha256"][1] = "src/app.py"
        self._refused(document, "emit_leaf_sha256[1]: is not a sha256 digest")

    def test_a_count_that_is_not_a_count(self) -> None:
        self._refused(dict(_attestation_v2(), not_tested_count=True), "not_tested_count: is not a count")
        self._refused(dict(_attestation_v2(), not_tested_count=-1), "not_tested_count: is not a count")

    def test_named_digests_that_are_empty_or_misnamed(self) -> None:
        self._refused(dict(_attestation_v2(), identity={}), "identity: is not a bounded object of digests")
        self._refused(dict(_attestation_v2(), identity={"Spec Hash": _DIGEST}), "is not a digest name")

    def test_a_determinism_status_outside_its_set(self) -> None:
        document = _attestation_v2()
        document["determinism"][0]["status"] = "PROBABLY"
        self._refused(document, "determinism[0].status")

    def test_a_cause_without_not_verified_and_not_verified_without_cause(self) -> None:
        document = _attestation_v2()
        document["determinism"][0]["cause"] = "some_cause"
        self._refused(document, "a cause goes with NOT_VERIFIED and only with it")
        document = _attestation_v2()
        del document["determinism"][1]["cause"]
        self._refused(document, "a cause goes with NOT_VERIFIED and only with it")

    def test_a_cause_that_is_not_a_bounded_name(self) -> None:
        document = _attestation_v2()
        document["determinism"][1]["cause"] = "x" * 200
        self._refused(document, "determinism[1].cause")


class TheCommandLine(unittest.TestCase):
    def _run(
        self, payload: dict, compare: bool = True, compare_with: dict | None = None,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmp:
            keys = Path(tmp) / "keys.json"
            keys.write_text(json.dumps({"keys": _KEYS}), encoding="utf-8")
            evidence = Path(tmp) / "attestation.json"
            evidence.write_text(json.dumps(_signed(payload)), encoding="utf-8")
            command = [sys.executable, str(ROOT / "verify_fingerprint.py"), "-f", str(evidence),
                       "--keys", str(keys)]
            if compare_with is not None:
                other = Path(tmp) / "other.json"
                other.write_text(json.dumps(_signed(compare_with)), encoding="utf-8")
                command += ["--compare", str(other)]
            elif compare:
                command += ["--compare", str(evidence)]
            return subprocess.run(command, capture_output=True, text=True, check=False)

    def test_a_signed_v2_passes_and_says_who_ran_the_tests(self) -> None:
        result = self._run(_attestation_v2("client", "self_attested"))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("tests run by client, seal self_attested", result.stdout)

    def test_a_signed_crossed_pair_fails_although_its_signature_verifies(self) -> None:
        result = self._run(_attestation_v2("client", "sealed"))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("[OK] signature", result.stdout)
        self.assertIn("[FAIL] attestation.seal_class", result.stdout)

    def test_the_checked_file_alone_is_checked(self) -> None:
        refused = self._run(_attestation_v2("client", "sealed"), compare=False)
        self.assertNotEqual(refused.returncode, 0, refused.stdout)
        self.assertIn("[FAIL] attestation.seal_class", refused.stdout)
        valid = self._run(_attestation_v2("client", "self_attested"), compare=False)
        self.assertEqual(valid.returncode, 0, valid.stdout)
        self.assertIn("tests run by client", valid.stdout)

    def test_the_compared_file_is_checked_too(self) -> None:
        result = self._run(
            _attestation_v2("client", "self_attested"), compare_with=_attestation_v2("client", "sealed")
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("tests run by client, seal self_attested", result.stdout)
        self.assertIn("[FAIL] attestation.seal_class", result.stdout)

    def test_a_misspelled_or_missing_schema_is_checked_not_skipped(self) -> None:
        for payload in (
            dict(_attestation_v2(), schema="Published-Attestation/2"),
            {k: v for k, v in _attestation_v2().items() if k != "schema"},
            dict(_attestation_v2(), schema=2),
        ):
            with self.subTest(schema=payload.get("schema")):
                result = self._run(payload)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("unknown attestation schema", result.stdout)

    def test_a_signed_unknown_schema_fails(self) -> None:
        result = self._run(dict(_attestation_v2(), schema="published-attestation/9"))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("unknown attestation schema", result.stdout)


if __name__ == "__main__":
    unittest.main()

"""A published platform seal is verified against the closed schema it names.

``published-platform-seal/1`` is the record of a ``seal-statement/3`` or
``/4`` seal. ``published-platform-seal/2`` is the record of a
``seal-statement/5`` seal: every service is graded A or better, states the
grade floor it was sealed at and how many of its tests failed. Either way the
seal key it names has to be a seal-signing key keys.json publishes.

The documents and keys are made in the test, so keys.json is not touched.

Run from the repository root: python -m unittest discover -s tests
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib
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
vf = importlib.import_module("verify_fingerprint")

_SEAL_KEY = Ed25519PrivateKey.generate()
_EVIDENCE_KEY = Ed25519PrivateKey.generate()


def _raw_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def _key(key: Ed25519PrivateKey, key_id: str, purpose: str) -> dict:
    public = _raw_b64(key)
    return {
        "kid": "sha256:" + hashlib.sha256(base64.b64decode(public)).hexdigest(),
        "key_id": key_id,
        "purpose": purpose,
        "class": "production",
        "algorithm": "Ed25519",
        "public_key": public,
        "status": "active",
        "status_since": None,
        "created_at": "2026-01-01T00:00:00+00:00",
        "expires_at": None,
    }


def _keys() -> list[dict]:
    return [_key(_SEAL_KEY, "seal-test", "seal-signing"), _key(_EVIDENCE_KEY, "evidence-test", "evidence-signing")]


def _hex(char: str) -> str:
    return char * 64


def _service(index: int) -> dict:
    return {
        "spec_hash": _hex(str(index)),
        "spec_version": 3,
        "verification": "devmatrix",
        "qa_score_hundredths": 9800,
        "grade": "A",
        "self_attested_grade": None,
        "seal_floor": "A",
        "failed": 2,
        "build_fingerprint": "sha256:" + _hex("b"),
        "merkle_root": "sha256:" + _hex("c"),
        "evidence_content_hash": "sha256:" + _hex("d"),
        "evidence_key_id": "evidence-test",
        "fingerprint_attestation": {
            "document_sha256": "sha256:" + _hex("e"),
            "reproducible_sha256": "sha256:" + _hex("f"),
        },
    }


def _record_v2() -> dict:
    """A published-platform-seal/2, measured by DevMatrix."""
    return {
        "schema": "published-platform-seal/2",
        "seal_hash": _hex("1"),
        "sealed_at": "2026-11-19T10:00:00Z",
        "statement_schema_id": "seal-statement/5",
        "statement_sha256": _hex("2"),
        "seal_signature": {"algorithm": "Ed25519", "key_id": "seal-test", "signature_b64": "c2lnbmF0dXJl"},
        "seal_public_key": {"key_id": "seal-test", "public_key_b64": _raw_b64(_SEAL_KEY)},
        "platform": {"spec_hash": _hex("3"), "spec_version": 4, "verification": "devmatrix",
                     "qa_score_hundredths": 9800},
        "services": [_service(4), _service(5)],
        "run_by": "devmatrix",
        "seal_class": "sealed",
    }


def _by_the_client(record: dict) -> dict:
    """The same record, of a platform its client tested: 10 applicable tests."""
    record["platform"].update(verification="self_attested", qa_score_hundredths=None)
    for service in record["services"]:
        service.update(
            verification="self_attested", qa_score_hundredths=None, grade=None,
            self_attested_grade={
                "letter": "A", "score_percent": 90, "passed": 8, "applicable": 10,
                "listed_not_emitted": 0, "listed_declared_skips": 0,
            },
        )
    record.update(run_by="client", seal_class="self_attested")
    return record


def _record_v1() -> dict:
    """A published-platform-seal/1 of a seal-statement/4 its client tested."""
    record = _by_the_client(_record_v2())
    record.update(schema="published-platform-seal/1", statement_schema_id="seal-statement/4")
    for service in record["services"]:
        del service["seal_floor"], service["failed"]
        service["self_attested_grade"].update(letter="B", failed=2, required_percent=80)
    return record


def _signed(payload: dict) -> dict:
    canonical = vf.canonical_payload(payload)
    return {
        "evidence_version": "1.0.0",
        "fingerprint": payload,
        "published_at": "2026-11-19T11:00:00+00:00",
        "signature": {
            "algorithm": "Ed25519",
            "key_id": "evidence-test",
            "public_key": _raw_b64(_EVIDENCE_KEY),
            "signature": base64.b64encode(_EVIDENCE_KEY.sign(canonical)).decode(),
            "signed_at": "2026-11-19T11:00:00+00:00",
            "signed_payload_hash": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        },
    }


class APublishedPlatformSeal(unittest.TestCase):
    def _refused(self, record: dict, reason: str, keys: list[dict] | None = None) -> None:
        with self.assertRaises(vf.AttestationRefused) as raised:
            vf.check_published_platform_seal(record, _keys() if keys is None else keys)
        self.assertIn(reason, str(raised.exception))

    def test_a_record_of_a_seal_at_the_grade_floor(self) -> None:
        lines = vf.check_published_platform_seal(_record_v2(), _keys())
        self.assertIn("published-platform-seal/2 of a seal-statement/5; tests run by devmatrix, seal sealed", lines[0])
        self.assertIn("seal key 'seal-test' (production), sealed 2026-11-19T10:00:00Z", lines[1])
        self.assertIn("services[0] graded A, sealed at grade A or better, 2 failed test(s)", lines[2])
        self.assertEqual(len(lines), 4)

    def test_a_record_of_a_platform_its_client_tested(self) -> None:
        lines = vf.check_published_platform_seal(_by_the_client(_record_v2()), _keys())
        self.assertIn("tests run by client, seal self_attested", lines[0])

    def test_a_record_of_an_earlier_seal_is_read_as_published(self) -> None:
        lines = vf.check_published_platform_seal(_record_v1(), _keys())
        self.assertIn("published-platform-seal/1 of a seal-statement/4", lines[0])

    def test_a_grade_below_the_floor(self) -> None:
        record = _record_v2()
        record["services"][1]["grade"] = "B"
        self._refused(record, "platform seal.services[1].grade: is not one of its declared values")

    def test_a_client_grade_below_the_floor(self) -> None:
        record = _by_the_client(_record_v2())
        record["services"][0]["self_attested_grade"]["letter"] = "D"
        self._refused(record, "services[0].self_attested_grade.letter: is not one of its declared values")

    def test_a_floor_other_than_a(self) -> None:
        record = _record_v2()
        record["services"][0]["seal_floor"] = "C"
        self._refused(record, "platform seal.services[0].seal_floor: is not one of its declared values")

    def test_a_record_published_from_another_statement(self) -> None:
        record = _record_v2()
        record["statement_schema_id"] = "seal-statement/4"
        self._refused(record, "platform seal.statement_schema_id: is not one of its declared values")
        earlier = _record_v1()
        earlier["statement_schema_id"] = "seal-statement/5"
        self._refused(earlier, "platform seal.statement_schema_id: is not one of its declared values")

    def test_a_failed_count_that_is_not_every_test_that_did_not_pass(self) -> None:
        record = _by_the_client(_record_v2())
        record["services"][0]["failed"] = 1
        self._refused(record, "platform seal.services[0].failed: is not every test that did not pass")

    def test_a_floor_in_an_earlier_record(self) -> None:
        record = _record_v1()
        record["services"][0]["seal_floor"] = "A"
        self._refused(record, "platform seal.services[0]: carries undeclared keys ['seal_floor']")

    def test_a_record_without_its_failed_count(self) -> None:
        record = _record_v2()
        del record["services"][0]["failed"]
        self._refused(record, "platform seal.services[0]: lacks ['failed']")

    def test_a_record_that_names_a_platform(self) -> None:
        record = _record_v2()
        record["platform"]["name"] = "shop"
        self._refused(record, "platform seal.platform: carries undeclared keys ['name']")

    def test_a_seal_class_that_does_not_go_with_the_runner(self) -> None:
        record = _record_v2()
        record["seal_class"] = "self_attested"
        self._refused(record, "does not go with tests run by 'devmatrix'")

    def test_both_accounts_of_the_tests(self) -> None:
        record = _by_the_client(_record_v2())
        record["services"][0]["grade"] = "A"
        self._refused(record, "is tested by its client and does not state exactly the client's grade")

    def test_a_seal_key_keys_json_does_not_publish(self) -> None:
        record = _record_v2()
        record["seal_public_key"]["public_key_b64"] = _raw_b64(Ed25519PrivateKey.generate())
        self._refused(record, "the public key in the file is not the one published for 'seal-test'")

    def test_an_evidence_key_does_not_sign_seals(self) -> None:
        keys = _keys()
        keys[0]["purpose"] = "evidence-signing"
        self._refused(_record_v2(), "the published key 'seal-test' does not sign seals", keys)

    def test_a_signature_by_another_key_than_the_one_named(self) -> None:
        record = _record_v2()
        record["seal_public_key"]["key_id"] = "seal-other"
        self._refused(record, "platform seal.seal_public_key: is not the key that signed the seal")

    def test_an_unknown_record_version(self) -> None:
        record = _record_v2()
        record["schema"] = "published-platform-seal/3"
        self._refused(record, "unknown platform seal schema 'published-platform-seal/3'")


class TheCommandOnAPublishedPlatformSeal(unittest.TestCase):
    def _run(self, record: dict) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmp:
            keys = Path(tmp) / "keys.json"
            keys.write_text(json.dumps({"schema_id": vf.KEYS_SCHEMA_ID, "keys": _keys()}), encoding="utf-8")
            published = Path(tmp) / "platform-seal.json"
            published.write_text(json.dumps(_signed(record)), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(ROOT / "verify_fingerprint.py"), "--keys", str(keys), "-f", str(published)],
                capture_output=True, text=True, check=False,
            )

    def test_it_verifies_the_signature_and_the_record(self) -> None:
        result = self._run(_record_v2())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for line in (
            "[OK] signature: Ed25519, key 'evidence-test' (production)",
            "[OK] platform seal: published-platform-seal/2 of a seal-statement/5",
            "VERIFICATION PASSED",
        ):
            self.assertIn(line, result.stdout)

    def test_it_fails_a_record_below_the_floor(self) -> None:
        record = copy.deepcopy(_record_v2())
        record["services"][0]["grade"] = "C"
        result = self._run(record)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("[FAIL] platform seal.services[0].grade: is not one of its declared values", result.stdout)
        self.assertIn("VERIFICATION FAILED", result.stdout)


if __name__ == "__main__":
    unittest.main()

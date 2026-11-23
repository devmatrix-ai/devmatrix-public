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

    def test_a_seal_taken_outside_the_keys_window(self) -> None:
        record = _record_v2()
        record["sealed_at"] = "2025-12-31T23:59:59Z"
        self._refused(record, "sealed at 2025-12-31T23:59:59Z, outside the window of 'seal-test'")
        keys = _keys()
        keys[0]["expires_at"] = "2026-11-01T00:00:00+00:00"
        self._refused(_record_v2(), "sealed at 2026-11-19T10:00:00Z, outside the window of 'seal-test'", keys)

    def test_a_revoked_seal_key(self) -> None:
        keys = _keys()
        keys[0]["status"] = "revoked"
        self._refused(_record_v2(), "the published key 'seal-test' is REVOKED, not active or retired", keys)

    def test_a_seal_key_that_is_not_a_production_key(self) -> None:
        keys = _keys()
        keys[0]["class"] = "staging"
        self._refused(_record_v2(), "'seal-test' is NOT a production key; this is not a DevMatrix seal", keys)

    def test_a_signature_by_another_key_than_the_one_named(self) -> None:
        record = _record_v2()
        record["seal_public_key"]["key_id"] = "seal-other"
        self._refused(record, "platform seal.seal_public_key: is not the key that signed the seal")

    def test_an_unknown_record_version(self) -> None:
        record = _record_v2()
        record["schema"] = "published-platform-seal/5"
        self._refused(record, "unknown platform seal schema 'published-platform-seal/5'")


def _record_v3(*not_judged: int | None) -> dict:
    """A published-platform-seal/3 of a seal-statement/6, measured by
    DevMatrix: each service counts its tests not judged."""
    record = _record_v2()
    record.update(schema="published-platform-seal/3", statement_schema_id="seal-statement/6")
    for service, count in zip(record["services"], not_judged or (0, 0)):
        service["not_judged"] = count
    return record


class APublishedPlatformSealOfStatement6(unittest.TestCase):
    """``published-platform-seal/3``: as /2, and every service counts its tests
    not judged, or states null when its grade was given before that count
    existed: «not stated», never 0. Only the count is published."""

    _refused = APublishedPlatformSeal._refused

    def test_a_count_is_said_with_where_the_tests_are_named(self) -> None:
        lines = vf.check_published_platform_seal(_record_v3(3, 1), _keys())
        self.assertIn("published-platform-seal/3 of a seal-statement/6", lines[0])
        self.assertIn("services[0]: 3 tests not judged (the signed statement names them)", lines[3])
        self.assertIn("services[1]: 1 test not judged (the signed statement names them)", lines[5])

    def test_a_count_not_stated_is_said_so_and_never_as_0(self) -> None:
        """MUT-RED: null printed as a count (or as 0)."""
        lines = vf.check_published_platform_seal(_by_the_client(_record_v3(None, 0)), _keys())
        self.assertIn("services[0] graded A,", lines[2])
        self.assertIn("services[0]: This seal does not state how many tests were not judged.", lines[3])
        self.assertIn("services[1]: 0 tests not judged (the signed statement names them)", lines[5])
        self.assertNotIn("services[0]: 0 tests", "\n".join(lines))

    def test_an_a_plus_beside_tests_not_judged_or_a_count_not_stated(self) -> None:
        """MUT-RED: the A+ check of /3 removed, or reading only a count above 0."""
        for count in (2, None):
            with self.subTest(count=count):
                record = _record_v3(count, 0)
                record["services"][0]["grade"] = "A+"
                self._refused(
                    record,
                    "platform seal.services[0]: is graded A+ beside tests not judged, or beside a count it does not state",
                )
        record = _record_v3(0, 0)
        record["services"][0]["grade"] = "A+"
        vf.check_published_platform_seal(record, _keys())

    def test_a_count_that_is_not_a_count(self) -> None:
        for value in (-1, "2", 1.5, True):
            with self.subTest(value=value):
                self._refused(_record_v3(value, 0), "platform seal.services[0].not_judged")

    def test_a_record_without_its_count(self) -> None:
        record = _record_v3()
        del record["services"][0]["not_judged"]
        self._refused(record, "platform seal.services[0]")

    def test_a_count_in_a_record_of_an_earlier_statement(self) -> None:
        """/2 is read as before: a count of tests not judged is not one of its keys."""
        record = _record_v2()
        record["services"][0]["not_judged"] = 0
        self._refused(record, "platform seal.services[0]")

    def test_a_record_of_statement_6_published_as_2(self) -> None:
        record = _record_v3()
        record["schema"] = "published-platform-seal/2"
        self._refused(record, "platform seal")
        record = _record_v2()
        record["statement_schema_id"] = "seal-statement/6"
        self._refused(record, "platform seal.statement_schema_id: is not one of its declared values")


def _record_v4(*bases: tuple[str, int | None]) -> dict:
    """A published-platform-seal/4 of a seal-statement/7, measured by
    DevMatrix: each service states what its grade rests on and its count of
    tests proven not applicable."""
    record = _record_v3()
    record.update(schema="published-platform-seal/4", statement_schema_id="seal-statement/7")
    for service, (basis, proven) in zip(record["services"], bases or (("qa_run", 2), ("compile", None))):
        service.update(basis=basis, proven_not_applicable=proven)
    return record


class APublishedPlatformSealOfStatement7(unittest.TestCase):
    """``published-platform-seal/4``: as /3, and every service states its
    basis and its count of tests proven not applicable, or null: «not
    stated», never 0. A seal never mixes measurers."""

    _refused = APublishedPlatformSeal._refused

    def test_each_service_says_its_basis_and_its_proofs(self) -> None:
        lines = vf.check_published_platform_seal(_record_v4(), _keys())
        self.assertIn("published-platform-seal/4 of a seal-statement/7", lines[0])
        self.assertIn("services[0]: rests on qa_run; 2 tests proven not applicable (the signed statement names them)", lines[4])
        self.assertIn("services[1]: rests on compile; This seal does not state its tests proven not applicable.", lines[7])

    def test_a_client_run_seal_is_one_build(self) -> None:
        record = _by_the_client(_record_v4(("client_run", 1), ("client_run", 1)))
        self._refused(record, "platform seal.services: a self-attested seal is one build")
        record["services"] = record["services"][:1]
        vf.check_published_platform_seal(record, _keys())

    def test_a_basis_its_measurer_does_not_measure(self) -> None:
        """MUT-RED: the basis-measurer check removed."""
        self._refused(_record_v4(("client_run", 1), ("compile", None)),
                      "platform seal.services[0].basis: rests on client_run, which devmatrix does not measure")
        self._refused(_by_the_client(_record_v4(("qa_run", 1), ("qa_run", 1))), "platform seal.services")

    def test_a_compile_that_states_proofs(self) -> None:
        """MUT-RED: the compile-count check removed."""
        self._refused(_record_v4(("qa_run", 2), ("compile", 0)),
                      "platform seal.services[1].proven_not_applicable: rests on the compile and states a count of proofs")

    def test_an_a_plus_beside_proofs_not_stated(self) -> None:
        """MUT-RED: the A+ check of /4 removed."""
        record = _record_v4(("compile", None), ("qa_run", 0))
        record["services"][0]["grade"] = "A+"
        self._refused(record, "platform seal.services[0]: is graded A+ beside tests proven not applicable it does not state")

    def test_an_unknown_basis_or_a_record_published_as_3(self) -> None:
        self._refused(_record_v4(("devmatrix", 1), ("compile", None)), "platform seal.services[0].basis")
        record = _record_v4()
        record["schema"] = "published-platform-seal/3"
        self._refused(record, "platform seal")
        record = _record_v3()
        record["statement_schema_id"] = "seal-statement/7"
        self._refused(record, "platform seal.statement_schema_id: is not one of its declared values")


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
            "Seal: " + _hex("1"),
            "Sealed at: 2026-11-19T10:00:00Z",
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

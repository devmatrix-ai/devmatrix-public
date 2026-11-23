"""A build's delivered fingerprint attestation, the platform seal and the
published attestation name one build, checked by one command:

    python verify_fingerprint.py --seal <bundle> --attestation <service>=<file> [--published <file>]

All three name the attestation by the SHA-256 of the delivered file's bytes.
The seal is signed by a seal-signing key keys.json publishes, the published
attestation by an evidence-signing key; the key inside the seal bundle proves
nothing by itself.

The documents and keys are made in the test, so keys.json is not touched.

Run from the repository root: python -m unittest discover -s tests
"""

from __future__ import annotations

import base64
import copy
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

_SEAL_KEY = Ed25519PrivateKey.generate()
_EVIDENCE_KEY = Ed25519PrivateKey.generate()
_SERVICE = "orders"
_JOB = "0b2f6c55-7f9e-4c1a-9a63-1f0a7e2c4d11"


def _raw_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def _key(key: Ed25519PrivateKey, key_id: str, purpose: str, key_class: str = "production") -> dict:
    public = _raw_b64(key)
    return {
        "kid": "sha256:" + hashlib.sha256(base64.b64decode(public)).hexdigest(),
        "key_id": key_id,
        "purpose": purpose,
        "class": key_class,
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


def _delivered() -> dict:
    """A fingerprint-attestation/2 document, as a build's download carries it."""
    services = {_SERVICE: _hex("1"), "billing": _hex("2")}
    reproducible = {
        "identity": {
            "platform_spec_hash": "sha256:" + _hex("3"),
            "service_spec_hashes_sha256": "sha256:" + vf.service_spec_hashes_sha256(services),
            "service_spec_hashes": services,
            "ir_structural_hash": "sha256:" + _hex("4"),
            "ir_semantic_hash": "sha256:" + _hex("5"),
            "compiler_toolchain_hash": "sha256:" + _hex("6"),
            "deterministic_seed": "sha256:" + _hex("7"),
            "build_fingerprint": "sha256:" + _hex("8"),
        },
        "merkle": {
            "nested_root": "sha256:" + _hex("9"),
            "sub_roots": {name: "sha256:" + _hex("d") for name in vf.SUB_ROOT_NAMES},
            "emit_root": "sha256:" + _hex("e"),
            "emit_leaves": [{"path": "services/orders/app.py", "leaf_sha256": "sha256:" + _hex("f")}],
        },
        "modules": [{"module": _SERVICE, "emission_sha256": "sha256:" + _hex("a"), "file_count": 3}],
    }
    return {
        "schema": vf.DELIVERED_ATTESTATION_SCHEMA,
        "job_id": _JOB,
        "reproducible": reproducible,
        "reproducible_sha256": vf.reproducible_sha256(reproducible),
        "attested": {
            "platform_verdict": {"uts_disposition": "PASSED"},
            "modules": [
                {"module": _SERVICE, "status": "VERIFIED"},
                {"module": "billing", "status": "NOT_VERIFIED", "cause": "no_baseline"},
            ],
            "terminal_gate_verdict_hash": "sha256:" + _hex("b"),
            "not_tested_count": 0,
        },
        "coverage": {"delivered_files": 10, "covered": 10, "uncovered": []},
        "certificate_fingerprint": "sha256:" + _hex("0"),
    }


def _run_by_client(document: dict) -> None:
    """The build's tests were run by the client, on its own machine."""
    document["attested"]["platform_verdict"] = {
        "uts_disposition": "NOT_RUN", "uts_not_run_reason": "runtime_phase_run_by_client",
    }


def _bytes(document: dict) -> bytes:
    """The bytes a fingerprint attestation is delivered as: sorted keys,
    two-space indent, one trailing newline."""
    return (json.dumps(document, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _statement(document: dict) -> dict:
    return {
        "schema_id": "seal-statement/4",
        "seal_hash": _hex("c"),
        "sealed_at": "2026-11-10T10:00:00+00:00",
        "platform": {"name": "shop", "spec_hash": _hex("3"), "spec_version": "1", "verification": "devmatrix",
                     "qa_score_hundredths": 9900},
        "services": [{
            "name": _SERVICE,
            "spec_hash": _hex("1"),
            "verification": "devmatrix",
            "fingerprint_attestation": {
                "document_sha256": _digest(_bytes(document)),
                "reproducible_sha256": document["reproducible_sha256"],
            },
        }],
        "key_id": "seal-test",
    }


def _published(document: dict, data: bytes | None = None) -> dict:
    return {
        "schema": vf.ATTESTATION_SCHEMA_V3,
        "job_id": _JOB,
        "attestation_sha256": _digest(_bytes(document) if data is None else data),
        "reproducible_sha256": document["reproducible_sha256"],
        "identity": copy.deepcopy(document["reproducible"]["identity"]),
        "merkle": {
            "nested_root": "sha256:" + _hex("9"),
            "sub_roots": {name: "sha256:" + _hex("d") for name in vf.SUB_ROOT_NAMES},
            "emit_root": "sha256:" + _hex("e"),
            "emit_leaf_sha256": ["sha256:" + _hex("f")],
        },
        "modules": [{"module": _SERVICE, "emission_sha256": "sha256:" + _hex("a")}],
        "determinism": [
            {"module": _SERVICE, "status": "VERIFIED"},
            {"module": "billing", "status": "NOT_VERIFIED", "cause": "no_baseline"},
        ],
        "terminal_gate_verdict_hash": "sha256:" + _hex("b"),
        "not_tested_count": 0,
        "coverage": {"delivered_files": 10, "covered": 10},
        "certificate_fingerprint": "sha256:" + _hex("0"),
        "run_by": "devmatrix",
        "seal_class": "sealed",
    }


def _signed(payload: dict) -> dict:
    canonical = vf.canonical_payload(payload)
    return {
        "evidence_version": "1.0.0",
        "fingerprint": payload,
        "published_at": "2026-11-10T11:00:00+00:00",
        "signature": {
            "algorithm": "Ed25519",
            "key_id": "evidence-test",
            "public_key": _raw_b64(_EVIDENCE_KEY),
            "signature": base64.b64encode(_EVIDENCE_KEY.sign(canonical)).decode(),
            "signed_at": "2026-11-10T11:00:00+00:00",
            "signed_payload_hash": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        },
    }


class OneBuild:
    """The three documents of one build, written to a directory; each test
    changes one thing before it writes them."""

    def __init__(self) -> None:
        self.document = _delivered()
        self.data: bytes | None = None
        self.statement = _statement(self.document)
        self.published: dict | None = _published(self.document)
        #: A published evidence file to pass as it is, instead of ``published``.
        self.published_file: Path | None = None
        self.keys = _keys()
        self.bundle_key = _SEAL_KEY
        self.signing_key = _SEAL_KEY

    def run(self, tmp: Path, *extra: str) -> subprocess.CompletedProcess[str]:
        bundle = tmp / "seal"
        bundle.mkdir()
        statement_bytes = json.dumps(self.statement, sort_keys=True).encode("utf-8")
        (bundle / "seal-statement.json").write_bytes(statement_bytes)
        (bundle / "seal-statement.sig.b64").write_text(
            base64.b64encode(self.signing_key.sign(statement_bytes)).decode() + "\n", encoding="ascii"
        )
        (bundle / "seal-public-key.pem").write_bytes(self.bundle_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        delivered = tmp / "fingerprint_attestation.json"
        delivered.write_bytes(_bytes(self.document) if self.data is None else self.data)
        keys = tmp / "keys.json"
        keys.write_text(json.dumps({"schema_id": vf.KEYS_SCHEMA_ID, "keys": self.keys}), encoding="utf-8")
        command = [sys.executable, str(ROOT / "verify_fingerprint.py"), "--keys", str(keys),
                   "--seal", str(bundle), "--attestation", f"{_SERVICE}={delivered}", *extra]
        if self.published_file is not None:
            command += ["--published", str(self.published_file)]
        elif self.published is not None:
            published = tmp / "published.json"
            published.write_text(json.dumps(_signed(self.published)), encoding="utf-8")
            command += ["--published", str(published)]
        return subprocess.run(command, capture_output=True, text=True, check=False)


class TheCommand(unittest.TestCase):
    def _run(self, build: OneBuild) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmp:
            return build.run(Path(tmp))

    def _fails(self, build: OneBuild, reason: str) -> None:
        result = self._run(build)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(reason, result.stdout)
        self.assertIn("VERIFICATION FAILED", result.stdout)

    def test_one_build_binds_end_to_end(self) -> None:
        result = self._run(OneBuild())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for line in (
            "[OK] seal: seal-statement/4, key 'seal-test' (production)",
            "[OK] orders: the delivered attestation is the sealed one",
            "[OK] orders: reproducible ",
            "[OK] orders: the attestation names the specs the seal names",
            "[OK] orders: tests run by devmatrix, as the seal states (measured by devmatrix)",
            "[OK] orders: the published attestation is exactly what the delivered file publishes as",
            "VERIFICATION PASSED",
        ):
            self.assertIn(line, result.stdout)

    def test_the_seal_alone_binds_too(self) -> None:
        build = OneBuild()
        build.published = None
        result = self._run(build)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("the delivered attestation is the sealed one", result.stdout)

    def test_a_delivered_file_the_seal_did_not_sign(self) -> None:
        build = OneBuild()
        build.statement["services"][0]["fingerprint_attestation"]["document_sha256"] = "sha256:" + _hex("0")
        self._fails(build, "the delivered attestation is not the sealed one")

    def test_a_published_digest_of_another_serialization(self) -> None:
        build = OneBuild()
        compact = json.dumps(build.document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        build.published = _published(build.document, compact)
        self._fails(build, "it differs in ['attestation_sha256']")

    def test_a_reproducible_digest_the_seal_does_not_state(self) -> None:
        build = OneBuild()
        build.statement["services"][0]["fingerprint_attestation"]["reproducible_sha256"] = "sha256:" + _hex("0")
        self._fails(build, "reproducible_sha256 differs")

    def test_a_reproducible_block_that_is_not_its_digest(self) -> None:
        build = OneBuild()
        build.document["reproducible"]["modules"][0]["emission_sha256"] = "sha256:" + _hex("0")
        build.statement = _statement(build.document)
        build.published = _published(build.document)
        self._fails(build, "reproducible_sha256 is not the digest of its reproducible block")

    def test_an_attestation_of_another_platform_spec(self) -> None:
        build = OneBuild()
        build.statement["platform"]["spec_hash"] = _hex("0")
        self._fails(build, "the attestation's platform spec hash")

    def test_an_attestation_of_another_service_spec(self) -> None:
        build = OneBuild()
        build.statement["services"][0]["spec_hash"] = _hex("0")
        self._fails(build, "the attestation's service spec hash")

    def test_a_published_identity_of_another_build(self) -> None:
        build = OneBuild()
        assert build.published is not None
        build.published["identity"]["ir_semantic_hash"] = "sha256:" + _hex("0")
        self._fails(build, "it differs in ['identity']")

    def test_a_seal_key_keys_json_does_not_publish(self) -> None:
        build = OneBuild()
        build.bundle_key = build.signing_key = Ed25519PrivateKey.generate()
        self._fails(build, "the public key in the file is not the one published for 'seal-test'")

    def test_an_evidence_key_does_not_sign_seals(self) -> None:
        build = OneBuild()
        build.keys[0]["purpose"] = "evidence-signing"
        self._fails(build, "the published key 'seal-test' does not sign seals")

    def test_a_seal_signature_that_does_not_verify(self) -> None:
        build = OneBuild()
        build.signing_key = Ed25519PrivateKey.generate()
        self._fails(build, "the statement's signature is INVALID for key 'seal-test'")

    def test_a_seal_key_that_is_not_a_production_key(self) -> None:
        # A keys file holds one environment's keys: a seal key of another
        # class next to a production evidence key is refused before any check.
        build = OneBuild()
        build.keys[0]["class"] = "staging"
        self._fails(build, "the keys mix ['production', 'staging'] keys")

    def test_a_seal_key_that_is_not_a_production_key_is_refused_in_process(self) -> None:
        build = OneBuild()
        with tempfile.TemporaryDirectory() as tmp:
            build.run(Path(tmp))
            keys = [dict(k, **{"class": "staging"}) for k in build.keys]
            with self.assertRaises(vf.BindingRefused) as raised:
                vf.read_seal(Path(tmp) / "seal", keys)
        self.assertIn("is NOT a production key; this is not a DevMatrix seal", str(raised.exception))

    def test_a_published_attestation_of_an_earlier_schema_cannot_be_bound(self) -> None:
        build = OneBuild()
        assert build.published is not None
        legacy = {k: v for k, v in build.published.items()}
        legacy["schema"] = vf.ATTESTATION_SCHEMA_V2
        legacy["identity"] = {"spec_hash": "sha256:" + _hex("3")}
        legacy["merkle"] = dict(legacy["merkle"], sub_roots={"root_a": "sha256:" + _hex("d")})
        build.published = legacy
        self._fails(build, "it cannot be bound to the delivered file")

    def test_a_service_the_seal_does_not_hold(self) -> None:
        build = OneBuild()
        build.statement["services"][0]["name"] = "billing"
        self._fails(build, "orders: no such service in this seal")

    def test_every_published_field_is_the_delivered_files(self) -> None:
        changes = {
            "job_id": lambda p: p.update(job_id="1c2f6c55-7f9e-4c1a-9a63-1f0a7e2c4d11"),
            "merkle": lambda p: p["merkle"].update(emit_root="sha256:" + _hex("1")),
            "modules": lambda p: p["modules"][0].update(emission_sha256="sha256:" + _hex("1")),
            "determinism": lambda p: p["determinism"][0].update(status="DRIFT"),
            "terminal_gate_verdict_hash": lambda p: p.update(terminal_gate_verdict_hash="sha256:" + _hex("1")),
            "not_tested_count": lambda p: p.update(not_tested_count=1),
            "coverage": lambda p: p["coverage"].update(covered=9),
            "certificate_fingerprint": lambda p: p.update(certificate_fingerprint="sha256:" + _hex("1")),
        }
        for field, change in changes.items():
            with self.subTest(field=field):
                build = OneBuild()
                assert build.published is not None
                change(build.published)
                self._fails(build, f"it differs in ['{field}']")

    def test_a_published_digest_of_the_rewritten_file_not_the_delivered_bytes(self) -> None:
        build = OneBuild()
        build.data = json.dumps(build.document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        build.statement["services"][0]["fingerprint_attestation"]["document_sha256"] = _digest(build.data)
        self._fails(build, "it differs in ['attestation_sha256']")

    def test_a_seal_service_that_names_no_measurer(self) -> None:
        build = OneBuild()
        build.published = None
        del build.statement["services"][0]["verification"]
        self._fails(build, "orders: the seal does not state who measured the build")

    def test_a_published_runner_the_file_does_not_state(self) -> None:
        build = OneBuild()
        assert build.published is not None
        build.published.update(run_by="client", seal_class="self_attested")
        self._fails(build, "it differs in ['run_by', 'seal_class']")

    def test_a_seal_measurer_the_file_does_not_state(self) -> None:
        build = OneBuild()
        build.published = None
        build.statement["services"][0]["verification"] = "self_attested"
        self._fails(build, "the seal says the build was measured by self_attested, but its attestation says "
                           "the tests were run by devmatrix")

    def test_a_build_the_client_ran_binds_to_its_self_attested_seal(self) -> None:
        build = OneBuild()
        _run_by_client(build.document)
        build.statement = _statement(build.document)
        build.statement["services"][0]["verification"] = "self_attested"
        build.published = dict(_published(build.document), run_by="client", seal_class="self_attested")
        result = self._run(build)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("tests run by client, as the seal states (measured by self_attested)", result.stdout)
        self.assertIn("tests run by client, seal self_attested)", result.stdout)

    def test_a_verdict_that_names_no_runner(self) -> None:
        build = OneBuild()
        build.document["attested"]["platform_verdict"] = {"uts_disposition": "NOT_RUN"}
        build.statement = _statement(build.document)
        build.published = None
        self._fails(build, "the delivered attestation's platform verdict does not state who ran the tests")

    def test_a_seal_that_states_no_measurer_is_refused_and_the_rest_still_runs(self) -> None:
        build = OneBuild()
        build.published = None
        build.statement["schema_id"] = "seal-statement/2"
        del build.statement["services"][0]["verification"]
        result = self._run(build)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("[FAIL] orders: the seal is a seal-statement/2, which does not state who measured the build", result.stdout)
        self.assertIn("re-seal the platform (a new seal is seal-statement/3 or later)", result.stdout)
        self.assertIn("[OK] orders: the delivered attestation is the sealed one", result.stdout)
        self.assertIn("[OK] orders: the attestation names the specs the seal names", result.stdout)

    def _a_real_published_2_is_refused_with_what_to_do_and_the_seal_still_binds(self, path: Path) -> None:
        build = OneBuild()
        build.published_file = path
        build.keys = _keys() + vf.load_keys(vf.KEYS_FILE)
        result = self._run(build)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("[OK] signature: Ed25519, key 'dm-prod-2026-01' (production)", result.stdout)
        self.assertIn(
            "[FAIL] published attestation: published-attestation/2 names the attestation by the digest "
            "of a compact re-serialization, not of the delivered file, so it cannot be bound to the "
            "delivered file; republish the build's attestation (it is published as "
            "published-attestation/3) and verify again",
            result.stdout,
        )
        for line in (
            "[OK] orders: the delivered attestation is the sealed one",
            "[OK] orders: the attestation names the specs the seal names",
            "[OK] orders: tests run by devmatrix, as the seal states (measured by devmatrix)",
        ):
            self.assertIn(line, result.stdout)

    def _a_real_published_3_is_taken_for_binding(self, path: Path) -> None:
        payload, lines, failures = vf._published_for_binding(path, vf.load_keys(vf.KEYS_FILE))
        self.assertEqual(failures, [])
        self.assertIsNotNone(payload)
        self.assertIn("[OK] signature: Ed25519, key 'dm-prod-2026-01' (production)", "\n".join(lines))

    def test_every_real_published_attestation_is_read_by_its_own_version(self) -> None:
        """Each file under attestations/ verifies; a /2 is refused for binding
        with what to do and the seal still binds; a /3 is taken for binding.
        A file of a version this test does not know fails it, so a new
        version published there cannot go unread."""
        by_version = {
            vf.ATTESTATION_SCHEMA_V2: self._a_real_published_2_is_refused_with_what_to_do_and_the_seal_still_binds,
            vf.ATTESTATION_SCHEMA_V3: self._a_real_published_3_is_taken_for_binding,
        }
        real = sorted((ROOT / "attestations" / "attestation").glob("*.json"))
        self.assertTrue(real, "no published attestation in the repository to read")
        for path in real:
            with self.subTest(published=path.name):
                verified = subprocess.run(
                    [sys.executable, str(ROOT / "verify_fingerprint.py"), "-f", str(path)],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
                schema = vf.signed_payload(vf.read_json(path))["schema"]
                if schema not in by_version:
                    self.fail(f"{path.name} is published as {schema!r}, a version this test does not read")
                by_version[schema](path)

    def test_seal_takes_attestations_and_no_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, str(ROOT / "verify_fingerprint.py"), "--seal", tmp],
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("--seal takes one or more --attestation", result.stderr)


def _floor_statement(document: dict, *failed: str) -> dict:
    """A seal-statement/5: the build is graded at the seal floor or above and
    names every test that failed."""
    statement = _statement(document)
    statement["schema_id"] = "seal-statement/5"
    statement["services"][0].update(
        qa_score_hundredths=9800, grade="A", self_attested_grade=None,
        seal_floor="A", failed_tests=list(failed),
    )
    return statement


def _client_floor_statement(document: dict, *failed: str) -> dict:
    """A seal-statement/5 of a build the client tested: 10 applicable tests."""
    statement = _floor_statement(document, *failed)
    statement["platform"].update(verification="self_attested", qa_score_hundredths=None)
    statement["services"][0].update(
        verification="self_attested", qa_score_hundredths=None, grade=None,
        self_attested_grade={
            "letter": "A", "score_percent": 90, "passed": 10 - len(failed), "applicable": 10,
            "listed_not_emitted": 0, "listed_declared_skips": 0, "run_ids": {_SERVICE: "run-1"},
        },
    )
    return statement


class ASealAtTheGradeFloor(unittest.TestCase):
    """From seal-statement/5 a build is sealed while its grade is A or better,
    and every test that failed is named."""

    _run = TheCommand._run
    _fails = TheCommand._fails

    def test_a_build_graded_at_the_floor_binds_and_names_its_failed_tests(self) -> None:
        build = OneBuild()
        build.statement = _floor_statement(build.document, "test_one", "test_two")
        result = self._run(build)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for line in (
            "[OK] seal: seal-statement/5, key 'seal-test' (production)",
            "[OK] orders: graded A (score 9800 hundredths), measured by DevMatrix; "
            "sealed at grade A or better, 2 failed test(s)",
            "      orders: failed test_one",
            "      orders: failed test_two",
            "[OK] orders: the delivered attestation is the sealed one",
            "[OK] orders: tests run by devmatrix, as the seal states (measured by devmatrix)",
            "VERIFICATION PASSED",
        ):
            self.assertIn(line, result.stdout)

    def test_a_build_the_client_ran_binds_at_the_floor(self) -> None:
        build = OneBuild()
        _run_by_client(build.document)
        build.statement = _client_floor_statement(build.document, "test_one")
        build.published = dict(_published(build.document), run_by="client", seal_class="self_attested")
        result = self._run(build)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "[OK] orders: graded A (90%), self-attested: 9/10 tests passed on the client's machine; "
            "sealed at grade A or better, 1 failed test(s)",
            result.stdout,
        )
        self.assertIn("      orders: failed test_one", result.stdout)

    def test_a_grade_below_the_floor(self) -> None:
        build = OneBuild()
        build.statement = _floor_statement(build.document)
        build.statement["services"][0]["grade"] = "B"
        self._fails(build, "orders: is graded 'B', below the grade A it was sealed at")

    def test_a_client_grade_below_the_floor(self) -> None:
        build = OneBuild()
        _run_by_client(build.document)
        build.statement = _client_floor_statement(build.document)
        build.statement["services"][0]["self_attested_grade"]["letter"] = "C"
        build.published = None
        self._fails(build, "orders: is graded 'C', below the grade A it was sealed at")

    def test_a_floor_other_than_a(self) -> None:
        build = OneBuild()
        build.statement = _floor_statement(build.document)
        build.statement["services"][0]["seal_floor"] = "C"
        self._fails(build, "orders: does not state that it was sealed at grade A or better")

    def test_failed_tests_named_twice_or_out_of_order(self) -> None:
        for failed in (("test_b", "test_a"), ("test_a", "test_a")):
            with self.subTest(failed=failed):
                build = OneBuild()
                build.statement = _floor_statement(build.document, *failed)
                self._fails(build, "orders: its failed tests are not each named once, in order")

    def test_failed_tests_that_are_not_names(self) -> None:
        build = OneBuild()
        build.statement = _floor_statement(build.document)
        build.statement["services"][0]["failed_tests"] = None
        self._fails(build, "orders: its failed tests are not names")

    def test_a_client_run_whose_failed_tests_are_not_every_test_that_did_not_pass(self) -> None:
        build = OneBuild()
        _run_by_client(build.document)
        build.statement = _client_floor_statement(build.document, "test_one")
        build.statement["services"][0]["self_attested_grade"]["passed"] = 10
        build.published = None
        self._fails(build, "orders: is self-attested and its failed tests are not every test that did not pass")

    def test_an_earlier_statement_states_no_floor_and_still_binds(self) -> None:
        result = self._run(OneBuild())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("sealed at grade", result.stdout)


class APublishedV3(unittest.TestCase):
    def test_it_states_the_spec_identity(self) -> None:
        lines = vf.check_published_attestation(_published(_delivered()))
        self.assertIn("tests run by devmatrix, seal sealed", lines[0])
        self.assertIn("2 module spec hashes", lines[1])

    def test_a_module_map_its_digest_does_not_name(self) -> None:
        document = _published(_delivered())
        document["identity"]["service_spec_hashes"][_SERVICE] = _hex("0")
        with self.assertRaises(vf.AttestationRefused) as raised:
            vf.check_published_attestation(document)
        self.assertIn("the module map is not the one its digest", str(raised.exception))

    def test_a_cause_outside_its_set(self) -> None:
        document = _published(_delivered())
        document["determinism"][1]["cause"] = "some_cause"
        with self.assertRaises(vf.AttestationRefused) as raised:
            vf.check_published_attestation(document)
        self.assertIn("determinism[1].cause", str(raised.exception))

    def test_a_sub_root_outside_its_set(self) -> None:
        document = _published(_delivered())
        document["merkle"]["sub_roots"]["root_a"] = "sha256:" + _hex("d")
        with self.assertRaises(vf.AttestationRefused) as raised:
            vf.check_published_attestation(document)
        self.assertIn("undeclared keys ['root_a']", str(raised.exception))

    def test_an_aggregate_spec_hash_is_not_read_into_it(self) -> None:
        document = _published(_delivered())
        document["identity"]["spec_hash"] = "sha256:" + _hex("3")
        with self.assertRaises(vf.AttestationRefused) as raised:
            vf.check_published_attestation(document)
        self.assertIn("undeclared keys ['spec_hash']", str(raised.exception))


if __name__ == "__main__":
    unittest.main()

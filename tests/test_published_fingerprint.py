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


def _projected_checks(**changes: object) -> dict:
    checks = {
        "schema_id": "dmx_customer_checks_pre_nda/v1",
        "sealed_schema_id": "dmx_customer_checks/v8",
        "status": "projected",
        "scopes": [],
        "totals": {},
        "tests": {
            "ran": True, "total": 10, "planned": 10, "not_reached": 0, "pass_rate": 0.9,
            "passed": 9, "failed": 1, "not_applicable": 0, "did_not_run": 0,
            "counted_in_another_tier": 0,
        },
        "tests_absent_reason": None,
    }
    checks.update(changes)
    return checks


def _complexity(**changes: object) -> dict:
    measurement = {
        "schema_id": "complexity-measurement/2", "state": "complete", "calibration": "not_calibrated",
        "total_milli": 1200, "band": None, "entitlement_reasons": ["Not calibrated."],
    }
    measurement.update(changes)
    return measurement


class EveryValueIsOfItsDeclaredForm(unittest.TestCase):
    def _accepted(self, **changes: object) -> None:
        vf.check_published_fingerprint(dict(_fingerprint(), **changes))

    def _refused(self, reason: str, **changes: object) -> None:
        with self.assertRaises(vf.AttestationRefused) as refused:
            vf.check_published_fingerprint(dict(_fingerprint(), **changes))
        self.assertIn(reason, str(refused.exception))

    def test_an_outcome_is_a_boolean_or_null(self) -> None:
        self._accepted(passed=None, terminal_success=False)
        self._refused("fingerprint.passed: is not true, false or null", passed="yes")
        self._refused("fingerprint.terminal_success: is not true, false or null", terminal_success=1)
        self._refused("fingerprint.seal.passed: is not true, false or null", seal={"passed": "true"})
        self._refused("carries undeclared keys ['by']", seal={"passed": True, "by": "x"})

    def test_a_digest_is_a_sha256_hex_digest(self) -> None:
        self._accepted(spec_hash=None, release_ref="release:" + "f" * 64)
        self._refused("fingerprint.spec_hash: is not a sha256 digest", spec_hash="c" * 63)
        self._refused("fingerprint.spec_hash: is not a sha256 digest", spec_hash="C" * 64)
        self._refused("fingerprint.release_ref", release_ref="release:abc")

    def test_an_identity_is_a_bounded_string_or_null(self) -> None:
        self._accepted(verdict_binding=None)
        self._refused("fingerprint.build_id: is not a bounded string or null", build_id=7)
        self._refused("fingerprint.job_id: is not a bounded string or null", job_id="j" * 257)

    def test_a_compilation_outcome_is_one_of_its_set(self) -> None:
        self._refused("fingerprint.compile_status: is not one of its declared values", compile_status="ok")

    def test_the_merkle_commitment(self) -> None:
        self._accepted(merkle_root="d" * 64)
        self._accepted(merkle_root={"root_hash": "d" * 64, "sbom_root": "", "leaf_count": 0, "schema_version": "1.4"})
        self._refused("fingerprint.merkle_root.ir_root: is not a sha256 digest", merkle_root={"ir_root": "xyz"})
        self._refused("fingerprint.merkle_root.leaf_count: is not a count", merkle_root={"leaf_count": -1})
        self._refused("carries undeclared keys ['private']", merkle_root={"private": "d" * 64})
        self._refused("fingerprint.merkle_root: is not a digest or an object", merkle_root=3)
        self._refused("fingerprint.merkle_root: is not a sha256 digest", merkle_root="")
        self._refused("fingerprint.merkle_root.root_hash: is not a sha256 digest", merkle_root={"root_hash": ""})
        self._refused("fingerprint.merkle_root.schema_version: is not one of its declared values",
                      merkle_root={"schema_version": "9999.0"})

    def test_the_determinism_claim(self) -> None:
        self._accepted(determinism={"status": "NOT_VERIFIED", "cause": "no_baseline"})
        self._accepted(determinism={"deterministic": None})
        self._refused("a cause goes with NOT_VERIFIED", determinism={"status": "VERIFIED", "cause": "no_baseline"})
        self._refused("fingerprint.determinism.status", determinism={"status": "MAYBE"})
        self._refused("fingerprint.determinism.deterministic", determinism={"deterministic": "true"})

    def test_the_customer_checks(self) -> None:
        self._accepted(customer_checks=_projected_checks())
        self._accepted(customer_checks=_projected_checks(tests=None, tests_absent_reason="runtime_phase_run_by_client"))
        self._accepted(customer_checks={
            "schema_id": "dmx_customer_checks_pre_nda/v1", "sealed_schema_id": "dmx_customer_checks/v5",
            "status": "not_projected", "reason": "cancelled",
        })
        self._refused("states its tests or why it has none", customer_checks=_projected_checks(tests=None))
        tests = dict(_projected_checks()["tests"], pass_rate="90%")
        self._refused("fingerprint.customer_checks.tests.pass_rate", customer_checks=_projected_checks(tests=tests))
        tests = dict(_projected_checks()["tests"], ran="yes")
        self._refused("fingerprint.customer_checks.tests.ran", customer_checks=_projected_checks(tests=tests))
        self._refused("fingerprint.customer_checks.sealed_schema_id",
                      customer_checks=_projected_checks(sealed_schema_id="dmx_customer_checks/v9"))

    def test_the_complexity_measurement(self) -> None:
        self._accepted(complexity_measurement=_complexity())
        self._accepted(complexity_measurement=_complexity(state="incomplete", total_milli=None))
        self._refused("a total goes with a complete measurement", complexity_measurement=_complexity(total_milli=None))
        self._refused("fingerprint.complexity_measurement.band: is not null", complexity_measurement=_complexity(band="S"))
        self._refused("fingerprint.complexity_measurement.total_milli: is above its bound",
                      complexity_measurement=_complexity(total_milli=1_000_001))
        self._refused("states no reason", complexity_measurement=_complexity(entitlement_reasons=[]))


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

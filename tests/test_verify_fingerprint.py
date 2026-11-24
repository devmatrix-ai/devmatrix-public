"""Every published fingerprint's signature verifies against keys.json, and the
verifier fails, never skips, on anything it cannot prove.

Run from the repository root: python -m unittest discover -s tests
(needs the ``cryptography`` package, as the verifier does).
"""

from __future__ import annotations

import base64
import copy
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import verify_fingerprint as vf  # noqa: E402

#: Every evidence file in this repository and the class of the key that signed it.
EXPECTED = {
    "fingerprints/20260221_modular_hip_test_20260221_103259_a57210ff.json": "production",
    "fingerprints/20260330_modular_hip_demo_1_20260323_001610_f210ce5a.json": "production",
    "fingerprints/20260704_hip_identity_BID.json": "production",
    "fingerprints/2db8e0ba-7642-44b7-8e66-d5aaacdba1cf/2db8e0ba-7642-44b7-8e66-d5aaacdba1cf.json": "production",
    "fingerprints/5fc1882a-0d3e-4bf0-b6a5-c5ba69820e5f/5fc1882a-0d3e-4bf0-b6a5-c5ba69820e5f.json": "production",
    "fingerprints/ae86be9a-cb25-4178-9bb1-39bc0aacd0d3/ae86be9a-cb25-4178-9bb1-39bc0aacd0d3.json": "production",
}


def _evidence(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def _production_sample() -> dict:
    return _evidence(next(n for n, c in EXPECTED.items() if c == "production"))


KEYS = vf.load_keys(vf.KEYS_FILE)

#: Where the evidence lives.
PRODUCTION_DIR = "fingerprints"


class EveryPublishedFingerprint(unittest.TestCase):
    def test_the_census_is_the_repository(self) -> None:
        found = {
            str(p.relative_to(ROOT)).replace("\\", "/")
            for p in (ROOT / PRODUCTION_DIR).rglob("*.json")
        }
        self.assertEqual(found, set(EXPECTED))

    def test_every_file_is_signed_by_a_production_key(self) -> None:
        files = sorted((ROOT / PRODUCTION_DIR).rglob("*.json"))
        self.assertTrue(files, f"{PRODUCTION_DIR} holds no evidence: the check reads nothing")
        for path in files:
            with self.subTest(path=str(path.relative_to(ROOT))):
                signature = json.loads(path.read_text(encoding="utf-8"))["signature"]
                (entry,) = [
                    key for key in KEYS
                    if key["key_id"] == signature["key_id"] and key["public_key"] == signature["public_key"]
                ]
                self.assertEqual(entry["class"], vf.PRODUCTION)

    def test_keys_json_lists_production_keys_only(self) -> None:
        self.assertTrue(KEYS)
        self.assertEqual({key["class"] for key in KEYS}, {vf.PRODUCTION})

    def test_each_verifies_with_its_published_key(self) -> None:
        for name, key_class in EXPECTED.items():
            with self.subTest(name=name):
                passed, lines = vf.verify_signature(_evidence(name), KEYS)
                self.assertTrue(passed, lines)
                self.assertIn(f"({key_class})", lines[0])

    def test_a_key_of_any_other_class_is_refused(self) -> None:
        evidence = _production_sample()
        keys = [dict(k, **{"class": "staging"}) for k in KEYS]
        passed, lines = vf.verify_signature(evidence, keys)
        self.assertFalse(passed, lines)
        self.assertIn("NOT a production key", lines[-1])


class ATamperedSignatureFails(unittest.TestCase):
    def _fails(self, evidence: dict, reason: str) -> None:
        passed, lines = vf.verify_signature(evidence, KEYS)
        self.assertFalse(passed, lines)
        self.assertIn(reason, lines[-1])

    def test_a_changed_signature(self) -> None:
        evidence = _production_sample()
        raw = bytearray(base64.b64decode(evidence["signature"]["signature"]))
        raw[0] ^= 1
        evidence["signature"]["signature"] = base64.b64encode(bytes(raw)).decode()
        self._fails(evidence, "INVALID")

    def test_a_changed_payload_with_its_hash_recomputed(self) -> None:
        evidence = _production_sample()
        evidence["fingerprint"]["spec_hash"] = "0" * 64
        payload = vf.canonical_payload(evidence["fingerprint"])
        evidence["signature"]["signed_payload_hash"] = "sha256:" + vf.hashlib.sha256(payload).hexdigest()
        self._fails(evidence, "INVALID")

    def test_a_changed_payload(self) -> None:
        evidence = _production_sample()
        evidence["fingerprint"]["spec_hash"] = "0" * 64
        self._fails(evidence, "signed_payload_hash does not match")

    def test_an_inline_key_that_is_not_the_published_one(self) -> None:
        evidence = _production_sample()
        evidence["signature"]["public_key"] = base64.b64encode(b"\x02" * 32).decode()
        self._fails(evidence, "not the one published")

    def test_an_unknown_key_id(self) -> None:
        evidence = _production_sample()
        evidence["signature"]["key_id"] = "dm-unknown"
        self._fails(evidence, "not a published DevMatrix key")

    def test_a_signature_outside_its_key_window(self) -> None:
        evidence = _production_sample()
        evidence["signature"]["signed_at"] = "2020-01-01T00:00:00+00:00"
        self._fails(evidence, "outside the window")

    def test_a_retired_key_after_its_window(self) -> None:
        name = "fingerprints/20260221_modular_hip_test_20260221_103259_a57210ff.json"
        evidence = _evidence(name)
        evidence["signature"]["signed_at"] = "2026-10-01T00:00:00+00:00"
        passed, lines = vf.verify_signature(evidence, KEYS)
        self.assertFalse(passed, lines)
        self.assertIn("outside the window", lines[-1])

    def test_another_algorithm(self) -> None:
        evidence = _production_sample()
        evidence["signature"]["algorithm"] = "RSA"
        self._fails(evidence, "unsupported algorithm")

    def test_a_signature_that_is_not_base64(self) -> None:
        evidence = _production_sample()
        evidence["signature"]["signature"] = "not base64!"
        self._fails(evidence, "signature is not base64")

    def test_a_signing_time_with_no_zone(self) -> None:
        evidence = _production_sample()
        evidence["signature"]["signed_at"] = "2026-10-06T13:03:14"
        self._fails(evidence, "names no time zone")

    def test_a_published_key_of_the_wrong_length(self) -> None:
        evidence = _production_sample()
        short = base64.b64encode(b"\x01" * 31).decode()
        evidence["signature"]["public_key"] = short
        keys = [dict(next(k for k in KEYS if k["key_id"] == evidence["signature"]["key_id"]), public_key=short)]
        passed, lines = vf.verify_signature(evidence, keys)
        self.assertFalse(passed, lines)
        self.assertIn("INVALID", lines[-1])

    def test_a_published_key_of_another_algorithm(self) -> None:
        evidence = _production_sample()
        keys = [dict(k, algorithm="RSA") for k in KEYS]
        passed, lines = vf.verify_signature(evidence, keys)
        self.assertFalse(passed, lines)
        self.assertIn("not an Ed25519 key", lines[-1])

    def test_a_file_with_no_signature(self) -> None:
        evidence = _production_sample()
        del evidence["signature"]
        self._fails(evidence, "carries no signed fingerprint")


def _run(*args: str, block_cryptography: bool = False) -> subprocess.CompletedProcess[str]:
    prelude = "import sys; sys.modules['cryptography'] = None; " if block_cryptography else ""
    code = (
        prelude
        + f"sys.argv = ['verify_fingerprint.py', *{list(args)!r}]; "
        + "import runpy; runpy.run_path('verify_fingerprint.py', run_name='__main__')"
    )
    if not block_cryptography:
        code = "import sys; " + code
    return subprocess.run(
        [sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=False
    )


class TheKeysFile(unittest.TestCase):
    def test_a_malformed_entry_is_an_error(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "keys.json"
            cases = {
                "an entry that is not an object": {"schema_id": vf.KEYS_SCHEMA_ID, "keys": [KEYS[0], "not an object"]},
                "the old form": {"keys": KEYS},
                "an entry with an undeclared field": {"schema_id": vf.KEYS_SCHEMA_ID, "keys": [dict(KEYS[0], anchor="x")]},
                "a kid that is not its key's": {"schema_id": vf.KEYS_SCHEMA_ID, "keys": [dict(KEYS[0], kid="sha256:" + "0" * 64)]},
                "one key listed twice": {"schema_id": vf.KEYS_SCHEMA_ID, "keys": [KEYS[0], dict(KEYS[0], status="revoked")]},
                "an unknown status": {"schema_id": vf.KEYS_SCHEMA_ID, "keys": [dict(KEYS[0], status="compromised")]},
            }
            for case, document in cases.items():
                with self.subTest(case=case):
                    path.write_text(json.dumps(document), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        vf.load_keys(path)

    def test_a_revoked_key_never_verifies(self) -> None:
        name = next(iter(EXPECTED))
        passed, lines = vf.verify_signature(_evidence(name), [dict(k, status="revoked") for k in KEYS])
        self.assertFalse(passed, lines)
        self.assertIn("REVOKED, not active or retired", lines[-1])

    def test_a_key_with_no_window_start_never_verifies(self) -> None:
        name = next(iter(EXPECTED))
        passed, lines = vf.verify_signature(_evidence(name), [dict(k, created_at=None) for k in KEYS])
        self.assertFalse(passed, lines)
        self.assertIn("names no window start", lines[-1])

    def test_only_an_active_or_retired_key_verifies(self) -> None:
        name = next(iter(EXPECTED))
        for status in ("Revoked", "suspended", ""):
            with self.subTest(status=status):
                passed, lines = vf.verify_signature(_evidence(name), [dict(k, status=status) for k in KEYS])
                self.assertFalse(passed, lines)
                self.assertIn("not active or retired", lines[-1])

    def test_a_key_listed_twice_never_verifies_whatever_the_order(self) -> None:
        name = next(iter(EXPECTED))
        for keys in (KEYS + [dict(k, status="revoked") for k in KEYS], [dict(k, status="revoked") for k in KEYS] + KEYS):
            passed, lines = vf.verify_signature(_evidence(name), keys)
            self.assertFalse(passed, lines)
            self.assertIn("more than once", lines[-1])

    def test_a_key_that_signs_no_evidence_never_verifies(self) -> None:
        name = next(iter(EXPECTED))
        passed, lines = vf.verify_signature(_evidence(name), [dict(k, purpose="seal-signing") for k in KEYS])
        self.assertFalse(passed, lines)
        self.assertIn("does not sign evidence", lines[-1])


PRODUCTION_PAIR = (
    "fingerprints/5fc1882a-0d3e-4bf0-b6a5-c5ba69820e5f/5fc1882a-0d3e-4bf0-b6a5-c5ba69820e5f.json",
    "fingerprints/ae86be9a-cb25-4178-9bb1-39bc0aacd0d3/ae86be9a-cb25-4178-9bb1-39bc0aacd0d3.json",
)

#: The two published attestations of one specification, schema /2.
ATTESTATION_PAIR = (
    "attestations/attestation/054abbd7-ef45-4e2f-a252-2f2ff833ad2d.json",
    "attestations/attestation/137c2ad3-a293-4173-ae39-2a4133ee136a.json",
)
#: The fields two runs of one specification differ in: when the run happened
#: and its own identifiers. The pair above shows it.
RUN_FIELDS = {
    "build_timestamp", "compile_attempt_id", "compiler_run_id",
    "dmx_build_identity.compile_attempt_id", "dmx_build_identity.compiler_run_id",
}


def _payload(name: str) -> dict:
    return vf.signed_payload(_evidence(name))


def _delivered() -> dict:
    """A delivered fingerprint-attestation/2 in every field its schema
    carries, with a path not covered that names its job, as builds deliver it."""
    job = "0f0e0d0c-0b0a-4909-8807-060504030201"
    digest = "sha256:" + "a" * 64
    tests = {key: 0 for key in vf.PRE_NDA_TEST_KEYS}
    tests.update(ran=True, total=3, passed=3, planned=3, not_reached=0, pass_rate=1.0)
    return {
        "schema": vf.DELIVERED_ATTESTATION_SCHEMA,
        "job_id": job,
        "reproducible_sha256": digest,
        "certificate_fingerprint": "sha256:" + "c" * 64,
        "legacy_links": {"gate_results_hash": "d" * 64},
        "coverage": {
            "covered": 2, "delivered_files": 3,
            "not_covered": [f"specification/{job}/app.dmx", "services/app/README.md"],
        },
        "signature": {
            "algorithm": "Ed25519", "key_id": "dm-prod-2026-01", "verify_key": "e" * 44,
            "signed_fields": ["attested", "coverage", "job_id", "reproducible", "schema"],
            "signed_at": "2026-11-24T09:00:00+00:00", "content_hash": "f" * 64, "signature": "g" * 88,
        },
        "reproducible": {
            "identity": {
                **{name: digest for name in vf.IDENTITY_LINKS_V3},
                vf.SERVICE_SPEC_HASHES: {"app": "b" * 64},
            },
            "merkle": {
                "algorithm": "sha256", "leaf_formula": "sha256(path || content)",
                "emit_root": "1" * 64, "nested_root": digest,
                "sub_roots": {name: "2" * 64 for name in vf.SUB_ROOT_NAMES},
                "emit_leaves": [
                    {"leaf_sha256": "3" * 64, "path": "services/app/main.py"},
                    {"leaf_sha256": "4" * 64, "path": "services/app/models.py"},
                ],
            },
            "modules": [{"module": "app", "emission_sha256": "5" * 64}],
        },
        "attested": {
            "not_tested_count": 0, "terminal_gate_verdict_hash": "6" * 64,
            "customer_checks": {
                "schema_id": "dmx_customer_checks/v9", "sealed_schema_id": "dmx_customer_checks/v9",
                "status": "projected", "scopes": [], "totals": {"passed": 3}, "tests": tests,
                "tests_absent_reason": None,
            },
            "modules": [{"module": "app", "status": "VERIFIED"}],
            "platform_verdict": {
                "all_gates_passed": True, "outcome": "succeeded", "terminal_success": True,
                "uts_disposition": "PASSED", "uts_not_run_reason": None,
            },
        },
    }


def _delivered_rerun(first: dict) -> dict:
    """Another run of the same build: its own job, signature and signing time."""
    second = copy.deepcopy(first)
    job = "11111111-2222-4333-8444-555555555555"
    second["job_id"] = job
    second["coverage"]["not_covered"] = [p.replace(first["job_id"], job) for p in first["coverage"]["not_covered"]]
    second["signature"] = dict(first["signature"], signed_at="2027-01-01T00:00:00+00:00",
                               content_hash="0" * 64, signature="AAAA")
    return second


def _attestation() -> dict:
    return copy.deepcopy(_payload(ATTESTATION_PAIR[0]))


class TheComparison(unittest.TestCase):
    def test_two_runs_of_one_specification_compare_identical_but_for_their_run(self) -> None:
        comparison = vf.compare_fingerprints(*(_payload(n) for n in PRODUCTION_PAIR))
        self.assertTrue(comparison.passed, comparison.differences)
        self.assertEqual(comparison.schema, vf.UNVERSIONED_FINGERPRINT)
        self.assertEqual((comparison.compared, comparison.identical), (22, 22))
        self.assertEqual(set(comparison.excluded), RUN_FIELDS)

    def test_one_module_emission_digest_differing_fails_by_its_path(self) -> None:
        """MUT-RED: lists are not walked (the module list is skipped)."""
        first = _attestation()
        second = _attestation()
        module = second["modules"][0]
        module["emission_sha256"] = "0" * 64
        comparison = vf.compare_fingerprints(first, second)
        self.assertFalse(comparison.passed)
        self.assertEqual(len(comparison.differences), 1, comparison.differences)
        self.assertTrue(
            comparison.differences[0].startswith(f"modules[{module['module']}].emission_sha256: DIFFERENT"),
            comparison.differences,
        )

    def test_modules_are_matched_by_name_not_by_position(self) -> None:
        first = _attestation()
        extra = {"module": "zz_second", "emission_sha256": "1" * 64}
        first["modules"] = [*first["modules"], extra]
        second = copy.deepcopy(first)
        second["modules"].reverse()
        self.assertTrue(vf.compare_fingerprints(first, second).passed)
        second["modules"] = [m for m in second["modules"] if m["module"] != "zz_second"]
        comparison = vf.compare_fingerprints(first, second)
        self.assertEqual(comparison.differences, ["modules[zz_second]: recorded only in the first document"])

    def test_the_order_of_the_emitted_leaves_is_content(self) -> None:
        first = _attestation()
        second = _attestation()
        leaves = second["merkle"]["emit_leaf_sha256"]
        leaves[0], leaves[1] = leaves[1], leaves[0]
        paths = [d.split(":")[0] for d in vf.compare_fingerprints(first, second).differences]
        self.assertEqual(paths, ["merkle.emit_leaf_sha256[0]", "merkle.emit_leaf_sha256[1]"])

    def test_a_run_field_differing_alone_compares_identical(self) -> None:
        first = _attestation()
        second = dict(_attestation(), job_id="00000000-0000-4000-8000-000000000000")
        comparison = vf.compare_fingerprints(first, second)
        self.assertTrue(comparison.passed, comparison.differences)
        self.assertIn("job_id", comparison.excluded)
        flat = _payload(PRODUCTION_PAIR[0])
        later = dict(flat, build_timestamp="2027-01-01T00:00:00")
        self.assertTrue(vf.compare_fingerprints(flat, later).passed)

    def test_a_field_unknown_to_the_table_fails_and_asks_for_an_update(self) -> None:
        first = _attestation()
        second = dict(_attestation(), new_digest="sha256:" + "2" * 64)
        comparison = vf.compare_fingerprints(first, second)
        self.assertEqual(
            comparison.differences,
            [f"new_digest: not in this verifier's table for {vf.ATTESTATION_SCHEMA_V2}: update the verifier"],
        )

    def test_a_schema_with_no_table_is_refused_never_compared_in_part(self) -> None:
        for schema in ("published-attestation/9", "published-platform-seal/1", None):
            with self.subTest(schema=schema):
                document = dict(_attestation(), schema=schema)
                with self.assertRaisesRegex(vf.ComparisonRefused, "update the verifier"):
                    vf.compare_fingerprints(document, document)

    def test_two_schemas_are_not_compared(self) -> None:
        with self.assertRaisesRegex(vf.ComparisonRefused, "different schemas"):
            vf.compare_fingerprints(_attestation(), _payload(PRODUCTION_PAIR[0]))

    def test_a_value_recorded_by_one_document_only_fails(self) -> None:
        first, second = (_payload(n) for n in PRODUCTION_PAIR)
        second = {k: v for k, v in second.items() if k != "spec_hash"}
        comparison = vf.compare_fingerprints(first, second)
        self.assertEqual(comparison.differences, ["spec_hash: recorded only in the first document"])

    def test_comparing_nothing_fails(self) -> None:
        comparison = vf.compare_fingerprints({}, {})
        self.assertEqual(comparison.compared, 0)
        self.assertFalse(comparison.passed)

    def test_every_published_document_compares_with_itself(self) -> None:
        names = sorted(EXPECTED) + sorted(
            str(p.relative_to(ROOT)) for p in (ROOT / "attestations").rglob("*.json")
        )
        self.assertGreater(len(names), len(EXPECTED))
        for name in names:
            with self.subTest(name=name):
                comparison = vf.compare_fingerprints(_payload(name), _payload(name))
                self.assertTrue(comparison.passed, comparison.differences)
                self.assertGreater(comparison.compared, 0)

    def test_two_published_runs_are_compared_on_their_emitted_files(self) -> None:
        """The two /2 attestations of one specification record the same
        module digests and differ in emitted files: the comparison names them."""
        comparison = vf.compare_fingerprints(*(_payload(n) for n in ATTESTATION_PAIR))
        paths = {d.split(":")[0] for d in comparison.differences}
        self.assertFalse(comparison.passed)
        self.assertIn("merkle.emit_root", paths)
        self.assertIn("merkle.emit_leaf_sha256[5]", paths)
        self.assertFalse(any(path.startswith("modules[") for path in paths))

    def test_each_table_names_exactly_the_fields_its_schema_declares(self) -> None:
        """MUT-RED: a schema gains a field and its comparison table does not."""
        declared = {
            vf.ATTESTATION_SCHEMA_V1: set(vf._V1_FIELDS),
            vf.ATTESTATION_SCHEMA_V2: set(vf._V2_FIELDS),
            vf.ATTESTATION_SCHEMA_V3: set(vf._V3_FIELDS),
            vf.PUBLISHED_FINGERPRINT_SCHEMA_V2: set(vf.PUBLISHED_FINGERPRINT_KEYS),
        }
        for schema, fields in declared.items():
            with self.subTest(schema=schema):
                self.assertEqual(set(vf.COMPARISON_TABLES[schema].fields), fields)

    def test_a_delivered_attestation_compares_with_another_run_of_its_build(self) -> None:
        """Two runs of one build: the job, the signature over each run and
        the job named in the paths not covered differ; nothing else."""
        first = _delivered()
        second = _delivered_rerun(first)
        comparison = vf.compare_fingerprints(first, second)
        self.assertEqual(comparison.schema, vf.DELIVERED_ATTESTATION_SCHEMA)
        self.assertTrue(comparison.passed, comparison.differences)
        self.assertEqual(
            set(comparison.excluded),
            {"job_id", "signature.signed_at", "signature.content_hash", "signature.signature"},
        )

    def test_a_delivered_attestation_differing_in_one_emitted_leaf_fails_by_its_path(self) -> None:
        """MUT-RED: the delivered table skips the Merkle leaves."""
        first = _delivered()
        second = _delivered_rerun(first)
        second["reproducible"]["merkle"]["emit_leaves"][0]["leaf_sha256"] = "0" * 64
        paths = [d.split(":")[0] for d in vf.compare_fingerprints(first, second).differences]
        self.assertEqual(paths, ["reproducible.merkle.emit_leaves[0].leaf_sha256"])

    def test_a_path_not_covered_is_read_without_the_job_that_names_it(self) -> None:
        """MUT-RED: the paths are compared raw, so every two runs differ."""
        first = _delivered()
        second = _delivered_rerun(first)
        self.assertTrue(vf.compare_fingerprints(first, second).passed)
        second["coverage"]["not_covered"] = [*second["coverage"]["not_covered"], "services/app/extra.txt"]
        self.assertEqual(
            vf.compare_fingerprints(first, second).differences,
            ["coverage.not_covered: 'services/app/extra.txt' recorded only in the second document"],
        )

    def test_only_run_fields_are_excluded(self) -> None:
        def excluded(rule: vf.FieldRule, path: str) -> set[str]:
            if isinstance(rule, vf.Excluded):
                return {path}
            if isinstance(rule, vf.Fields):
                return set().union(*(excluded(r, f"{path}.{k}".lstrip(".")) for k, r in rule.fields.items()))
            if isinstance(rule, (vf.Named, vf.OrderedList)):
                return excluded(rule.value if isinstance(rule, vf.Named) else rule.item, f"{path}[]")
            if isinstance(rule, vf.KeyedList):
                return excluded(rule.item, f"{path}[]")
            return set()

        found = {schema: excluded(table, "") for schema, table in vf.COMPARISON_TABLES.items()}
        self.assertEqual(found, {
            vf.ATTESTATION_SCHEMA_V1: {"job_id", "attestation_sha256"},
            vf.ATTESTATION_SCHEMA_V2: {"job_id", "attestation_sha256"},
            vf.ATTESTATION_SCHEMA_V3: {"job_id", "attestation_sha256"},
            vf.PUBLISHED_FINGERPRINT_SCHEMA_V2: {"job_id"},
            vf.DELIVERED_ATTESTATION_SCHEMA: {
                "job_id", "signature.signed_at", "signature.content_hash", "signature.signature",
            },
            vf.UNVERSIONED_FINGERPRINT: RUN_FIELDS | {"created_at", "run_id", "build_identity.resolved_at"},
        })


class TheCommandLine(unittest.TestCase):
    def test_the_documented_quick_check_passes(self) -> None:
        result = _run("-f", PRODUCTION_PAIR[0], "--compare", PRODUCTION_PAIR[1])
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("[OK] signature", result.stdout)
        self.assertIn("Compared by the build fingerprint (no schema named) table: 22 values, identical: 22", result.stdout)
        self.assertIn("[OK] every compared value is identical (22)", result.stdout)

    def test_a_key_of_another_class_is_refused_and_no_option_accepts_it(self) -> None:
        import tempfile
        name = next(iter(EXPECTED))
        with tempfile.TemporaryDirectory() as tmp:
            keys = Path(tmp) / "keys.json"
            keys.write_text(json.dumps({"schema_id": vf.KEYS_SCHEMA_ID, "keys": [dict(k, **{"class": "staging"}) for k in KEYS]}), encoding="utf-8")
            refused = _run("-f", name, "--compare", name, "--keys", str(keys))
        self.assertNotEqual(refused.returncode, 0, refused.stdout)
        self.assertIn("NOT a production key", refused.stdout)
        options = set(re.findall(r"(?<![\w-])--?[a-z][a-z-]*", _run("--help").stdout))
        self.assertEqual(
            options,
            {"-h", "--help", "-f", "--fingerprint", "-s", "--spec", "-o", "--output",
             "--compare", "--keys", "--allow-unsigned",
             # 2026-11-11: the seal binding names its inputs; none of them
             # accepts a key that is not a production key (the seal test
             # ``test_a_seal_key_that_is_not_a_production_key``).
             "--seal", "--attestation", "--published",
             # 2026-11-23: the seal's evidence bundle, read only as the
             # seal statement verified with a production key says.
             "--evidence",
             # 2026-11-23: the verdict as a JSON file, by reason class, for
             # comparing two verifiers over the same signed vectors.
             "--verdict-json"},
        )

    def test_without_cryptography_the_signature_fails_never_skips(self) -> None:
        name = next(n for n, c in EXPECTED.items() if c == "production")
        result = _run("-f", name, "--compare", name, block_cryptography=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("signature NOT verified", result.stdout)
        self.assertIn("VERIFICATION FAILED", result.stdout)

    def test_an_unsigned_flat_fingerprint_needs_the_flag(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            flat = Path(tmp) / "build_fingerprint.json"
            flat.write_text(json.dumps(_payload(PRODUCTION_PAIR[0])), encoding="utf-8")
            name = str(flat)
            refused = _run("-f", name, "--compare", name)
            allowed = _run("-f", name, "--compare", name, "--allow-unsigned")
        self.assertNotEqual(refused.returncode, 0, refused.stdout)
        self.assertIn("carries no signature", refused.stdout)
        self.assertEqual(allowed.returncode, 0, allowed.stdout)
        self.assertIn("UNSIGNED", allowed.stdout)


if __name__ == "__main__":
    unittest.main()

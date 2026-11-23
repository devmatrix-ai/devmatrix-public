"""From seal-statement/7 every sealed build states what its grade rests on
(the compile, a QA run on DevMatrix or the client's run), the build it seals,
the QA run it rests on, and its tests proven not applicable. The seal's
evidence bundle holds the QA run report and the proof rows; ``--evidence``
checks them against the signed statement:

    python verify_fingerprint.py --seal <bundle> --attestation <service>=<file> --evidence <evidence dir>

The evidence folder is untrusted: no link is followed, only the names an
evidence bundle holds are read, each within its bound. A seal never mixes
measurers. Without ``--evidence`` the verifier says what it did not check.

Run from the repository root: python -m unittest discover -s tests
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import verify_fingerprint as vf  # noqa: E402
from test_a_delivered_attestation_binds_to_its_seal import (  # noqa: E402
    _SERVICE,
    OneBuild,
    _client_statement6,
    _hex,
    _published,
    _run_by_client,
    _statement6,
)

_BUILD = "5d0c1f7e-3a2b-4c6d-8e9f-0a1b2c3d4e5f"
_RUN = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
_COLLECTED_IDS = ["tests/test_a.py::test_a", "tests/test_b.py::test_b"]
_COLLECTED = vf.collected_test_ids_sha256(_COLLECTED_IDS)


def _rows() -> list[dict]:
    """The proof rows of the build: one proven, one not shown."""
    return [
        {"module_id": _SERVICE, "test_id": "tests/test_p.py::test_p", "witnesses": ["tests/test_w.py::test_w"],
         "witnessed": True},
        {"module_id": _SERVICE, "test_id": "tests/test_q.py::test_q", "witnesses": [], "witnessed": False},
    ]


def _texts(found: tuple[list[str], list]) -> tuple[list[str], list[str]]:
    """The lines and the printed text of each failure."""
    lines, failures = found
    return lines, [failure.text for failure in failures]


def _run_by_the_client(document: dict) -> None:
    """The build was delivered with its tests left to the client."""
    document["attested"]["platform_verdict"] = {
        "uts_disposition": "NOT_RUN", "uts_not_run_reason": "runtime_phase_run_by_client",
    }


def _deferred_to_its_qa_run(document: dict) -> None:
    """The build was delivered with its tests deferred to a QA run."""
    document["attested"]["platform_verdict"] = {
        "uts_disposition": "NOT_RUN", "uts_not_run_reason": "runtime_phase_deferred_to_qa_run",
    }


def _proof_bytes(rows: list[dict]) -> bytes:
    return json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _report() -> dict:
    """A qa-run-report/2 of the build: 20 applicable, one UTS red, one
    emitted-suite red, one emitted test not run, and the proof rows."""
    return {
        "schema_id": "qa-run-report/2",
        "qa_run_id": _RUN,
        "attempt": 1,
        "compilation_id": _BUILD,
        "outcome": "completed",
        "grade_letter": "A",
        "score_percent": 95,
        "applicable": 20,
        "passed": 19,
        "reds_total": 1,
        "modules": [{"module_id": _SERVICE, "passed": 19, "applicable": 20}],
        "reds": [{"name": f"{_SERVICE}::uts::test_x", "module_id": _SERVICE, "tier": "uts",
                  "category": "other", "outcome": "failed"}],
        "advisory_reds": [],
        "emitted_suite": {
            "passed": 5, "failed": 1, "errors": 0,
            "reds": [{"name": "tests/test_e.py::test_e", "module_id": _SERVICE, "category": "other",
                      "outcome": "failed"}],
            "not_tested": [{"name": "tests/test_n.py::test_n", "module_id": _SERVICE, "category": "other",
                            "outcome": "not_tested", "reason": "skipped"}],
            "modules": [{
                "module_id": _SERVICE, "collected_test_ids": list(_COLLECTED_IDS),
                "collected_test_ids_sha256": _COLLECTED,
                "proven_not_applicable": [{k: v for k, v in row.items() if k != "module_id"} for row in _rows()],
            }],
        },
        "provenance": {"compiler_revision": "abc", "started_at": "2026-11-23T09:00:00Z",
                       "finished_at": "2026-11-23T10:00:00Z"},
    }


def _report_bytes(report: dict) -> bytes:
    return json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _proofs(service: dict, rows: list[dict] | None) -> None:
    """The service states the proofs of ``rows``, or none (``None``)."""
    if rows is None:
        service.update(proven_not_applicable_count=None, proven_not_applicable_tests=[],
                       proof_rows_sha256=None, collected_node_ids_sha256=None)
        return
    proven = [f"{row['module_id']}::{row['test_id']}" for row in rows if row["witnessed"]]
    service.update(
        proven_not_applicable_count=len(proven), proven_not_applicable_tests=proven,
        proof_rows_sha256=hashlib.sha256(_proof_bytes(rows)).hexdigest(),
        collected_node_ids_sha256={_SERVICE: _COLLECTED},
    )


def _on_the_compile(document: dict) -> dict:
    """A seal-statement/7 of a build DevMatrix tested at compile time."""
    statement = _statement6(document)
    statement["schema_id"] = "seal-statement/7"
    statement["services"][0].update(compilation_id=_BUILD, basis="compile", qa_run=None)
    _proofs(statement["services"][0], None)
    return statement


def _on_the_client_run(document: dict) -> dict:
    """A seal-statement/7 of a build its client tested, with its proofs."""
    statement = _client_statement6(document, 1, f"{_SERVICE}::tests/test_q.py::test_q")
    statement["schema_id"] = "seal-statement/7"
    statement["services"][0].update(compilation_id=_BUILD, basis="client_run", qa_run=None)
    _proofs(statement["services"][0], _rows())
    return statement


def _on_the_qa_run(document: dict, report: dict | None = None) -> dict:
    """A seal-statement/7 of a build measured by a QA run on DevMatrix."""
    report = _report() if report is None else report
    statement = _statement6(
        document, f"{_SERVICE}::tests/test_n.py::test_n", f"{_SERVICE}::tests/test_q.py::test_q",
        failed=(f"{_SERVICE}::uts::test_x",),
    )
    statement["schema_id"] = "seal-statement/7"
    service = statement["services"][0]
    service.update(
        compilation_id=_BUILD, basis="qa_run", grade="A", qa_score_hundredths=9500,
        qa_run={
            "qa_run_id": _RUN, "attempt": 1, "report_schema_id": "qa-run-report/2",
            "report_sha256": hashlib.sha256(_report_bytes(report)).hexdigest(),
            "finished_at": "2026-11-23T10:00:00.000000Z",
            "letter": "A", "score_percent": 95, "passed": 19, "applicable": 20,
            "emitted_failed_tests": [f"{_SERVICE}::tests/test_e.py::test_e"], "modules": 1,
        },
    )
    _proofs(service, _rows())
    return statement


def _evidence(folder: Path, statement: dict, files: dict[str, bytes], absent: list[dict] | None = None) -> Path:
    """An unzipped evidence bundle of ``statement`` holding ``files``, with
    its manifest and the statement's bytes as the seal bundle writes them."""
    held = dict(files)
    held["seal-statement.json"] = json.dumps(statement, sort_keys=True).encode("utf-8")
    manifest = {
        "schema": vf.EVIDENCE_SCHEMA, "seal_hash": statement["seal_hash"],
        "files": [{"path": name, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
                  for name, data in sorted(held.items())],
        "absent": absent or [],
    }
    held[vf.EVIDENCE_MANIFEST] = json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8")
    for name, data in held.items():
        path = folder / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return folder


def _qa_files(report: dict | None = None, rows: list[dict] | None = None) -> dict[str, bytes]:
    return {
        f"qa-runs/{_BUILD}/report.json": _report_bytes(_report() if report is None else report),
        f"proofs/{_BUILD}.json": _proof_bytes(_rows() if rows is None else rows),
    }


def _statement_bytes(statement: dict) -> bytes:
    return json.dumps(statement, sort_keys=True).encode("utf-8")


class ASealOfStatement7(unittest.TestCase):
    """What a seal-statement/7 states, read from the signed statement."""

    def _run(self, build: OneBuild, *extra: str):
        with tempfile.TemporaryDirectory() as tmp:
            return build.run(Path(tmp), *extra)

    def _refused(self, build: OneBuild, reason: str) -> None:
        result = self._run(build)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("[OK] seal: seal-statement/7", result.stdout)  # the signature verified first
        self.assertIn(f"[FAIL] {reason}", result.stdout)

    def test_a_build_sealed_on_its_compile(self) -> None:
        build = OneBuild()
        build.statement = _on_the_compile(build.document)
        result = self._run(build)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"      {_SERVICE}: rests on the compile of build {_BUILD}", result.stdout)
        self.assertIn(f"      {_SERVICE}: {vf.PROOFS_NOT_STATED}", result.stdout)
        self.assertNotIn("[NOT CHECKED]", result.stdout)

    def test_without_evidence_it_says_what_it_did_not_check(self) -> None:
        """MUT-RED: the NOT CHECKED line removed."""
        build = OneBuild()
        _run_by_client(build.document)
        build.statement = _on_the_client_run(build.document)
        build.published = dict(_published(build.document), run_by="client", seal_class="self_attested")
        result = self._run(build)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            f"[NOT CHECKED] {_SERVICE}: QA run report and proof rows not checked: no evidence given (--evidence)",
            result.stdout,
        )
        self.assertIn(f"      {_SERVICE}: 1 test proven not applicable", result.stdout)

    def test_a_client_run_seal_with_its_evidence(self) -> None:
        build = OneBuild()
        _run_by_client(build.document)
        build.statement = _on_the_client_run(build.document)
        build.published = dict(_published(build.document), run_by="client", seal_class="self_attested")
        with tempfile.TemporaryDirectory() as tmp:
            folder = _evidence(Path(tmp) / "evidence", build.statement,
                               {f"proofs/{_BUILD}.json": _proof_bytes(_rows())})
            result = build.run(Path(tmp), "--evidence", str(folder))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("[OK] evidence: the manifest names exactly the files held", result.stdout)
        self.assertIn(f"[OK] {_SERVICE}: proof rows proofs/{_BUILD}.json is the one the seal signed", result.stdout)
        self.assertNotIn("[NOT CHECKED]", result.stdout)

    def test_a_qa_run_seal_binds_to_its_deferred_build_with_its_evidence(self) -> None:
        """A build measured by a QA run was delivered with its tests deferred
        to that run; it binds to its seal like any other (contract §5 item 8)."""
        build = OneBuild()
        _deferred_to_its_qa_run(build.document)
        build.statement = _on_the_qa_run(build.document)
        build.published = None
        with tempfile.TemporaryDirectory() as tmp:
            folder = _evidence(Path(tmp) / "evidence", build.statement, _qa_files())
            result = build.run(Path(tmp), "--evidence", str(folder))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for line in (
            f"      {_SERVICE}: rests on QA run {_RUN} (attempt 1, qa-run-report/2",
            f"[OK] {_SERVICE}: the delivered attestation is the sealed one",
            f"[OK] {_SERVICE}: tests deferred to a QA run, as the seal states (rests on qa_run)",
            f"[OK] {_SERVICE}: QA run report qa-runs/{_BUILD}/report.json is the one the seal signed",
            "VERIFICATION PASSED",
        ):
            self.assertIn(line, result.stdout)

    def test_a_basis_its_delivered_attestation_does_not_state(self) -> None:
        """MUT-RED: the basis-runner binding removed."""
        for runner, statement_of, reason in (
            ("devmatrix", _on_the_qa_run, "the seal says its grade rests on qa_run, but its attestation says the "
                                          "tests were run by devmatrix"),
            ("client", _on_the_qa_run, "the seal says its grade rests on qa_run, but its attestation says the "
                                       "tests were run by client"),
            ("deferred", _on_the_compile, "the seal says its grade rests on compile, but its attestation says the "
                                          "tests were deferred to a QA run"),
            ("devmatrix", _on_the_client_run, "the seal says its grade rests on client_run, but its attestation "
                                              "says the tests were run by devmatrix"),
        ):
            with self.subTest(reason=reason):
                build = OneBuild()
                if runner == "deferred":
                    _deferred_to_its_qa_run(build.document)
                elif runner == "client":
                    _run_by_the_client(build.document)
                build.statement = statement_of(build.document)
                build.published = None
                result = self._run(build)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(f"[FAIL] {_SERVICE}: {reason}", result.stdout)

    def test_a_client_run_seal_binds_to_a_deferred_build(self) -> None:
        """A paid build with no completed QA run may be run by the client
        (contract §5 item 9): its client-run seal binds."""
        for runner in ("client", "deferred"):
            with self.subTest(runner=runner):
                build = OneBuild()
                if runner == "deferred":
                    _deferred_to_its_qa_run(build.document)
                else:
                    _run_by_the_client(build.document)
                build.statement = _on_the_client_run(build.document)
                build.published = None
                result = self._run(build)
                shown = "deferred to a QA run" if runner == "deferred" else "run by client"
                self.assertIn(f"[OK] {_SERVICE}: tests {shown}, as the seal states (rests on client_run)",
                              result.stdout)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("VERIFICATION PASSED", result.stdout)

    def test_a_deferred_build_before_statement_7_does_not_bind(self) -> None:
        build = OneBuild()
        _deferred_to_its_qa_run(build.document)
        build.statement = _statement6(build.document)
        build.published = None
        result = self._run(build)
        self.assertIn(f"[FAIL] {_SERVICE}: the seal says the build was measured by devmatrix, but its attestation "
                      "says the tests were deferred to a QA run", result.stdout)

    def test_a_deferred_build_has_no_published_attestation_to_bind(self) -> None:
        """No published attestation version states a QA-run runner, so it is
        refused by name, never projected as another runner."""
        build = OneBuild()
        _deferred_to_its_qa_run(build.document)
        build.statement = _on_the_qa_run(build.document)
        result = self._run(build)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(f"[FAIL] {_SERVICE}: the delivered attestation says its tests were deferred to a QA run, "
                      "which no published attestation version states; bind it to its seal without --published", result.stdout)

    def test_a_seal_that_mixes_measurers(self) -> None:
        """MUT-RED: the mixture check removed (§8a)."""
        build = OneBuild()
        build.statement = _on_the_compile(build.document)
        other = copy.deepcopy(_on_the_client_run(build.document)["services"][0])
        other["name"] = "zz-billing"
        build.statement["services"].append(other)
        self._refused(build, "the signed statement is refused by its content: it mixes builds measured by "
                             "['devmatrix', 'self_attested'] in one seal")

    def test_a_self_attested_seal_over_two_builds(self) -> None:
        build = OneBuild()
        _run_by_client(build.document)
        build.statement = _on_the_client_run(build.document)
        other = copy.deepcopy(build.statement["services"][0])
        other["name"] = "zz-billing"
        build.statement["services"].append(other)
        self._refused(build, "the signed statement is refused by its content: it is self-attested over 2 builds")

    def test_an_a_plus_beside_proofs_not_stated(self) -> None:
        """MUT-RED: the A+ check of /7 removed."""
        build = OneBuild()
        build.statement = _on_the_compile(build.document)
        build.statement["services"][0]["grade"] = "A+"
        self._refused(build, f"{_SERVICE}: the signed statement is refused by its content: it is graded A+ "
                             "beside tests proven not applicable it does not state")

    def test_a_basis_its_measurer_does_not_measure(self) -> None:
        """MUT-RED: the basis-measurer check removed."""
        build = OneBuild()
        build.statement = _on_the_compile(build.document)
        build.statement["services"][0]["basis"] = "client_run"
        self._refused(build, f"{_SERVICE}: the signed statement is refused by its content: it rests on "
                             "client_run but states it was measured by devmatrix")

    def test_counts_where_the_version_says_none_or_one(self) -> None:
        """MUT-RED: the version predicate of the null count removed."""
        for change, reason in (
            ("compile_count", "rests on the compile and states a count of tests proven not applicable"),
            ("v2_null", "rests on a QA run report that states proofs and states no count of them"),
            ("v1_count", "rests on a QA run report that predates proofs and states a count of them"),
        ):
            with self.subTest(change=change):
                build = OneBuild()
                if change == "compile_count":
                    build.statement = _on_the_compile(build.document)
                    _proofs(build.statement["services"][0], _rows())
                else:
                    build.statement = _on_the_qa_run(build.document)
                    service = build.statement["services"][0]
                    if change == "v2_null":
                        _proofs(service, None)
                    else:
                        service["qa_run"]["report_schema_id"] = "qa-run-report/1"
                self._refused(build, f"{_SERVICE}: the signed statement is refused by its content: it {reason}")

    def test_a_qa_run_report_1_states_no_proofs(self) -> None:
        statement = _on_the_qa_run(OneBuild().document)
        service = statement["services"][0]
        service["qa_run"]["report_schema_id"] = "qa-run-report/1"
        _proofs(service, None)
        lines, failures = _texts(vf.seal_floor_findings(statement))
        self.assertEqual(failures, [])
        self.assertIn(f"      {_SERVICE}: {vf.PROOFS_NOT_STATED}", lines)

    def test_proofs_that_do_not_hold(self) -> None:
        """MUT-RED: each proofs rule removed in turn."""
        for change, reason in (
            ({"proven_not_applicable_count": 2}, "counts 2 tests proven not applicable but names 1"),
            ({"proven_not_applicable_tests": ["no-module-separator"]},
             "its tests proven not applicable are not each named <module>::<test> once, in order"),
            ({"proven_not_applicable_tests": [f"{_SERVICE}::tests/test_q.py::test_q"]},
             "a test it names proven not applicable is also named failed or not judged"),
            ({"collected_node_ids_sha256": {_SERVICE: None}},
             f"proves tests not applicable in modules whose collected tests it does not digest: ['{_SERVICE}']"),
            ({"proof_rows_sha256": None}, "states no digest of its proof rows"),
        ):
            with self.subTest(reason=reason):
                statement = _on_the_qa_run(OneBuild().document)
                statement["services"][0].update(change)
                _, failures = _texts(vf.seal_floor_findings(statement))
                self.assertEqual(failures, [f"{_SERVICE}: the signed statement is refused by its content: it {reason}"])

    def test_a_qa_run_stated_inexactly(self) -> None:
        """MUT-RED: each QA run rule removed in turn."""
        for field, value, reason in (
            ("letter", "B", "states a grade that is not its QA run's"),
            ("score_percent", 96, "states a score that is not its QA run's"),
            ("passed", 18, "does not name every test its QA run failed"),
            ("report_schema_id", "qa-run-report/3", "names a QA run report of an unknown version 'qa-run-report/3'"),
            ("qa_run_id", "run-1", "names no QA run by its id"),
            ("modules", 0, "states no count of the modules its QA run measured"),
            ("emitted_failed_tests", ["b", "a"], "its emitted suite's failed tests are not each named once, in order"),
        ):
            with self.subTest(field=field):
                statement = _on_the_qa_run(OneBuild().document)
                statement["services"][0]["qa_run"][field] = value
                _, failures = _texts(vf.seal_floor_findings(statement))
                self.assertEqual(failures, [f"{_SERVICE}: the signed statement is refused by its content: it {reason}"])
        statement = _on_the_compile(OneBuild().document)
        statement["services"][0]["qa_run"] = _on_the_qa_run(OneBuild().document)["services"][0]["qa_run"]
        _, failures = _texts(vf.seal_floor_findings(statement))
        self.assertEqual(failures, [f"{_SERVICE}: the signed statement is refused by its content: it rests on compile "
                                    "and names a QA run"])

    def test_every_earlier_version_is_read_as_before(self) -> None:
        for version in ("seal-statement/3", "seal-statement/4"):
            with self.subTest(version=version):
                build = OneBuild()
                build.statement["schema_id"] = version
                result = self._run(build)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("rests on", result.stdout)
                self.assertNotIn("[NOT CHECKED]", result.stdout)


class AHostileSealStatement(unittest.TestCase):
    def test_a_statement_nested_too_deep_is_refused_not_a_traceback(self) -> None:
        """MUT-RED: the statement parsed without catching nesting too deep."""
        build = OneBuild()
        with tempfile.TemporaryDirectory() as tmp:
            build.run(Path(tmp))
            (Path(tmp) / "seal" / "seal-statement.json").write_bytes(b"[" * 100_000)
            with self.assertRaises(vf.BindingRefused) as raised:
                vf.read_seal(Path(tmp) / "seal", build.keys)
        self.assertEqual(str(raised.exception), "the seal statement is not JSON")


class TheEvidence(unittest.TestCase):
    """The evidence bundle checked against a verified seal-statement/7."""

    def _findings(self, statement: dict, files: dict[str, bytes], absent: list[dict] | None = None,
                  change=None) -> tuple[list[str], list[str]]:
        with tempfile.TemporaryDirectory() as tmp:
            folder = _evidence(Path(tmp) / "evidence", statement, files, absent)
            if change is not None:
                change(folder)
            return _texts(vf.evidence_findings(folder, statement, _statement_bytes(statement)))

    def test_the_report_and_the_proofs_agree_with_the_seal(self) -> None:
        statement = _on_the_qa_run(OneBuild().document)
        lines, failures = self._findings(statement, _qa_files())
        self.assertEqual(failures, [])
        self.assertIn(f"[OK] {_SERVICE}: QA run report qa-runs/{_BUILD}/report.json is the one the seal signed, "
                      "and agrees with it", lines)
        self.assertIn(f"[OK] {_SERVICE}: proof rows proofs/{_BUILD}.json is the one the seal signed, and agrees with it",
                      lines)

    def test_one_flipped_byte_in_each_signed_file_fails(self) -> None:
        """MUT-RED per field class: the report digest, the proof rows digest,
        the manifest's digest of a file, and the statement it holds."""
        statement = _on_the_qa_run(OneBuild().document)

        def flip(name: str):
            def change(folder: Path) -> None:
                path = folder / name
                data = bytearray(path.read_bytes())
                data[len(data) // 2] ^= 0x01
                path.write_bytes(bytes(data))
            return change

        for name, reason in (
            (f"qa-runs/{_BUILD}/report.json", f"{_SERVICE}: the QA run report is not the one the seal signed (report_sha256)"),
            (f"proofs/{_BUILD}.json", f"{_SERVICE}: the proof rows file is not the one the seal signed (proof_rows_sha256)"),
            ("seal-statement.json", "evidence: the bundle's seal-statement.json is not the statement verified"),
        ):
            with self.subTest(name=name):
                _, failures = self._findings(statement, _qa_files(), change=flip(name))
                self.assertIn(reason, failures)
                self.assertIn(f"evidence: '{name}' is not the file the manifest names", failures)

    def test_a_report_that_says_otherwise_than_the_seal(self) -> None:
        """MUT-RED per report field class: a run field, the reds, the
        emitted reds, the tests not run, the finish instant, the collected
        digests and the proof rows."""
        cases = (
            (lambda r: r.update(attempt=2), f"{_SERVICE}: the QA run report states attempt 2, the seal 1"),
            (lambda r: r.update(compilation_id=_RUN), f"{_SERVICE}: the QA run report states build '{_RUN}', the seal '{_BUILD}'"),
            (lambda r: r.update(grade_letter="B"), f"{_SERVICE}: the QA run report states grade 'B', the seal 'A'"),
            (lambda r: r["modules"].append({"module_id": "billing", "passed": 1, "applicable": 1}),
             f"{_SERVICE}: the QA run report measured 2 modules, the seal 1"),
            (lambda r: r["reds"][0].update(name=f"{_SERVICE}::uts::test_y"),
             f"{_SERVICE}: the seal's failed tests are not the QA run report's reds"),
            (lambda r: r["emitted_suite"]["reds"][0].update(module_id="billing"),
             f"{_SERVICE}: the seal's emitted suite failures are not the QA run report's"),
            (lambda r: r["emitted_suite"]["not_tested"][0].update(name="tests/test_m.py::test_m"),
             f"{_SERVICE}: tests the QA run did not test that the seal does not name not judged: "
             f"['{_SERVICE}::tests/test_m.py::test_m']"),
            (lambda r: r["provenance"].update(finished_at="2026-11-23T10:00:01Z"),
             f"{_SERVICE}: the QA run report finished at '2026-11-23T10:00:01Z', the seal says '2026-11-23T10:00:00.000000Z'"),
            (lambda r: r["emitted_suite"]["modules"][0].update(
                collected_test_ids=["tests/test_c.py::test_c"],
                collected_test_ids_sha256=vf.collected_test_ids_sha256(["tests/test_c.py::test_c"])),
             f"{_SERVICE}: the seal's collected test digests are not the QA run report's"),
            (lambda r: r["emitted_suite"]["modules"][0].update(collected_test_ids_sha256=_hex("6")),
             f"{_SERVICE}: the QA run report's collected test digest for {_SERVICE} is not the digest of the tests "
             "it collected"),
            (lambda r: r["emitted_suite"]["modules"][0].update(collected_test_ids=list(reversed(_COLLECTED_IDS))),
             f"{_SERVICE}: the QA run report's collected tests for {_SERVICE} are not strictly ordered test ids"),
            (lambda r: r["emitted_suite"]["modules"][0].pop("collected_test_ids"),
             f"{_SERVICE}: the QA run report does not state its modules' collected tests and proofs"),
            (lambda r: r["emitted_suite"]["modules"][0]["proven_not_applicable"][1].update(witnesses=["x"]),
             f"{_SERVICE}: the proof rows the seal digests are not the QA run report's"),
            (lambda r: r["emitted_suite"]["modules"][0].update(proven_not_applicable=None),
             f"{_SERVICE}: the QA run report states no proofs for ['{_SERVICE}'], and the seal states a count"),
        )
        for change, reason in cases:
            with self.subTest(reason=reason):
                report = _report()
                change(report)
                statement = _on_the_qa_run(OneBuild().document, report)  # the seal signs this report's digest
                _, failures = self._findings(statement, _qa_files(report))
                self.assertIn(reason, failures)

    def test_proof_rows_that_do_not_hold(self) -> None:
        """MUT-RED: the serialization, the order, the witnessed set, the not
        shown rows."""
        cases = (
            (_proof_bytes(_rows()) + b"\n", "the proof rows file is not written in the seal's serialization"),
            (_proof_bytes(list(reversed(_rows()))), "the proof rows are not each once, sorted by module and test"),
            (_proof_bytes([dict(_rows()[0], witnessed=False), _rows()[1]]),
             "the witnessed proof rows are not the tests the seal states proven not applicable"),
            (_proof_bytes(_rows() + [{"module_id": _SERVICE, "test_id": "tests/test_r.py::test_r", "witnesses": [],
                                       "witnessed": False}]),
             f"proofs not shown that the seal does not name not judged: ['{_SERVICE}::tests/test_r.py::test_r']"),
        )
        for data, reason in cases:
            with self.subTest(reason=reason):
                document = OneBuild().document
                _run_by_client(document)
                statement = _on_the_client_run(document)
                statement["services"][0]["proof_rows_sha256"] = hashlib.sha256(data).hexdigest()
                _, failures = self._findings(statement, {f"proofs/{_BUILD}.json": data})
                self.assertIn(f"{_SERVICE}: {reason}", failures)

    def test_a_file_the_seal_rests_on_that_is_not_held(self) -> None:
        statement = _on_the_qa_run(OneBuild().document)
        files = _qa_files()
        del files[f"qa-runs/{_BUILD}/report.json"]
        _, failures = self._findings(statement, files)
        self.assertIn(f"{_SERVICE}: the bundle neither holds its QA run report qa-runs/{_BUILD}/report.json "
                      "nor lists it absent", failures)

    def test_the_proofs_of_a_client_run_are_checked_too(self) -> None:
        """Proof rows carry a signed digest whatever the basis: a client run
        that states proofs has them checked, absent or flipped fails."""
        build = OneBuild()
        _run_by_client(build.document)
        statement = _on_the_client_run(build.document)
        name = f"proofs/{_BUILD}.json"
        rows = _proof_bytes(_rows())
        lines, failures = self._findings(statement, {name: rows})
        self.assertEqual(failures, [])
        self.assertIn(f"[OK] {_SERVICE}: proof rows {name} is the one the seal signed, and agrees with it", lines)
        flipped = rows[:-2] + bytes([rows[-2] ^ 1]) + rows[-1:]
        _, failures = self._findings(statement, {name: flipped})
        self.assertEqual(failures, [f"{_SERVICE}: the proof rows file is not the one the seal signed (proof_rows_sha256)"])
        _, failures = self._findings(statement, {}, [{"path": name, "state": "not_found", "reason": "purged"}])
        self.assertEqual(failures, [f"{_SERVICE}: the bundle lists its proof rows {name} absent ('not_found': "
                                    "'purged'), and the seal rests on it"])

    def test_a_file_the_seal_rests_on_listed_absent_fails(self) -> None:
        """MUT-RED: an absent file the statement signs the digest of left unchecked."""
        statement = _on_the_qa_run(OneBuild().document)
        files = _qa_files()
        del files[f"qa-runs/{_BUILD}/report.json"]
        absent = [{"path": f"qa-runs/{_BUILD}/report.json", "state": "not_found", "reason": "purged"}]
        _, failures = self._findings(statement, files, absent)
        self.assertEqual(failures, [f"{_SERVICE}: the bundle lists its QA run report qa-runs/{_BUILD}/report.json "
                                    "absent ('not_found': 'purged'), and the seal rests on it"])

    def test_a_report_the_seal_does_not_rest_on(self) -> None:
        statement = _on_the_compile(OneBuild().document)
        _, failures = self._findings(statement, _qa_files())
        self.assertIn(f"evidence: files the seal does not rest on: ['proofs/{_BUILD}.json', "
                      f"'qa-runs/{_BUILD}/report.json']", failures)

    def test_a_hostile_manifest_is_a_failure_never_a_traceback(self) -> None:
        """MUT-RED: only ValueError caught, or a path not checked as text."""
        statement = _on_the_qa_run(OneBuild().document)
        for content, reason in (
            (b"[" * 100_000, f"evidence: {vf.EVIDENCE_MANIFEST} is not JSON"),
            (json.dumps({"schema": vf.EVIDENCE_SCHEMA, "seal_hash": statement["seal_hash"],
                         "files": [{"path": [1], "sha256": "x", "size_bytes": 1}], "absent": []}).encode(),
             "evidence: the manifest's files are not each a path, a digest and a size"),
            (json.dumps({"schema": vf.EVIDENCE_SCHEMA, "seal_hash": statement["seal_hash"], "files": [],
                         "absent": [{"path": "a", "state": {"x": 1}, "reason": None}]}).encode(),
             "evidence: the manifest's absent files are not each a path, a state and a reason"),
            (json.dumps({"schema": vf.EVIDENCE_SCHEMA, "seal_hash": statement["seal_hash"], "files": [],
                         "absent": [{"path": "a", "state": "gone", "reason": ["x"]}]}).encode(),
             "evidence: the manifest's absent files are not each a path, a state and a reason"),
        ):
            with self.subTest(reason=reason):
                def hostile(folder: Path, content: bytes = content) -> None:
                    (folder / vf.EVIDENCE_MANIFEST).write_bytes(content)
                _, failures = self._findings(statement, _qa_files(), change=hostile)
                self.assertIn(reason, failures)

    def test_an_absent_reason_is_printed_escaped(self) -> None:
        """MUT-RED: the state and reason printed raw."""
        statement = _on_the_qa_run(OneBuild().document)
        files = _qa_files()
        del files[f"qa-runs/{_BUILD}/report.json"]
        absent = [{"path": f"qa-runs/{_BUILD}/report.json", "state": "gone", "reason": "x\n[OK] fine"}]
        _, failures = self._findings(statement, files, absent)
        self.assertEqual(failures, [f"{_SERVICE}: the bundle lists its QA run report qa-runs/{_BUILD}/report.json "
                                    "absent ('gone': 'x\\n[OK] fine'), and the seal rests on it"])

    def test_a_manifest_of_another_seal(self) -> None:
        statement = _on_the_qa_run(OneBuild().document)

        def other_seal(folder: Path) -> None:
            manifest = json.loads((folder / vf.EVIDENCE_MANIFEST).read_text())
            manifest["seal_hash"] = _hex("0")
            (folder / vf.EVIDENCE_MANIFEST).write_text(json.dumps(manifest))
        _, failures = self._findings(statement, _qa_files(), change=other_seal)
        self.assertIn("evidence: the bundle is of another seal than the statement verified", failures)


class AnUntrustedEvidenceFolder(unittest.TestCase):
    """The evidence folder is read as untrusted: refused, never followed."""

    def _refused(self, change, reason: str) -> None:
        statement = _on_the_qa_run(OneBuild().document)
        with tempfile.TemporaryDirectory() as tmp:
            folder = _evidence(Path(tmp) / "evidence", statement, _qa_files())
            change(Path(tmp), folder)
            lines, failures = _texts(vf.evidence_findings(folder, statement, _statement_bytes(statement)))
        self.assertEqual(lines, [])
        self.assertEqual(len(failures), 1, failures)
        self.assertIn(reason, failures[0])

    def test_a_file_that_is_a_link(self) -> None:
        """MUT-RED: the regular-file check removed (the link would be read)."""
        def link(tmp: Path, folder: Path) -> None:
            (tmp / "outside.json").write_text("{}")
            os.symlink(tmp / "outside.json", folder / "verify.py")
        self._refused(link, "'verify.py' is not a regular file (a link is not followed)")

    def test_a_folder_that_is_a_link(self) -> None:
        """MUT-RED: the folder-link check removed."""
        def link(tmp: Path, folder: Path) -> None:
            (tmp / "elsewhere").mkdir()
            os.symlink(tmp / "elsewhere", folder / "client-runs")
        self._refused(link, "'client-runs' is a link; links are not followed")

    def test_the_folder_itself_a_link(self) -> None:
        statement = _on_the_qa_run(OneBuild().document)
        with tempfile.TemporaryDirectory() as tmp:
            folder = _evidence(Path(tmp) / "evidence", statement, _qa_files())
            os.symlink(folder, Path(tmp) / "alias")
            _, failures = _texts(vf.evidence_findings(Path(tmp) / "alias", statement, _statement_bytes(statement)))
        self.assertIn("is not a folder (a link is not followed)", failures[0])

    def test_a_name_an_evidence_bundle_never_holds(self) -> None:
        """MUT-RED: the name check removed."""
        for name, reason in (
            ("notes.txt", "'notes.txt' is not a file an evidence bundle holds"),
            ("qa-runs/not-a-uuid/report.json", "'qa-runs/not-a-uuid' is not a folder an evidence bundle holds"),
            ("proofs/../x.json", "'x.json' is not a file an evidence bundle holds"),
            (f"proofs/{_BUILD}.json.bak", f"'proofs/{_BUILD}.json.bak' is not a file an evidence bundle holds"),
            ("client-runs/x/client-verification.json", "'client-runs/x' is not a folder an evidence bundle holds"),
        ):
            with self.subTest(name=name):
                def add(tmp: Path, folder: Path, name: str = name) -> None:
                    path = folder / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("{}")
                self._refused(add, reason)

    def test_a_file_over_its_bound(self) -> None:
        """MUT-RED: the per-file bound removed."""
        def big(tmp: Path, folder: Path) -> None:
            (folder / "VERIFY.md").write_bytes(b"x" * (vf.EVIDENCE_OTHER_MAX_BYTES + 1))
        self._refused(big, "'VERIFY.md' is over its bound of 1048576 bytes")

    def test_an_unknown_folder_even_empty(self) -> None:
        """MUT-RED: the folder name check removed."""
        self._refused(lambda tmp, folder: (folder / "extra").mkdir(), "'extra' is not a folder an evidence bundle holds")

    def test_a_folder_that_cannot_be_read(self) -> None:
        """MUT-RED: unreadable folders skipped in silence. As root, which
        reads every folder, the walk's error is injected instead."""
        locked: list[Path] = []

        def lock(tmp: Path, folder: Path) -> None:
            (folder / "client-runs").mkdir()
            os.chmod(folder / "client-runs", 0)
            locked.append(folder / "client-runs")
        walk = os.walk
        if os.geteuid() == 0:
            def failing_walk(top, onerror=None, followlinks=False):
                onerror(PermissionError(13, "Permission denied", str(Path(top) / "client-runs")))
                return iter(())
            os.walk = failing_walk
        try:
            self._refused(lock, "a folder of the evidence bundle cannot be read")
        finally:
            os.walk = walk
            for path in locked:
                if path.exists():
                    os.chmod(path, 0o700)

    def test_a_fifo_is_not_read(self) -> None:
        """MUT-RED: the regular-file check removed (reading would block)."""
        self._refused(lambda tmp, folder: os.mkfifo(folder / "VERIFY.md"),
                      "'VERIFY.md' is not a regular file (a link is not followed)")

    def test_a_name_with_control_characters_is_printed_escaped(self) -> None:
        """MUT-RED: names printed raw."""
        def add(tmp: Path, folder: Path) -> None:
            (folder / "x\n[OK] all good\x1b[8m").write_text("{}")
        statement = _on_the_qa_run(OneBuild().document)
        with tempfile.TemporaryDirectory() as tmp:
            folder = _evidence(Path(tmp) / "evidence", statement, _qa_files())
            add(Path(tmp), folder)
            _, failures = _texts(vf.evidence_findings(folder, statement, _statement_bytes(statement)))
        self.assertEqual(failures, ["evidence: 'x\\n[OK] all good\\x1b[8m' is not a file an evidence bundle holds"])

    def test_more_files_than_its_bound(self) -> None:
        """MUT-RED: the count bound removed."""
        saved = vf.EVIDENCE_MAX_FILES
        vf.EVIDENCE_MAX_FILES = 3
        try:
            self._refused(lambda tmp, folder: None, "the evidence bundle holds more than 3 files")
        finally:
            vf.EVIDENCE_MAX_FILES = saved

    def test_more_bytes_than_its_bound(self) -> None:
        """MUT-RED: the total bound removed."""
        saved = vf.evidence_total_cap
        vf.evidence_total_cap = lambda services: 1000
        try:
            self._refused(lambda tmp, folder: None, "the evidence bundle is over its bound of 1000 bytes")
        finally:
            vf.evidence_total_cap = saved



class TheVerdictJson(unittest.TestCase):
    """``--verdict-json`` names the verdict and the reason class of every
    failure (contract §5 item 11); the printed verdict and the exit status
    are those without it."""

    def _verdict(self, build: OneBuild, evidence=None) -> tuple[dict, subprocess.CompletedProcess[str]]:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "verdict.json"
            extra = ["--verdict-json", str(out)]
            if evidence is not None:
                extra += ["--evidence", str(evidence(Path(tmp)))]
            result = build.run(Path(tmp), *extra)
            return json.loads(out.read_text(encoding="utf-8")), result

    def _deferred_on_its_qa_run(self) -> OneBuild:
        build = OneBuild()
        _deferred_to_its_qa_run(build.document)
        build.statement = _on_the_qa_run(build.document)
        build.published = None
        return build

    def test_a_binding_that_holds(self) -> None:
        build = self._deferred_on_its_qa_run()
        verdict, result = self._verdict(build, lambda tmp: _evidence(tmp / "evidence", build.statement, _qa_files()))
        self.assertEqual(verdict, {"verdict": "VERIFIED", "reason_classes": [], "key_class": "production"})
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_a_run_that_stops_early_leaves_no_earlier_verdict(self) -> None:
        """MUT-RED: the verdict file not reset at the start of a run."""
        build = OneBuild()
        build.published = None
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "verdict.json"
            out.write_text(json.dumps({"verdict": "VERIFIED", "reason_classes": [], "key_class": "production"}))
            keys = Path(tmp) / "refused-keys.json"
            keys.write_text("{}", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(vf.__file__), "--keys", str(keys), "--seal", str(Path(tmp) / "seal"),
                 "--attestation", f"{_SERVICE}={Path(tmp) / 'none.json'}", "--verdict-json", str(out)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertEqual(json.loads(out.read_text(encoding="utf-8")),
                             {"verdict": "FAILED", "reason_classes": ["unclassified"], "key_class": None})
            self.assertEqual(sorted(path.name for path in Path(tmp).iterdir()),
                             ["refused-keys.json", "verdict.json"])

    def test_the_printed_verdict_is_the_same_without_it(self) -> None:
        build = self._deferred_on_its_qa_run()
        build.statement["services"][0]["basis"] = "compile"
        runs = []
        for extra in ((), ("--verdict-json",)):
            with tempfile.TemporaryDirectory() as tmp:
                args = [*extra, str(Path(tmp) / "verdict.json")] if extra else []
                result = build.run(Path(tmp), *args)
                runs.append((result.returncode, result.stdout.replace(tmp, "<tmp>")))
        self.assertEqual(runs[0], runs[1])
        self.assertEqual(runs[0][0], 1)

    def test_each_failure_names_its_class(self) -> None:
        """MUT-RED: a producer's class changed."""
        def runner() -> tuple[OneBuild, object]:
            build = OneBuild()
            build.statement = _on_the_qa_run(build.document)
            build.published = None
            return build, lambda tmp: _evidence(tmp / "evidence", build.statement, _qa_files())

        def mixture() -> tuple[OneBuild, object]:
            build = OneBuild()
            build.statement = _on_the_compile(build.document)
            other = copy.deepcopy(_on_the_client_run(build.document)["services"][0])
            other["name"] = "zz-billing"
            build.statement["services"].append(other)
            return build, None

        def unknown_version() -> tuple[OneBuild, object]:
            build = OneBuild()
            build.statement["schema_id"] = "seal-statement/8"
            return build, None

        def signature() -> tuple[OneBuild, object]:
            build = OneBuild()
            build.signing_key = vf_test_other_key()
            return build, None

        def attestation_digest() -> tuple[OneBuild, object]:
            build = OneBuild()
            build.statement["services"][0]["fingerprint_attestation"]["document_sha256"] = "sha256:" + _hex("9")
            build.published = None
            return build, None

        def published_deferred() -> tuple[OneBuild, object]:
            build = self._deferred_on_its_qa_run()
            build.published = _published(OneBuild().document)
            return build, lambda tmp: _evidence(tmp / "evidence", build.statement, _qa_files())

        def evidence_refused() -> tuple[OneBuild, object]:
            build = self._deferred_on_its_qa_run()

            def folder(tmp: Path) -> Path:
                made = _evidence(tmp / "evidence", build.statement, _qa_files())
                (tmp / "outside.json").write_text("{}")
                os.symlink(tmp / "outside.json", made / "verify.py")
                return made
            return build, folder

        def evidence_tampered() -> tuple[OneBuild, object]:
            build = self._deferred_on_its_qa_run()
            files = _qa_files()
            name = f"qa-runs/{_BUILD}/report.json"
            files[name] = files[name][:-2] + bytes([files[name][-2] ^ 1]) + files[name][-1:]
            return build, lambda tmp: _evidence(tmp / "evidence", build.statement, files)

        def attestation_identity() -> tuple[OneBuild, object]:
            build = OneBuild()
            build.data = b"[" * 100_000
            build.published = None
            return build, None

        def evidence_absent() -> tuple[OneBuild, object]:
            build = self._deferred_on_its_qa_run()
            files = _qa_files()
            del files[f"proofs/{_BUILD}.json"]
            absent = [{"path": f"proofs/{_BUILD}.json", "state": "not_found", "reason": "purged"}]
            return build, lambda tmp: _evidence(tmp / "evidence", build.statement, files, absent)

        for expected, make in (
            ("evidence_absent", evidence_absent),
            ("attestation_identity", attestation_identity),
            ("runner", runner), ("mixture", mixture), ("unknown_version", unknown_version),
            ("signature", signature), ("attestation_digest", attestation_digest),
            ("published_deferred", published_deferred), ("evidence_refused", evidence_refused),
            ("evidence_tampered", evidence_tampered),
        ):
            with self.subTest(expected=expected):
                build, evidence = make()
                verdict, result = self._verdict(build, evidence)
                self.assertEqual(verdict["verdict"], "FAILED", result.stdout)
                self.assertEqual(verdict["reason_classes"], [expected], result.stdout)
                self.assertEqual(verdict["key_class"], "production")
                self.assertEqual(result.returncode, 1)


def vf_test_other_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.generate()


if __name__ == "__main__":
    unittest.main()

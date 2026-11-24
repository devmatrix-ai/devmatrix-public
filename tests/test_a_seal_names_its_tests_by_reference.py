"""From seal-statement/8 a seal names every test by a reference, never by the
name the build was tested under: a UTS test by its module, its tier's tenant
name, the tier's family and an opaque id; a test of the delivered suite by its
module and node id. The statement names the key the ids were derived under
(``test_id_key``), and a QA run it rests on is bound through the sealed
projection of its report (``qa-run-report-sealed/1``), whose reds carry the
same ids. The verifier never needs that key, and refuses a statement that
carries anything in its place.

Run from the repository root: python -m unittest discover -s tests
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import verify_fingerprint as vf  # noqa: E402
from test_a_delivered_attestation_binds_to_its_seal import _SERVICE, OneBuild, _run_by_client  # noqa: E402
from test_a_seal_states_what_its_grade_rests_on import (  # noqa: E402
    _BUILD,
    _evidence,
    _on_the_client_run,
    _on_the_compile,
    _on_the_qa_run,
    _proof_bytes,
    _published,
    _report,
    _report_bytes,
    _rows,
)

_KEY = "sti-test-2026-11"
_ID = "t" + "1" * 32
_OTHER_ID = "t" + "2" * 32
#: The name the build's UTS red was tested under: never printed from /8 on.
_INTERNAL = f"{_SERVICE}::uts::test_x"
_UTS = {"kind": "uts", "module_id": _SERVICE, "tier": "Contracts", "tier_category": "contracts", "id": _ID}


def _ordered(refs: list[dict]) -> list[dict]:
    return sorted(refs, key=lambda ref: json.dumps(ref, sort_keys=True, separators=(",", ":")).encode())


def _ref(name: str) -> dict:
    """The /8 reference of a test a /7 statement names: the UTS red by its
    id, any other by its module and node id."""
    if name == _INTERNAL:
        return dict(_UTS)
    module, node = name.split("::", 1)
    return {"kind": "suite", "module_id": module, "node_id": node}


def _sealed_report() -> dict:
    """The sealed projection of the QA run report: its reds by reference."""
    report = _report()
    report.update(schema_id=vf.QA_RUN_REPORT_SEALED, source_schema_id="qa-run-report/2")
    report["reds"] = [{"module_id": _SERVICE, "tier": "Contracts", "tier_category": "contracts", "id": _ID,
                       "category": "other", "outcome": "failed"}]
    return report


def _as_8(statement: dict, report: dict | None = None) -> dict:
    """``statement`` as the seal-statement/8 of the same build."""
    statement = copy.deepcopy(statement)
    statement.update(schema_id=vf.SEAL_STATEMENT_WITH_TEST_IDS, test_id_key=_KEY, key_id="seal-test")
    for service in statement["services"]:
        service["failed_tests"] = _ordered([_ref(name) for name in service["failed_tests"]])
        service["not_judged_tests"] = _ordered([_ref(name) for name in service["not_judged_tests"]])
        service["not_run_tiers"] = [
            {"module_id": tier["group"].split("::")[0], "tier": tier["tier"], "tier_category": "contracts",
             "count": tier["count"]}
            for tier in service["not_run_tiers"]
        ]
        if service["basis"] == "qa_run":
            sealed = _sealed_report() if report is None else report
            service["qa_run"].update(
                report_schema_id=vf.QA_RUN_REPORT_SEALED, source_schema_id="qa-run-report/2",
                report_sha256=hashlib.sha256(_report_bytes(sealed)).hexdigest(),
            )
    return statement


def _qa_build(report: dict | None = None) -> OneBuild:
    build = OneBuild()
    build.document["attested"]["platform_verdict"] = {
        "uts_disposition": "NOT_RUN", "uts_not_run_reason": "runtime_phase_deferred_to_qa_run",
    }
    build.statement = _as_8(_on_the_qa_run(build.document), report)
    build.published = None
    return build


def _sealed_files(report: dict | None = None) -> dict[str, bytes]:
    return {
        f"qa-runs/{_BUILD}/report.json": _report_bytes(_sealed_report() if report is None else report),
        f"proofs/{_BUILD}.json": _proof_bytes(_rows()),
    }


class ASealOfStatement8(unittest.TestCase):
    def _run(self, build: OneBuild, files: dict[str, bytes] | None = None):
        with tempfile.TemporaryDirectory() as tmp:
            extra: list[str] = []
            if files is not None:
                extra = ["--evidence", str(_evidence(Path(tmp) / "evidence", build.statement, files))]
            return build.run(Path(tmp), *extra)

    def _verified(self, build: OneBuild, files: dict[str, bytes] | None = None) -> str:
        result = self._run(build, files)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"[OK] seal: test ids derived under key {_KEY}", result.stdout)
        return result.stdout

    def _refused(self, build: OneBuild, text: str, files: dict[str, bytes] | None = None) -> str:
        result = self._run(build, files)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("[OK] seal: seal-statement/8", result.stdout)  # the signature verified first
        self.assertIn(text, result.stdout)
        return result.stdout

    def test_a_build_sealed_on_its_compile(self) -> None:
        build = OneBuild()
        build.statement = _as_8(_on_the_compile(build.document))
        self._verified(build)

    def test_a_qa_run_seal_prints_each_test_by_reference_with_its_evidence(self) -> None:
        """MUT-RED: the line printed from the name instead of the reference."""
        out = self._verified(_qa_build(), _sealed_files())
        self.assertIn(f"      {_SERVICE}: failed {_SERVICE} · Contracts (contracts) · {_ID}", out)
        self.assertIn(f"      {_SERVICE}: not measured {_SERVICE} · tests/test_n.py::test_n", out)
        self.assertIn(f"[OK] {_SERVICE}: QA run report qa-runs/{_BUILD}/report.json is the one the seal signed", out)
        self.assertNotIn("test_x", out)

    def test_a_client_run_seal_names_its_failed_tests_by_node_id(self) -> None:
        build = OneBuild()
        _run_by_client(build.document)
        statement = _on_the_client_run(build.document)
        statement["services"][0]["failed_tests"] = [f"{_SERVICE}::tests/test_f.py::test_f"]
        statement["services"][0]["self_attested_grade"]["passed"] = (
            statement["services"][0]["self_attested_grade"]["applicable"] - 1
        )
        build.statement = _as_8(statement)
        build.published = dict(_published(build.document), run_by="client", seal_class="self_attested")
        out = self._verified(build)
        self.assertIn(f"      {_SERVICE}: failed {_SERVICE} · tests/test_f.py::test_f", out)

    def test_a_tier_not_run_is_printed_by_its_module_and_tenant_name(self) -> None:
        build = OneBuild()
        build.statement = _as_8(_on_the_compile(build.document))
        service = build.statement["services"][0]
        service.update(not_run_tiers=[{"module_id": _SERVICE, "tier": "Security", "tier_category": "security",
                                       "count": 3}], not_judged_count=3, grade="A")
        out = self._verified(build)
        self.assertIn(f"      {_SERVICE}: {_SERVICE} · Security: 3 checks not run", out)

    def test_a_statement_that_refers_to_its_tests_otherwise(self) -> None:
        """MUT-RED: each check of a reference removed in turn; each case names
        the one check that refuses it, its counts kept whole."""
        twin = dict(_UTS, tier="Behavior", tier_category="behavior")
        cases = {
            "a name": (lambda s: s["failed_tests"].__setitem__(0, _INTERNAL),
                       "its failed tests list one that is not a test reference"),
            "another kind": (lambda s: s["failed_tests"].__setitem__(0, dict(_UTS, kind="named")),
                             "list one that is not a reference of the kind its basis names"),
            "a suite reference on a DevMatrix measure": (lambda s: s["failed_tests"].__setitem__(
                0, {"kind": "suite", "module_id": _SERVICE, "node_id": "tests/test_x.py::test_x"}),
                "list one that is not a reference of the kind its basis names"),
            "a field more": (lambda s: s["failed_tests"].__setitem__(0, dict(_UTS, name=_INTERNAL)),
                             "list one that is not exactly the fields of its kind"),
            "a line break": (lambda s: s["failed_tests"].__setitem__(0, dict(_UTS, tier="Con\ntracts")),
                             "list one that holds a field that is not printable text"),
            "no opaque id": (lambda s: s["failed_tests"].__setitem__(0, dict(_UTS, id="x" * 33)),
                             "list one that has no opaque test id"),
            "an unknown family": (lambda s: s["failed_tests"].__setitem__(0, dict(_UTS, tier_category="other")),
                                  "list one that names a family that is not a UTS tier family"),
            "out of order": (lambda s: s.__setitem__("not_judged_tests", list(reversed(s["not_judged_tests"]))),
                             "its tests not judged are not each referenced once, in order"),
            "one id twice in a list": (lambda s: s.__setitem__("failed_tests", _ordered([dict(_UTS), twin])),
                                       "its failed tests name one UTS test id twice"),
            "a failed id also not judged": (
                lambda s: s.__setitem__("not_judged_tests", _ordered([twin, s["not_judged_tests"][0]])),
                "a UTS test id it names not judged is also named failed"),
        }
        for case, (edit, text) in cases.items():
            with self.subTest(case=case):
                build = _qa_build()
                edit(build.statement["services"][0])
                out = self._refused(build, text)
                self.assertNotIn(_INTERNAL, out)

    def test_a_self_attested_seal_names_no_uts_test_not_judged(self) -> None:
        """MUT-RED: the kinds of a self-attested not judged list widened."""
        build = OneBuild()
        _run_by_client(build.document)
        build.statement = _as_8(_on_the_client_run(build.document))
        build.statement["services"][0]["not_judged_tests"] = [dict(_UTS)]
        build.published = dict(_published(build.document), run_by="client", seal_class="self_attested")
        self._refused(build, "its tests not judged list one that is not a reference of the kind its basis names")

    def test_references_are_ordered_by_their_ascii_escaped_bytes(self) -> None:
        """A node id beyond ASCII sorts by its escaped bytes, as the signer's
        canonical JSON writes it. MUT-RED: the order taken from UTF-8 bytes."""
        build = OneBuild()
        build.statement = _as_8(_on_the_compile(build.document))
        refs = [{"kind": "suite", "module_id": _SERVICE, "node_id": f"tests/t.py::test[{c}]"} for c in ("z", "é")]
        build.statement["services"][0].update(not_judged_tests=_ordered(refs), not_judged_count=2, grade="A")
        self.assertEqual(build.statement["services"][0]["not_judged_tests"][0]["node_id"], "tests/t.py::test[é]")
        self._verified(build)

    def test_a_refusal_never_prints_what_a_reference_holds(self) -> None:
        """MUT-RED: a refusal text that repeats the reference."""
        build = _qa_build()
        build.statement["services"][0]["failed_tests"][0]["name"] = "internal-node-name-not-for-print"
        out = self._refused(build, "list one that is not exactly the fields of its kind")
        self.assertNotIn("internal-node-name-not-for-print", out)

    def test_the_key_of_the_ids_is_named_by_a_key_id(self) -> None:
        """MUT-RED: the key id shape or the exact field set not checked. The
        shape refuses what no key id can be (padding, capitals, 64 characters
        and more); a short lowercase string is a key id by shape, so that key
        material never travels rests on the signer, not on this check."""
        cases = {
            "no key named": lambda s: s.pop("test_id_key"),
            "base64 key material": lambda s: s.__setitem__("test_id_key", "a2V5LW1hdGVyaWFs" * 4 + "=="),
            "longer than a key id": lambda s: s.__setitem__("test_id_key", "0" * 64),
            "capitals": lambda s: s.__setitem__("test_id_key", "Sti-test-2026-11"),
            "a field more": lambda s: s.__setitem__("test_id_secret", "k" * 32),
        }
        for case, edit in cases.items():
            with self.subTest(case=case):
                build = OneBuild()
                build.statement = _as_8(_on_the_compile(build.document))
                edit(build.statement)
                out = self._refused(build, "the signed statement is refused by its content: it ")
                self.assertNotIn("a2V5LW1hdGVyaWFs", out)
                self.assertNotIn("k" * 32, out)
                self.assertNotIn("Sti-test", out)

    def test_a_tier_not_run_declared_as_before(self) -> None:
        build = OneBuild()
        build.statement = _as_8(_on_the_compile(build.document))
        build.statement["services"][0].update(
            not_run_tiers=[{"group": f"{_SERVICE}::Security::*", "tier": "Security", "count": 3}],
            not_judged_count=3, grade="A",
        )
        self._refused(build, "a tier not run it declares is not a module, a tier, a family and a count")

    def test_a_tier_not_run_declared_otherwise(self) -> None:
        """MUT-RED: each check of a tier not run removed in turn."""
        tier = {"module_id": _SERVICE, "tier": "Security", "tier_category": "security", "count": 3}
        cases = {
            "no module": ([dict(tier, module_id="")], "does not name its module and tier"),
            "a line break": ([dict(tier, tier="Secu\nrity")], "does not name its module and tier"),
            "an unknown family": ([dict(tier, tier_category="other")], "names a family that is not a UTS tier family"),
            "no count": ([dict(tier, count=0)], "has no whole count above zero"),
            "a part count": ([dict(tier, count=1.5)], "has no whole count above zero"),
            "twice": ([tier, dict(tier, tier_category="behavior")], "its tiers not run are not each declared once"),
            "out of order": ([dict(tier, tier="Security"), dict(tier, tier="Behavior")],
                             "its tiers not run are not each declared once, in order"),
        }
        for case, (tiers, text) in cases.items():
            with self.subTest(case=case):
                build = OneBuild()
                build.statement = _as_8(_on_the_compile(build.document))
                build.statement["services"][0].update(not_run_tiers=tiers, grade="A")
                self._refused(build, text)

    def test_a_qa_run_bound_otherwise(self) -> None:
        """MUT-RED: the sealed version or its source not checked."""
        for case, edit, text in (
            ("no source version", lambda run: run.pop("source_schema_id"), "rests on a QA run it does not state exactly"),
            ("an unsealed report", lambda run: run.update(report_schema_id="qa-run-report/2"),
             f"names a QA run report that is not a {vf.QA_RUN_REPORT_SEALED}"),
            ("an unknown source", lambda run: run.update(source_schema_id="qa-run-report/9"),
             "names a QA run report projected from an unknown version"),
        ):
            with self.subTest(case=case):
                build = _qa_build()
                edit(build.statement["services"][0]["qa_run"])
                self._refused(build, text)

    def test_a_source_report_that_predates_proofs_states_no_count(self) -> None:
        build = _qa_build()
        build.statement["services"][0]["qa_run"]["source_schema_id"] = "qa-run-report/1"
        self._refused(build, "rests on a QA run report that predates proofs and states a count of them")


class TheSealedReport(unittest.TestCase):
    _run = ASealOfStatement8._run

    def _tampered(self, report: dict, text: str) -> str:
        """A seal that signs ``report`` and names its failed test by ``_UTS``."""
        build = _qa_build(report)
        result = self._run(build, _sealed_files(report))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(text, result.stdout)
        return result.stdout

    def test_a_red_of_another_id(self) -> None:
        """MUT-RED: the ids not compared."""
        report = _sealed_report()
        report["reds"][0]["id"] = _OTHER_ID
        self._tampered(report, "the seal's failed tests are not the sealed QA run report's reds, by id")

    def test_a_red_of_another_tier(self) -> None:
        """MUT-RED: only the ids compared."""
        report = _sealed_report()
        report["reds"][0]["tier"] = "Behavior"
        self._tampered(report, "has another module, tier or family than its red")

    def test_a_red_that_still_carries_its_name(self) -> None:
        """MUT-RED: the red's exact fields not checked."""
        report = _sealed_report()
        report["reds"][0]["name"] = _INTERNAL
        out = self._tampered(report, "the sealed QA run report's reds are not each a test reference")
        self.assertNotIn(_INTERNAL, out)

    def test_an_advisory_red_that_carries_its_name(self) -> None:
        report = _sealed_report()
        report["advisory_reds"] = [dict(report["reds"][0], id=_OTHER_ID, name=_INTERNAL)]
        out = self._tampered(report, "the sealed QA run report's advisory reds are not each a test reference")
        self.assertNotIn(_INTERNAL, out)

    def test_a_red_listed_twice(self) -> None:
        """MUT-RED: the reds' once-in-order check removed (the ids would fold)."""
        report = _sealed_report()
        report["reds"] = _ordered([report["reds"][0], dict(report["reds"][0], category="security")])
        self._tampered(report, "the sealed QA run report's reds are not each once, in order")

    def test_a_report_projected_from_another_version(self) -> None:
        report = _sealed_report()
        report["source_schema_id"] = "qa-run-report/1"
        self._tampered(report, "the QA run report states source version")


if __name__ == "__main__":
    unittest.main()

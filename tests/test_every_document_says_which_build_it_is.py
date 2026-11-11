"""Every document the verifier reads says which build, job or run it is.

THE DEFECT (measured 2026-11-11 on build 5c9aab67): the verifier printed
``Build ID: N/A`` and ``Timestamp: N/A`` for a published attestation, which
names itself by ``job_id``. ``N/A`` read as "this document names no build";
the document named its job.

Now the header prints the identity and the time each kind of document
declares (``build_id``, ``job_id`` or ``run_id``; ``build_timestamp`` or
``created_at``), and when it was published, marked as outside the signature.
A document that names none is refused, never shown as ``N/A``.

MUT-RED: the header reads ``build_id`` only again -> the attestation legs RED.
"""
from __future__ import annotations

import importlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
vf = importlib.import_module("verify_fingerprint")

#: Every published document of this repository, fingerprints and attestations.
PUBLISHED = sorted(
    str(p.relative_to(ROOT)).replace("\\", "/")
    for folder in ("fingerprints", "attestations")
    for p in (ROOT / folder).rglob("*.json")
)


def _evidence(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    code = (
        f"import sys; sys.argv = ['verify_fingerprint.py', *{list(args)!r}]; "
        "import runpy; runpy.run_path('verify_fingerprint.py', run_name='__main__')"
    )
    return subprocess.run(
        [sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=False
    )


class EveryPublishedDocument(unittest.TestCase):
    def test_the_census_reads_attestations_and_fingerprints(self) -> None:
        self.assertTrue(any(n.startswith("attestations/") for n in PUBLISHED), PUBLISHED)
        self.assertTrue(any(n.startswith("fingerprints/") for n in PUBLISHED), PUBLISHED)

    def test_each_names_the_identity_it_declares(self) -> None:
        for name in PUBLISHED:
            with self.subTest(name=name):
                evidence = _evidence(name)
                payload = vf.signed_payload(evidence)
                lines = vf.identity_lines(evidence)
                declared = [
                    f"{label}: {payload[field]}"
                    for field, label in vf.IDENTITY_FIELDS
                    if payload.get(field)
                ]
                self.assertTrue(declared, name)
                self.assertEqual(lines[: len(declared)], declared)
                self.assertFalse(any("N/A" in line for line in lines), lines)

    def test_an_attestation_is_named_by_its_job(self) -> None:
        name = next(n for n in PUBLISHED if n.startswith("attestations/"))
        job = vf.signed_payload(_evidence(name))["job_id"]
        result = _run("-f", name)
        self.assertIn(f"Job ID: {job}", result.stdout)
        self.assertNotIn("N/A", result.stdout)

    def test_a_document_that_names_nothing_is_refused(self) -> None:
        with self.assertRaises(vf.IdentityMissing):
            vf.identity_lines({"fingerprint": {"merkle_root": "0" * 64}})


if __name__ == "__main__":
    unittest.main()

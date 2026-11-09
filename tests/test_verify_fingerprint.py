"""Every published fingerprint's signature verifies against keys.json, and the
verifier fails, never skips, on anything it cannot prove.

Run from the repository root: python -m unittest discover -s tests
(needs the ``cryptography`` package, as the verifier does).
"""

from __future__ import annotations

import base64
import json
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
    "fingerprints/20260226_modular_hip_test_20260221_103259_0d1cc2ed.json": "development",
    "fingerprints/20260226_modular_hip_test_20260221_103259_0fe80102.json": "development",
    "fingerprints/20260226_modular_hip_test_20260221_103259_5ac138f8.json": "development",
    "fingerprints/20260227_modular_hip_test_20260221_103259_0fe80102.json": "development",
    "fingerprints/20260307_modular_hip_test_20260221_103259_06795d66.json": "development",
    "fingerprints/20260307_modular_hip_test_20260221_103259_78c759c7.json": "development",
    "fingerprints/20260307_modular_hip_test_20260221_103259_aa4f830a.json": "development",
    "fingerprints/20260307_modular_hip_test_20260221_103259_c21a5055.json": "development",
    "fingerprints/20260309_modular_hip_test_20260221_103259_37461c8e.json": "development",
    "fingerprints/20260309_modular_hip_test_20260221_103259_d1944e6e.json": "development",
    "fingerprints/20260310_modular_hip_test_20260221_103259_50241602.json": "development",
    "fingerprints/20260312_modular_hip_test_20260221_103259_7601fde4.json": "development",
    "fingerprints/20260326_modular_hip_demo_1_20260323_001610_a204d694.json": "production",
    "fingerprints/20260326_modular_hip_demo_1_20260323_001610_a899023a.json": "production",
    "fingerprints/20260327_modular_hip_demo_1_20260323_001610_0eb9c5d4.json": "production",
    "fingerprints/20260329_modular_hip_demo_1_20260323_001610_500ea2a3.json": "production",
    "fingerprints/20260329_modular_hip_demo_1_20260323_001610_64294ea4.json": "production",
    "fingerprints/20260329_modular_hip_demo_1_20260323_001610_90719278.json": "production",
    "fingerprints/20260330_modular_hip_demo_1_20260323_001610_f210ce5a.json": "production",
    "fingerprints/20260616_825ab1f9_88cb_443d_ace3_9a7986f53f9c_825ab1f9.json": "local",
    "fingerprints/20260616_c4de1106_ee10_425a_b0f8_cb6e2a98b9e6_c4de1106.json": "local",
    "fingerprints/20260618_bf9f5c6f_bd6c_4af7_896a_e2db7c38dbad_bf9f5c6f.json": "local",
    "fingerprints/20260704_hip_identity_BID.json": "production",
    "fingerprints/2db8e0ba-7642-44b7-8e66-d5aaacdba1cf/2db8e0ba-7642-44b7-8e66-d5aaacdba1cf.json": "production",
    "fingerprints/5fc1882a-0d3e-4bf0-b6a5-c5ba69820e5f/5fc1882a-0d3e-4bf0-b6a5-c5ba69820e5f.json": "production",
    "fingerprints/ae86be9a-cb25-4178-9bb1-39bc0aacd0d3/ae86be9a-cb25-4178-9bb1-39bc0aacd0d3.json": "production",
}


def _evidence(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def _production_sample() -> dict:
    return _evidence(next(n for n, c in EXPECTED.items() if c == "production"))


def _development_sample() -> dict:
    return _evidence(next(n for n, c in EXPECTED.items() if c == "development"))


KEYS = vf.load_keys(vf.KEYS_FILE)


class EveryPublishedFingerprint(unittest.TestCase):
    def test_the_census_is_the_repository(self) -> None:
        found = {
            str(p.relative_to(ROOT)).replace("\\", "/")
            for p in (ROOT / "fingerprints").rglob("*.json")
        }
        self.assertEqual(found, set(EXPECTED))

    def test_each_verifies_with_its_published_key(self) -> None:
        for name, key_class in EXPECTED.items():
            with self.subTest(name=name):
                passed, lines = vf.verify_signature(_evidence(name), KEYS, allow_non_production=True)
                self.assertTrue(passed, lines)
                self.assertIn(f"({key_class})", lines[0])

    def test_only_production_keys_pass_by_default(self) -> None:
        for name, key_class in EXPECTED.items():
            with self.subTest(name=name):
                passed, lines = vf.verify_signature(_evidence(name), KEYS)
                self.assertEqual(passed, key_class == "production", lines)
                if key_class != "production":
                    self.assertIn("NOT a production key", lines[-1])


class ATamperedSignatureFails(unittest.TestCase):
    def _fails(self, evidence: dict, reason: str) -> None:
        passed, lines = vf.verify_signature(evidence, KEYS, allow_non_production=True)
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
        evidence["signature"]["public_key"] = _development_sample()["signature"]["public_key"]
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


class TheCommandLine(unittest.TestCase):
    def test_a_production_fingerprint_passes(self) -> None:
        name = next(n for n, c in EXPECTED.items() if c == "production")
        result = _run("-f", name, "--compare", name)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("[OK] signature", result.stdout)

    def test_a_development_fingerprint_fails_unless_allowed(self) -> None:
        name = next(n for n, c in EXPECTED.items() if c == "development")
        refused = _run("-f", name, "--compare", name)
        self.assertNotEqual(refused.returncode, 0, refused.stdout)
        self.assertIn("NOT a production key", refused.stdout)
        allowed = _run("-f", name, "--compare", name, "--allow-non-production")
        self.assertEqual(allowed.returncode, 0, allowed.stdout)
        self.assertIn("[WARN]", allowed.stdout)

    def test_without_cryptography_the_signature_fails_never_skips(self) -> None:
        name = next(n for n, c in EXPECTED.items() if c == "production")
        result = _run("-f", name, "--compare", name, block_cryptography=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("signature NOT verified", result.stdout)
        self.assertIn("VERIFICATION FAILED", result.stdout)

    def test_an_unsigned_flat_fingerprint_needs_the_flag(self) -> None:
        name = "examples/build_fingerprint_example.json"
        refused = _run("-f", name, "--compare", name)
        self.assertNotEqual(refused.returncode, 0, refused.stdout)
        self.assertIn("carries no signature", refused.stdout)
        allowed = _run("-f", name, "--compare", name, "--allow-unsigned")
        self.assertEqual(allowed.returncode, 0, allowed.stdout)
        self.assertIn("UNSIGNED", allowed.stdout)


if __name__ == "__main__":
    unittest.main()

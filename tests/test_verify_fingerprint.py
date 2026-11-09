"""Every published fingerprint's signature verifies against keys.json, and the
verifier fails, never skips, on anything it cannot prove.

Run from the repository root: python -m unittest discover -s tests
(needs the ``cryptography`` package, as the verifier does).
"""

from __future__ import annotations

import base64
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
        keys = [dict(k, public_key=short) for k in KEYS if k["key_id"] == evidence["signature"]["key_id"]]
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
            path.write_text(json.dumps({"keys": [KEYS[0], "not an object"]}), encoding="utf-8")
            with self.assertRaises(ValueError):
                vf.load_keys(path)

    def test_a_key_not_published_independently_says_so(self) -> None:
        for name in EXPECTED:
            with self.subTest(name=name):
                passed, lines = vf.verify_signature(_evidence(name), KEYS)
                self.assertTrue(passed, lines)
                self.assertTrue(any("published only in keys.json" in line for line in lines), lines)


PRODUCTION_PAIR = (
    "fingerprints/5fc1882a-0d3e-4bf0-b6a5-c5ba69820e5f/5fc1882a-0d3e-4bf0-b6a5-c5ba69820e5f.json",
    "fingerprints/ae86be9a-cb25-4178-9bb1-39bc0aacd0d3/ae86be9a-cb25-4178-9bb1-39bc0aacd0d3.json",
)

#: Evidence files whose fingerprint records no hash at all.
RECORDS_NO_HASH = {"fingerprints/20260330_modular_hip_demo_1_20260323_001610_f210ce5a.json"}


def _payload(name: str) -> dict:
    return vf.signed_payload(_evidence(name))


class TheComparison(unittest.TestCase):
    def test_two_runs_of_one_specification_compare_every_hash_identical(self) -> None:
        results = vf.compare_fingerprints(*(_payload(n) for n in PRODUCTION_PAIR))
        self.assertEqual(
            [path for path, _, _ in results],
            ["code_bundle_hash", "ir_semantic_hash", "ir_structural_hash", "security_arc_hash", "spec_hash"],
        )
        self.assertTrue(all(passed for _, passed, _ in results), results)

    def test_nested_hashes_are_compared_by_their_path(self) -> None:
        nested = {"ir_hashes": {"spec_hash": "a" * 64}}
        results = vf.compare_fingerprints(nested, dict(nested))
        self.assertIn("ir_hashes.spec_hash", [path for path, _, _ in results])

    def test_a_changed_hash_fails(self) -> None:
        first, second = (_payload(n) for n in PRODUCTION_PAIR)
        second = dict(second, code_bundle_hash="0" * 64)
        results = dict((path, passed) for path, passed, _ in vf.compare_fingerprints(first, second))
        self.assertFalse(results["code_bundle_hash"])

    def test_a_hash_recorded_by_one_fingerprint_only_fails(self) -> None:
        first, second = (_payload(n) for n in PRODUCTION_PAIR)
        second = {k: v for k, v in second.items() if k != "spec_hash"}
        results = {path: (passed, message) for path, passed, message in vf.compare_fingerprints(first, second)}
        self.assertFalse(results["spec_hash"][0])
        self.assertIn("only in the first", results["spec_hash"][1])

    def test_two_fingerprints_with_no_hash_fail(self) -> None:
        (name,) = RECORDS_NO_HASH
        results = vf.compare_fingerprints(_payload(name), _payload(name))
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0][1])
        self.assertIn("nothing compared", results[0][2])

    def test_the_signature_is_not_compared_as_a_hash(self) -> None:
        paths = vf.hash_fields(_payload(PRODUCTION_PAIR[0]))
        self.assertNotIn("signed_payload_hash", " ".join(paths))

    def test_which_evidence_records_hashes(self) -> None:
        empty = {name for name in EXPECTED if not vf.hash_fields(_payload(name))}
        self.assertEqual(empty, RECORDS_NO_HASH)


class TheCommandLine(unittest.TestCase):
    def test_the_documented_quick_check_passes(self) -> None:
        result = _run("-f", PRODUCTION_PAIR[0], "--compare", PRODUCTION_PAIR[1])
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("[OK] signature", result.stdout)
        self.assertIn("Hashes compared by path: 5, identical: 5", result.stdout)

    def test_a_key_of_another_class_is_refused_and_no_option_accepts_it(self) -> None:
        import tempfile
        name = next(iter(EXPECTED))
        with tempfile.TemporaryDirectory() as tmp:
            keys = Path(tmp) / "keys.json"
            keys.write_text(json.dumps({"keys": [dict(k, **{"class": "staging"}) for k in KEYS]}), encoding="utf-8")
            refused = _run("-f", name, "--compare", name, "--keys", str(keys))
        self.assertNotEqual(refused.returncode, 0, refused.stdout)
        self.assertIn("NOT a production key", refused.stdout)
        options = set(re.findall(r"(?<![\w-])--?[a-z][a-z-]*", _run("--help").stdout))
        self.assertEqual(
            options,
            {"-h", "--help", "-f", "--fingerprint", "-s", "--spec", "-o", "--output",
             "--compare", "--keys", "--allow-unsigned"},
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

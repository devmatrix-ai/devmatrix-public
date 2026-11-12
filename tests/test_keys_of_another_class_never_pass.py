"""Evidence signed by a key that is not a production key never passes.

A keys file holds one environment's keys. A file of production keys is
exactly a devmatrix-keys/1 document, and only it can end in VERIFICATION
PASSED with exit status 0. A file of keys of any other class names them with
a label; evidence that verifies against it ends in "<label> — not a
production attestation" with exit status NOT_PRODUCTION_EXIT, never 0 and
never PASSED. The verdict names the keys file it was reached with.

The keys here are made for the test and named with a neutral class and
label, so keys.json is not touched.

Run from the repository root: python -m unittest discover -s tests
"""

from __future__ import annotations

import base64
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

_CLASS = "staging"
_LABEL = "staging-x"


def _signer(key_id: str, key_class: str) -> tuple[Ed25519PrivateKey, dict]:
    key = Ed25519PrivateKey.generate()
    public = base64.b64encode(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    return key, {
        "kid": "sha256:" + hashlib.sha256(base64.b64decode(public)).hexdigest(),
        "key_id": key_id,
        "purpose": "evidence-signing",
        "class": key_class,
        "algorithm": "Ed25519",
        "public_key": public,
        "status": "active",
        "status_since": None,
        "created_at": "2026-01-01T00:00:00+00:00",
        "expires_at": None,
    }


_OTHER_KEY, _OTHER = _signer("other-test", _CLASS)
_PRODUCTION_KEY, _PRODUCTION = _signer("production-test", vf.PRODUCTION)


def _signed(key: Ed25519PrivateKey, entry: dict) -> dict:
    payload = {"job_id": "0b2f6c55-7f9e-4c1a-9a63-1f0a7e2c4d11", "spec_hash": "sha256:" + "a" * 64}
    canonical = vf.canonical_payload(payload)
    return {
        "evidence_version": "1.0.0",
        "fingerprint": payload,
        "published_at": "2026-11-12T10:00:00+00:00",
        "signature": {
            "algorithm": "Ed25519",
            "key_id": entry["key_id"],
            "public_key": entry["public_key"],
            "signature": base64.b64encode(key.sign(canonical)).decode(),
            "signed_at": "2026-11-12T10:00:00+00:00",
            "signed_payload_hash": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        },
    }


def _document(keys: list[dict], **extra: object) -> dict:
    return {"schema_id": vf.KEYS_SCHEMA_ID, "keys": keys, **extra}


def _run(evidence: dict, document: dict) -> tuple[subprocess.CompletedProcess[str], Path]:
    with tempfile.TemporaryDirectory() as tmp:
        keys = Path(tmp) / "keys.json"
        keys.write_text(json.dumps(document), encoding="utf-8")
        fingerprint = Path(tmp) / "evidence.json"
        fingerprint.write_text(json.dumps(evidence), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(ROOT / "verify_fingerprint.py"), "-f", str(fingerprint), "--keys", str(keys)],
            capture_output=True, text=True, check=False,
        )
        return result, keys.resolve()


class KeysOfAnotherClass(unittest.TestCase):
    def test_their_evidence_verifies_but_never_passes(self) -> None:
        result, keys = _run(_signed(_OTHER_KEY, _OTHER), _document([_OTHER], label=_LABEL))
        self.assertEqual(result.returncode, vf.NOT_PRODUCTION_EXIT, result.stdout)
        self.assertNotEqual(vf.NOT_PRODUCTION_EXIT, 0)
        self.assertIn(f"{_LABEL} — not a production attestation", result.stdout)
        self.assertIn(f"Keys: {keys} ({_CLASS} keys)", result.stdout)
        self.assertNotIn("PASSED", result.stdout)

    def test_against_production_keys_they_fail(self) -> None:
        passed, lines = vf.verify_signature(_signed(_OTHER_KEY, _OTHER), [_OTHER])
        self.assertFalse(passed, lines)
        self.assertIn("is NOT a production key; this is not a DevMatrix attestation", lines[-1])
        result, _ = _run(_signed(_OTHER_KEY, _OTHER), _document([_PRODUCTION]))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("VERIFICATION FAILED", result.stdout)

    def test_a_file_that_mixes_classes_is_refused(self) -> None:
        result, _ = _run(_signed(_OTHER_KEY, _OTHER), _document([_PRODUCTION, _OTHER], label=_LABEL))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(f"the keys mix ['production', '{_CLASS}'] keys", result.stdout)

    def test_a_production_key_does_not_count_among_them(self) -> None:
        passed, lines = vf.verify_signature(_signed(_PRODUCTION_KEY, _PRODUCTION), [_PRODUCTION], _CLASS)
        self.assertFalse(passed, lines)
        self.assertIn(f"is a 'production' key; these keys are '{_CLASS}' keys", lines[-1])

    def test_a_file_of_them_without_a_label_is_refused_by_name(self) -> None:
        result, _ = _run(_signed(_OTHER_KEY, _OTHER), _document([_OTHER]))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(f"a '{_CLASS}' key is NOT a production key, and the file declares no label", result.stdout)

    def test_a_label_that_claims_production_or_a_pass_is_refused(self) -> None:
        for label in ("production", "VERIFICATION PASSED", "", "x" * 65, "line\nbreak"):
            with self.subTest(label=label):
                result, _ = _run(_signed(_OTHER_KEY, _OTHER), _document([_OTHER], label=label))
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("is not a label for", result.stdout)


class ProductionKeys(unittest.TestCase):
    def test_pass_with_exit_zero_naming_the_keys_file(self) -> None:
        result, keys = _run(_signed(_PRODUCTION_KEY, _PRODUCTION), _document([_PRODUCTION]))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("VERIFICATION PASSED", result.stdout)
        self.assertIn(f"Keys: {keys} (production keys)", result.stdout)

    def test_a_file_of_them_carries_no_label(self) -> None:
        result, _ = _run(_signed(_PRODUCTION_KEY, _PRODUCTION), _document([_PRODUCTION], label=_LABEL))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("lists production keys and a label", result.stdout)


if __name__ == "__main__":
    unittest.main()

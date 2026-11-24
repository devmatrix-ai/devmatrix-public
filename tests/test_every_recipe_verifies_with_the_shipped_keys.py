"""Every documented recipe verifies with the keys.json this repository ships.

HOW_TO_VERIFY.md documents two kinds of signature: evidence (``-f`` on a
file of ``fingerprints/`` or ``attestations/``) is signed by an
``evidence-signing`` key, a seal (``--seal``, ``-f`` on a published platform
seal) by a ``seal-signing`` key. Each purpose has one active production key
in keys.json, with the instant it started signing; every published evidence
file verifies with keys.json as shipped, and fails once keys.json lacks the
key that signed it.

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

import verify_fingerprint as vf  # noqa: E402

#: The purpose of the key each documented recipe checks a signature with.
RECIPE_PURPOSES = {
    "evidence (-f fingerprints/, -f attestations/)": "evidence-signing",
    "seal (--seal, -f platform-seals/)": "seal-signing",
}
PUBLISHED = sorted(
    path for folder in ("fingerprints", "attestations", "platform-seals")
    for path in (ROOT / folder).rglob("*.json")
)


def _verify(path: Path, keys: Path | None = None) -> subprocess.CompletedProcess[str]:
    argv = [sys.executable, str(ROOT / "verify_fingerprint.py"), "-f", str(path)]
    if keys is not None:
        argv += ["--keys", str(keys)]
    return subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=120)


class TheShippedKeys(unittest.TestCase):
    def test_every_recipe_has_one_active_production_key_with_its_start(self) -> None:
        """MUT-RED: keys.json without the seal key."""
        keys = vf.load_keys(vf.KEYS_FILE)
        for recipe, purpose in RECIPE_PURPOSES.items():
            with self.subTest(recipe=recipe):
                active = [k for k in keys if k["purpose"] == purpose and k["status"] == "active"
                          and k["class"] == "production"]
                self.assertEqual(len(active), 1, f"{purpose}: {[k['key_id'] for k in active]}")
                self.assertIsNotNone(active[0]["created_at"])

    def test_every_published_file_verifies_with_the_shipped_keys(self) -> None:
        self.assertTrue(PUBLISHED, "no published evidence file to verify")
        for path in PUBLISHED:
            with self.subTest(file=path.relative_to(ROOT).as_posix()):
                result = _verify(path)
                self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])

    def test_without_the_key_that_signed_it_every_published_file_fails(self) -> None:
        """The recipe reads keys.json: a keys file that lacks the key a file
        was signed with fails that file, so the pass above is the keys'."""
        document = json.loads(vf.KEYS_FILE.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            for path in PUBLISHED:
                signed = json.loads(path.read_text(encoding="utf-8"))
                kid = signed.get("signature", {}).get("public_key")
                with self.subTest(file=path.relative_to(ROOT).as_posix()):
                    others = [k for k in document["keys"] if k["public_key"] != kid]
                    self.assertLess(len(others), len(document["keys"]), "keys.json lists no key the file names")
                    keys = Path(tmp) / "keys.json"
                    keys.write_text(json.dumps({"schema_id": document["schema_id"], "keys": others}),
                                    encoding="utf-8")
                    result = _verify(path, keys)
                    self.assertNotEqual(result.returncode, 0, result.stdout[-2000:])


if __name__ == "__main__":
    unittest.main()

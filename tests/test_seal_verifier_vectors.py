"""The public verifier judges the shared signed seal vectors as the backend's
bundled verifier does: by verdict, reason class and key class, never by
wording. The vectors are a byte-for-byte copy whose digest is pinned here."""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "seal-verifier-vectors"
VECTORS_SCHEMA = "seal-verifier-vectors/2"
#: sha256 over the set's files, as ``PIN.sha256`` states it: one line per
#: file, ``<sha256>  <path>``, sorted by path, PIN.sha256 itself excluded.
PINNED_SHA256 = "8fbe93880aeded0a58cf0549345bbde0a3f7fd901f77eea5b25e17b19f1f8a0b"
#: The bundled verdicts of a run with a keys file, and of one without.
VERDICTS = frozenset({"VERIFIED", "FAILED"})
VERDICTS_WITHOUT_KEYS = frozenset({"CONSISTENT_ORIGIN_NOT_CHECKED", "FAILED"})
#: What this verifier gives a vector run without a keys file: it always
#: checks origin, against the keys.json it ships, which publishes no fixture
#: key; so the seal is refused on its key, never verified. The bundled
#: verifier's verdict for such a run (origin not checked) is its own.
WITHOUT_KEYS = {"verdict": "FAILED", "reason_classes": ["key"], "key_class": "production"}


def pin_lines(root: Path) -> list[str]:
    """``<sha256>  <path>`` of every file of the set but PIN.sha256, sorted."""
    files = sorted(path for path in root.rglob("*") if path.is_file() and path.name != "PIN.sha256")
    return [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root).as_posix()}" for path in files]


def pin_text(root: Path) -> str:
    return "".join(line + "\n" for line in pin_lines(root))


class TheSharedVectors(unittest.TestCase):
    def test_the_set_is_the_pinned_one(self) -> None:
        """MUT-RED: a file added, removed or changed."""
        self.assertTrue(VECTORS.is_dir(), f"{VECTORS} is missing")
        stated = (VECTORS / "PIN.sha256").read_text(encoding="utf-8")
        self.assertEqual(pin_text(VECTORS), stated, "PIN.sha256 does not name exactly the files held")
        self.assertEqual(hashlib.sha256(stated.encode("utf-8")).hexdigest(), PINNED_SHA256)

    def test_every_vector_is_judged_as_it_expects(self) -> None:
        """MUT-RED: a verdict, a class or the key class differs; no vector."""
        document = json.loads((VECTORS / "VECTORS.json").read_text(encoding="utf-8"))
        self.assertEqual(document.get("schema"), VECTORS_SCHEMA)
        vectors = document.get("vectors")
        self.assertIsInstance(vectors, list)
        self.assertGreater(len(vectors), 0, "no vector loaded: nothing was compared")
        self.assertTrue(any(vector["keys"] is not None for vector in vectors),
                        "no vector names a keys file: nothing is compared with the bundled verdict")
        ids = [vector["id"] for vector in vectors]
        self.assertEqual(len(ids), len(set(ids)), "a vector id is repeated")
        with tempfile.TemporaryDirectory() as work:
            copy = Path(work) / "set"
            shutil.copytree(VECTORS, copy, symlinks=False)
            for vector in vectors:
                with self.subTest(vector=vector["id"]):
                    self._judge(copy, vector)

    def _judge(self, copy: Path, vector: dict) -> None:
        """Run the public verifier over one vector of the temp copy ``copy``,
        its declared links made there, and compare its verdict."""
        keys = vector["keys"]
        if keys is None:
            self.assertIn(vector["expect"], VERDICTS_WITHOUT_KEYS)
            self.assertIsNone(vector["key_class"], "a vector run without keys states no key class")
        else:
            self.assertIn(vector["expect"], VERDICTS)
        for link, target in sorted(vector.get("links", {}).items()):
            self.assertFalse((copy / link).exists(), f"the set holds {link}, which the vector makes a link")
            self.assertTrue((copy / target).is_file(), f"link target {target} is not a file of the set")
            (copy / link).parent.mkdir(parents=True, exist_ok=True)
            (copy / link).symlink_to((copy / target).resolve())
        if keys is not None:
            self.assertTrue((copy / keys).is_file(), f"keys file {keys} is not a file of the set")
        command = [sys.executable, str(ROOT / "verify_fingerprint.py"),
                   *(["--keys", str(copy / keys)] if keys is not None else []),
                   "--seal", str(copy / vector["seal"])]
        for service, download in sorted(vector["downloads"].items()):
            command += ["--attestation", f"{service}={copy / download}"]
        if vector.get("evidence") is not None:
            command += ["--evidence", str(copy / vector["evidence"])]
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "verdict.json"
            result = subprocess.run([*command, "--verdict-json", str(out)],
                                    capture_output=True, text=True, check=False)
            self.assertTrue(out.is_file(), result.stdout + result.stderr)
            verdict = json.loads(out.read_text(encoding="utf-8"))
        if keys is None:
            self.assertEqual(verdict, WITHOUT_KEYS, result.stdout)
            return
        self.assertEqual(
            verdict,
            {"verdict": vector["expect"], "reason_classes": vector["reason_classes"],
             "key_class": vector["key_class"]},
            result.stdout,
        )


if __name__ == "__main__":
    unittest.main()

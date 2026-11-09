"""Nothing in this repository speaks of a build or a key other than production.

Every tracked text file is read, this one and the signed evidence included.
The words the check looks for are stored here ROT13-encoded, so that this file
does not contain them either; ``_word`` decodes them. Matches are whole words:
the product's name and its domain name are not matches.
"""

from __future__ import annotations

import codecs
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _word(encoded: str) -> str:
    return codecs.decode(encoded, "rot13")


#: A short build-mode word not preceded by a dot (the domain is not a match),
#: two long forms of it, any word starting with the other build mode, and the
#: negated class of key.
FORBIDDEN = re.compile(
    rf"(?<![.\w]){_word('qri')}(?![a-z])"
    rf"|\b{_word('qrirybczrag')}\b"
    rf"|\b{_word('qrfneebyyb')}\b"
    rf"|\b{_word('ybpny')}\w*"
    rf"|\b{_word('aba')}[-_ ]?{_word('cebqhpgvba')}\b",
    re.IGNORECASE,
)


def _tracked() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True, check=True
    )
    return [name for name in result.stdout.split("\0") if name]


def _hits(names: list[str]) -> list[str]:
    hits = []
    for name in names:
        try:
            text = (ROOT / name).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if FORBIDDEN.search(line):
                hits.append(f"{name}:{number}: {line.strip()[:120]}")
    return hits


class TheWording(unittest.TestCase):
    def test_no_file_speaks_of_another_build_or_key_class(self) -> None:
        names = [n for n in _tracked() if not (n.startswith("fingerprints/") and n.endswith(".json"))]
        self.assertGreater(len(names), 10, "the check reads almost nothing")
        self.assertIn("tests/test_public_wording.py", names)
        self.assertEqual(_hits(names), [])

    def test_no_evidence_file_records_another_build_mode(self) -> None:
        names = [n for n in _tracked() if n.startswith("fingerprints/") and n.endswith(".json")]
        self.assertTrue(names, "no evidence to read")
        self.assertEqual(_hits(names), [])

    def test_the_pattern_sees_the_words_and_not_the_domain(self) -> None:
        for encoded in ("qri", "Qri zbqr", "qz-qri-2026-02", "ohvyq_zbqr qri_k", "qrirybczrag",
                        "ra qrfneebyyb", "ybpny", "ybpnyyl", "ybpnyubfg", "aba-cebqhpgvba"):
            with self.subTest(word=encoded):
                self.assertTrue(FORBIDDEN.search(_word(encoded)), encoded)
        for word in ("devmatrix.dev", "https://devmatrix.dev/", "aeghysels@devmatrix.dev",
                     "DevMatrix", "devmatrix-public", "@builddevmatrix", "production"):
            with self.subTest(word=word):
                self.assertFalse(FORBIDDEN.search(word), word)


if __name__ == "__main__":
    unittest.main()

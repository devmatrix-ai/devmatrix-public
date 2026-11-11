"""keys.json is refreshed from the devmatrix-keys/1 document DevMatrix
publishes, by refresh_keys.py, and only when that document can replace it.

The documents and keys are made in the test; nothing is read over the
network and the repository's keys.json is not touched.

Run from the repository root: python -m unittest discover -s tests
"""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import ssl
import sys
import tempfile
import unittest
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from collections.abc import Callable
from email.message import Message
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import refresh_keys as rk  # noqa: E402
import verify_fingerprint as vf  # noqa: E402

_URL = vf.KEYS_URL


def _key(seed: str, purpose: str, status: str, created_at: str, **fields: object) -> dict:
    raw = hashlib.sha256(seed.encode()).digest()
    key = {
        "kid": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "key_id": f"dm-{seed}",
        "purpose": purpose,
        "class": "production",
        "algorithm": "Ed25519",
        "public_key": base64.b64encode(raw).decode("ascii"),
        "status": status,
        "status_since": None,
        "created_at": created_at,
        "expires_at": None,
    }
    key.update(fields)
    return key


_RETIRED = _key(
    "evidence-1", "evidence-signing", "retired", "2026-02-21T15:12:37+00:00",
    status_since="2026-07-04T22:25:59+00:00", expires_at="2026-07-04T22:25:59+00:00",
)
_EVIDENCE = _key("evidence-2", "evidence-signing", "active", "2026-09-16T11:01:14+00:00")
_SEAL = _key("seal-1", "seal-signing", "active", "2026-10-01T00:00:00+00:00")


def _document(*keys: dict) -> dict:
    return {"schema_id": "devmatrix-keys/1", "keys": [copy.deepcopy(k) for k in keys]}


def _bytes(document: dict) -> bytes:
    return json.dumps(document).encode()


class _Answer:
    def __init__(self, status: int, body: bytes, on_read: "Callable[[], None]" = lambda: None) -> None:
        self.status, self._body, self._on_read = status, body, on_read

    def read(self, amount: int) -> bytes:
        self._on_read()
        chunk, self._body = self._body[:amount], self._body[amount:]
        return chunk

    def __enter__(self) -> "_Answer":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _Served:
    """An opener that answers every request with one status and body."""

    def __init__(self, status: int, body: bytes, on_read: Callable[[], None] = lambda: None) -> None:
        self.answer = _Answer(status, body, on_read)
        self.timeouts: list[float] = []

    def open(self, request: urllib.request.Request, timeout: float) -> _Answer:
        self.timeouts.append(timeout)
        return self.answer


class _Repo:
    """A keys.json today: the evidence view, as published before seal keys."""

    def __init__(self, test: unittest.TestCase, *keys: dict) -> None:
        directory = tempfile.TemporaryDirectory()
        test.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "keys.json"
        self.path.write_bytes(rk.document_bytes(_document(*(keys or (_RETIRED, _EVIDENCE)))))

    def run(self, served: dict | bytes, *args: str) -> tuple[int, str, str]:
        body = served if isinstance(served, bytes) else _bytes(served)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = rk.main(["--keys", str(self.path), *args], via=_Served(200, body))
        return code, out.getvalue(), err.getvalue()


class TheRefresh(unittest.TestCase):
    def test_the_published_document_with_its_seal_key_replaces_keys_json(self) -> None:
        repo = _Repo(self)
        served = _document(_RETIRED, _EVIDENCE, _SEAL)
        code, out, _ = repo.run(served)
        self.assertEqual(code, 0)
        self.assertEqual(repo.path.read_bytes(), rk.document_bytes(served))
        self.assertIn("added, seal-signing, active", out)
        self.assertEqual(vf.load_keys(repo.path)[2]["purpose"], "seal-signing")
        code, out, _ = repo.run(served, "--check")
        self.assertEqual((code, out.strip()), (0, f"{repo.path} is what {_URL} publishes"))

    def test_check_writes_nothing_and_fails_when_keys_json_differs(self) -> None:
        repo = _Repo(self)
        before = repo.path.read_bytes()
        code, _, err = repo.run(_document(_RETIRED, _EVIDENCE, _SEAL), "--check")
        self.assertEqual(code, 1)
        self.assertIn("differs from what", err)
        self.assertEqual(repo.path.read_bytes(), before)

    def test_the_fetch_is_bounded_in_time(self) -> None:
        served = _Served(200, _bytes(_document(_RETIRED, _EVIDENCE, _SEAL)))
        rk.fetch(_URL, served)
        self.assertEqual(served.timeouts, [rk.FETCH_TIMEOUT_SECONDS])

    def test_a_slow_answer_is_refused_at_one_deadline_for_the_whole_read(self) -> None:
        """Each read is quick enough for a socket timeout; together they are not."""
        clock = [0.0]

        def tick() -> None:
            clock[0] += rk.FETCH_TIMEOUT_SECONDS / 3

        body = b" " * (rk._READ_CHUNK_BYTES * 5)
        with mock.patch.object(rk.time, "monotonic", lambda: clock[0]):
            with self.assertRaisesRegex(rk.RefreshRefused, "did not answer within"):
                rk.fetch(_URL, _Served(200, body, tick))

    def test_a_key_is_retired_by_setting_its_end_once(self) -> None:
        repo = _Repo(self, _RETIRED, _EVIDENCE, _SEAL)
        retired = dict(_EVIDENCE, status="retired", status_since="2026-12-01T00:00:00+00:00",
                       expires_at="2026-12-01T00:00:00+00:00")
        successor = _key("evidence-3", "evidence-signing", "active", "2026-12-01T00:00:00+00:00")
        code, out, err = repo.run(_document(_RETIRED, retired, successor, _SEAL))
        self.assertEqual(code, 0, err)
        self.assertIn("active -> retired", out)


class TheRefusals(unittest.TestCase):
    def _refused(self, served: dict | bytes, *needles: str, repo: _Repo | None = None) -> None:
        repo = repo or _Repo(self)
        before = repo.path.read_bytes()
        code, _, err = repo.run(served)
        self.assertEqual(code, 1, err)
        for needle in needles:
            self.assertIn(needle, err)
        self.assertEqual(repo.path.read_bytes(), before, "a refused document was written")

    def test_a_kid_that_is_not_its_public_keys_digest(self) -> None:
        seal = dict(_SEAL, kid="sha256:" + "0" * 64)
        self._refused(_document(_RETIRED, _EVIDENCE, seal), "kid is not the SHA-256 of its public key")

    def test_a_key_of_another_class(self) -> None:
        seal = dict(_SEAL, **{"class": "staging"})
        self._refused(_document(_RETIRED, _EVIDENCE, seal), "'staging' key; keys.json lists production keys only")

    def test_a_purpose_with_no_active_key(self) -> None:
        self._refused(_document(_RETIRED, _EVIDENCE), "seal-signing has 0 active keys")

    def test_a_purpose_with_two_active_keys(self) -> None:
        second = _key("seal-2", "seal-signing", "active", "2026-10-02T00:00:00+00:00")
        self._refused(_document(_RETIRED, _EVIDENCE, _SEAL, second), "seal-signing has 2 active keys")

    def test_an_unknown_purpose(self) -> None:
        other = _key("other-1", "release-signing", "retired", "2026-10-02T00:00:00+00:00")
        self._refused(_document(_RETIRED, _EVIDENCE, _SEAL, other), "signs for 'release-signing'")

    def test_a_key_that_is_not_ed25519(self) -> None:
        seal = dict(_SEAL, algorithm="RSA")
        self._refused(_document(_RETIRED, _EVIDENCE, seal), "'RSA' key, not Ed25519")

    def test_a_dropped_key(self) -> None:
        self._refused(_document(_EVIDENCE, _SEAL), "dm-evidence-1", "no longer published; a key is never dropped")

    def test_a_rewritten_key(self) -> None:
        evidence = dict(_EVIDENCE, created_at="2026-01-01T00:00:00+00:00")
        self._refused(_document(_RETIRED, evidence, _SEAL), "created_at changed")

    def test_a_status_that_goes_back(self) -> None:
        revived = dict(_RETIRED, status="active")
        evidence = dict(_EVIDENCE, status="retired")
        self._refused(_document(revived, evidence, _SEAL), "status went back from retired to active")

    def test_a_retired_window_that_is_reopened_or_widened(self) -> None:
        for change in ({"expires_at": None}, {"expires_at": "2027-01-01T00:00:00+00:00"},
                       {"status_since": None}, {"status_since": "2026-08-01T00:00:00+00:00"}):
            field = next(iter(change))
            with self.subTest(change=change):
                self._refused(_document(dict(_RETIRED, **change), _EVIDENCE, _SEAL),
                              f"{field} changed", "once set it never changes")

    def test_not_a_keys_document(self) -> None:
        self._refused({"schema_id": "devmatrix-keys/2", "keys": []}, "is not a devmatrix-keys/1 document")
        self._refused(b"<html>sign in</html>", "is not UTF-8 JSON")

    def test_a_document_over_the_size_limit(self) -> None:
        self._refused(b" " * (rk.MAX_DOCUMENT_BYTES + 1), f"more than {rk.MAX_DOCUMENT_BYTES} bytes")

    def test_an_answer_other_than_200(self) -> None:
        with self.assertRaisesRegex(rk.RefreshRefused, "answered 204, not 200"):
            rk.fetch(_URL, _Served(204, b""))

    def test_a_url_that_is_not_https(self) -> None:
        with self.assertRaisesRegex(rk.RefreshRefused, "is not an https URL"):
            rk.fetch("http://devmatrix.dev/.well-known/devmatrix-keys.json", _Served(200, b"{}"))


class TheOpener(unittest.TestCase):
    def test_a_redirect_is_refused_not_followed(self) -> None:
        """The URL answered 307 to the sign-in page before the keys were served;
        that answer must refuse, never be read as the keys."""
        request = urllib.request.Request(_URL)
        headers = Message()
        headers["Location"] = "https://devmatrix.dev/sign-in"
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code=code), self.assertRaisesRegex(rk.RefreshRefused, f"answered {code}, a redirect"):
                rk.opener().error("https", request, io.BytesIO(b""), code, "Redirect", headers)

    def test_no_proxy_is_used_even_when_the_environment_names_one(self) -> None:
        with mock.patch.dict(os.environ, {"https_proxy": "http://proxy.invalid:3128", "HTTPS_PROXY": "http://proxy.invalid:3128"}):
            built = rk.opener()
        proxies = [h.proxies for h in built.handlers if isinstance(h, urllib.request.ProxyHandler)]
        self.assertEqual(proxies, [])

    def test_the_certificate_and_host_name_are_verified(self) -> None:
        handlers = [h for h in rk.opener().handlers if isinstance(h, urllib.request.HTTPSHandler)]
        self.assertEqual(len(handlers), 1)
        context = handlers[0]._context
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)


class TheRepositoryKeys(unittest.TestCase):
    def test_keys_json_is_laid_out_as_the_refresh_writes_it(self) -> None:
        data = vf.KEYS_FILE.read_bytes()
        self.assertEqual(rk.document_bytes(json.loads(data)), data)


if __name__ == "__main__":
    unittest.main()

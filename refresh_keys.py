#!/usr/bin/env python3
"""Refresh keys.json from the devmatrix-keys/1 document DevMatrix publishes.

keys.json is a copy of https://devmatrix.dev/.well-known/devmatrix-keys.json.
This script reads that document (or a saved copy of it), checks it with the
verifier's own reader and against the keys.json it would replace, and writes
it unchanged. It refuses, naming why:

- a document that is not devmatrix-keys/1, an entry whose kid is not the
  SHA-256 of its public key, a public key listed twice or an unknown status;
- a key that is not a production Ed25519 key, or one of no known purpose;
- a purpose with no key, or with other than one active key;
- a key keys.json lists that the document no longer lists: evidence signed by
  a retired key still verifies, so a key is never dropped;
- a key whose label, purpose, class, algorithm, public key or start changed;
- a status that goes back (only active to retired or revoked, and retired to
  revoked, are allowed).

The document is read over https only, with certificate verification, a
timeout and a size limit; a redirect is refused, because the keys are read
only where they are published.

Standard library only.

Usage:
    python refresh_keys.py                 # read the published document, write keys.json
    python refresh_keys.py --check         # write nothing; exit 1 if keys.json differs
    python refresh_keys.py --from saved-devmatrix-keys.json
"""

from __future__ import annotations

import argparse
import base64
import json
import ssl
import sys
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path
from typing import IO, Protocol
from urllib.parse import urlsplit

import verify_fingerprint as vf

#: Every purpose a published key signs for; each has exactly one active key.
PURPOSES = ("evidence-signing", "seal-signing")
ALGORITHM = "Ed25519"
ED25519_PUBLIC_KEY_BYTES = 32
FETCH_TIMEOUT_SECONDS = 20
#: The published document is a few kilobytes; anything near this is not it.
MAX_DOCUMENT_BYTES = 1 << 20
#: The fields of a key that never change once it is published.
FIXED_FIELDS = ("key_id", "purpose", "class", "algorithm", "public_key", "created_at")
#: The status changes a published key can make.
FORWARD = frozenset({("active", "retired"), ("active", "revoked"), ("retired", "revoked")})


class RefreshRefused(ValueError):
    """The document cannot replace keys.json; the message says why."""


class _Response(Protocol):
    status: int

    def read(self, amount: int) -> bytes: ...

    def __enter__(self) -> "_Response": ...

    def __exit__(self, *exc: object) -> None: ...


class Opener(Protocol):
    def open(self, request: urllib.request.Request, timeout: float) -> _Response: ...


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    """Every redirect is refused: the keys are read only at the URL given."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> None:
        raise RefreshRefused(
            f"{req.full_url} answered {code}, a redirect to {newurl}; "
            "the keys are read only where they are published"
        )


def opener() -> urllib.request.OpenerDirector:
    """An opener that verifies the certificate and host name and follows no redirect."""
    context = ssl.create_default_context()
    return urllib.request.build_opener(_RefuseRedirect(), urllib.request.HTTPSHandler(context=context))


def fetch(url: str, via: Opener | None = None) -> bytes:
    """The bytes published at the https ``url``, or :class:`RefreshRefused`."""
    if urlsplit(url).scheme != "https":
        raise RefreshRefused(f"{url} is not an https URL")
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with (via or opener()).open(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
            if response.status != 200:
                raise RefreshRefused(f"{url} answered {response.status}, not 200")
            data = response.read(MAX_DOCUMENT_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise RefreshRefused(f"{url} answered {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RefreshRefused(f"could not read {url}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise RefreshRefused(f"{url} did not answer within {FETCH_TIMEOUT_SECONDS} s") from exc
    if len(data) > MAX_DOCUMENT_BYTES:
        raise RefreshRefused(f"{url} answered more than {MAX_DOCUMENT_BYTES} bytes")
    return data


def read_file(path: Path) -> bytes:
    """The bytes of a saved document, within the same size limit."""
    with open(path, "rb") as handle:
        data = handle.read(MAX_DOCUMENT_BYTES + 1)
    if len(data) > MAX_DOCUMENT_BYTES:
        raise RefreshRefused(f"{path} holds more than {MAX_DOCUMENT_BYTES} bytes")
    return data


def served_keys(data: bytes, source: str) -> tuple[dict, list[dict]]:
    """The document in ``data`` and its keys, checked as one keys.json can be."""
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RefreshRefused(f"{source} is not UTF-8 JSON: {exc}") from exc
    try:
        keys = vf.keys_of(document, source)
    except ValueError as exc:
        raise RefreshRefused(str(exc)) from exc
    refusals = []
    for key in keys:
        name = f"{key['key_id']} ({key['kid']})"
        if key["class"] != vf.PRODUCTION:
            refusals.append(f"{name} is a {key['class']!r} key; keys.json lists production keys only")
        if key["purpose"] not in PURPOSES:
            refusals.append(f"{name} signs for {key['purpose']!r}, not one of {', '.join(PURPOSES)}")
        if key["algorithm"] != ALGORITHM:
            refusals.append(f"{name} is a {key['algorithm']!r} key, not {ALGORITHM}")
        elif len(base64.b64decode(key["public_key"])) != ED25519_PUBLIC_KEY_BYTES:
            refusals.append(f"{name} is not a {ED25519_PUBLIC_KEY_BYTES}-byte {ALGORITHM} public key")
    for purpose in PURPOSES:
        active = [key["key_id"] for key in keys if key["purpose"] == purpose and key["status"] == "active"]
        if len(active) != 1:
            refusals.append(f"{purpose} has {len(active)} active keys {active}, not one")
    if refusals:
        raise RefreshRefused(f"{source}:\n  " + "\n  ".join(refusals))
    return document, keys


def changes(published: list[dict], served: list[dict]) -> list[str]:
    """What ``served`` changes in the ``published`` keys, or
    :class:`RefreshRefused` when it drops or rewrites one."""
    by_kid = {key["kid"]: key for key in served}
    refusals, lines = [], []
    for old in published:
        name = f"{old['key_id']} ({old['kid']})"
        new = by_kid.get(old["kid"])
        if new is None:
            refusals.append(f"{name} is in keys.json and no longer published; a key is never dropped")
            continue
        for field in FIXED_FIELDS:
            if new[field] != old[field]:
                refusals.append(f"{name} {field} changed from {old[field]!r} to {new[field]!r}")
        if new["status"] != old["status"]:
            if (old["status"], new["status"]) not in FORWARD:
                refusals.append(f"{name} status went back from {old['status']} to {new['status']}")
            else:
                lines.append(f"{name}: {old['status']} -> {new['status']}")
        elif new != old:
            lines.append(f"{name}: dates changed")
    known = {key["kid"] for key in published}
    lines += [f"{key['key_id']} ({key['kid']}): added, {key['purpose']}, {key['status']}"
              for key in served if key["kid"] not in known]
    if refusals:
        raise RefreshRefused("the published keys cannot replace keys.json:\n  " + "\n  ".join(refusals))
    return lines


def document_bytes(document: dict) -> bytes:
    """keys.json as written: the document unchanged, indented, one final newline."""
    return (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def refresh(data: bytes, source: str, keys_file: Path) -> tuple[bytes, list[str]]:
    """The keys.json bytes ``data`` gives, and what they change, or :class:`RefreshRefused`."""
    document, served = served_keys(data, source)
    try:
        published = vf.load_keys(keys_file)
    except ValueError as exc:
        raise RefreshRefused(f"the current {keys_file} cannot be read: {exc}") from exc
    return document_bytes(document), changes(published, served)


def main(argv: list[str] | None = None, via: Opener | None = None) -> int:
    parser = argparse.ArgumentParser(description="Refresh keys.json from the keys DevMatrix publishes")
    parser.add_argument(
        "--from", dest="source", default=vf.KEYS_URL,
        help=f"https URL or saved file of the devmatrix-keys/1 document (default {vf.KEYS_URL})",
    )
    parser.add_argument("--keys", type=Path, default=vf.KEYS_FILE, help="keys.json to refresh")
    parser.add_argument("--check", action="store_true", help="write nothing; exit 1 if keys.json differs")
    args = parser.parse_args(argv)
    try:
        if "://" in args.source:
            data = fetch(args.source, via)
        else:
            data = read_file(Path(args.source))
        written, lines = refresh(data, args.source, args.keys)
    except (RefreshRefused, OSError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    current = args.keys.read_bytes()
    if written == current:
        print(f"{args.keys} is what {args.source} publishes")
        return 0
    for line in lines or ["the document is laid out differently"]:
        print(line)
    if args.check:
        print(f"{args.keys} differs from what {args.source} publishes", file=sys.stderr)
        return 1
    args.keys.write_bytes(written)
    print(f"wrote {args.keys}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

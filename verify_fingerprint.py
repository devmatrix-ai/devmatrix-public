#!/usr/bin/env python3
"""
DevMatrix Build Fingerprint Verification Tool

Verifies that a DevMatrix build is reproducible by checking
cryptographic hashes against the build fingerprint, and that the evidence was
signed by DevMatrix: the Ed25519 signature of a published evidence pack is
checked against the public keys in keys.json.

The hashes use the Python standard library only. The signature needs the
`cryptography` package (pip install cryptography); without it the verification
fails, it is never skipped.

Usage:
    python verify_fingerprint.py --seal <seal bundle dir> --attestation <service>=fingerprint_attestation.json [--published attestations/<job>.json] [--evidence <evidence bundle dir>]
    python verify_fingerprint.py --fingerprint build_fingerprint.json --spec spec.md --output generated/
    python verify_fingerprint.py --fingerprint build_fingerprint.json --compare other_fingerprint.json
    python verify_fingerprint.py --fingerprint fingerprints/run_a.json --compare fingerprints/run_b.json
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

#: The public keys that sign DevMatrix evidence, published with this script.
KEYS_FILE = Path(__file__).resolve().parent / "keys.json"

#: The only class of key that signs a DevMatrix attestation.
PRODUCTION = "production"
#: The exit status when every check passed against keys that are not
#: production keys: not 0, so that whoever reads only the exit status never
#: takes it for a pass. Such a verdict never says PASSED.
NOT_PRODUCTION_EXIT = 3
#: A keys file whose keys are not production keys names them with a label,
#: printed in the verdict: a bounded word that never claims production or a pass.
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}")
_CLASS = re.compile(r"[a-z][a-z0-9_-]{0,31}")

#: The registry keys.json is a copy of: DevMatrix publishes every key it signs
#: with there, without sign-in, in the same devmatrix-keys/1 document.
KEYS_URL = "https://devmatrix.dev/.well-known/devmatrix-keys.json"
KEYS_SCHEMA_ID = "devmatrix-keys/1"
#: The statuses a published key can have; only the first two verify.
KEY_STATUSES = frozenset({"active", "retired", "revoked"})
VERIFYING_STATUSES = frozenset({"active", "retired"})
KEY_FIELDS = frozenset({
    "kid", "key_id", "purpose", "class", "algorithm", "public_key",
    "status", "status_since", "created_at", "expires_at",
})


def sha256_file(filepath: Path) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def sha256_directory(dirpath: Path) -> str:
    """
    Compute SHA-256 hash of a directory's contents.

    Canonical algorithm (see REPRODUCIBILITY_SPEC.md):
    - List all files recursively
    - Exclude: __pycache__/, node_modules/, .git/, *.pyc
    - Sort lexicographically by relative path (Unix-style separators)
    - Hash stream: rel_path + \n + file_hash + \n for each file
    """
    sha256 = hashlib.sha256()

    # Patterns to exclude
    exclude_patterns = {
        "__pycache__",
        "node_modules",
        ".git",
    }
    exclude_extensions = {".pyc"}

    # List all files
    files = list(dirpath.rglob("*"))

    # Filter to files only, excluding patterns
    def should_include(filepath: Path) -> bool:
        if not filepath.is_file():
            return False
        if filepath.suffix in exclude_extensions:
            return False
        # Check if any parent directory matches exclude patterns
        for part in filepath.relative_to(dirpath).parts:
            if part in exclude_patterns:
                return False
        return True

    files = [f for f in files if should_include(f)]

    # Sort lexicographically by relative path (Unix-style separators)
    files = sorted(files, key=lambda f: str(f.relative_to(dirpath)).replace("\\", "/"))

    # Hash each file with delimiters
    for filepath in files:
        # Use Unix-style separators for cross-platform consistency
        rel_path = str(filepath.relative_to(dirpath)).replace("\\", "/")
        file_hash = sha256_file(filepath)

        # Canonical format: rel_path + \n + file_hash + \n
        sha256.update(rel_path.encode("utf-8"))
        sha256.update(b"\n")
        sha256.update(file_hash.encode("utf-8"))
        sha256.update(b"\n")

    return sha256.hexdigest()


def read_json(filepath: Path) -> dict:
    """Read a JSON object from ``filepath``."""
    with open(filepath, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{filepath} does not hold a JSON object")
    return data


def load_fingerprint(filepath: Path) -> dict:
    """
    Load and parse a build fingerprint JSON file.

    Supports both:
    - Flat `build_fingerprint.json` objects (generated by the compiler output)
    - Published evidence pack objects with a nested `fingerprint` payload
    """
    return flatten_fingerprint(read_json(filepath))


def flatten_fingerprint(data: dict) -> dict:
    """The fingerprint fields of ``data``, an evidence pack or a flat fingerprint."""

    # Evidence pack format:
    # {
    #   "evidence_version": "...",
    #   "fingerprint": { ... },
    #   "published_at": "...",
    #   "signature": { ... }
    # }
    if isinstance(data, dict) and isinstance(data.get("fingerprint"), dict):
        flattened = dict(data["fingerprint"])
        flattened["evidence_version"] = data.get("evidence_version")
        flattened["published_at"] = data.get("published_at")
        flattened["signature"] = data.get("signature")
        return flattened

    return data


def verify_spec_hash(fingerprint: dict, spec_path: Path) -> tuple[bool, str]:
    """Verify spec_hash matches the specification file."""
    expected = fingerprint.get("spec_hash")
    if not expected:
        return False, "No spec_hash in fingerprint"

    actual = sha256_file(spec_path)

    if actual == expected:
        return True, f"spec_hash matches: {actual[:16]}..."
    else:
        return False, f"spec_hash MISMATCH: expected {expected[:16]}..., got {actual[:16]}..."


def verify_code_bundle_hash(fingerprint: dict, output_dir: Path) -> tuple[bool, str]:
    """Verify code_bundle_hash matches the generated code."""
    expected = fingerprint.get("code_bundle_hash")
    if not expected:
        return False, "No code_bundle_hash in fingerprint"

    actual = sha256_directory(output_dir)

    if actual == expected:
        return True, f"code_bundle_hash matches: {actual[:16]}..."
    else:
        return False, f"code_bundle_hash MISMATCH: expected {expected[:16]}..., got {actual[:16]}..."


def canonical_payload(fingerprint: dict) -> bytes:
    """The bytes DevMatrix signs: the fingerprint as JSON with sorted keys, no
    whitespace, UTF-8."""
    return json.dumps(
        fingerprint, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def load_keys(path: Path) -> list[dict]:
    """The published keys in ``path`` (keys.json, a devmatrix-keys/1 document).

    Each key is identified by ``kid``, the SHA-256 of its public key; one
    ``key_id`` once named two keys, so a key is found by its label and its
    public key together.
    """
    return trusted_keys_of(read_json(path), str(path)).keys


def keys_of(document: object, path: str) -> list[dict]:
    """The keys of a devmatrix-keys/1 ``document`` read from ``path``: the
    exact fields, each ``kid`` recomputed from its public key, no public key
    twice and a known status, or ``ValueError`` naming what is wrong."""
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_id", "keys"}
        or document["schema_id"] != KEYS_SCHEMA_ID
    ):
        raise ValueError(f"{path} is not a {KEYS_SCHEMA_ID} document")
    keys = document["keys"]
    if not isinstance(keys, list) or not keys:
        raise ValueError(f"{path} lists no keys")
    malformed = [i for i, k in enumerate(keys) if not isinstance(k, dict) or set(k) != KEY_FIELDS]
    if malformed:
        raise ValueError(f"{path}: key entries {malformed} are not {KEYS_SCHEMA_ID} keys")
    kids = set()
    for i, key in enumerate(keys):
        raw = _b64(key["public_key"], f"key {i} public_key")
        if key["kid"] != "sha256:" + hashlib.sha256(raw).hexdigest():
            raise ValueError(f"{path}: key {i} kid is not the SHA-256 of its public key")
        if key["kid"] in kids:
            raise ValueError(f"{path}: key {i} lists public key {key['kid']} a second time")
        kids.add(key["kid"])
        if key["status"] not in KEY_STATUSES:
            raise ValueError(f"{path}: key {i} status {key['status']!r} is not one of {sorted(KEY_STATUSES)}")
    return keys


def keys_class(keys: list[dict]) -> str:
    """The one class of every key in ``keys``, or ``ValueError``: a keys file
    holds the keys of one environment."""
    classes = sorted({str(key.get("class")) for key in keys})
    if len(classes) != 1:
        raise ValueError(f"the keys mix {classes} keys: a keys file holds one environment's keys")
    if not _CLASS.fullmatch(classes[0]):
        raise ValueError(f"key class {classes[0]!r} is not a key class")
    return classes[0]


class TrustedKeys:
    """The keys of a keys file, their one class, the label a file of keys
    that are not production keys gives them, and where they were read from."""

    def __init__(self, keys: list[dict], key_class: str, label: str | None, source: str) -> None:
        self.keys = keys
        self.key_class = key_class
        self.label = label
        self.source = source


def trusted_keys_of(document: object, path: str) -> TrustedKeys:
    """The keys of the keys file ``document`` read from ``path``, or
    ``ValueError`` naming why. A file of production keys is exactly a
    devmatrix-keys/1 document. A file of keys of any other class adds
    ``label``, the name its verdict prints; without one it is refused, so
    such keys are never read as production keys."""
    if not isinstance(document, dict):
        raise ValueError(f"{path} is not a {KEYS_SCHEMA_ID} document")
    label = document.get("label")
    keys = keys_of({k: v for k, v in document.items() if k != "label"}, path)
    key_class = keys_class(keys)
    if key_class == PRODUCTION:
        if "label" in document:
            raise ValueError(f"{path} lists production keys and a label: production keys carry none")
        return TrustedKeys(keys, key_class, None, path)
    if label is None:
        raise ValueError(
            f"{path} lists {key_class!r} keys; a {key_class!r} key is NOT a production key, "
            "and the file declares no label for them"
        )
    if (
        not isinstance(label, str)
        or not _LABEL.fullmatch(label)
        or any(word in label.casefold() for word in ("production", "pass"))
    ):
        raise ValueError(f"{path}: label {label!r} is not a label for {key_class!r} keys")
    return TrustedKeys(keys, key_class, label, path)


def class_refusal(entry: dict, key_id: object, accept: str, document: str) -> str | None:
    """Why the key ``entry`` does not count when ``accept`` keys are trusted,
    or ``None`` when it does. ``document`` names what it would sign."""
    if entry.get("class") == accept:
        return None
    if accept == PRODUCTION:
        return f"{key_id!r} is NOT a production key; this is not a DevMatrix {document}"
    return f"{key_id!r} is a {entry.get('class')!r} key; these keys are {accept!r} keys"



def _instant(value: object, what: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{what} is not a timestamp")
    instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if instant.tzinfo is None:
        raise ValueError(f"{what} names no time zone")
    return instant


def _b64(value: object, what: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{what} is missing")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{what} is not base64") from exc


class KeyRefused(ValueError):
    """The key a document names is not one keys.json publishes for it."""


def published_key(
    keys: list[dict], key_id: object, public_key: object, purpose: str, signs: str,
    at: object, verb: str,
) -> dict:
    """The one entry of keys.json for ``key_id`` and the inline ``public_key``,
    or :class:`KeyRefused`: an Ed25519 key of ``purpose`` (it signs ``signs``)
    that is not revoked and whose window holds ``at``, the instant the signer
    claims (``verb`` names it: signed, sealed). The window bounds the claim; it
    does not protect against a retired private key that leaked."""
    published = [k for k in keys if k.get("key_id") == key_id]
    if not published:
        raise KeyRefused(f"key_id {key_id!r} is not a published DevMatrix key")
    matching = [k for k in published if k.get("public_key") == public_key]
    if not matching:
        raise KeyRefused(f"the public key in the file is not the one published for {key_id!r}")
    if len(matching) != 1:
        raise KeyRefused(f"keys.json lists the key of {key_id!r} more than once")
    entry = matching[0]
    if entry.get("algorithm") != "Ed25519":
        raise KeyRefused(f"the published key {key_id!r} is not an Ed25519 key")
    if entry.get("purpose") != purpose:
        raise KeyRefused(f"the published key {key_id!r} does not sign {signs}")
    if entry.get("status") not in VERIFYING_STATUSES:
        raise KeyRefused(f"the published key {key_id!r} is {str(entry.get('status')).upper()}, not active or retired")
    if entry.get("created_at") is None:
        raise KeyRefused(f"the published key {key_id!r} names no window start (created_at)")
    instant = _instant(at, f"{verb}_at")
    valid_from = _instant(entry.get("created_at"), "created_at")
    valid_until = None if entry.get("expires_at") is None else _instant(entry.get("expires_at"), "expires_at")
    if instant < valid_from or (valid_until is not None and instant > valid_until):
        raise KeyRefused(f"{verb} at {at}, outside the window of {key_id!r}")
    return entry


def verify_signature(
    evidence: dict, keys: list[dict], accept: str = PRODUCTION
) -> tuple[bool, list[str]]:
    """Verify the Ed25519 signature of a published evidence pack.

    Passes only when every step holds:
    1. the pack carries a ``fingerprint`` object and a ``signature`` object;
    2. the algorithm is Ed25519;
    3. ``signed_payload_hash`` is the SHA-256 of the canonical fingerprint;
    4. ``key_id`` and the inline ``public_key`` are one entry of keys.json, an
       evidence-signing key that is not revoked;
    5. ``signed_at`` falls inside that entry's ``created_at`` .. ``expires_at``
       window (``signed_at`` is claimed
       by the signer, not signed: the window bounds the claim, it does not
       protect against a retired private key that leaked);
    6. the signature verifies over the canonical fingerprint with that key;
    7. the key is of the class ``accept`` trusts: a production key, unless
       the caller verifies against a keys file of another class. A key that
       is not a production key never passes as production, with no option to
       accept it.

    Returns whether it passed and the lines to report.
    """
    fingerprint = evidence.get("fingerprint")
    signature = evidence.get("signature")
    if not isinstance(fingerprint, dict) or not isinstance(signature, dict):
        return False, ["[FAIL] signature: this file carries no signed fingerprint"]
    if signature.get("algorithm") != "Ed25519":
        return False, [f"[FAIL] signature: unsupported algorithm {signature.get('algorithm')!r}"]

    payload = canonical_payload(fingerprint)
    payload_hash = "sha256:" + hashlib.sha256(payload).hexdigest()
    if signature.get("signed_payload_hash") != payload_hash:
        return False, ["[FAIL] signature: signed_payload_hash does not match the fingerprint"]

    key_id = signature.get("key_id")
    try:
        entry = published_key(
            keys, key_id, signature.get("public_key"), "evidence-signing", "evidence",
            signature.get("signed_at"), "signed",
        )
        public_key = _b64(entry.get("public_key"), "public_key")
        signature_bytes = _b64(signature.get("signature"), "signature")
    except KeyRefused as refused:
        return False, [f"[FAIL] signature: {refused}"]
    except ValueError as exc:
        return False, [f"[FAIL] signature: {exc}"]

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return False, [
            "[FAIL] signature NOT verified: the 'cryptography' package is required "
            "(pip install cryptography)"
        ]
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature_bytes, payload)
    except (InvalidSignature, ValueError):
        return False, [f"[FAIL] signature: INVALID for key {key_id!r}"]

    lines = [f"[OK] signature: Ed25519, key {key_id!r} ({entry.get('class')}), signed {signature.get('signed_at')}"]
    refusal = class_refusal(entry, key_id, accept, "attestation")
    if refusal is not None:
        return False, lines + [f"[FAIL] signature: {refusal}"]
    if accept != PRODUCTION:
        lines.append(f"[NOTE] signature: {key_id!r} is a {accept!r} key, NOT a production key")
    return True, lines


def check_signature(
    label: str, evidence: dict, keys: list[dict], allow_unsigned: bool, accept: str = PRODUCTION
) -> bool:
    """Print the signature verdict of ``evidence``; an unsigned file fails
    unless ``allow_unsigned``."""
    suffix = f"  ({label})" if label else ""
    if "signature" not in evidence and "fingerprint" not in evidence:
        if allow_unsigned:
            print(f"[WARN] UNSIGNED: signature not verified (--allow-unsigned); hashes only{suffix}")
            return True
        print(
            "[FAIL] signature: this file carries no signature; "
            f"--allow-unsigned checks the hashes of an unsigned build{suffix}"
        )
        return False
    passed, lines = verify_signature(evidence, keys, accept)
    for line in lines:
        print(f"{line}{suffix}")
    return passed


# ---------------------------------------------------------------------------
# Published attestations: the closed schema of the document DevMatrix publishes
# for a delivered build (digests, counts, module identifiers and closed-set
# statuses only). The same rules DevMatrix applies before publishing one.
# ---------------------------------------------------------------------------

ATTESTATION_SCHEMA_V1 = "published-attestation/1"
ATTESTATION_SCHEMA_V2 = "published-attestation/2"
ATTESTATION_SCHEMA_PREFIX = "published-attestation/"

_SHA256 = re.compile(r"(sha256:)?[0-9a-f]{64}")
_MODULE_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,127}")
_JOB_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_MAX_COUNT = 10**9
_MAX_ITEMS = 100_000

#: The name of a digest in the identity and the Merkle sub-roots, and of a
#: NOT_VERIFIED cause: a bounded lower-case identifier.
_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
_MAX_NAMED_DIGESTS = 64
#: Whether a module's emission was shown deterministic: the public claim.
DETERMINISM_NOT_VERIFIED = "NOT_VERIFIED"
DETERMINISM_STATUSES = ("VERIFIED", DETERMINISM_NOT_VERIFIED, "DRIFT")
#: Who ran the build's tests, and the seal class that goes with each:
#: DevMatrix ran them and sealed the build, or the client ran them on its own
#: machine and the build is self-attested. Every other pairing is refused.
RUN_BY_VALUES = ("devmatrix", "client")
SEAL_CLASSES = ("sealed", "self_attested")
SEAL_CLASS_OF_RUN_BY = {"devmatrix": "sealed", "client": "self_attested"}


class AttestationRefused(ValueError):
    """The document is not exactly the published attestation schema it names."""


Check = Callable[[object, str], None]


def _digest(value: object, where: str) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise AttestationRefused(f"{where}: is not a sha256 digest")


def _pattern(pattern: "re.Pattern[str]") -> Check:
    def check(value: object, where: str) -> None:
        if not isinstance(value, str) or pattern.fullmatch(value) is None:
            raise AttestationRefused(f"{where}: is not an identifier of the declared form")
    return check


def _one_of(allowed: tuple) -> Check:
    def check(value: object, where: str) -> None:
        if not isinstance(value, str) or value not in allowed:
            raise AttestationRefused(f"{where}: is not one of its declared values")
    return check


def _count(value: object, where: str) -> None:
    if type(value) is not int or not 0 <= value <= _MAX_COUNT:
        raise AttestationRefused(f"{where}: is not a count")


def _object(fields: Mapping[str, Check], optional: frozenset = frozenset()) -> Check:
    def check(value: object, where: str) -> None:
        if not isinstance(value, dict):
            raise AttestationRefused(f"{where}: is not an object")
        undeclared = sorted(set(value) - set(fields))
        if undeclared:
            raise AttestationRefused(f"{where}: carries undeclared keys {undeclared}")
        missing = sorted(set(fields) - set(value) - optional)
        if missing:
            raise AttestationRefused(f"{where}: lacks {missing}")
        for key, item in value.items():
            fields[key](item, f"{where}.{key}")
    return check


def _list(item: Check) -> Check:
    def check(value: object, where: str) -> None:
        if not isinstance(value, list) or len(value) > _MAX_ITEMS:
            raise AttestationRefused(f"{where}: is not a bounded list")
        for index, element in enumerate(value):
            item(element, f"{where}[{index}]")
    return check


def _named_digests(value: object, where: str) -> None:
    """A non-empty, bounded object of digests, each under a bounded name."""
    if not isinstance(value, dict) or not 0 < len(value) <= _MAX_NAMED_DIGESTS:
        raise AttestationRefused(f"{where}: is not a bounded object of digests")
    for name, digest in value.items():
        if _NAME.fullmatch(name) is None:
            raise AttestationRefused(f"{where}: {name!r} is not a digest name of the declared form")
        _digest(digest, f"{where}.{name}")


_MODULE = _pattern(_MODULE_ID)

_V1_FIELDS: dict = {
    "schema": _one_of((ATTESTATION_SCHEMA_V1,)),
    "job_id": _pattern(_JOB_ID),
    "attestation_sha256": _digest,
    "reproducible_sha256": _digest,
    "identity": _named_digests,
    "merkle": _object({
        "nested_root": _digest,
        "sub_roots": _named_digests,
        "emit_root": _digest,
        "emit_leaf_sha256": _list(_digest),
    }),
    "modules": _list(_object({"module": _MODULE, "emission_sha256": _digest})),
    "determinism": _list(_object(
        {
            "module": _MODULE,
            "status": _one_of(DETERMINISM_STATUSES),
            "cause": _pattern(_NAME),
        },
        optional=frozenset({"cause"}),
    )),
    "terminal_gate_verdict_hash": _digest,
    "not_tested_count": _count,
    "coverage": _object({"delivered_files": _count, "covered": _count}),
    "certificate_fingerprint": _digest,
}
#: ``/2`` is ``/1`` plus who ran the tests and the seal class. A ``/1`` document
#: states neither, and none is read into it.
_V2_FIELDS: dict = dict(
    _V1_FIELDS,
    schema=_one_of((ATTESTATION_SCHEMA_V2,)),
    run_by=_one_of(RUN_BY_VALUES),
    seal_class=_one_of(SEAL_CLASSES),
)
ATTESTATION_SCHEMA_V3 = "published-attestation/3"
#: The digests ``/3`` states for the build's identity: the platform source's
#: hash, the digest of the module map that travels beside them, and the links
#: of the build. ``/1`` and ``/2`` stated one aggregate ``spec_hash`` instead,
#: a different subject that is never compared with ``platform_spec_hash``.
IDENTITY_LINKS_V3 = (
    "platform_spec_hash",
    "service_spec_hashes_sha256",
    "ir_structural_hash",
    "ir_semantic_hash",
    "compiler_toolchain_hash",
    "deterministic_seed",
    "build_fingerprint",
)
#: The identity key that maps each module to the SHA-256 of its source.
SERVICE_SPEC_HASHES = "service_spec_hashes"
#: The Merkle sub-roots ``/3`` names, a closed set.
SUB_ROOT_NAMES = ("artifact_root", "dependency_root", "model_root", "specification_root")
#: Why a module's determinism is NOT_VERIFIED in ``/3``, a closed set.
NOT_VERIFIED_CAUSES = (
    "not_measured_yet",
    "gate_did_not_run",
    "no_baseline",
    "in_build_unmeasured",
    "gate_row_absent_from_ledger",
)


def _module_map(value: object, where: str) -> None:
    if not isinstance(value, dict) or len(value) > _MAX_ITEMS:
        raise AttestationRefused(f"{where}: is not a bounded module map")
    for module, digest in value.items():
        _MODULE(module, f"{where} key")
        _digest(digest, f"{where}.{module}")


def service_spec_hashes_sha256(service_spec_hashes: Mapping[str, str]) -> str:
    """The digest ``/3`` links for the module map: SHA-256 of the map as JSON
    with sorted keys and no whitespace, UTF-8, as bare hex."""
    canonical = json.dumps(
        dict(sorted(service_spec_hashes.items())), sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


#: ``/3`` is ``/2`` with the spec identity of the platform and its modules,
#: named Merkle sub-roots and a closed set of NOT_VERIFIED causes. Its
#: ``attestation_sha256`` is the SHA-256 of the delivered attestation file's
#: bytes, the digest a seal signs; ``/1`` and ``/2`` stated the digest of
#: another serialization.
_V3_FIELDS: dict = dict(
    _V2_FIELDS,
    schema=_one_of((ATTESTATION_SCHEMA_V3,)),
    identity=_object({
        **{name: _digest for name in IDENTITY_LINKS_V3},
        SERVICE_SPEC_HASHES: _module_map,
    }),
    merkle=_object({
        "nested_root": _digest,
        "sub_roots": _object({name: _digest for name in SUB_ROOT_NAMES}),
        "emit_root": _digest,
        "emit_leaf_sha256": _list(_digest),
    }),
    determinism=_list(_object(
        {
            "module": _MODULE,
            "status": _one_of(DETERMINISM_STATUSES),
            "cause": _one_of(NOT_VERIFIED_CAUSES),
        },
        optional=frozenset({"cause"}),
    )),
)
ATTESTATION_SCHEMAS: Mapping[str, Check] = {
    ATTESTATION_SCHEMA_V1: _object(_V1_FIELDS),
    ATTESTATION_SCHEMA_V2: _object(_V2_FIELDS),
    ATTESTATION_SCHEMA_V3: _object(_V3_FIELDS),
}


#: The published fingerprint: the public projection of a build's fingerprint
#: record. ``/2`` is the only one ever published; it carries no
#: ``code_bundle_hash``, which the delivered code never reproduced (each
#: module's delivered code is sealed in the export manifest instead).
PUBLISHED_FINGERPRINT_PREFIX = "published-fingerprint/"
PUBLISHED_FINGERPRINT_SCHEMA_V2 = "published-fingerprint/2"
#: Schemas that were defined but never published: refused by name, never read.
PUBLISHED_FINGERPRINT_NEVER_PUBLISHED = ("published-fingerprint/1",)
#: The top-level keys a published fingerprint may carry; only the first two
#: are always present.
PUBLISHED_FINGERPRINT_REQUIRED = ("schema", "source_record_digest")
PUBLISHED_FINGERPRINT_KEYS = PUBLISHED_FINGERPRINT_REQUIRED + (
    "build_id", "job_id", "spec_hash", "verdict_binding", "compile_status", "release_ref",
    "merkle_root", "determinism", "passed", "terminal_success", "seal",
    "customer_checks", "complexity_measurement",
)
_HEX64 = re.compile(r"[0-9a-f]{64}")
_RELEASE_REF = re.compile(r"release:[0-9a-f]{64}")
_MAX_IDENTITY = 256
#: The compilation outcomes a published fingerprint may state.
COMPILE_STATUSES = (
    "succeeded", "completed_incomplete", "completed_unverified", "completed_runtime_by_client",
    "completed_awaiting_qa", "halted_with_gate_failures", "halted_task_exception", "refused_at_admission",
    "halted_service_build_failure", "halted_with_test_failures", "halted_delivery_refused",
    "cancelled", "unknown",
)
#: The published Merkle commitment: digests (empty when the build carries no
#: such layer), its leaf count and its proof schema version.
MERKLE_ROOT_DIGESTS = ("root_hash", "specs_root", "ir_root", "emit_root", "sbom_root")
MERKLE_ROOT_KEYS = MERKLE_ROOT_DIGESTS + ("leaf_count", "schema_version")
#: The sub-roots a build may carry empty (it has no such layer); the root never is.
MERKLE_SUB_ROOTS = ("specs_root", "ir_root", "emit_root", "sbom_root")
#: The Merkle proof schemas a published commitment may name.
MERKLE_SCHEMA_VERSIONS = ("1.1", "1.2", "1.3", "1.4")
#: The customer's checks before the NDA, and the sealed schemas it copies.
PRE_NDA_CUSTOMER_CHECKS_SCHEMA = "dmx_customer_checks_pre_nda/v1"
SEALED_CUSTOMER_CHECKS_SCHEMAS = (
    "dmx_customer_checks/v5", "dmx_customer_checks/v6", "dmx_customer_checks/v7", "dmx_customer_checks/v8",
    "dmx_customer_checks/v9",
)
CUSTOMER_CHECKS_NOT_PROJECTED_REASONS = (
    "halted_before_gates", "projection_refused", "predates_projection", "task_exception",
    "refused_at_admission", "cancelled",
)
RUN_BY_CLIENT_CAUSE = "runtime_phase_run_by_client"
#: Why a build delivered awaiting its QA run states no tests: they run in the
#: QA run, after the compile.
DEFERRED_TO_QA_RUN_CAUSE = "runtime_phase_deferred_to_qa_run"
#: The status of a build delivered awaiting its QA run: its tests have not run
#: yet, so it is not sealable until the QA run grades it.
AWAITING_QA_STATUS = "completed_awaiting_qa"
PRE_NDA_TEST_KEYS = (
    "ran", "total", "planned", "not_reached", "pass_rate", "passed", "failed",
    "not_applicable", "did_not_run", "counted_in_another_tier",
)
#: The published complexity measurement.
COMPLEXITY_SCHEMA = "complexity-measurement/2"
COMPLEXITY_STATES = ("complete", "incomplete", "instrument_error")
COMPLEXITY_CALIBRATIONS = ("not_calibrated",)
COMPLEXITY_KEYS = ("schema_id", "state", "calibration", "total_milli", "band", "entitlement_reasons")
_MAX_COMPLEXITY_MILLI = 1_000_000


def _hex64(value: object, where: str) -> None:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise AttestationRefused(f"{where}: is not a sha256 digest")


def _bool_or_null(value: object, where: str) -> None:
    if value is not None and type(value) is not bool:
        raise AttestationRefused(f"{where}: is not true, false or null")


def _identity(value: object, where: str) -> None:
    if value is not None and (not isinstance(value, str) or len(value) > _MAX_IDENTITY):
        raise AttestationRefused(f"{where}: is not a bounded string or null")


def _hex64_or_null(value: object, where: str) -> None:
    if value is not None:
        _hex64(value, where)


def _merkle_sub_root(value: object, where: str) -> None:
    """A Merkle sub-root digest, or empty: the build carries no such layer."""
    if value != "":
        _hex64(value, where)


def _merkle_root(value: object, where: str) -> None:
    if isinstance(value, str):
        _hex64(value, where)
        return
    if not isinstance(value, dict):
        raise AttestationRefused(f"{where}: is not a digest or an object")
    undeclared = sorted(set(value) - set(MERKLE_ROOT_KEYS))
    if undeclared:
        raise AttestationRefused(f"{where}: carries undeclared keys {undeclared}")
    for key, item in value.items():
        if key == "leaf_count":
            _count(item, f"{where}.{key}")
        elif key == "schema_version":
            _one_of(MERKLE_SCHEMA_VERSIONS)(item, f"{where}.{key}")
        elif key in MERKLE_SUB_ROOTS:
            _merkle_sub_root(item, f"{where}.{key}")
        else:
            _hex64(item, f"{where}.{key}")


def _determinism(value: object, where: str) -> None:
    if not isinstance(value, dict):
        raise AttestationRefused(f"{where}: is not an object")
    if "status" in value:
        _object(
            {"status": _one_of(DETERMINISM_STATUSES), "cause": _one_of(NOT_VERIFIED_CAUSES)},
            optional=frozenset({"cause"}),
        )(value, where)
        if (value["status"] == DETERMINISM_NOT_VERIFIED) != ("cause" in value):
            raise AttestationRefused(f"{where}: a cause goes with NOT_VERIFIED and only with it")
        return
    _object({"deterministic": _bool_or_null})(value, where)


def _count_or_null(value: object, where: str) -> None:
    if value is not None:
        _count(value, where)


def _or_null(check: Check) -> Check:
    def checked(value: object, where: str) -> None:
        if value is not None:
            check(value, where)
    return checked


def _null(value: object, where: str) -> None:
    """A field the schema states always null: no band is determined yet."""
    if value is not None:
        raise AttestationRefused(f"{where}: is not null")


def _text(value: object, where: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise AttestationRefused(f"{where}: is not a bounded non-empty text")


def _rate_or_null(value: object, where: str) -> None:
    if value is not None and (type(value) not in (int, float) or not value >= 0):
        raise AttestationRefused(f"{where}: is not a non-negative rate or null")


def _strict_bool(value: object, where: str) -> None:
    if type(value) is not bool:
        raise AttestationRefused(f"{where}: is not true or false")


def _signed_count_or_null(value: object, where: str) -> None:
    """A count of tests not reached; a report written before the reach was
    bounded may state it negative."""
    if value is not None and (type(value) is not int or abs(value) > _MAX_COUNT):
        raise AttestationRefused(f"{where}: is not a bounded integer or null")


_PRE_NDA_TESTS = _object({
    "ran": _strict_bool, "total": _count, "planned": _count_or_null,
    "not_reached": _signed_count_or_null, "pass_rate": _rate_or_null, "passed": _count,
    "failed": _count, "not_applicable": _count_or_null, "did_not_run": _count,
    "counted_in_another_tier": _count,
})


def _any_object(value: object, where: str) -> None:
    if not isinstance(value, dict):
        raise AttestationRefused(f"{where}: is not an object")


def _any_list(value: object, where: str) -> None:
    if not isinstance(value, list) or len(value) > _MAX_ITEMS:
        raise AttestationRefused(f"{where}: is not a bounded list")


def _customer_checks(value: object, where: str) -> None:
    """The pre-NDA copy of the customer's checks. Its scopes and totals are
    the sealed ones, in the shape of the sealed schema it names; this checks
    they are a list and an object, not that shape."""
    if not isinstance(value, dict):
        raise AttestationRefused(f"{where}: is not an object")
    common = {
        "schema_id": _one_of((PRE_NDA_CUSTOMER_CHECKS_SCHEMA,)),
        "sealed_schema_id": _one_of(SEALED_CUSTOMER_CHECKS_SCHEMAS),
    }
    if value.get("status") == "not_projected":
        _object({**common, "status": _one_of(("not_projected",)),
                 "reason": _one_of(CUSTOMER_CHECKS_NOT_PROJECTED_REASONS)})(value, where)
        return
    _object({
        **common, "status": _one_of(("projected",)), "scopes": _any_list, "totals": _any_object,
        "tests": _or_null(_PRE_NDA_TESTS),
        "tests_absent_reason": _or_null(_one_of((RUN_BY_CLIENT_CAUSE, DEFERRED_TO_QA_RUN_CAUSE))),
    })(value, where)
    if (value["tests"] is None) == (value["tests_absent_reason"] is None):
        raise AttestationRefused(f"{where}: states its tests or why it has none, exactly one")


def _complexity(value: object, where: str) -> None:
    _object({
        "schema_id": _one_of((COMPLEXITY_SCHEMA,)), "state": _one_of(COMPLEXITY_STATES),
        "calibration": _one_of(COMPLEXITY_CALIBRATIONS),
        "total_milli": _count_or_null,
        "band": _null,
        "entitlement_reasons": _list(_text),
    })(value, where)
    total = value["total_milli"]
    if (value["state"] == "complete") != (total is not None):
        raise AttestationRefused(f"{where}.total_milli: a total goes with a complete measurement and only with it")
    if total is not None and total > _MAX_COMPLEXITY_MILLI:
        raise AttestationRefused(f"{where}.total_milli: is above its bound")
    if not value["entitlement_reasons"]:
        raise AttestationRefused(f"{where}.entitlement_reasons: states no reason")


#: How each value of a published fingerprint is checked.
PUBLISHED_FINGERPRINT_VALUES: Mapping[str, Check] = {
    "schema": _one_of((PUBLISHED_FINGERPRINT_SCHEMA_V2,)),
    "source_record_digest": _hex64,
    "build_id": _identity,
    "job_id": _identity,
    "spec_hash": _hex64_or_null,
    "verdict_binding": _identity,
    "compile_status": _one_of(COMPILE_STATUSES),
    "release_ref": _pattern(_RELEASE_REF),
    "merkle_root": _merkle_root,
    "determinism": _determinism,
    "passed": _bool_or_null,
    "terminal_success": _bool_or_null,
    "seal": _object({"passed": _bool_or_null}),
    "customer_checks": _customer_checks,
    "complexity_measurement": _complexity,
}


def is_published_fingerprint(payload: dict) -> bool:
    """Whether a signed payload names a published-fingerprint schema."""
    schema = payload.get("schema")
    return isinstance(schema, str) and schema.startswith(PUBLISHED_FINGERPRINT_PREFIX)


def check_published_fingerprint(payload: dict) -> list[str]:
    """Validate a published fingerprint against the one schema ever published.

    Raises :class:`AttestationRefused` for a schema that was never published
    (named as such), an unknown one, a ``code_bundle_hash`` (named), any other
    undeclared top-level key, a missing required key, or a value not of its
    declared form (``PUBLISHED_FINGERPRINT_VALUES``): booleans are booleans,
    digests are sha256 hex digests, closed sets are closed, and the nested
    objects carry exactly their declared keys.
    """
    schema = payload.get("schema")
    if schema in PUBLISHED_FINGERPRINT_NEVER_PUBLISHED:
        raise AttestationRefused(
            f"fingerprint schema {schema!r} was never published; "
            f"a published fingerprint is {PUBLISHED_FINGERPRINT_SCHEMA_V2}"
        )
    if schema != PUBLISHED_FINGERPRINT_SCHEMA_V2:
        raise AttestationRefused(f"unknown fingerprint schema {schema!r}")
    if "code_bundle_hash" in payload:
        raise AttestationRefused(
            f"fingerprint: {schema} carries no code_bundle_hash; the delivered code is "
            "sealed per module in the export manifest"
        )
    undeclared = sorted(set(payload) - set(PUBLISHED_FINGERPRINT_KEYS))
    if undeclared:
        raise AttestationRefused(f"fingerprint: carries undeclared keys {undeclared}")
    missing = sorted(set(PUBLISHED_FINGERPRINT_REQUIRED) - set(payload))
    if missing:
        raise AttestationRefused(f"fingerprint: lacks {missing}")
    for key, value in payload.items():
        PUBLISHED_FINGERPRINT_VALUES[key](value, f"fingerprint.{key}")
    if payload.get("compile_status") == AWAITING_QA_STATUS:
        if payload.get("seal", {}).get("passed") is True:
            raise AttestationRefused(
                "fingerprint.seal: a build awaiting its QA run is not sealable, and this one states a passed seal"
            )
        return [f"[OK] fingerprint: {schema}", "      fingerprint: awaiting its QA run: not sealable until it is graded"]
    return [f"[OK] fingerprint: {schema}"]


def is_published_attestation(payload: dict) -> bool:
    """Whether a signed payload is, or claims to be, a published attestation:
    it carries a ``schema`` key (no other evidence this verifier reads does),
    or states who ran the tests or a seal class. Each of these is checked
    against the schema it names, so a malformed or misspelled schema fails
    rather than going unchecked."""
    return any(key in payload for key in ("schema", "run_by", "seal_class"))


def check_published_attestation(payload: dict) -> list[str]:
    """Validate a published attestation against the closed schema it names.

    Returns the lines to report; raises :class:`AttestationRefused` when the
    schema is unknown or the document is not exactly that schema: an
    undeclared or missing key at any level, a value not of its declared form,
    a determinism cause on a status other than NOT_VERIFIED (or none on it),
    or, in ``/2``, a seal class that does not go with who ran the tests.
    """
    schema = payload.get("schema")
    check = ATTESTATION_SCHEMAS.get(schema) if isinstance(schema, str) else None
    if check is None:
        raise AttestationRefused(f"unknown attestation schema {schema!r}")
    check(payload, "attestation")
    for index, row in enumerate(payload["determinism"]):
        if (row["status"] == DETERMINISM_NOT_VERIFIED) != ("cause" in row):
            raise AttestationRefused(
                f"attestation.determinism[{index}]: a cause goes with NOT_VERIFIED and only with it"
            )
    if schema == ATTESTATION_SCHEMA_V1:
        return [f"[OK] attestation: {schema}; who ran the tests is not stated in this schema"]
    if SEAL_CLASS_OF_RUN_BY[payload["run_by"]] != payload["seal_class"]:
        raise AttestationRefused(
            f"attestation.seal_class: {payload['seal_class']!r} does not go with tests run by "
            f"{payload['run_by']!r}"
        )
    lines = [
        f"[OK] attestation: {schema}; tests run by {payload['run_by']}, seal {payload['seal_class']}"
    ]
    if schema == ATTESTATION_SCHEMA_V3:
        identity = payload["identity"]
        link = identity["service_spec_hashes_sha256"].removeprefix("sha256:")
        if service_spec_hashes_sha256(identity[SERVICE_SPEC_HASHES]) != link:
            raise AttestationRefused(
                "attestation.identity: the module map is not the one its digest service_spec_hashes_sha256 names"
            )
        lines.append(
            f"[OK] attestation: platform spec {identity['platform_spec_hash']}, "
            f"{len(identity[SERVICE_SPEC_HASHES])} module spec hashes"
        )
    return lines


# ---------------------------------------------------------------------------
# Published platform seals: the public record of a signed platform seal. It
# carries digests, versions, closed-set statuses, grades and counts, the
# digest of the exact signed seal statement and the seal signature over it;
# no platform or service name. A holder of the seal statement checks its
# SHA-256 against ``statement_sha256``.
# ---------------------------------------------------------------------------

#: The seal statement from which every sealed build states the lowest grade it
#: could be sealed at (``seal_floor``) and every test that failed, by name.
SEAL_STATEMENT_WITH_FLOOR = "seal-statement/5"
#: The seal statement from which every sealed build also states how many of
#: its tests were not judged (``not_judged_count``), naming them, and a
#: self-attested grade its own count (``listed_not_judged``); null when the
#: grade was given before that count existed: «not stated», never 0.
SEAL_STATEMENT_WITH_NOT_JUDGED = "seal-statement/6"
#: The seal statement from which every sealed build also states what its grade
#: rests on (``basis``: the compile, a QA run on DevMatrix or the client's run),
#: the build it seals (``compilation_id``), the QA run it rests on, and its
#: tests proven not applicable, with the digests of the evidence files that
#: show them.
SEAL_STATEMENT_WITH_BASIS = "seal-statement/7"
#: The statements that state the grade floor and every failed test.
SEAL_STATEMENTS_WITH_FLOOR = (SEAL_STATEMENT_WITH_FLOOR, SEAL_STATEMENT_WITH_NOT_JUDGED, SEAL_STATEMENT_WITH_BASIS)
#: The statements that count and name their tests not judged.
SEAL_STATEMENTS_WITH_NOT_JUDGED = (SEAL_STATEMENT_WITH_NOT_JUDGED, SEAL_STATEMENT_WITH_BASIS)
#: What a seal-statement/7 grade rests on, and who measured the build then.
MEASURER_OF_BASIS = {"compile": "devmatrix", "qa_run": "devmatrix", "client_run": "self_attested"}
#: The QA run reports a seal-statement/7 names, and the one that predates
#: proofs: a seal over it states no count of tests proven not applicable.
QA_RUN_REPORT_SCHEMAS = ("qa-run-report/1", "qa-run-report/2")
QA_RUN_REPORT_WITHOUT_PROOFS = "qa-run-report/1"
#: What a seal says when it does not state its tests proven not applicable.
PROOFS_NOT_STATED = "This seal does not state its tests proven not applicable."
#: What a seal says when it does not state how many tests were not judged.
NOT_JUDGED_NOT_STATED = "This seal does not state how many tests were not judged."
#: The grades, best first; the lowest grade a build is sealed at from
#: seal-statement/5 on, and the grades at or above it.
GRADES = ("A+", "A", "B", "C", "D", "F")
SEAL_FLOOR = "A"
SEALABLE_GRADES = GRADES[: GRADES.index(SEAL_FLOOR) + 1]
PUBLISHED_PLATFORM_SEAL_PREFIX = "published-platform-seal/"
#: The record of a seal-statement/3 or /4 seal: the client's grade states the
#: share of tests it was sealed at.
PUBLISHED_PLATFORM_SEAL_V1 = "published-platform-seal/1"
#: The record of a seal-statement/5 seal: every service states the grade
#: floor it was sealed at (``seal_floor``), its grade at or above it, and how
#: many of its tests failed (``failed``); no share of tests.
PUBLISHED_PLATFORM_SEAL_V2 = "published-platform-seal/2"
#: The record of a seal-statement/6 seal: as /2, and every service states how
#: many of its tests were not judged (``not_judged``), or null when its grade
#: was given before that count existed. Only the count is published; the
#: signed statement names the tests.
PUBLISHED_PLATFORM_SEAL_V3 = "published-platform-seal/3"
#: The record of a seal-statement/7 seal: as /3, and every service states what
#: its grade rests on (``basis``) and how many of its tests were proven not
#: applicable (``proven_not_applicable``), or null when it does not state them.
PUBLISHED_PLATFORM_SEAL_V4 = "published-platform-seal/4"
#: The seal statements each record version is published from.
PLATFORM_SEAL_STATEMENTS = {
    PUBLISHED_PLATFORM_SEAL_V1: ("seal-statement/3", "seal-statement/4"),
    PUBLISHED_PLATFORM_SEAL_V2: (SEAL_STATEMENT_WITH_FLOOR,),
    PUBLISHED_PLATFORM_SEAL_V3: (SEAL_STATEMENT_WITH_NOT_JUDGED,),
    PUBLISHED_PLATFORM_SEAL_V4: (SEAL_STATEMENT_WITH_BASIS,),
}
#: The record versions that state the grade floor and the failed count.
PLATFORM_SEALS_WITH_FLOOR = (PUBLISHED_PLATFORM_SEAL_V2, PUBLISHED_PLATFORM_SEAL_V3, PUBLISHED_PLATFORM_SEAL_V4)
#: The record versions that count the tests not judged.
PLATFORM_SEALS_WITH_NOT_JUDGED = (PUBLISHED_PLATFORM_SEAL_V3, PUBLISHED_PLATFORM_SEAL_V4)
#: Who measured a sealed platform, as the record states it, and who ran its tests.
VERIFICATION_OF_RUN_BY = {"devmatrix": "devmatrix", "self_attested": "client"}
_HEX64_ONLY = re.compile(r"[0-9a-f]{64}")
_SEAL_KEY_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_SEALED_AT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z")
_BASE64 = re.compile(r"[A-Za-z0-9+/]{1,4096}={0,2}")
_MAX_SEALED_SERVICES = 10_000


def _count_upto(upper: int) -> Check:
    def check(value: object, where: str) -> None:
        if type(value) is not int or not 0 <= value <= upper:
            raise AttestationRefused(f"{where}: is not a count in its range")
    return check


def _services_list(item: Check) -> Check:
    def check(value: object, where: str) -> None:
        if not isinstance(value, list) or not 0 < len(value) <= _MAX_SEALED_SERVICES:
            raise AttestationRefused(f"{where}: is not a bounded, non-empty list")
        for index, element in enumerate(value):
            item(element, f"{where}[{index}]")
    return check


_SEAL_VERIFICATION = _one_of(tuple(VERIFICATION_OF_RUN_BY))
_SERVICE_COMMON: Mapping[str, Check] = {
    "spec_hash": _digest,
    "spec_version": _count,
    "verification": _SEAL_VERIFICATION,
    "qa_score_hundredths": _or_null(_count_upto(10_000)),
    "build_fingerprint": _digest,
    "merkle_root": _digest,
    "evidence_content_hash": _digest,
    "evidence_key_id": _pattern(_SEAL_KEY_ID),
    "fingerprint_attestation": _or_null(_object({
        "document_sha256": _digest,
        "reproducible_sha256": _digest,
    })),
}
_SEALED_SERVICE_V1 = _object({
    **_SERVICE_COMMON,
    "grade": _or_null(_one_of(GRADES)),
    "self_attested_grade": _or_null(_object({
        "letter": _one_of(GRADES),
        "score_percent": _count_upto(100),
        "passed": _count,
        "applicable": _count,
        "failed": _count,
        "listed_not_emitted": _count,
        "listed_declared_skips": _count,
        "required_percent": _count_upto(100),
    })),
})
_SEALED_SERVICE_V2 = _object({
    **_SERVICE_COMMON,
    "grade": _or_null(_one_of(SEALABLE_GRADES)),
    "self_attested_grade": _or_null(_object({
        "letter": _one_of(SEALABLE_GRADES),
        "score_percent": _count_upto(100),
        "passed": _count,
        "applicable": _count,
        "listed_not_emitted": _count,
        "listed_declared_skips": _count,
    })),
    "seal_floor": _one_of((SEAL_FLOOR,)),
    "failed": _count,
})
_SEALED_SERVICE_V3 = _object({
    **_SERVICE_COMMON,
    "grade": _or_null(_one_of(SEALABLE_GRADES)),
    "self_attested_grade": _or_null(_object({
        "letter": _one_of(SEALABLE_GRADES),
        "score_percent": _count_upto(100),
        "passed": _count,
        "applicable": _count,
        "listed_not_emitted": _count,
        "listed_declared_skips": _count,
    })),
    "seal_floor": _one_of((SEAL_FLOOR,)),
    "failed": _count,
    "not_judged": _or_null(_count),
})
_SEALED_SERVICE_V4 = _object({
    **_SERVICE_COMMON,
    "grade": _or_null(_one_of(SEALABLE_GRADES)),
    "self_attested_grade": _or_null(_object({
        "letter": _one_of(SEALABLE_GRADES),
        "score_percent": _count_upto(100),
        "passed": _count,
        "applicable": _count,
        "listed_not_emitted": _count,
        "listed_declared_skips": _count,
    })),
    "seal_floor": _one_of((SEAL_FLOOR,)),
    "failed": _count,
    "not_judged": _or_null(_count),
    "basis": _one_of(tuple(MEASURER_OF_BASIS)),
    "proven_not_applicable": _or_null(_count),
})


def _platform_seal_record(schema: str, service: Check) -> Check:
    """The closed schema of one published platform-seal record version."""
    return _object({
        "schema": _one_of((schema,)),
        "seal_hash": _pattern(_HEX64_ONLY),
        "sealed_at": _pattern(_SEALED_AT),
        "statement_schema_id": _one_of(PLATFORM_SEAL_STATEMENTS[schema]),
        "statement_sha256": _pattern(_HEX64_ONLY),
        "seal_signature": _object({
            "algorithm": _one_of(("Ed25519",)),
            "key_id": _pattern(_SEAL_KEY_ID),
            "signature_b64": _pattern(_BASE64),
        }),
        "seal_public_key": _object({
            "key_id": _pattern(_SEAL_KEY_ID),
            "public_key_b64": _pattern(_BASE64),
        }),
        "platform": _object({
            "spec_hash": _digest,
            "spec_version": _count,
            "verification": _SEAL_VERIFICATION,
            "qa_score_hundredths": _or_null(_count_upto(10_000)),
        }),
        "services": _services_list(service),
        "run_by": _one_of(RUN_BY_VALUES),
        "seal_class": _one_of(SEAL_CLASSES),
    })


PLATFORM_SEAL_SCHEMAS: Mapping[str, Check] = {
    PUBLISHED_PLATFORM_SEAL_V1: _platform_seal_record(PUBLISHED_PLATFORM_SEAL_V1, _SEALED_SERVICE_V1),
    PUBLISHED_PLATFORM_SEAL_V2: _platform_seal_record(PUBLISHED_PLATFORM_SEAL_V2, _SEALED_SERVICE_V2),
    PUBLISHED_PLATFORM_SEAL_V3: _platform_seal_record(PUBLISHED_PLATFORM_SEAL_V3, _SEALED_SERVICE_V3),
    PUBLISHED_PLATFORM_SEAL_V4: _platform_seal_record(PUBLISHED_PLATFORM_SEAL_V4, _SEALED_SERVICE_V4),
}


def is_published_platform_seal(payload: dict) -> bool:
    """Whether a signed payload names a published platform-seal schema."""
    schema = payload.get("schema")
    return isinstance(schema, str) and schema.startswith(PUBLISHED_PLATFORM_SEAL_PREFIX)


def _measurer_refusal(record: dict) -> str | None:
    """Why the record does not state one measurer and only that measurer's
    account, or ``None``: DevMatrix's score (and, on a service, its grade)
    when DevMatrix ran the tests; the client's grade and no DevMatrix score
    or grade when the client ran them."""
    platform = record["platform"]
    measurer = platform["verification"]
    if VERIFICATION_OF_RUN_BY[measurer] != record["run_by"]:
        return "platform seal.run_by: is not who the platform states measured it"
    by_devmatrix = measurer == "devmatrix"
    if (platform["qa_score_hundredths"] is not None) != by_devmatrix:
        return "platform seal.platform.qa_score_hundredths: is not the account of who measured the platform"
    for index, service in enumerate(record["services"]):
        where = f"platform seal.services[{index}]"
        if service["verification"] != measurer:
            return f"{where}.verification: names another measurer than its platform"
        devmatrix_account = (service["qa_score_hundredths"], service["grade"])
        client_grade = service["self_attested_grade"]
        if by_devmatrix and (None in devmatrix_account or client_grade is not None):
            return f"{where}: is tested by DevMatrix and does not state exactly its score and grade"
        if not by_devmatrix and (devmatrix_account != (None, None) or client_grade is None):
            return f"{where}: is tested by its client and does not state exactly the client's grade"
        if record["schema"] in PLATFORM_SEALS_WITH_FLOOR and client_grade is not None:
            passed, applicable = client_grade["passed"], client_grade["applicable"]
            if not 0 < applicable or passed > applicable:
                return f"{where}.self_attested_grade: its test counts do not hold"
            if service["failed"] != applicable - passed:
                return f"{where}.failed: is not every test that did not pass"
        if record["schema"] in PLATFORM_SEALS_WITH_NOT_JUDGED:
            letter = service["grade"] if client_grade is None else client_grade["letter"]
            if letter == "A+" and service["not_judged"] != 0:
                return f"{where}: is graded A+ beside tests not judged, or beside a count it does not state"
        if record["schema"] == PUBLISHED_PLATFORM_SEAL_V4:
            if MEASURER_OF_BASIS[service["basis"]] != measurer:
                return f"{where}.basis: rests on {service['basis']}, which {measurer} does not measure"
            if service["basis"] == "compile" and service["proven_not_applicable"] is not None:
                return f"{where}.proven_not_applicable: rests on the compile and states a count of proofs"
            if letter == "A+" and service["proven_not_applicable"] is None:
                return f"{where}: is graded A+ beside tests proven not applicable it does not state"
    if record["schema"] == PUBLISHED_PLATFORM_SEAL_V4 and not by_devmatrix and len(record["services"]) != 1:
        return "platform seal.services: a self-attested seal is one build"
    return None


def check_published_platform_seal(payload: dict, keys: list[dict], accept: str = PRODUCTION) -> list[str]:
    """Validate a published platform seal against the closed schema it names.

    Returns the lines to report; raises :class:`AttestationRefused` when the
    schema is unknown, the record is not exactly that schema (an undeclared or
    missing key at any level, a value not of its declared form, a record
    version published from another seal statement), the seal class does not
    go with who ran the tests, the record states another measurer's account
    beside its own, or the seal key it names is not a seal-signing key
    keys.json publishes for that ``key_id``, whose window holds ``sealed_at``.
    From ``/2`` every service is graded at the seal floor or above and, when
    the client ran its tests, ``failed`` is every test that did not pass.
    """
    schema = payload.get("schema")
    check = PLATFORM_SEAL_SCHEMAS.get(schema) if isinstance(schema, str) else None
    if check is None:
        raise AttestationRefused(f"unknown platform seal schema {schema!r}")
    check(payload, "platform seal")
    if SEAL_CLASS_OF_RUN_BY[payload["run_by"]] != payload["seal_class"]:
        raise AttestationRefused(
            f"platform seal.seal_class: {payload['seal_class']!r} does not go with tests run by "
            f"{payload['run_by']!r}"
        )
    key_id = payload["seal_signature"]["key_id"]
    if payload["seal_public_key"]["key_id"] != key_id:
        raise AttestationRefused("platform seal.seal_public_key: is not the key that signed the seal")
    refusal = _measurer_refusal(payload)
    if refusal is not None:
        raise AttestationRefused(refusal)
    try:
        entry = published_key(
            keys, key_id, payload["seal_public_key"]["public_key_b64"], "seal-signing", "seals",
            payload["sealed_at"], "sealed",
        )
    except ValueError as exc:
        raise AttestationRefused(f"platform seal: {exc}") from exc
    refusal = class_refusal(entry, key_id, accept, "seal")
    if refusal is not None:
        raise AttestationRefused(f"platform seal: {refusal}")
    services = payload["services"]
    lines = [
        f"[OK] platform seal: {schema} of a {payload['statement_schema_id']}; tests run by "
        f"{payload['run_by']}, seal {payload['seal_class']}; {len(services)} sealed service(s)",
        f"[OK] platform seal: seal key {key_id!r} ({entry.get('class')}), sealed {payload['sealed_at']}; "
        f"the seal statement's SHA-256 is {payload['statement_sha256']}",
    ]
    if schema in PLATFORM_SEALS_WITH_FLOOR:
        for index, service in enumerate(services):
            grade = service["self_attested_grade"]
            letter = service["grade"] if grade is None else grade["letter"]
            lines.append(
                f"[OK] platform seal: services[{index}] graded {letter}, sealed at grade "
                f"{service['seal_floor']} or better, {service['failed']} failed test(s)"
            )
            if schema in PLATFORM_SEALS_WITH_NOT_JUDGED:
                lines.append(f"      platform seal: services[{index}]: {_published_not_judged_line(service['not_judged'])}")
            if schema == PUBLISHED_PLATFORM_SEAL_V4:
                proven = service["proven_not_applicable"]
                said = PROOFS_NOT_STATED if proven is None else (
                    f"{proven} {'test' if proven == 1 else 'tests'} proven not applicable (the signed statement names them)"
                )
                lines.append(f"      platform seal: services[{index}]: rests on {service['basis']}; {said}")
    return lines


def _published_not_judged_line(count: int | None) -> str:
    """What a published /3 record says of a service's tests not judged: the
    count, with the signed statement as where they are named; or, for null,
    that the seal does not state it, never 0."""
    if count is None:
        return NOT_JUDGED_NOT_STATED
    noun = "test" if count == 1 else "tests"
    return f"{count} {noun} not judged (the signed statement names them)"


def check_attestation(label: str, evidence: dict, keys: list[dict], accept: str = PRODUCTION) -> bool:
    """Print the schema verdict of ``evidence`` when its signed payload is a
    published fingerprint, a published platform seal or a published
    attestation; other documents have nothing to check here."""
    payload = signed_payload(evidence)
    suffix = f"  ({label})" if label else ""
    if is_published_platform_seal(payload):
        try:
            lines = check_published_platform_seal(payload, keys, accept)
        except AttestationRefused as refusal:
            print(f"[FAIL] {refusal}{suffix}")
            return False
        for line in lines:
            print(f"{line}{suffix}")
        return True
    fingerprint = is_published_fingerprint(payload)
    if not fingerprint and not is_published_attestation(payload):
        return True
    try:
        lines = (check_published_fingerprint if fingerprint else check_published_attestation)(payload)
    except AttestationRefused as refusal:
        print(f"[FAIL] {refusal}{suffix}")
        return False
    for line in lines:
        print(f"{line}{suffix}")
    return True


#: The field each kind of published document names itself by: a build
#: fingerprint its build, a published attestation its job, the earliest
#: fingerprints their run. A document that names none is refused, never
#: shown as ``N/A``.
#: A published platform seal is named by its seal hash.
IDENTITY_FIELDS = (("build_id", "Build ID"), ("job_id", "Job ID"), ("run_id", "Run ID"), ("seal_hash", "Seal"))
#: When the signed document says it was made, in the field its kind uses.
TIME_FIELDS = (("build_timestamp", "Timestamp"), ("created_at", "Created at"), ("sealed_at", "Sealed at"))


class IdentityMissing(ValueError):
    """The document names no build, job or run, so no output can say which
    one was verified."""


def identity_lines(evidence: dict) -> list[str]:
    """The lines that say which document is being verified: the identity and
    the time its signed payload declares, and when it was published (which
    the signature does not cover). Refuses a document that names none."""
    payload = signed_payload(evidence)
    names = [
        f"{label}: {payload[field]}"
        for field, label in IDENTITY_FIELDS
        if isinstance(payload.get(field), str) and payload[field]
    ]
    if not names:
        raise IdentityMissing(
            "the document names no "
            + ", ".join(field for field, _label in IDENTITY_FIELDS)
            + "; there is nothing to say which build was verified"
        )
    lines = names + [
        f"{label}: {payload[field]}"
        for field, label in TIME_FIELDS
        if isinstance(payload.get(field), str) and payload[field]
    ]
    published = evidence.get("published_at")
    if isinstance(published, str) and published:
        lines.append(f"Published at: {published} (not covered by the signature)")
    return lines


def print_identity(evidence: dict) -> None:
    """Print :func:`identity_lines`, or refuse with exit 1."""
    try:
        lines = identity_lines(evidence)
    except IdentityMissing as missing:
        print(f"ERROR: {missing}")
        sys.exit(1)
    for line in lines:
        print(line)


def signed_payload(evidence: dict) -> dict:
    """The fingerprint a file carries: the signed ``fingerprint`` object of an
    evidence pack, or the whole of a flat ``build_fingerprint.json``."""
    payload = evidence.get("fingerprint")
    return payload if isinstance(payload, dict) else evidence


def hash_fields(fingerprint: dict, prefix: str = "") -> dict[str, str]:
    """Every hash a fingerprint records, by its path (``ir_hashes.spec_hash``,
    ``modules.<name>.code_bundle_hash``, ``code_bundle_hash``): each non-empty
    string field whose name ends in ``_hash``, at any depth. Fingerprint
    schemas changed over time; comparing by path compares what both files
    record under the same name and never renames one schema's field into
    another's."""
    fields: dict[str, str] = {}
    for key, value in fingerprint.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            fields.update(hash_fields(value, path))
        elif isinstance(value, str) and key.endswith("_hash") and value:
            fields[path] = value
    return fields


def compare_fingerprints(fp1: dict, fp2: dict) -> list[tuple[str, bool, str]]:
    """Compare every hash the two fingerprints record, by path.

    A hash recorded by only one of them fails (the two fingerprints do not
    record the same things), and two fingerprints that record no hash at all
    fail: nothing was compared, so nothing was shown identical.
    """
    first, second = hash_fields(fp1), hash_fields(fp2)
    paths = sorted(set(first) | set(second))
    if not paths:
        return [("hashes", False, "no hash recorded in either fingerprint: nothing compared")]

    results = []
    for path in paths:
        v1, v2 = first.get(path), second.get(path)
        if v1 is None or v2 is None:
            where = "first" if v2 is None else "second"
            results.append((path, False, f"{path}: recorded only in the {where} fingerprint"))
        elif v1 == v2:
            results.append((path, True, f"{path}: IDENTICAL ({v1[:16]}...)"))
        else:
            results.append((path, False, f"{path}: DIFFERENT ({v1[:16]}... vs {v2[:16]}...)"))
    return results


# ---------------------------------------------------------------------------
# One build bound end to end: the fingerprint attestation delivered in the
# build's download, the platform seal that signs its digest, and the published
# attestation. All three name the attestation by the SHA-256 of the delivered
# file's bytes.
# ---------------------------------------------------------------------------

#: The fingerprint attestation a build's download carries.
DELIVERED_ATTESTATION_SCHEMA = "fingerprint-attestation/2"
#: The delivered attestation format before a seal could bind one: it states
#: no platform verdict, so who ran the build's tests cannot be read from it.
DELIVERED_ATTESTATION_SCHEMA_V1 = "fingerprint-attestation/1"
#: The seal statements whose services state their fingerprint attestation.
SEAL_STATEMENT_SCHEMAS = (
    "seal-statement/2", "seal-statement/3", "seal-statement/4", "seal-statement/5", "seal-statement/6",
    SEAL_STATEMENT_WITH_BASIS,
)
SEAL_FILES = ("seal-statement.json", "seal-statement.sig.b64", "seal-public-key.pem")


#: Why a binding check failed, one class per failure (contract §5 item 11):
#: what ``--verdict-json`` reports, so two verifiers are compared by verdict
#: and class, never by wording.
REASON_CLASSES = frozenset({
    "signature", "key", "unknown_version", "statement_version", "basis_measurer", "mixture", "runner",
    "qa_run_binding", "proofs", "grade_floor", "not_judged", "evidence_tampered", "evidence_refused",
    "attestation_digest", "attestation_identity", "published_deferred", "evidence_absent",
})


@dataclass(frozen=True)
class Failure:
    """One failed check: what is printed after ``[FAIL]``, and its class."""

    text: str
    reason_class: str

    def __post_init__(self) -> None:
        if self.reason_class not in REASON_CLASSES:
            raise ValueError(f"{self.reason_class!r} is not a reason class")

    def under(self, prefix: str) -> "Failure":
        """The same failure, its text after ``prefix``."""
        return Failure(prefix + self.text, self.reason_class)


class BindingRefused(ValueError):
    """The delivered attestation, the seal and the published attestation do
    not name one build; ``reason_class`` says why (:data:`REASON_CLASSES`)."""

    def __init__(self, text: str, reason_class: str) -> None:
        super().__init__(text)
        self.failure = Failure(text, reason_class)


def _bare(digest: object) -> object:
    return digest.removeprefix("sha256:") if isinstance(digest, str) else digest


def _sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def reproducible_sha256(block: object) -> str:
    """The digest of an attestation's reproducible block: its JSON with sorted
    keys and no whitespace, UTF-8."""
    canonical = json.dumps(block, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return _sha256_prefixed(canonical.encode("utf-8"))


def read_seal(bundle: Path, keys: list[dict], accept: str = PRODUCTION) -> tuple[dict, list[str]]:
    """The seal statement of a seal verification bundle once its signature
    verifies, and the lines to report (:func:`read_signed_seal`)."""
    statement, lines, _ = read_signed_seal(bundle, keys, accept)
    return statement, lines


def read_signed_seal(bundle: Path, keys: list[dict], accept: str = PRODUCTION) -> tuple[dict, list[str], bytes]:
    """The seal statement of a seal verification bundle, once its signature
    verifies with a published seal-signing key of keys.json, and the lines
    to report. The key inside the bundle proves nothing by itself: it has to
    be the one keys.json publishes for the statement's ``key_id``."""
    missing = [name for name in SEAL_FILES if not (bundle / name).is_file()]
    if missing:
        raise BindingRefused(f"the seal bundle {bundle} lacks {missing}", "signature")
    statement_bytes = (bundle / "seal-statement.json").read_bytes()
    statement, parsed = _json_of(statement_bytes)
    if not parsed:
        raise BindingRefused("the seal statement is not JSON", "signature")
    if not isinstance(statement, dict) or statement.get("schema_id") not in SEAL_STATEMENT_SCHEMAS:
        raise BindingRefused("the seal statement is not one that states its builds' attestations", "unknown_version")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise BindingRefused("the 'cryptography' package is required (pip install cryptography)", "signature") from exc
    try:
        pem_key = serialization.load_pem_public_key((bundle / "seal-public-key.pem").read_bytes())
    except ValueError as exc:
        raise BindingRefused(f"seal: seal-public-key.pem is not a public key: {exc}", "signature") from exc
    if not isinstance(pem_key, Ed25519PublicKey):
        raise BindingRefused("seal-public-key.pem is not an Ed25519 key", "signature")
    raw = pem_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = statement.get("key_id")
    try:
        entry = published_key(
            keys, key_id, base64.b64encode(raw).decode("ascii"), "seal-signing", "seals",
            statement.get("sealed_at"), "sealed",
        )
    except ValueError as exc:
        raise BindingRefused(f"seal: {exc}", "key") from exc
    try:
        signature = _b64((bundle / "seal-statement.sig.b64").read_text(encoding="ascii").strip(), "seal signature")
    except ValueError as exc:
        raise BindingRefused(f"seal: {exc}", "signature") from exc
    try:
        pem_key.verify(signature, statement_bytes)
    except InvalidSignature as exc:
        raise BindingRefused(f"seal: the statement's signature is INVALID for key {key_id!r}", "signature") from exc
    refusal = class_refusal(entry, key_id, accept, "seal")
    if refusal is not None:
        raise BindingRefused(f"seal: {refusal}", "key")
    lines = [
        f"[OK] seal: {statement['schema_id']}, key {key_id!r} ({entry.get('class')}), "
        f"sealed {statement.get('sealed_at')}"
    ]
    if accept != PRODUCTION:
        lines.append(f"[NOTE] seal: {key_id!r} is a {accept!r} key, NOT a production key")
    return statement, lines, statement_bytes


def _delivered(path: Path) -> tuple[bytes, dict]:
    data = path.read_bytes()
    document, parsed = _json_of(data)
    if parsed and isinstance(document, dict) and document.get("schema") == DELIVERED_ATTESTATION_SCHEMA_V1:
        raise BindingRefused(
            f"{path}: this build's attestation predates the format a seal can bind; compile again and seal again "
            "to verify offline",
            "attestation_identity",
        )
    if not parsed or not isinstance(document, dict) or document.get("schema") != DELIVERED_ATTESTATION_SCHEMA:
        raise BindingRefused(f"{path} is not a {DELIVERED_ATTESTATION_SCHEMA} document", "attestation_identity")
    reproducible = document.get("reproducible")
    identity = reproducible.get("identity") if isinstance(reproducible, dict) else None
    if not isinstance(identity, dict) or not isinstance(identity.get(SERVICE_SPEC_HASHES), dict):
        raise BindingRefused(f"{path} states no spec identity", "attestation_identity")
    if reproducible_sha256(reproducible) != document.get("reproducible_sha256"):
        raise BindingRefused(f"{path}: reproducible_sha256 is not the digest of its reproducible block", "attestation_digest")
    return data, document


#: Who measured a sealed build, as the seal statement states it from
#: seal-statement/3 on (``verification``), and who ran its tests then.
RUN_BY_OF_MEASURER = {"devmatrix": "devmatrix", "self_attested": "client"}
#: The seal statement that states no measurer.
SEAL_STATEMENT_WITHOUT_MEASURER = "seal-statement/2"
#: The test dispositions of a delivered platform verdict that DevMatrix ran;
#: tests not run because the client runs them carry ``RUN_BY_CLIENT_CAUSE``.
RAN_BY_DEVMATRIX = frozenset({"PASSED", "FAILED", "PARTIAL", "INCOMPLETE"})
TESTS_NOT_RUN = "NOT_RUN"
RUN_BY_CLIENT_CAUSE = "runtime_phase_run_by_client"
#: The runner of a build delivered with its tests deferred to a QA run
#: (``DEFERRED_TO_QA_RUN_CAUSE``).
DEFERRED_RUN_BY = "deferred"
#: Who may have run a sealed build's tests, as its delivered attestation
#: states it, for each basis a seal-statement/7 grade rests on. A build whose
#: tests were deferred to a QA run rests on that run, or on the client's own
#: run when no QA run completed.
DELIVERED_RUN_BY_OF_BASIS = {
    "compile": frozenset({"devmatrix"}),
    "qa_run": frozenset({DEFERRED_RUN_BY}),
    "client_run": frozenset({"client", DEFERRED_RUN_BY}),
}


def _tests_of(run_by: str) -> str:
    """How the tests of a build are said to have run, by its runner."""
    if run_by == DEFERRED_RUN_BY:
        return "deferred to a QA run"
    return f"run by {run_by}"


def _field(value: object, key: str) -> object:
    return value.get(key) if isinstance(value, dict) else None


def delivered_run_by(document: dict) -> str:
    """Who ran the build's tests, read from the delivered attestation's
    platform verdict: DevMatrix when it ran them, the client when they were
    not run because the client runs them, and ``deferred`` when they were not
    run because they were deferred to a QA run. Anything else is
    refused: tests run by nobody are never said to be tested."""
    verdict = _field(_field(document, "attested"), "platform_verdict")
    disposition = _field(verdict, "uts_disposition")
    if disposition == TESTS_NOT_RUN and _field(verdict, "uts_not_run_reason") == RUN_BY_CLIENT_CAUSE:
        return "client"
    if disposition == TESTS_NOT_RUN and _field(verdict, "uts_not_run_reason") == DEFERRED_TO_QA_RUN_CAUSE:
        return DEFERRED_RUN_BY
    if isinstance(disposition, str) and disposition in RAN_BY_DEVMATRIX:
        return "devmatrix"
    raise BindingRefused("the delivered attestation's platform verdict does not state who ran the tests", "runner")


def project_published(document: dict, data: bytes) -> dict:
    """The published attestation DevMatrix publishes for ``document``, a
    delivered fingerprint attestation read from the bytes ``data``: the same
    fields from the same places, with the seal class that goes with who ran
    the tests, and the digest of the delivered bytes themselves. A field the
    file does not carry is projected as ``None``, so it can never equal a
    stated one."""
    reproducible = _field(document, "reproducible")
    attested = _field(document, "attested")
    merkle = _field(reproducible, "merkle")
    coverage = _field(document, "coverage")
    leaves = _field(merkle, "emit_leaves")
    modules = _field(reproducible, "modules")
    determinism = _field(attested, "modules")
    run_by = delivered_run_by(document)
    if run_by not in SEAL_CLASS_OF_RUN_BY:
        raise BindingRefused(
            f"the delivered attestation says its tests were {_tests_of(run_by)}, which no published "
            "attestation version states; bind it to its seal without --published",
            "published_deferred",
        )
    return {
        "schema": ATTESTATION_SCHEMA_V3,
        "job_id": _field(document, "job_id"),
        "attestation_sha256": _sha256_prefixed(data),
        "reproducible_sha256": _field(document, "reproducible_sha256"),
        "identity": _field(reproducible, "identity"),
        "merkle": {
            "nested_root": _field(merkle, "nested_root"),
            "sub_roots": _field(merkle, "sub_roots"),
            "emit_root": _field(merkle, "emit_root"),
            "emit_leaf_sha256": [_field(row, "leaf_sha256") for row in leaves] if isinstance(leaves, list) else None,
        },
        "modules": [
            {"module": _field(row, "module"), "emission_sha256": _field(row, "emission_sha256")}
            for row in modules
        ] if isinstance(modules, list) else None,
        "determinism": determinism if isinstance(determinism, list) else None,
        "terminal_gate_verdict_hash": _field(attested, "terminal_gate_verdict_hash"),
        "not_tested_count": _field(attested, "not_tested_count"),
        "coverage": {
            "delivered_files": _field(coverage, "delivered_files"),
            "covered": _field(coverage, "covered"),
        },
        "certificate_fingerprint": _field(document, "certificate_fingerprint"),
        "run_by": run_by,
        "seal_class": SEAL_CLASS_OF_RUN_BY[run_by],
    }


def bind_attestation(
    service: str, path: Path, statement: dict, published: dict | None, lines: list[str],
) -> list[Failure]:
    """Bind one service's delivered attestation to the seal and, when given,
    to the published attestation. Every check runs; the lines of those that
    hold are appended to ``lines`` and the ones that do not are returned:

    1. the file's SHA-256 is the ``document_sha256`` the seal signed for the
       service, and ``reproducible_sha256`` is the seal's;
    2. the file names the specs the seal names (its platform spec hash and its
       hash for the service);
    3. who ran the tests, read from the file, is who the seal says measured
       the build (a seal-statement/2 states no measurer, and is refused);
    4. the published attestation is exactly what the file publishes as: every
       field, its digest, identity, runner and seal class included.
    """
    by_name = {s.get("name"): s for s in statement.get("services", []) if isinstance(s, dict)}
    sealed = by_name.get(service)
    if sealed is None:
        return [Failure(f"{service}: no such service in this seal", "attestation_identity")]
    sealed_attestation = sealed.get("fingerprint_attestation")
    if not isinstance(sealed_attestation, dict):
        return [Failure(f"{service}: the seal states no fingerprint attestation for it", "attestation_identity")]
    try:
        data, document = _delivered(path)
    except BindingRefused as refused:
        return [refused.failure.under(f"{service}: ")]
    failures: list[Failure] = []
    digest = _sha256_prefixed(data)
    lines.append(f"      {service}: delivered attestation {digest}")
    if sealed_attestation.get("document_sha256") != digest:
        failures.append(Failure(
            f"{service}: the delivered attestation is not the sealed one ({sealed_attestation.get('document_sha256')})",
            "attestation_digest",
        ))
    else:
        lines.append(f"[OK] {service}: the delivered attestation is the sealed one")
    if sealed_attestation.get("reproducible_sha256") != document["reproducible_sha256"]:
        failures.append(Failure(
            f"{service}: reproducible_sha256 differs: delivered {document['reproducible_sha256']}, "
            f"sealed {sealed_attestation.get('reproducible_sha256')}",
            "attestation_digest",
        ))
    else:
        lines.append(f"[OK] {service}: reproducible {document['reproducible_sha256']}")
    identity = document["reproducible"]["identity"]
    platform = statement.get("platform")
    spec_pairs = (
        ("platform spec", _bare(identity.get("platform_spec_hash")),
         platform.get("spec_hash") if isinstance(platform, dict) else None),
        ("service spec", identity[SERVICE_SPEC_HASHES].get(service), sealed.get("spec_hash")),
    )
    spec_failures = [
        Failure(f"{service}: the attestation's {what} hash {attested} is not the sealed {sealed_hash}",
                "attestation_identity")
        for what, attested, sealed_hash in spec_pairs
        if attested is None or attested != sealed_hash
    ]
    failures += spec_failures
    if not spec_failures:
        lines.append(f"[OK] {service}: the attestation names the specs the seal names")
    failures += _measurer_failures(service, statement, sealed, document, lines)
    if published is not None:
        failures += _published_failures(service, data, document, published, lines)
    return failures


def _measurer_failures(
    service: str, statement: dict, sealed: dict, document: dict, lines: list[str],
) -> list[Failure]:
    if statement.get("schema_id") == SEAL_STATEMENT_WITHOUT_MEASURER:
        return [Failure(
            f"{service}: the seal is a {SEAL_STATEMENT_WITHOUT_MEASURER}, which does not state who measured "
            "the build, so who ran its tests cannot be checked against it; re-seal the platform (a new seal "
            "is seal-statement/3 or later) and verify the new seal",
            "statement_version",
        )]
    measurer = sealed.get("verification")
    if measurer not in RUN_BY_OF_MEASURER:
        return [Failure(f"{service}: the seal does not state who measured the build", "statement_version")]
    try:
        run_by = delivered_run_by(document)
    except BindingRefused as refused:
        return [refused.failure.under(f"{service}: ")]
    if statement.get("schema_id") == SEAL_STATEMENT_WITH_BASIS:
        basis = sealed.get("basis")
        allowed = DELIVERED_RUN_BY_OF_BASIS.get(basis, frozenset()) if isinstance(basis, str) else frozenset()
        if run_by not in allowed:
            return [Failure(
                f"{service}: the seal says its grade rests on {basis}, "
                f"but its attestation says the tests were {_tests_of(run_by)}",
                "runner",
            )]
        lines.append(f"[OK] {service}: tests {_tests_of(run_by)}, as the seal states (rests on {basis})")
        return []
    if RUN_BY_OF_MEASURER[measurer] != run_by:
        return [Failure(
            f"{service}: the seal says the build was measured by {measurer}, "
            f"but its attestation says the tests were {_tests_of(run_by)}",
            "runner",
        )]
    lines.append(f"[OK] {service}: tests run by {run_by}, as the seal states (measured by {measurer})")
    return []


def _whole(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_COUNT


def _floor_problem(sealed: dict) -> Failure | None:
    """Why one service of a seal-statement/5 does not state the grade floor
    it was sealed at and every test that failed, or ``None``: the floor is
    ``SEAL_FLOOR``, the grade (DevMatrix's, or the client's when the client
    ran the tests) is at it or above, and the failed tests are names, each
    once and in order; a build the client tested names exactly the tests
    that did not pass."""
    if sealed.get("seal_floor") != SEAL_FLOOR:
        return Failure(f"does not state that it was sealed at grade {SEAL_FLOOR} or better", "statement_version")
    failed = sealed.get("failed_tests")
    if not isinstance(failed, list) or not all(isinstance(name, str) and name for name in failed):
        return Failure("its failed tests are not names", "statement_version")
    if failed != sorted(set(failed)):
        return Failure("its failed tests are not each named once, in order", "statement_version")
    measurer = sealed.get("verification")
    if measurer == "devmatrix":
        if sealed.get("self_attested_grade") is not None:
            return Failure("is measured by devmatrix and states a client grade", "basis_measurer")
        letter = sealed.get("grade")
    elif measurer == "self_attested":
        grade = sealed.get("self_attested_grade")
        if not isinstance(grade, dict):
            return Failure("is self-attested and states no client grade", "statement_version")
        if sealed.get("grade") is not None or sealed.get("qa_score_hundredths") is not None:
            return Failure("is self-attested and states a DevMatrix grade or score", "basis_measurer")
        letter = grade.get("letter")
        passed, applicable = grade.get("passed"), grade.get("applicable")
        if not (_whole(passed) and _whole(applicable) and 0 < applicable and passed <= applicable):
            return Failure("is self-attested and its test counts do not hold", "statement_version")
        if len(failed) != applicable - passed:
            return Failure("is self-attested and its failed tests are not every test that did not pass", "statement_version")
    else:
        return Failure("does not state who measured the build", "statement_version")
    if letter not in SEALABLE_GRADES:
        return Failure(f"is graded {letter!r}, below the grade {SEAL_FLOOR} it was sealed at", "grade_floor")
    return None


#: The seal statement whose client grade states the share of tests it was
#: sealed at (``required_percent``) and names every failed test.
SEAL_STATEMENT_WITH_SHARE = "seal-statement/4"


#: The fields of a seal-statement/4 client grade, exactly.
SHARE_GRADE_FIELDS = frozenset({
    "applicable", "letter", "listed_declared_skips", "listed_not_emitted", "passed", "run_ids",
    "score_percent", "failed_tests", "required_percent",
})


def _measurer_v4_problem(subject: dict, is_service: bool) -> Failure | None:
    """Why a seal-statement/4 subject (a service, or the platform) does not
    state who measured it coherently, or ``None``: DevMatrix states its score
    (and, for a service, its grade and no client grade); the client states no
    DevMatrix score or grade, and a service its client grade, exactly its
    fields and its runs, at its share (:func:`_share_problem`)."""
    verification = subject.get("verification")
    if verification == "devmatrix":
        score = subject.get("qa_score_hundredths")
        if not isinstance(score, int) or isinstance(score, bool):
            return Failure("is measured by DevMatrix and states no score", "basis_measurer")
        if is_service and not isinstance(subject.get("grade"), str):
            return Failure("is measured by DevMatrix and states no grade", "basis_measurer")
        if is_service and subject.get("self_attested_grade") is not None:
            return Failure("is measured by DevMatrix and states a client grade", "basis_measurer")
        return None
    if verification != "self_attested":
        return Failure("does not state who measured it", "statement_version")
    if subject.get("qa_score_hundredths") is not None:
        return Failure("is self-attested and states a DevMatrix score", "basis_measurer")
    if not is_service:
        return None
    if subject.get("grade") is not None:
        return Failure("is self-attested and states a DevMatrix grade", "basis_measurer")
    grade = subject.get("self_attested_grade")
    if not isinstance(grade, dict) or set(grade) != SHARE_GRADE_FIELDS:
        return Failure("is self-attested and its client grade is not exactly " + ", ".join(sorted(SHARE_GRADE_FIELDS)),
                       "statement_version")
    if not (isinstance(grade["run_ids"], dict) and grade["run_ids"]):
        return Failure("is self-attested and names no client run", "statement_version")
    return _share_problem(subject)


def _share_problem(sealed: dict) -> Failure | None:
    """Why a self-attested service of a seal-statement/4 does not state the
    share it was sealed at and every failed test, or ``None``: the share is a
    whole percent from 1 to 100 and met by the counts, and the failed tests
    are the ones that did not pass, each named once, in order."""
    grade = sealed["self_attested_grade"]
    required, passed, applicable = grade["required_percent"], grade["passed"], grade["applicable"]
    if not (_whole(required) and 1 <= required <= 100):
        return Failure("is self-attested and its required share is not a whole percent from 1 to 100",
                       "statement_version")
    if not (_whole(passed) and _whole(applicable) and passed <= applicable and applicable > 0):
        return Failure("is self-attested and its test counts do not hold", "statement_version")
    if passed * 100 < required * applicable:
        return Failure(f"is self-attested and {passed}/{applicable} tests passed, below the {required}% it states",
                       "grade_floor")
    failed = grade["failed_tests"]
    if not (isinstance(failed, list) and all(isinstance(name, str) and name for name in failed)):
        return Failure("is self-attested and its failed tests are not names", "statement_version")
    if failed != sorted(set(failed)) or len(failed) != applicable - passed:
        return Failure("is self-attested and its failed tests are not every test that did not pass, once each",
                       "statement_version")
    return None


def _share_findings(statement: dict) -> tuple[list[str], list[Failure]]:
    """The lines and failures of who measured the platform and every service
    of a seal-statement/4, and of the share every self-attested service
    states (:func:`_measurer_v4_problem`)."""
    services = statement.get("services")
    lines: list[str] = []
    failures: list[Failure] = []
    platform = statement.get("platform")
    problem = _measurer_v4_problem(platform, False) if isinstance(platform, dict) else Failure(
        "states no platform", "statement_version")
    if problem is not None:
        failures.append(problem.under("platform: "))
    for index, sealed in enumerate(services if isinstance(services, list) else []):
        name = sealed.get("name") if isinstance(sealed, dict) else None
        label = name if isinstance(name, str) and name else f"services[{index}]"
        if not isinstance(sealed, dict):
            failures.append(Failure(f"{label}: is not a sealed service", "statement_version"))
            continue
        problem = _measurer_v4_problem(sealed, True)
        if problem is not None:
            failures.append(problem.under(f"{label}: "))
            continue
        if sealed["verification"] != "self_attested":
            continue
        grade = sealed["self_attested_grade"]
        lines.append(
            f"[OK] {label}: self-attested {grade['passed']}/{grade['applicable']} tests passed, at or above the "
            f"{grade['required_percent']}% it was sealed at, {len(grade['failed_tests'])} failed test(s) named"
        )
    return lines, failures


def seal_floor_findings(statement: dict) -> tuple[list[str], list[Failure]]:
    """The lines and the failures of the grade floor of every service of a
    seal-statement/5: each service is graded at the floor or above and names
    every test that failed; both are printed. Earlier statements state no
    floor, and nothing is read into them."""
    version = statement.get("schema_id")
    if version == SEAL_STATEMENT_WITH_SHARE:
        return _share_findings(statement)
    if version not in SEAL_STATEMENTS_WITH_FLOOR:
        return [], []
    services = statement.get("services")
    if not isinstance(services, list) or not services:
        return [], [Failure("the seal lists no sealed service", "statement_version")]
    lines: list[str] = []
    failures: list[Failure] = []
    if version == SEAL_STATEMENT_WITH_BASIS:
        if not all(isinstance(sealed, dict) for sealed in services):
            return [], [Failure("the signed statement lists a sealed service that is not one", "statement_version")]
        mixture = _mixture_problem(statement)
        if mixture is not None:
            return [], [mixture.under("the signed statement is refused by its content: it ")]
    for index, sealed in enumerate(services):
        name = sealed.get("name") if isinstance(sealed, dict) else None
        label = name if isinstance(name, str) and name else f"services[{index}]"
        if not isinstance(sealed, dict):
            failures.append(Failure(f"{label}: is not a sealed service", "statement_version"))
            continue
        problem = _floor_problem(sealed) or (
            _not_judged_problem(sealed) if version in SEAL_STATEMENTS_WITH_NOT_JUDGED else None
        ) or (
            _basis_problem(sealed) if version == SEAL_STATEMENT_WITH_BASIS else None
        )
        if problem is not None:
            failures.append(problem.under(f"{label}: ") if version != SEAL_STATEMENT_WITH_BASIS
                            else problem.under(f"{label}: the signed statement is refused by its content: it "))
            continue
        failed = sealed["failed_tests"]
        if sealed["verification"] == "devmatrix":
            account = f"graded {sealed['grade']} (score {sealed.get('qa_score_hundredths')} hundredths), measured by DevMatrix"
        else:
            grade = sealed["self_attested_grade"]
            account = (
                f"graded {grade['letter']} ({grade.get('score_percent')}%), self-attested: "
                f"{grade['passed']}/{grade['applicable']} tests passed on the client's machine"
            )
        lines.append(
            f"[OK] {label}: {account}; sealed at grade {SEAL_FLOOR} or better, {len(failed)} failed test(s)"
        )
        lines += [f"      {label}: failed {test}" for test in failed]
        if version in SEAL_STATEMENTS_WITH_NOT_JUDGED:
            lines += _not_judged_lines(label, sealed)
        if version == SEAL_STATEMENT_WITH_BASIS:
            lines += _basis_lines(label, sealed)
    return lines, failures


def _not_run_tiers_problem(tiers: object) -> Failure | None:
    """Why the tiers not run a seal-statement/6 service declares are not each
    one group of its own tier with a whole count above zero, once, in order;
    or ``None``."""
    if not isinstance(tiers, list):
        return Failure("its tiers not run are not a list", "statement_version")
    for tier in tiers:
        if not (isinstance(tier, dict) and set(tier) == {"group", "tier", "count"}):
            return Failure("a tier not run it declares is not a group, a tier and a count", "statement_version")
        group, name, count = tier["group"], tier["tier"], tier["count"]
        if not (
            isinstance(group, str) and isinstance(name, str) and name
            and group.endswith("::" + name + "::*") and group.count("::") == 2
            and not group.startswith("::")
        ):
            return Failure("a tier not run it declares is not a group of its own tier", "statement_version")
        if not (_whole(count) and count > 0):
            return Failure("a tier not run it declares has no whole count above zero", "statement_version")
    groups = [tier["group"] for tier in tiers]
    if groups != sorted(set(groups)):
        return Failure("its tiers not run are not each declared once, in order", "statement_version")
    return None


def _not_judged_problem(sealed: dict) -> Failure | None:
    """Why one service of a seal-statement/6 does not state its tests not
    judged, or ``None``: each named once, in order, none of them also named
    failed, the total is the names plus every tier not run, and no grade of A+
    beside one. A self-attested grade counts its own (``listed_not_judged``)
    and names as many; null is a count the grade does not state (given before
    the count existed): it names none, totals none, and bears no A+."""
    names = sealed.get("not_judged_tests")
    if not (isinstance(names, list) and all(isinstance(name, str) and name for name in names)):
        return Failure("its tests not judged are not names", "not_judged")
    if names != sorted(set(names)):
        return Failure("its tests not judged are not each named once, in order", "not_judged")
    if set(names) & set(sealed["failed_tests"]):
        return Failure("a test it names not judged is also named failed", "not_judged")
    tiers = sealed.get("not_run_tiers")
    problem = _not_run_tiers_problem(tiers)
    if problem is not None:
        return problem
    if sealed["verification"] != "devmatrix":
        if tiers:
            return Failure("is self-attested and declares tiers not run", "not_judged")
        grade = sealed["self_attested_grade"]
        if "listed_not_judged" not in grade:
            return Failure("is self-attested and its grade does not state its count of tests not judged", "not_judged")
        count = grade["listed_not_judged"]
        if count is None:
            if names:
                return Failure("is self-attested, states no count of tests not judged and names some", "not_judged")
            if sealed.get("not_judged_count") is not None:
                return Failure("is self-attested, states no count of tests not judged and totals one", "not_judged")
            if grade["letter"] == "A+":
                return Failure("is graded A+ beside a count of tests not judged it does not state", "not_judged")
            return None
        if not _whole(count):
            return Failure("is self-attested and its count of tests not judged is not a whole number", "not_judged")
        if count != len(names):
            return Failure(f"is self-attested and counts {count} tests not judged but names {len(names)}", "not_judged")
    total = sealed.get("not_judged_count")
    if not _whole(total):
        return Failure("its count of tests not judged is not a whole number", "not_judged")
    declared = len(names) + sum(tier["count"] for tier in tiers)
    if total != declared:
        return Failure(f"counts {total} tests not judged but declares {declared}", "not_judged")
    letter = sealed["grade"] if sealed["verification"] == "devmatrix" else sealed["self_attested_grade"]["letter"]
    if total and letter == "A+":
        return Failure("is graded A+ beside tests not judged", "not_judged")
    return None


def _not_judged_lines(label: str, sealed: dict) -> list[str]:
    """The lines a seal-statement/6 service prints of its tests not judged:
    «not stated» for a grade given before the count existed, never 0; else
    the total, each test by name and each tier not run by its count."""
    if sealed["verification"] != "devmatrix" and sealed["self_attested_grade"]["listed_not_judged"] is None:
        return [f"      {label}: {NOT_JUDGED_NOT_STATED}"]
    total = sealed["not_judged_count"]
    noun = "test" if total == 1 else "tests"
    lines = [f"      {label}: {total} {noun} not judged (out of the score, never A+)"]
    lines += [f"      {label}: not judged {test}" for test in sealed["not_judged_tests"]]
    lines += [f"      {label}: {tier['tier']}: {tier['count']} not run" for tier in sealed["not_run_tiers"]]
    return lines


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
#: A test named in its module: ``<module_id>::<node id>``.
_MODULE_TEST = re.compile(r"[^:\s][^\s]*::[^\s].*")
_QA_RUN_FIELDS = frozenset({
    "qa_run_id", "attempt", "report_schema_id", "report_sha256", "finished_at",
    "letter", "score_percent", "passed", "applicable", "emitted_failed_tests", "modules",
})


def _names_in_order(value: object) -> bool:
    return (
        isinstance(value, list)
        and all(isinstance(name, str) and name for name in value)
        and value == sorted(set(value))
    )


def _qa_run_problem(sealed: dict) -> Failure | None:
    """Why the QA run a seal-statement/7 service rests on is not stated
    exactly, or ``None``: its run, attempt, report version and digest, when it
    finished, and the grade the statement carries (letter, score, counts), with
    the UTS reds named in ``failed_tests`` and the emitted suite's apart."""
    run = sealed.get("qa_run")
    if not (isinstance(run, dict) and set(run) == _QA_RUN_FIELDS):
        return Failure("rests on a QA run it does not state exactly", "qa_run_binding")
    if not (isinstance(run["qa_run_id"], str) and _UUID.fullmatch(run["qa_run_id"])):
        return Failure("names no QA run by its id", "qa_run_binding")
    if not (_whole(run["attempt"]) and run["attempt"] >= 1):
        return Failure("names no attempt of its QA run", "qa_run_binding")
    if not (_whole(run["modules"]) and run["modules"] >= 1):
        return Failure("states no count of the modules its QA run measured", "qa_run_binding")
    if run["report_schema_id"] not in QA_RUN_REPORT_SCHEMAS:
        return Failure(f"names a QA run report of an unknown version {run['report_schema_id']!r}", "qa_run_binding")
    if not (isinstance(run["report_sha256"], str) and _HEX64_ONLY.fullmatch(run["report_sha256"])):
        return Failure("states no digest of its QA run report", "qa_run_binding")
    if not (isinstance(run["finished_at"], str) and run["finished_at"]):
        return Failure("states no time its QA run finished", "qa_run_binding")
    if run["letter"] != sealed.get("grade"):
        return Failure("states a grade that is not its QA run's", "qa_run_binding")
    score, passed, applicable = run["score_percent"], run["passed"], run["applicable"]
    if not (_whole(score) and score <= 100 and _whole(passed) and _whole(applicable)
            and 0 < applicable and passed <= applicable):
        return Failure("states QA run counts that do not hold", "qa_run_binding")
    if sealed.get("qa_score_hundredths") != score * 100:
        return Failure("states a score that is not its QA run's", "qa_run_binding")
    if len(sealed["failed_tests"]) != applicable - passed:
        return Failure("does not name every test its QA run failed", "qa_run_binding")
    if not _names_in_order(run["emitted_failed_tests"]):
        return Failure("its emitted suite's failed tests are not each named once, in order", "qa_run_binding")
    return None


def _proofs_problem(sealed: dict) -> Failure | None:
    """Why the tests proven not applicable a seal-statement/7 service states
    do not hold, or ``None``. A count is stated, or null only where the
    measurement predates proofs (a ``qa-run-report/1``, or a client run, whose
    judgement version the statement does not carry); a compile states none.
    A stated count names as many tests, each ``<module>::<node id>`` once and
    in order, none also failed or not judged, each of a module whose
    collected tests are digested, with the digest of the proof rows."""
    basis = sealed["basis"]
    count = sealed.get("proven_not_applicable_count")
    tests = sealed.get("proven_not_applicable_tests")
    rows_digest = sealed.get("proof_rows_sha256")
    collected = sealed.get("collected_node_ids_sha256")
    if not isinstance(tests, list):
        return Failure("its tests proven not applicable are not a list", "proofs")
    if count is None:
        if basis == "qa_run" and sealed["qa_run"]["report_schema_id"] != QA_RUN_REPORT_WITHOUT_PROOFS:
            return Failure("rests on a QA run report that states proofs and states no count of them", "proofs")
        if tests or rows_digest is not None:
            return Failure("states no count of tests proven not applicable and names or digests some", "proofs")
        if basis in ("compile", "qa_run") and collected is not None:
            return Failure("states no count of tests proven not applicable and digests the tests its run collected", "proofs")
        return None
    if basis == "compile":
        return Failure("rests on the compile and states a count of tests proven not applicable", "proofs")
    if basis == "qa_run" and sealed["qa_run"]["report_schema_id"] == QA_RUN_REPORT_WITHOUT_PROOFS:
        return Failure("rests on a QA run report that predates proofs and states a count of them", "proofs")
    if not _whole(count):
        return Failure("its count of tests proven not applicable is not a whole number", "proofs")
    if not (_names_in_order(tests) and all(_MODULE_TEST.fullmatch(name) for name in tests)):
        return Failure("its tests proven not applicable are not each named <module>::<test> once, in order", "proofs")
    if count != len(tests):
        return Failure(f"counts {count} tests proven not applicable but names {len(tests)}", "proofs")
    if set(tests) & (set(sealed["failed_tests"]) | set(sealed["not_judged_tests"])):
        return Failure("a test it names proven not applicable is also named failed or not judged", "proofs")
    if not (isinstance(rows_digest, str) and _HEX64_ONLY.fullmatch(rows_digest)):
        return Failure("states no digest of its proof rows", "proofs")
    if not (isinstance(collected, dict) and all(
        isinstance(module, str) and module and (digest is None or (isinstance(digest, str) and _HEX64_ONLY.fullmatch(digest)))
        for module, digest in collected.items()
    )):
        return Failure("its digests of the tests each module collected are not module digests", "proofs")
    unproven = sorted({name.split("::", 1)[0] for name in tests if collected.get(name.split("::", 1)[0]) is None})
    if unproven:
        return Failure(f"proves tests not applicable in modules whose collected tests it does not digest: {unproven}", "proofs")
    return None


def _basis_problem(sealed: dict) -> Failure | None:
    """Why one service of a seal-statement/7 does not state what its grade
    rests on, or ``None``: the build it seals, a basis whose measurer is the
    one it states, the QA run exactly when it rests on one, and its tests
    proven not applicable (:func:`_proofs_problem`). An A+ beside proofs it
    does not state is refused like an A+ beside tests not judged."""
    compilation_id = sealed.get("compilation_id")
    if not (isinstance(compilation_id, str) and _UUID.fullmatch(compilation_id)):
        return Failure("names no build by its compilation id", "statement_version")
    basis = sealed.get("basis")
    if basis not in MEASURER_OF_BASIS:
        return Failure(f"states an unknown basis {basis!r}", "statement_version")
    if MEASURER_OF_BASIS[basis] != sealed["verification"]:
        return Failure(f"rests on {basis} but states it was measured by {sealed['verification']}", "basis_measurer")
    if basis == "qa_run":
        problem = _qa_run_problem(sealed)
        if problem is not None:
            return problem
    elif "qa_run" not in sealed:
        return Failure("does not state whether it rests on a QA run", "qa_run_binding")
    elif sealed["qa_run"] is not None:
        return Failure(f"rests on {basis} and names a QA run", "qa_run_binding")
    problem = _proofs_problem(sealed)
    if problem is not None:
        return problem
    letter = sealed["grade"] if sealed["verification"] == "devmatrix" else sealed["self_attested_grade"]["letter"]
    if letter == "A+" and sealed["proven_not_applicable_count"] is None:
        return Failure("is graded A+ beside tests proven not applicable it does not state", "not_judged")
    return None


def _mixture_problem(statement: dict) -> Failure | None:
    """Why a seal-statement/7 is not one measurer's seal, or ``None``: every
    service measured by DevMatrix (on the compile or a QA run), or exactly one
    build its client ran; the platform states the same measurer."""
    services = statement["services"]
    measurers = sorted({service.get("verification") for service in services}, key=str)
    if len(measurers) != 1:
        return Failure(f"mixes builds measured by {measurers} in one seal", "mixture")
    platform = statement.get("platform")
    if not isinstance(platform, dict) or platform.get("verification") != measurers[0]:
        return Failure("states another measurer for the platform than for its builds", "mixture")
    if measurers[0] == "self_attested" and len(services) != 1:
        return Failure(f"is self-attested over {len(services)} builds; a self-attested seal is one build", "mixture")
    return None


def _basis_lines(label: str, sealed: dict) -> list[str]:
    """The lines a seal-statement/7 service prints of what its grade rests on
    and of its tests proven not applicable."""
    basis = sealed["basis"]
    if basis == "qa_run":
        run = sealed["qa_run"]
        lines = [
            f"      {label}: rests on QA run {run['qa_run_id']} (attempt {run['attempt']}, "
            f"{run['report_schema_id']}, finished {run['finished_at']}): {run['passed']}/{run['applicable']} passed",
        ]
        lines += [f"      {label}: emitted suite failed {test}" for test in run["emitted_failed_tests"]]
    elif basis == "client_run":
        lines = [f"      {label}: rests on the client's run of build {sealed['compilation_id']}"]
    else:
        lines = [f"      {label}: rests on the compile of build {sealed['compilation_id']}"]
    count = sealed["proven_not_applicable_count"]
    if count is None:
        lines.append(f"      {label}: {PROOFS_NOT_STATED}")
    else:
        noun = "test" if count == 1 else "tests"
        lines.append(f"      {label}: {count} {noun} proven not applicable")
        lines += [f"      {label}: proven not applicable {test}" for test in sealed["proven_not_applicable_tests"]]
    return lines


def _published_failures(
    service: str, data: bytes, document: dict, published: dict, lines: list[str],
) -> list[Failure]:
    try:
        expected = project_published(document, data)
    except BindingRefused as refused:
        return [refused.failure.under(f"{service}: ")]
    differing = sorted(key for key in set(expected) | set(published) if expected.get(key) != published.get(key))
    if differing:
        return [Failure(
            f"{service}: the published attestation is not what the delivered file publishes as; "
            f"it differs in {differing}",
            "attestation_identity",
        )]
    lines.append(
        f"[OK] {service}: the published attestation is exactly what the delivered file publishes as "
        f"(its digest, identity, tests run by {published['run_by']}, seal {published['seal_class']})"
    )
    return []


def _published_for_binding(
    path: Path, keys: list[dict], accept: str = PRODUCTION,
) -> tuple[dict | None, list[str], list[Failure]]:
    """The published attestation to bind, the lines to report and the
    failures; ``None`` when it cannot be bound, so the rest still runs."""
    try:
        evidence = read_json(path)
    except (OSError, ValueError, RecursionError) as exc:
        return None, [], [Failure(f"published attestation: cannot read {path}: {exc}", "attestation_identity")]
    passed, lines = verify_signature(evidence, keys, accept)
    if not passed:
        return None, [], [Failure("published attestation: " + "; ".join(lines), "signature")]
    payload = signed_payload(evidence)
    try:
        lines += check_published_attestation(payload)
    except AttestationRefused as refusal:
        return None, lines, [Failure(str(refusal), "attestation_identity")]
    if payload.get("schema") != ATTESTATION_SCHEMA_V3:
        return None, lines, [Failure(
            f"published attestation: {payload.get('schema')} names the attestation by the digest of a compact "
            "re-serialization, not of the delivered file, so it cannot be bound to the delivered file; "
            f"republish the build's attestation (it is published as {ATTESTATION_SCHEMA_V3}) and verify again",
            "attestation_digest",
        )]
    return payload, lines, []


# ---------------------------------------------------------------------------
# The evidence bundle of a seal (unzipped): what a seal-statement/7 rests on.
# The directory is untrusted: only the names below are read, none followed
# through a link, each bounded in size, the whole bounded in count and size.
# ---------------------------------------------------------------------------

EVIDENCE_SCHEMA = "seal-evidence-bundle/1"
EVIDENCE_MANIFEST = "MANIFEST.json"
#: The files an evidence bundle holds at its top.
EVIDENCE_TOP_FILES = frozenset({
    EVIDENCE_MANIFEST, "seal-payload.json", "seal-statement.json", "seal-statement.sig.b64",
    "seal-public-key.pem", "verify.py", "VERIFY.md",
})
_UUID_TEXT = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_COMPONENT_TEXT = r"(?!\.+/)[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"
_CLIENT_RUN_FILE = re.compile(
    rf"client-runs/{_UUID_TEXT}/(client-verification\.json|{_COMPONENT_TEXT}/{_COMPONENT_TEXT}/(judged-suite\.json|junit\.xml))"
)
_QA_RUN_REPORT_FILE = re.compile(rf"qa-runs/({_UUID_TEXT})/report\.json")
_PROOFS_FILE = re.compile(rf"proofs/({_UUID_TEXT})\.json")
#: Contract bounds: a QA run report (and the proof rows, a subset of it) is
#: at most 4 MiB; every other file the bundle carried before is under 1 MiB
#: together; so a bundle is at most 1 MiB plus 8 MiB per sealed service.
EVIDENCE_REPORT_MAX_BYTES = 4 * 1024 * 1024
EVIDENCE_OTHER_MAX_BYTES = 1024 * 1024
EVIDENCE_MAX_FILES = 10_000


def evidence_total_cap(services: int) -> int:
    """The bound of a whole evidence bundle of ``services`` sealed services:
    the files it carried before, plus a report and its proof rows each."""
    return EVIDENCE_OTHER_MAX_BYTES + 2 * EVIDENCE_REPORT_MAX_BYTES * max(services, 1)


class EvidenceRefused(ValueError):
    """The evidence bundle cannot be read as one: a link, a file that is not
    a regular file, an unknown name, or a file or a whole over its bound."""


def _evidence_name_cap(name: str) -> int | None:
    """The size bound of an evidence bundle file named ``name``, or ``None``
    when the bundle holds no file of that name."""
    if _QA_RUN_REPORT_FILE.fullmatch(name) or _PROOFS_FILE.fullmatch(name):
        return EVIDENCE_REPORT_MAX_BYTES
    if name in EVIDENCE_TOP_FILES or _CLIENT_RUN_FILE.fullmatch(name):
        return EVIDENCE_OTHER_MAX_BYTES
    return None


def _shown(value: object) -> str:
    """A value read from the evidence folder as it is printed: escaped, so no
    control character or newline it carries reaches the report."""
    return ascii(value)


_EVIDENCE_FOLDER = re.compile(
    rf"(qa-runs|proofs|client-runs)(/{_UUID_TEXT})?|qa-runs/{_UUID_TEXT}|client-runs/{_UUID_TEXT}/{_COMPONENT_TEXT}(/{_COMPONENT_TEXT})?"
)


def _evidence_folder_known(name: str) -> bool:
    if name.startswith("proofs/"):
        return False
    return bool(_EVIDENCE_FOLDER.fullmatch(name))


def read_evidence(root: Path, services: int) -> dict[str, bytes]:
    """Every file of the unzipped evidence bundle ``root``, by its name in
    the bundle. Refused (:class:`EvidenceRefused`) at the first link (file or
    folder), file that is not a regular file (checked again once opened), name
    or folder the bundle never holds, folder that cannot be read, file over
    its bound, more than ``EVIDENCE_MAX_FILES`` entries, or more bytes than the
    bound for ``services`` sealed services. A platform that cannot open a file
    without following a link is refused rather than followed."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise EvidenceRefused("this platform cannot open a file without following a link")
    if root.is_symlink() or not root.is_dir():
        raise EvidenceRefused(f"{_shown(str(root))} is not a folder (a link is not followed)")
    total_cap = evidence_total_cap(services)
    held: dict[str, bytes] = {}
    entries = 0
    total = 0

    def unreadable(error: OSError) -> None:
        raise EvidenceRefused(f"a folder of the evidence bundle cannot be read: {_shown(error.filename)}")

    for folder, subfolders, files in os.walk(root, onerror=unreadable, followlinks=False):
        for sub in sorted(subfolders):
            name = os.path.relpath(os.path.join(folder, sub), root).replace(os.sep, "/")
            if os.path.islink(os.path.join(folder, sub)):
                raise EvidenceRefused(f"{_shown(name)} is a link; links are not followed")
            if not _evidence_folder_known(name):
                raise EvidenceRefused(f"{_shown(name)} is not a folder an evidence bundle holds")
        entries += len(subfolders) + len(files)
        if entries > EVIDENCE_MAX_FILES:
            raise EvidenceRefused(f"the evidence bundle holds more than {EVIDENCE_MAX_FILES} files")
        for file in sorted(files):
            path = os.path.join(folder, file)
            name = os.path.relpath(path, root).replace(os.sep, "/")
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode):
                raise EvidenceRefused(f"{_shown(name)} is not a regular file (a link is not followed)")
            cap = _evidence_name_cap(name)
            if cap is None:
                raise EvidenceRefused(f"{_shown(name)} is not a file an evidence bundle holds")
            if info.st_size > cap:
                raise EvidenceRefused(f"{_shown(name)} is over its bound of {cap} bytes")
            descriptor = os.open(path, os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(descriptor, "rb") as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                    raise EvidenceRefused(f"{_shown(name)} is not a regular file (a link is not followed)")
                data = handle.read(cap + 1)
            if len(data) > cap:
                raise EvidenceRefused(f"{_shown(name)} is over its bound of {cap} bytes")
            total += len(data)
            if total > total_cap:
                raise EvidenceRefused(f"the evidence bundle is over its bound of {total_cap} bytes")
            held[name] = data
    return held


def _json_of(data: bytes) -> tuple[object, bool]:
    """The JSON document ``data`` holds and whether it parsed. Every parse
    failure, nesting too deep included, is a document that is not JSON."""
    try:
        return json.loads(data), True
    except (ValueError, RecursionError):
        return None, False


def _manifest_failures(held: dict[str, bytes], statement: dict, statement_bytes: bytes) -> tuple[list[Failure], dict]:
    """The failures of the bundle's manifest against the files it holds,
    and the files it says are not held, by name: the manifest is of this seal,
    names every held file once with its digest and size, and names as absent
    only files it does not hold; the statement it holds is the one verified."""
    if EVIDENCE_MANIFEST not in held:
        return [Failure(f"evidence: the bundle has no {EVIDENCE_MANIFEST}", "evidence_tampered")], {}
    manifest, parsed = _json_of(held[EVIDENCE_MANIFEST])
    if not parsed:
        return [Failure(f"evidence: {EVIDENCE_MANIFEST} is not JSON", "evidence_tampered")], {}
    if not (isinstance(manifest, dict) and set(manifest) == {"schema", "seal_hash", "files", "absent"}
            and manifest["schema"] == EVIDENCE_SCHEMA):
        return [Failure(f"evidence: {EVIDENCE_MANIFEST} is not a {EVIDENCE_SCHEMA} manifest", "evidence_tampered")], {}
    failures: list[Failure] = []
    if manifest["seal_hash"] != statement.get("seal_hash"):
        failures.append(Failure("evidence: the bundle is of another seal than the statement verified", "evidence_tampered"))
    files, absent = manifest["files"], manifest["absent"]
    if not (isinstance(files, list) and all(
        isinstance(e, dict) and set(e) == {"path", "sha256", "size_bytes"} and isinstance(e["path"], str)
        for e in files
    )):
        return failures + [Failure("evidence: the manifest's files are not each a path, a digest and a size", "evidence_tampered")], {}
    if not (isinstance(absent, list) and all(
        isinstance(e, dict) and set(e) == {"path", "state", "reason"} and isinstance(e["path"], str)
        and isinstance(e["state"], str) and (e["reason"] is None or isinstance(e["reason"], str))
        for e in absent
    )):
        return failures + [Failure("evidence: the manifest's absent files are not each a path, a state and a reason", "evidence_tampered")], {}
    listed = {entry["path"]: entry for entry in files}
    if len(listed) != len(files) or sorted(listed) != sorted(set(held) - {EVIDENCE_MANIFEST}):
        failures.append(Failure("evidence: the manifest does not name exactly the files the bundle holds", "evidence_tampered"))
    for name, entry in sorted(listed.items()):
        data = held.get(name)
        if data is not None and (entry["sha256"] != hashlib.sha256(data).hexdigest() or entry["size_bytes"] != len(data)):
            failures.append(Failure(f"evidence: {_shown(name)} is not the file the manifest names", "evidence_tampered"))
    gone = {entry["path"]: entry for entry in absent}
    if len(gone) != len(absent) or set(gone) & set(held):
        failures.append(Failure("evidence: the manifest names a file absent twice, or absent and held", "evidence_tampered"))
    if "seal-statement.json" in held and held["seal-statement.json"] != statement_bytes:
        failures.append(Failure("evidence: the bundle's seal-statement.json is not the statement verified", "evidence_tampered"))
    return failures, gone


def _canonical_seal_bytes(document: object) -> bytes:
    """The seal's own serialization: sorted keys, compact separators,
    ASCII-escaped, UTF-8 (not RFC 8785)."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


_PROOF_ROW_FIELDS = frozenset({"module_id", "test_id", "witnesses", "witnessed"})


def _proofs_failures(label: str, sealed: dict, data: bytes) -> list[Failure]:
    """The failures of a service's proof rows file against what the seal
    signed: its digest, its exact serialization, rows sorted by (module,
    test), each once, with sorted distinct witnesses; the witnessed rows are
    exactly the tests the seal states proven not applicable, each of a module
    whose collected tests the seal digests, and every other row's test is
    named not judged."""
    if hashlib.sha256(data).hexdigest() != sealed["proof_rows_sha256"]:
        return [Failure(f"{label}: the proof rows file is not the one the seal signed (proof_rows_sha256)", "evidence_tampered")]
    rows, parsed = _json_of(data)
    if not parsed:
        return [Failure(f"{label}: the proof rows file is not JSON", "evidence_tampered")]
    if _canonical_seal_bytes(rows) != data:
        return [Failure(f"{label}: the proof rows file is not written in the seal's serialization", "evidence_tampered")]
    if not (isinstance(rows, list) and all(
        isinstance(row, dict) and set(row) == _PROOF_ROW_FIELDS
        and isinstance(row["module_id"], str) and row["module_id"]
        and isinstance(row["test_id"], str) and row["test_id"]
        and _names_in_order(row["witnesses"]) and isinstance(row["witnessed"], bool)
        for row in rows
    )):
        return [Failure(f"{label}: the proof rows are not each a module, a test, sorted distinct witnesses and whether witnessed", "evidence_tampered")]
    keys = [(row["module_id"], row["test_id"]) for row in rows]
    if keys != sorted(set(keys)):
        return [Failure(f"{label}: the proof rows are not each once, sorted by module and test", "evidence_tampered")]
    witnessed = [f"{row['module_id']}::{row['test_id']}" for row in rows if row["witnessed"]]
    shown_not = [f"{row['module_id']}::{row['test_id']}" for row in rows if not row["witnessed"]]
    failures: list[Failure] = []
    if witnessed != sealed["proven_not_applicable_tests"]:
        failures.append(Failure(f"{label}: the witnessed proof rows are not the tests the seal states proven not applicable", "evidence_tampered"))
    missing = sorted(set(shown_not) - set(sealed["not_judged_tests"]))
    if missing:
        failures.append(Failure(f"{label}: proofs not shown that the seal does not name not judged: {missing}", "evidence_tampered"))
    return failures


def _report_failures(label: str, sealed: dict, data: bytes) -> list[Failure]:
    """The failures of a service's QA run report against what the seal
    signed: its digest, its version, the run, attempt and build it names, a
    completed run, the grade, score and counts, and the modules it measured."""
    run = sealed["qa_run"]
    if hashlib.sha256(data).hexdigest() != run["report_sha256"]:
        return [Failure(f"{label}: the QA run report is not the one the seal signed (report_sha256)", "evidence_tampered")]
    report, parsed = _json_of(data)
    if not parsed:
        return [Failure(f"{label}: the QA run report is not JSON", "evidence_tampered")]
    if not isinstance(report, dict):
        return [Failure(f"{label}: the QA run report is not a report", "evidence_tampered")]
    pairs = (
        ("version", report.get("schema_id"), run["report_schema_id"]),
        ("QA run", report.get("qa_run_id"), run["qa_run_id"]),
        ("attempt", report.get("attempt"), run["attempt"]),
        ("build", report.get("compilation_id"), sealed["compilation_id"]),
        ("outcome", report.get("outcome"), "completed"),
        ("grade", report.get("grade_letter"), run["letter"]),
        ("score", report.get("score_percent"), run["score_percent"]),
        ("tests passed", report.get("passed"), run["passed"]),
        ("tests applicable", report.get("applicable"), run["applicable"]),
    )
    failures = [
        Failure(f"{label}: the QA run report states {what} {stated!r}, the seal {signed!r}", "evidence_tampered")
        for what, stated, signed in pairs if stated != signed
    ]
    if failures:
        return failures
    measured = report.get("modules")
    if not isinstance(measured, list) or len(measured) != run["modules"]:
        count = len(measured) if isinstance(measured, list) else None
        failures.append(Failure(
            f"{label}: the QA run report measured {count!r} modules, the seal {run['modules']!r}", "evidence_tampered",
        ))
    finished = _field(report.get("provenance"), "finished_at")
    try:
        same_instant = _instant(finished, "report finished_at") == _instant(run["finished_at"], "seal finished_at")
    except ValueError:
        same_instant = False
    if not same_instant:
        failures.append(Failure(f"{label}: the QA run report finished at {finished!r}, the seal says {run['finished_at']!r}", "evidence_tampered"))
    reds = report.get("reds")
    suite = report.get("emitted_suite")
    if not isinstance(reds, list) or not all(isinstance(red, dict) and isinstance(red.get("name"), str) for red in reds):
        return failures + [Failure(f"{label}: the QA run report names no reds", "evidence_tampered")]
    if sorted(red["name"] for red in reds) != sealed["failed_tests"]:
        failures.append(Failure(f"{label}: the seal's failed tests are not the QA run report's reds", "evidence_tampered"))
    if suite is None:
        emitted_reds, not_tested, modules = [], [], None
    elif isinstance(suite, dict):
        emitted_reds, not_tested, modules = suite.get("reds"), suite.get("not_tested"), suite.get("modules")
    else:
        return failures + [Failure(f"{label}: the QA run report's emitted suite is not one", "evidence_tampered")]
    def module_names(rows: object) -> list[str] | None:
        if not isinstance(rows, list) or not all(
            isinstance(row, dict) and isinstance(row.get("module_id"), str) and isinstance(row.get("name"), str)
            for row in rows
        ):
            return None
        return sorted(f"{row['module_id']}::{row['name']}" for row in rows)
    emitted_names, not_tested_names = module_names(emitted_reds), module_names(not_tested)
    if emitted_names is None or not_tested_names is None:
        return failures + [Failure(f"{label}: the QA run report's emitted suite does not name its reds and tests not run", "evidence_tampered")]
    if emitted_names != run["emitted_failed_tests"]:
        failures.append(Failure(f"{label}: the seal's emitted suite failures are not the QA run report's", "evidence_tampered"))
    unnamed = sorted(set(not_tested_names) - set(sealed["not_judged_tests"]))
    if unnamed:
        failures.append(Failure(f"{label}: tests the QA run did not test that the seal does not name not judged: {unnamed}", "evidence_tampered"))
    if run["report_schema_id"] == QA_RUN_REPORT_WITHOUT_PROOFS:
        return failures
    failures += _report_proof_failures(label, sealed, modules)
    return failures


def _report_proof_failures(label: str, sealed: dict, modules: object) -> list[Failure]:
    """The failures of a qa-run-report/2's modules against the seal: the
    seal's collected digests are the report's, every module states its proof
    rows, and the proof rows file the seal digests is those rows, each with
    its module, rebuilt byte for byte."""
    if not (isinstance(modules, list) and all(
        isinstance(module, dict) and isinstance(module.get("module_id"), str)
        and set(module) == {"module_id", "collected_test_ids_sha256", "proven_not_applicable"}
        for module in modules
    )):
        return [Failure(f"{label}: the QA run report does not state its modules' collected tests and proofs", "evidence_tampered")]
    collected = {module["module_id"]: module["collected_test_ids_sha256"] for module in modules}
    if len(collected) != len(modules) or collected != sealed["collected_node_ids_sha256"]:
        return [Failure(f"{label}: the seal's collected test digests are not the QA run report's", "evidence_tampered")]
    unstated = sorted(module["module_id"] for module in modules if module["proven_not_applicable"] is None)
    if unstated:
        return [Failure(f"{label}: the QA run report states no proofs for {unstated}, and the seal states a count", "evidence_tampered")]
    rows = []
    for module in modules:
        if not isinstance(module["proven_not_applicable"], list) or not all(
            isinstance(row, dict) for row in module["proven_not_applicable"]
        ):
            return [Failure(f"{label}: the QA run report's proofs for {module['module_id']} are not rows", "evidence_tampered")]
        rows += [dict(row, module_id=module["module_id"]) for row in module["proven_not_applicable"]]
    rows.sort(key=lambda row: (str(row.get("module_id")), str(row.get("test_id"))))
    if hashlib.sha256(_canonical_seal_bytes(rows)).hexdigest() != sealed["proof_rows_sha256"]:
        return [Failure(f"{label}: the proof rows the seal digests are not the QA run report's", "evidence_tampered")]
    return []


def evidence_findings(
    root: Path, statement: dict, statement_bytes: bytes,
) -> tuple[list[str], list[Failure]]:
    """The lines and failures of checking the evidence bundle ``root``
    against a verified seal statement; every check is named in a line."""
    services = statement.get("services") if isinstance(statement.get("services"), list) else []
    try:
        held = read_evidence(root, len(services))
    except (EvidenceRefused, OSError) as refused:
        return [], [Failure(f"evidence: {refused}", "evidence_refused")]
    failures, gone = _manifest_failures(held, statement, statement_bytes)
    lines = [f"[OK] evidence: {len(held)} file(s) read from {_shown(str(root))}, none through a link, each within its bound"]
    if not failures:
        lines.append("[OK] evidence: the manifest names exactly the files held, each by its digest and size")
    expected: set[str] = set()
    if statement.get("schema_id") == SEAL_STATEMENT_WITH_BASIS:
        for index, sealed in enumerate(services):
            label = sealed.get("name", f"services[{index}]")
            checks = []
            if sealed["basis"] == "qa_run":
                checks.append((f"qa-runs/{sealed['compilation_id']}/report.json", _report_failures, "QA run report"))
            if sealed["proven_not_applicable_count"] is not None:
                checks.append((f"proofs/{sealed['compilation_id']}.json", _proofs_failures, "proof rows"))
            for name, check, what in checks:
                expected.add(name)
                if name not in held:
                    entry = gone.get(name)
                    if entry is None:
                        failures.append(Failure(
                            f"{label}: the bundle neither holds its {what} {name} nor lists it absent",
                            "evidence_tampered",
                        ))
                    else:
                        # The manifest is not signed, and what the seal rests on is kept while the seal
                        # exists: a file whose digest the statement signs listed absent is never a reason
                        # to leave it unchecked.
                        failures.append(Failure(
                            f"{label}: the bundle lists its {what} {name} absent "
                            f"({_shown(entry['state'])}: {_shown(entry['reason'])}), and the seal rests on it",
                            "evidence_absent",
                        ))
                    continue
                found = check(label, sealed, held[name])
                failures += found
                if not found:
                    lines.append(f"[OK] {label}: {what} {name} is the one the seal signed, and agrees with it")
    stray = sorted(name for name in held if (_QA_RUN_REPORT_FILE.fullmatch(name) or _PROOFS_FILE.fullmatch(name))
                   and name not in expected)
    if stray:
        failures.append(Failure(f"evidence: files the seal does not rest on: {_shown(stray)}", "evidence_tampered"))
    return lines, failures


def unchecked_evidence_lines(statement: dict) -> list[str]:
    """What a seal-statement/7 rests on that was not checked because no
    evidence bundle was given: said plainly, never left to a bare OK."""
    if statement.get("schema_id") != SEAL_STATEMENT_WITH_BASIS:
        return []
    return [
        f"[NOT CHECKED] {sealed.get('name', f'services[{index}]')}: QA run report and proof rows not checked: "
        "no evidence given (--evidence)"
        for index, sealed in enumerate(statement["services"])
        if isinstance(sealed, dict) and (sealed.get("basis") == "qa_run" or sealed.get("proven_not_applicable_count") is not None)
    ]


def verify_binding(
    bundle: Path, attestations: list[tuple[str, Path]], published_path: Path | None, keys: list[dict],
    accept: str = PRODUCTION, evidence: Path | None = None, failed: list[Failure] | None = None,
) -> bool:
    """Print the verdict of binding each delivered attestation to the seal
    (and the published attestation, when given); whether all of it held.
    Every check that can run does: the [OK] lines say what was verified and
    the [FAIL] lines what was not. The failures, with their classes, are
    added to ``failed`` when given."""
    lines: list[str] = []
    try:
        statement, seal_lines, statement_bytes = read_signed_seal(bundle, keys, accept)
    except BindingRefused as refusal:
        refused = [refusal.failure]
    except (OSError, ValueError, RecursionError) as refusal:
        refused = [Failure(str(refusal), "signature")]
    else:
        refused = []
    if refused:
        if failed is not None:
            failed += refused
        print(f"[FAIL] {refused[0].text}")
        return False
    lines += seal_lines
    floor_lines, failures = seal_floor_findings(statement)
    lines += floor_lines
    if evidence is None:
        lines += unchecked_evidence_lines(statement)
    elif not failures:
        evidence_lines, evidence_failures = evidence_findings(evidence, statement, statement_bytes)
        lines += evidence_lines
        failures += evidence_failures
    else:
        lines.append("[NOT CHECKED] evidence: not read, the signed statement is refused")
    published = None
    if published_path is not None:
        published, published_lines, published_failures = _published_for_binding(published_path, keys, accept)
        lines += published_lines
        failures += published_failures
    if published is not None and len(attestations) != 1:
        failures.append(Failure(
            "a published attestation is one build's: name exactly one --attestation with it", "attestation_identity",
        ))
        published = None
    for service, path in attestations:
        try:
            failures += bind_attestation(service, path, statement, published, lines)
        except (OSError, ValueError, RecursionError) as exc:
            failures.append(Failure(f"{service}: cannot read {path}: {exc}", "attestation_identity"))
    for line in lines:
        print(line)
    for failure in failures:
        print(f"[FAIL] {failure.text}")
    if failed is not None:
        failed += failures
    return not failures


#: What ``--verdict-json`` writes for a failure that carries no class: a
#: name outside :data:`REASON_CLASSES`, so a harness comparing classes fails.
UNCLASSIFIED = "unclassified"


def verdict_document(passed: bool, failed: list[Failure], key_class: str) -> dict:
    """The verdict of a binding as ``--verdict-json`` writes it: VERIFIED
    exactly when no check failed, the sorted distinct reason classes of the
    failures, and the class of the keys it was reached with. A failure that is
    not a :class:`Failure` is written as ``unclassified``, never dropped."""
    classes = sorted({failure.reason_class if isinstance(failure, Failure) else UNCLASSIFIED for failure in failed})
    return {
        "verdict": "VERIFIED" if passed and not failed else "FAILED",
        "reason_classes": classes,
        "key_class": key_class,
    }


#: What ``--verdict-json`` holds from the start of a run until its verdict
#: is reached: a run that stops before it (keys refused, usage refused, an
#: error) never leaves an earlier verdict at the path.
ABORTED_VERDICT = {"verdict": "FAILED", "reason_classes": [UNCLASSIFIED], "key_class": None}


def write_verdict_json(path: Path, document: dict) -> None:
    """Write ``document`` to ``path`` whole: to a file beside it, then moved
    over it, so a reader never sees half of one."""
    partial = path.with_name(path.name + ".partial")
    partial.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(partial, path)


def _attestation_argument(value: str) -> tuple[str, Path]:
    service, separator, path = value.partition("=")
    if not separator or not service or not path:
        raise argparse.ArgumentTypeError("name the service: <service>=<fingerprint_attestation.json>")
    return service, Path(path)


def load_trusted_keys(path: Path) -> TrustedKeys:
    """The keys of the keys file at ``path`` and where they were read from;
    exits 1 naming why when the file is missing or refused."""
    source = path.resolve()
    if not source.is_file():
        print(f"ERROR: Keys file not found: {source}")
        sys.exit(1)
    try:
        return trusted_keys_of(read_json(source), str(source))
    except (OSError, ValueError) as exc:
        print(f"[FAIL] keys file refused: {exc}")
        print("VERIFICATION FAILED")
        sys.exit(1)


def keys_line(trusted: TrustedKeys) -> str:
    return f"Keys: {trusted.source} ({trusted.key_class} keys)"


def exit_with_verdict(passed: bool, trusted: TrustedKeys, failed: str) -> None:
    """Print the verdict, naming the keys it was reached with, and exit: 0
    only when every check passed against production keys; NOT_PRODUCTION_EXIT,
    with the label the keys file gives, when it passed against keys of any
    other class; 1 when a check failed."""
    print()
    print("=" * 60)
    if not passed:
        print("VERIFICATION FAILED")
        print(failed)
        print(keys_line(trusted))
        sys.exit(1)
    if trusted.key_class != PRODUCTION:
        print(f"{trusted.label} — not a production attestation")
        print(f"Every check above held against {trusted.key_class!r} keys, which are NOT production keys.")
        print(keys_line(trusted))
        sys.exit(NOT_PRODUCTION_EXIT)
    print("VERIFICATION PASSED")
    print("Every check above passed.")
    print(keys_line(trusted))
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="Verify DevMatrix build fingerprints",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Verify spec and output against fingerprint
  python verify_fingerprint.py -f build_fingerprint.json -s spec.md -o generated/

  # Compare two fingerprints (from different runs)
  python verify_fingerprint.py -f fingerprint1.json --compare fingerprint2.json
        """
    )

    parser.add_argument(
        "-f", "--fingerprint",
        type=Path,
        help="Path to a fingerprint JSON (build output or evidence pack)"
    )

    parser.add_argument(
        "-s", "--spec",
        type=Path,
        help="Path to specification file (to verify spec_hash)"
    )

    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Path to generated output directory (to verify code_bundle_hash)"
    )

    parser.add_argument(
        "--compare",
        type=Path,
        help="Path to another fingerprint to compare (for determinism testing)"
    )

    parser.add_argument(
        "--keys",
        type=Path,
        default=KEYS_FILE,
        help="Published public keys (default: keys.json next to this script)"
    )

    parser.add_argument(
        "--allow-unsigned",
        action="store_true",
        help="Accept a flat build_fingerprint.json that carries no signature (hashes only)"
    )

    parser.add_argument(
        "--seal",
        type=Path,
        help="A platform seal's verification bundle (unzipped directory): bind each --attestation to it"
    )

    parser.add_argument(
        "--attestation",
        type=_attestation_argument,
        action="append",
        default=[],
        metavar="SERVICE=FILE",
        help="A build's delivered verification/<run>/fingerprint_attestation.json, named by its service"
    )

    parser.add_argument(
        "--evidence",
        type=Path,
        help="The seal's evidence bundle (unzipped directory): check the QA run reports and proof rows a seal-statement/7 rests on"
    )

    parser.add_argument(
        "--verdict-json",
        type=Path,
        help="With --seal: also write the verdict, each failure's reason class and the keys' class to this JSON file"
    )

    parser.add_argument(
        "--published",
        type=Path,
        help="The published attestation of the same build (attestations/<job>.json)"
    )

    args = parser.parse_args()

    if (args.seal is not None or args.attestation or args.published is not None or args.evidence is not None
            or args.verdict_json is not None):
        if args.verdict_json is not None:
            write_verdict_json(args.verdict_json, ABORTED_VERDICT)
        if args.seal is None or not args.attestation or args.fingerprint is not None:
            parser.error("--seal takes one or more --attestation SERVICE=FILE (and optionally --published, --evidence "
                         "and --verdict-json), without --fingerprint")
        trusted = load_trusted_keys(args.keys)
        print("=" * 60)
        print("DevMatrix Seal and Attestation Verification")
        print("=" * 60)
        print(keys_line(trusted))
        failed: list[Failure] = []
        passed = verify_binding(
            args.seal, args.attestation, args.published, trusted.keys, trusted.key_class, args.evidence, failed,
        )
        if args.verdict_json is not None:
            write_verdict_json(args.verdict_json, verdict_document(passed, failed, trusted.key_class))
        exit_with_verdict(passed, trusted, "At least one check above failed: see the [FAIL] lines.")
    if args.fingerprint is None:
        parser.error("name a --fingerprint, or a --seal with its --attestation files")

    # Load primary fingerprint
    if not args.fingerprint.exists():
        print(f"ERROR: Fingerprint file not found: {args.fingerprint}")
        sys.exit(1)

    evidence = read_json(args.fingerprint)
    fingerprint = flatten_fingerprint(evidence)
    trusted = load_trusted_keys(args.keys)
    keys, accept = trusted.keys, trusted.key_class

    print("=" * 60)
    print("DevMatrix Build Fingerprint Verification")
    print("=" * 60)
    print(keys_line(trusted))
    print(f"\nFingerprint: {args.fingerprint}")
    print_identity(evidence)
    print()

    all_passed = check_signature(
        "", evidence, keys, args.allow_unsigned, accept
    )
    if not check_attestation("", evidence, keys, accept):
        all_passed = False

    # Mode 1: Compare two fingerprints
    if args.compare:
        if not args.compare.exists():
            print(f"ERROR: Comparison fingerprint not found: {args.compare}")
            sys.exit(1)

        evidence2 = read_json(args.compare)
        print(f"Comparing with: {args.compare}")
        print_identity(evidence2)
        if not check_signature(
            str(args.compare), evidence2, keys, args.allow_unsigned, accept
        ):
            all_passed = False
        if not check_attestation(str(args.compare), evidence2, keys, accept):
            all_passed = False
        print()

        results = compare_fingerprints(signed_payload(evidence), signed_payload(evidence2))
        compared = sum(1 for _, passed, _ in results if passed)
        print(f"Hashes compared by path: {len(results)}, identical: {compared}")

        for key, passed, message in results:
            status = "[OK]" if passed else "[FAIL]"
            print(f"{status} {message}")
            if not passed:
                all_passed = False

    # Mode 2: Verify against actual files
    else:
        if args.spec:
            if not args.spec.exists():
                print(f"ERROR: Spec file not found: {args.spec}")
                sys.exit(1)

            passed, message = verify_spec_hash(fingerprint, args.spec)
            status = "[OK]" if passed else "[FAIL]"
            print(f"{status} {message}")
            if not passed:
                all_passed = False

        if args.output:
            if not args.output.exists():
                print(f"ERROR: Output directory not found: {args.output}")
                sys.exit(1)

            passed, message = verify_code_bundle_hash(fingerprint, args.output)
            status = "[OK]" if passed else "[FAIL]"
            print(f"{status} {message}")
            if not passed:
                all_passed = False

        if not args.spec and not args.output:
            print("No verification targets specified.")
            print("Use --spec and/or --output to verify hashes.")
            print("Use --compare to compare two fingerprints.")

    exit_with_verdict(all_passed, trusted, "At least one check above failed: see the [FAIL] lines.")


if __name__ == "__main__":
    main()

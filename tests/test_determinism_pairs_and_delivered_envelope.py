"""Two documents compared as a determinism pair, and a delivered attestation's
own signature.

Two builds are a determinism pair only when they share their identity inputs
(specification, toolchain and, from the documents that state it, runtime); a
pair that does not is refused, naming every input that differs. Whether two
builds reproduced is decided by their reproducible block alone. The fields a
run attests are compared, except the gate verdict, which is compared only
when both documents state the same regression baseline (equal digests): two
builds that ruled against different baselines are still a determinism pair.
Documents that state no baseline predate it, and a difference in their
attested fields is said not to be evidence of a determinism break.

``published-attestation/4`` and ``fingerprint-attestation/3`` state the
runtime key and the regression baseline; a /3 delivered file is published as
/4.

A delivered attestation checked with ``-f`` is checked against its own table
and its own signature; compared with ``--compare``, the comparison decides and
the envelope of each is stated apart, an unsigned one as unsigned.

Every document here is synthetic and signed with a key made for the test.

Run from the repository root: python -m unittest discover -s tests
"""

from __future__ import annotations

import base64
import copy
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
sys.path.insert(0, str(Path(__file__).resolve().parent))

import verify_fingerprint as vf  # noqa: E402
import test_a_delivered_attestation_binds_to_its_seal as bind  # noqa: E402
import test_verify_fingerprint as compare  # noqa: E402

_KEY = Ed25519PrivateKey.generate()
_KEY_ID = "evidence-delivered-test"
_RAW = _KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
_RUNTIME_KEY = "0123456789abcdef0123"


def _keys(key_class: str = "production") -> list[dict]:
    public = base64.b64encode(_RAW).decode()
    return [{
        "kid": "sha256:" + hashlib.sha256(_RAW).hexdigest(), "key_id": _KEY_ID, "purpose": "evidence-signing",
        "class": key_class, "algorithm": "Ed25519", "public_key": public, "status": "active",
        "status_since": None, "created_at": "2026-01-01T00:00:00+00:00", "expires_at": None,
    }]


def _sealed(document: dict) -> dict:
    """``document`` with its reproducible digest recomputed and signed as a
    build signs the attestation it delivers."""
    document = copy.deepcopy(document)
    document["reproducible_sha256"] = vf.reproducible_sha256(document["reproducible"])
    document.pop("signature", None)
    content_hash = hashlib.sha256(json.dumps(document, sort_keys=True).encode("utf-8")).hexdigest()
    document["signature"] = {
        "algorithm": "ed25519", "key_id": _KEY_ID, "verify_key": _RAW.hex(),
        "signed_fields": sorted(document), "signed_at": "2026-11-24T09:00:00+00:00",
        "content_hash": content_hash,
        "signature": base64.b64encode(_KEY.sign(content_hash.encode("utf-8"))).decode(),
    }
    return document


def _baseline(state: str = "declared", prior_builds: "int | None" = 3, digest: str = "a" * 64) -> dict:
    return {"state": state, "prior_builds": prior_builds, "digest": digest}


def _v3(document: dict, baseline: "dict | None" = None) -> dict:
    """A delivered /2 written as /3: the runtime key and the regression baseline."""
    document = copy.deepcopy(document)
    document["schema"] = vf.DELIVERED_ATTESTATION_SCHEMA_V3
    document["reproducible"]["identity"][vf.RUNTIME_KEY] = _RUNTIME_KEY
    document["attested"][vf.REGRESSION_BASELINE] = baseline or _baseline()
    document["reproducible_sha256"] = vf.reproducible_sha256(document["reproducible"])
    return document


def _published_v4(published: dict, baseline: "dict | None" = None) -> dict:
    published = copy.deepcopy(published)
    published["schema"] = vf.ATTESTATION_SCHEMA_V4
    published["identity"][vf.RUNTIME_KEY] = _RUNTIME_KEY
    published[vf.REGRESSION_BASELINE] = baseline or _baseline()
    return published


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(ROOT / "verify_fingerprint.py"), *args],
                          capture_output=True, text=True, check=False)


def _write(tmp: Path, name: str, document: dict) -> str:
    path = tmp / name
    path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return str(path)


def _keys_file(tmp: Path, key_class: str = "production") -> str:
    return _write(tmp, "keys.json", {"schema_id": vf.KEYS_SCHEMA_ID, "keys": _keys(key_class)})


class APublishedV4(unittest.TestCase):
    def test_it_states_the_runtime_and_the_regression_baseline(self) -> None:
        lines = vf.check_published_attestation(_published_v4(bind._published(bind._delivered())))
        self.assertIn("tests run by devmatrix, seal sealed", lines[0])
        self.assertIn("2 module spec hashes", lines[1])

    def _refused(self, document: dict, reason: str) -> None:
        with self.assertRaises(vf.AttestationRefused) as raised:
            vf.check_published_attestation(document)
        self.assertIn(reason, str(raised.exception))

    def test_a_runtime_key_that_is_not_its_form(self) -> None:
        """MUT-RED: the runtime key is accepted in any form."""
        for key in ("0123456789ABCDEF0123", "0123456789abcdef012", "0123456789abcdef01234", 12):
            with self.subTest(key=key):
                document = _published_v4(bind._published(bind._delivered()))
                document["identity"][vf.RUNTIME_KEY] = key
                self._refused(document, f"identity.{vf.RUNTIME_KEY}")

    def test_a_baseline_is_its_three_keys_of_their_form(self) -> None:
        """MUT-RED: a state outside its set, a prior count that is not a count,
        or a digest that is not 64 lower-case hex characters is accepted."""
        cases = {
            "regression_baseline.state": [_baseline(state="promoted"), _baseline(state=None)],
            "regression_baseline.prior_builds": [_baseline(prior_builds=-1), _baseline(prior_builds="3"),
                                                 _baseline(prior_builds=True)],
            "regression_baseline.digest": [_baseline(digest="sha256:" + "a" * 64), _baseline(digest="A" * 64),
                                           _baseline(digest="a" * 63), _baseline(digest=None)],
        }
        for reason, baselines in cases.items():
            for baseline in baselines:
                with self.subTest(baseline=baseline):
                    self._refused(_published_v4(bind._published(bind._delivered()), baseline), reason)
        document = _published_v4(bind._published(bind._delivered()))
        document[vf.REGRESSION_BASELINE]["since"] = "2026-11-24"
        self._refused(document, "undeclared keys ['since']")
        document = _published_v4(bind._published(bind._delivered()))
        del document[vf.REGRESSION_BASELINE]
        self._refused(document, "lacks ['regression_baseline']")
        document = _published_v4(bind._published(bind._delivered()))
        del document[vf.REGRESSION_BASELINE]["prior_builds"]
        self._refused(document, "prior_builds")

    def test_a_first_build_and_a_count_of_any_state_are_its_form(self) -> None:
        """A first build reads absent and 0; the count is independent of the
        state (declared with 0, unreadable with a count, any with null)."""
        for baseline in (_baseline("absent", 0), _baseline("declared", 0), _baseline("unreadable", 7),
                         _baseline("declared", None), _baseline("unreadable", None)):
            with self.subTest(baseline=baseline):
                vf.check_published_attestation(_published_v4(bind._published(bind._delivered()), baseline))

    def test_a_module_map_its_digest_does_not_name(self) -> None:
        """MUT-RED: the module map is checked for /3 only."""
        document = _published_v4(bind._published(bind._delivered()))
        document["identity"]["service_spec_hashes"][bind._SERVICE] = bind._hex("0")
        self._refused(document, "the module map is not the one its digest")


class ADeliveredV3(unittest.TestCase):
    def _build(self, published_baseline: "dict | None" = None, delivered_v3: bool = True) -> bind.OneBuild:
        build = bind.OneBuild()
        if delivered_v3:
            build.document = _v3(build.document)
        build.statement = bind._statement(build.document)
        build.published = _published_v4(bind._published(build.document), published_baseline)
        return build

    def _result(self, build: bind.OneBuild) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmp:
            return build.run(Path(tmp))

    def test_it_binds_to_its_seal_and_its_published_v4(self) -> None:
        """MUT-RED: a /3 delivered file is projected as /3, or a /4 cannot be bound."""
        result = self._result(self._build())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("[OK] orders: the published attestation is exactly what the delivered file publishes as",
                      result.stdout)

    def test_a_published_v4_of_another_baseline(self) -> None:
        """MUT-RED: the baseline is not projected into what a /3 publishes as."""
        result = self._result(self._build(published_baseline=_baseline(digest="b" * 64)))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("it differs in ['regression_baseline']", result.stdout)

    def test_a_published_v4_is_not_what_a_v2_delivered_file_publishes_as(self) -> None:
        result = self._result(self._build(delivered_v3=False))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("it differs in ['identity', 'regression_baseline', 'schema']", result.stdout)

    def test_a_v1_delivered_file_still_says_what_to_do(self) -> None:
        build = self._build()
        build.document["schema"] = "fingerprint-attestation/1"
        result = self._result(build)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("predates the format a seal can bind", result.stdout)


class ADeterminismPair(unittest.TestCase):
    def test_builds_of_different_inputs_are_refused_naming_every_input(self) -> None:
        """MUT-RED: the refusal names the first input that differs only."""
        first = compare._delivered()
        second = compare._delivered_rerun(first)
        identity = second["reproducible"]["identity"]
        identity["compiler_toolchain_hash"] = "sha256:" + "9" * 64
        identity["platform_spec_hash"] = "sha256:" + "8" * 64
        with self.assertRaises(vf.ComparisonRefused) as refused:
            vf.compare_fingerprints(first, second)
        self.assertEqual(
            str(refused.exception),
            "not a determinism pair: reproducible.identity.compiler_toolchain_hash differs; "
            "reproducible.identity.platform_spec_hash differs",
        )

    def test_every_kind_of_document_names_its_inputs(self) -> None:
        cases = {
            "unversioned fingerprint": (compare._payload(compare.PRODUCTION_PAIR[0]), ("compiler_version",)),
            "published /2": (compare._attestation(), ("identity", "spec_hash")),
            "published /4": (_published_v4(bind._published(bind._delivered())), ("identity", vf.RUNTIME_KEY)),
            "delivered /3": (_v3(compare._delivered()), ("reproducible", "identity", vf.RUNTIME_KEY)),
        }
        for case, (document, path) in cases.items():
            with self.subTest(case=case):
                other = copy.deepcopy(document)
                parent = other
                for key in path[:-1]:
                    parent = parent[key]
                parent[path[-1]] = "fedcba9876543210fedc" if path[-1] == vf.RUNTIME_KEY else "other"
                with self.assertRaises(vf.ComparisonRefused) as refused:
                    vf.compare_fingerprints(document, other)
                self.assertEqual(str(refused.exception), f"not a determinism pair: {'.'.join(path)} differs")

    def test_an_input_one_document_does_not_state_is_an_input_that_differs(self) -> None:
        first = compare._delivered()
        second = compare._delivered_rerun(first)
        del second["reproducible"]["identity"]["platform_spec_hash"]
        with self.assertRaises(vf.ComparisonRefused) as refused:
            vf.compare_fingerprints(first, second)
        self.assertIn("reproducible.identity.platform_spec_hash differs", str(refused.exception))

    def test_verdicts_ruled_against_different_baselines_are_not_compared(self) -> None:
        """Only the verdict: the rest of the attested block is compared, and
        the two builds are still a determinism pair. MUT-RED: the verdict is
        compared whatever the baselines, or more than the verdict is left out."""
        first = _v3(compare._delivered(), _baseline("absent", 0, "c" * 64))
        second = _v3(compare._delivered_rerun(first), _baseline("declared", 1, "d" * 64))
        second["attested"]["terminal_gate_verdict_hash"] = "sha256:" + "7" * 64
        comparison = vf.compare_fingerprints(first, second)
        self.assertTrue(comparison.passed, comparison.differences)
        self.assertEqual(comparison.excluded["attested.terminal_gate_verdict_hash"], vf.DIFFERENT_BASELINES)
        self.assertTrue(comparison.reproducible_identical)
        self.assertEqual(vf.determinism_lines(comparison), [
            f"[OK] determinism: the reproducible block is identical ({comparison.reproducible_compared} values)",
            "[NOTE] terminal_gate_verdict_hash not comparable: the builds ruled against different baselines",
        ])
        second["attested"]["not_tested_count"] = 4
        comparison = vf.compare_fingerprints(first, second)
        self.assertEqual(comparison.differences, ["attested.not_tested_count: DIFFERENT (0 vs 4)"])
        self.assertIn("[NOTE] attested fields differ; the builds ruled against different baselines",
                      vf.determinism_lines(comparison))

    def test_a_baseline_one_document_does_not_state_does_not_compare_the_verdict(self) -> None:
        """MUT-RED: a missing digest is read as the same baseline."""
        first = _v3(compare._delivered())
        second = _v3(compare._delivered_rerun(first))
        del second["attested"][vf.REGRESSION_BASELINE]
        second["attested"]["terminal_gate_verdict_hash"] = "sha256:" + "7" * 64
        comparison = vf.compare_fingerprints(first, second)
        self.assertEqual(comparison.excluded["attested.terminal_gate_verdict_hash"], vf.DIFFERENT_BASELINES)

    def test_verdicts_ruled_against_the_same_baseline_are_compared(self) -> None:
        """MUT-RED: the verdict is never compared."""
        first = _v3(compare._delivered())
        second = _v3(compare._delivered_rerun(first))
        second["attested"]["terminal_gate_verdict_hash"] = "sha256:" + "7" * 64
        comparison = vf.compare_fingerprints(first, second)
        self.assertEqual(len(comparison.differences), 1)
        self.assertTrue(comparison.differences[0].startswith("attested.terminal_gate_verdict_hash: DIFFERENT"))
        self.assertEqual(vf.determinism_lines(comparison), [
            f"[OK] determinism: the reproducible block is identical ({comparison.reproducible_compared} values)",
            "[NOTE] attested fields differ under the same regression baseline",
        ])

    def test_published_v4_documents_of_different_baselines(self) -> None:
        first = _published_v4(bind._published(bind._delivered()), _baseline("absent", 0, "c" * 64))
        second = _published_v4(bind._published(bind._delivered()), _baseline("declared", 2, "d" * 64))
        second["terminal_gate_verdict_hash"] = "sha256:" + "7" * 64
        comparison = vf.compare_fingerprints(first, second)
        self.assertTrue(comparison.passed, comparison.differences)
        self.assertEqual(comparison.excluded["terminal_gate_verdict_hash"], vf.DIFFERENT_BASELINES)
        second["not_tested_count"] = 3
        self.assertFalse(vf.compare_fingerprints(first, second).passed)

    def test_documents_that_predate_the_reference_state_say_so(self) -> None:
        """MUT-RED: an attested difference is read as a determinism break, or
        the determinism verdict is taken from every field."""
        first = compare._delivered()
        second = compare._delivered_rerun(first)
        second["attested"]["modules"][0]["status"] = "NOT_VERIFIED"
        comparison = vf.compare_fingerprints(first, second)
        self.assertFalse(comparison.passed)
        self.assertEqual(vf.determinism_lines(comparison), [
            f"[OK] determinism: the reproducible block is identical ({comparison.reproducible_compared} values)",
            "[NOTE] attested fields differ; these documents predate the regression baseline, "
            "so this is not evidence of a determinism break",
        ])

    def test_a_reproducible_block_that_differs_did_not_reproduce(self) -> None:
        first = compare._delivered()
        second = compare._delivered_rerun(first)
        second["reproducible"]["modules"][0]["emission_sha256"] = "0" * 64
        second["attested"]["not_tested_count"] = 2
        comparison = vf.compare_fingerprints(first, second)
        self.assertEqual(vf.determinism_lines(comparison), [
            "[FAIL] determinism: the reproducible block differs: these builds did not reproduce",
        ])

    def test_a_document_with_no_split_states_no_determinism_verdict(self) -> None:
        comparison = vf.compare_fingerprints(*(compare._payload(n) for n in compare.PRODUCTION_PAIR))
        self.assertEqual(vf.determinism_lines(comparison), [])


class TheDeliveredEnvelope(unittest.TestCase):
    def _check(self, document: dict, key_class: str = "production") -> tuple[bool, str]:
        return vf.check_delivered_attestation(document, _keys(key_class))

    def test_a_signed_attestation_verifies(self) -> None:
        for document in (_sealed(compare._delivered()), _sealed(_v3(compare._delivered()))):
            with self.subTest(schema=document["schema"]):
                verified, message = self._check(document)
                self.assertTrue(verified, message)
                self.assertEqual(
                    message, f"{document['schema']}, Ed25519, key {_KEY_ID!r} (production), signed 2026-11-24T09:00:00+00:00",
                )

    def test_tests_stated_as_null_are_its_form(self) -> None:
        document = compare._delivered()
        document["attested"]["customer_checks"]["tests"] = None
        self.assertTrue(self._check(_sealed(document))[0])

    def test_an_unsigned_attestation_is_said_to_be_unsigned(self) -> None:
        """MUT-RED: an unsigned attestation is read as verified."""
        document = _sealed(compare._delivered())
        del document["signature"]
        self.assertEqual(self._check(document), (False, "fingerprint-attestation/2 is UNSIGNED: nothing says DevMatrix made it"))

    def test_a_field_changed_after_signing(self) -> None:
        """MUT-RED: the signed content is not recomputed."""
        document = _sealed(compare._delivered())
        document["attested"]["not_tested_count"] = 7
        verified, message = self._check(document)
        self.assertFalse(verified)
        self.assertIn("CHANGED AFTER SIGNING", message)

    def test_a_field_removed_before_signing_is_not_covered(self) -> None:
        """The run's own times and history are not signed: the build signs
        what reproduces."""
        self.assertEqual(
            vf.signing_view({"a": 1, "signature": {}, "nested": [{"created_at": "x", "b": 2}], "build_identity": {}}),
            {"a": 1, "nested": [{"b": 2}]},
        )

    def test_a_signature_that_does_not_verify(self) -> None:
        """MUT-RED: the Ed25519 signature is not checked."""
        document = _sealed(compare._delivered())
        document["signature"]["signature"] = base64.b64encode(_KEY.sign(b"something else")).decode()
        self.assertEqual(self._check(document), (False, f"fingerprint-attestation/2: the signature is INVALID for key {_KEY_ID!r}"))

    def test_a_key_keys_json_does_not_publish(self) -> None:
        """MUT-RED: the key is not looked up in keys.json."""
        document = _sealed(compare._delivered())
        other = Ed25519PrivateKey.generate()
        raw = other.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        document["signature"]["verify_key"] = raw.hex()
        document["signature"]["signature"] = base64.b64encode(
            other.sign(document["signature"]["content_hash"].encode("utf-8"))
        ).decode()
        verified, message = self._check(document)
        self.assertFalse(verified)
        self.assertIn(f"NOT signed by a published key: the public key in the file is not the one published for {_KEY_ID!r}", message)

    def test_a_key_that_is_not_a_production_key(self) -> None:
        verified, message = self._check(_sealed(compare._delivered()), key_class="staging")
        self.assertFalse(verified)
        self.assertIn("is NOT a production key", message)

    def test_a_document_that_is_not_exactly_its_schema(self) -> None:
        """MUT-RED: the document is not checked against its table."""
        document = compare._delivered()
        document["attested"]["source"] = "app.py"
        del document["coverage"]["covered"]
        verified, message = self._check(_sealed(document))
        self.assertFalse(verified)
        self.assertEqual(
            message,
            "fingerprint-attestation/2 is not exactly its schema: attested: carries undeclared keys ['source']; "
            "coverage: lacks ['covered']",
        )

    def test_a_reproducible_digest_that_is_not_its_blocks(self) -> None:
        document = _sealed(compare._delivered())
        document["reproducible"]["modules"][0]["emission_sha256"] = "0" * 64
        verified, message = self._check(document)
        self.assertFalse(verified)
        self.assertIn("reproducible_sha256 is not the digest of its reproducible block", message)


class TheCommandLine(unittest.TestCase):
    def test_a_signed_delivered_attestation_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = _run("-f", _write(Path(tmp), "a.json", _sealed(compare._delivered())),
                          "--keys", _keys_file(Path(tmp)))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("[OK] delivered attestation: fingerprint-attestation/2, Ed25519", result.stdout)
        self.assertNotIn("unknown attestation schema", result.stdout)

    def test_an_unsigned_delivered_attestation_fails_alone(self) -> None:
        """MUT-RED: a delivered attestation checked alone passes unverified."""
        document = _sealed(compare._delivered())
        del document["signature"]
        with tempfile.TemporaryDirectory() as tmp:
            result = _run("-f", _write(Path(tmp), "a.json", document), "--keys", _keys_file(Path(tmp)))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("[FAIL] delivered attestation: fingerprint-attestation/2 is UNSIGNED", result.stdout)

    def test_an_unsigned_attestation_is_compared_only_when_asked(self) -> None:
        """MUT-RED: an unsigned delivered attestation is compared without --allow-unsigned."""
        first = _sealed(compare._delivered())
        second = compare._delivered_rerun(first)
        del second["signature"]
        with tempfile.TemporaryDirectory() as tmp:
            result = _run("-f", _write(Path(tmp), "a.json", first), "--compare", _write(Path(tmp), "b.json", second),
                          "--keys", _keys_file(Path(tmp)))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("[OK] delivered attestation: fingerprint-attestation/2, Ed25519", result.stdout)
        self.assertIn("[FAIL] delivered attestation: fingerprint-attestation/2 is UNSIGNED: nothing says DevMatrix "
                      "made it; --allow-unsigned compares an unsigned attestation", result.stdout)
        self.assertIn("VERIFICATION FAILED", result.stdout)

    def test_two_unsigned_attestations_that_compare_equal_pass_and_say_they_are_unsigned(self) -> None:
        first = _sealed(compare._delivered())
        second = compare._delivered_rerun(first)
        del first["signature"], second["signature"]
        with tempfile.TemporaryDirectory() as tmp:
            result = _run("-f", _write(Path(tmp), "a.json", first), "--compare", _write(Path(tmp), "b.json", second),
                          "--keys", _keys_file(Path(tmp)), "--allow-unsigned")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout.count("[NOTE] delivered attestation: NOT verified: fingerprint-attestation/2 is UNSIGNED"), 2)
        self.assertIn("[OK] determinism: the reproducible block is identical", result.stdout)
        self.assertIn("The comparison passed: the verdict is the comparison's. NOT verified: 2 of the 2 delivered "
                      "attestations compared", result.stdout)
        self.assertNotIn("Every check above passed.", result.stdout)
        self.assertNotIn("VERIFICATION PASSED", result.stdout)
        self.assertIn("COMPARISON PASSED (2 of 2 delivered attestations NOT verified)", result.stdout)

    def test_two_signed_runs_of_one_build_compare_equal(self) -> None:
        first = _sealed(compare._delivered())
        second = _sealed(compare._delivered_rerun(first))
        with tempfile.TemporaryDirectory() as tmp:
            result = _run("-f", _write(Path(tmp), "a.json", first), "--compare", _write(Path(tmp), "b.json", second),
                          "--keys", _keys_file(Path(tmp)))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("Each delivered attestation compared is verified.", result.stdout)
        self.assertIn("VERIFICATION PASSED", result.stdout)

    def test_unsigned_attestations_that_differ_fail_by_the_comparison(self) -> None:
        first = _sealed(compare._delivered())
        second = compare._delivered_rerun(first)
        second["attested"]["not_tested_count"] = 5
        del first["signature"], second["signature"]
        with tempfile.TemporaryDirectory() as tmp:
            result = _run("-f", _write(Path(tmp), "a.json", first), "--compare", _write(Path(tmp), "b.json", second),
                          "--keys", _keys_file(Path(tmp)), "--allow-unsigned")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("[FAIL] attested.not_tested_count: DIFFERENT (0 vs 5)", result.stdout)
        self.assertIn("[NOTE] attested fields differ; these documents predate the regression baseline", result.stdout)

    def test_a_pair_of_different_inputs_is_refused(self) -> None:
        first = _sealed(compare._delivered())
        second = compare._delivered_rerun(first)
        second["reproducible"]["identity"]["compiler_toolchain_hash"] = "sha256:" + "9" * 64
        second = _sealed(second)
        with tempfile.TemporaryDirectory() as tmp:
            result = _run("-f", _write(Path(tmp), "a.json", first), "--compare", _write(Path(tmp), "b.json", second),
                          "--keys", _keys_file(Path(tmp)))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("[FAIL] comparison: not a determinism pair: reproducible.identity.compiler_toolchain_hash differs",
                      result.stdout)


if __name__ == "__main__":
    unittest.main()

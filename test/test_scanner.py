"""Detection, benign controls and bounded work; no evaluation-oracle imports."""

import base64
import dataclasses
import json
import random
import subprocess
import sys
import unittest
from urllib.parse import quote

from security.scanner import DEFAULT_SCAN_LIMITS, ScanLimits, inspect_sensitive, scan_sensitive


FAKE = "password=SCANNER_ONLY_FAKE"


def encoded(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


class ScannerTests(unittest.TestCase):
    def test_credential_signatures_and_assignment_context(self) -> None:
        samples = [FAKE, "api_key=SCANNER_ONLY_FAKE", "access_token=SCANNER_ONLY_FAKE",
                   "ak_0000000000000000", "sk-proj-0000000000000000",
                   "ghp_00000000000000000000", "AKIA0000000000000000",
                   "Authorization: Bearer SCANNER_ONLY_FAKE_TOKEN",
                   "Authorization: Basic " + encoded("user:fake_password"),
                   "eyJhbGciOiJub25lIn0.eyJzdWIiOiJmYWtlIn0.fake_signature"]
        for family in ("", "RSA ", "DSA ", "EC ", "OPENSSH ", "ENCRYPTED "):
            samples.append(f"-----BEGIN {family}PRIVATE KEY-----")
        for sample in samples:
            with self.subTest(sample=sample):
                result = inspect_sensitive(sample)
                self.assertTrue(result.detected)
                self.assertFalse(result.limited)
                self.assertNotIn(sample, repr(result))

    def test_benign_docs_and_legal_parameters(self) -> None:
        samples = ["The PASSWORD field is documented here.", "Use Bearer authentication.",
                   "password_policy=strict&max_tokens=64&page_token=cursor_64",
                   "authorization=Bearer <token>", "api_key=${EXAMPLE_KEY}",
                   'password="<redacted>"', 'api_key="your_api_key"',
                   "-----BEGIN PUBLIC KEY-----", "-----BEGIN RSA PUBLIC KEY-----",
                   '{"properties":{"password":{"type":"string"}}}',
                   '{"password":"[REDACTED]","token":"next_page"}',
                   '{"temperature":0.5,"max_tokens":512,"format":"base64"}']
        for sample in samples:
            for variant in (sample, encoded(sample), quote(sample, safe="")):
                with self.subTest(variant=variant):
                    self.assertFalse(inspect_sensitive(variant).blocked)

    def test_multilayer_and_linewrapped_encoding(self) -> None:
        b64 = encoded(FAKE)
        samples = [b64, b64.rstrip("="), "\n".join(b64[i:i+5] for i in range(0, len(b64), 5)),
                   encoded(encoded(FAKE)), quote(quote(FAKE, safe=""), safe=""),
                   encoded(quote(FAKE, safe="")), quote(encoded(FAKE), safe=""),
                   "http://127.0.0.1/?value=" + quote(FAKE, safe=""),
                   encoded("pwd=x"), base64.urlsafe_b64encode((FAKE + "\u00ff").encode()).decode()]
        for sample in samples:
            with self.subTest(sample=sample):
                result = inspect_sensitive(sample)
                self.assertTrue(result.detected, result)
                self.assertTrue(result.finding.transformations)

    def test_json_nested_escaped_and_duplicate_fields(self) -> None:
        samples = [r'{"profile":{"\u0070assword":"SCANNER_ONLY_FAKE"}}',
                   r'{"password":"\u0053CANNER_ONLY_FAKE"}',
                   r'{"\u0061uthorization":"Bearer SCANNER_ONLY_FAKE_TOKEN"}',
                   r'{"\u0070assword":"SCANNER_ONLY_FAKE","password":"<redacted>"}',
                   '{"api-key":"SCANNER_ONLY_FAKE"}',
                   json.dumps({"items": [{"value": encoded(FAKE)}]}),
                   json.dumps({"nested": json.dumps({"password": "SCANNER_ONLY_FAKE"})}),
                   '{"password":123456}', "pass" + "word=" + "SCANNER_ONLY_FAKE"]
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertTrue(inspect_sensitive(sample).detected)

    def test_each_resource_budget_fails_closed_distinctly(self) -> None:
        constraints = [
            ("input_length", "x" * 21, {"max_input_chars": 20}),
            ("total_characters", encoded(FAKE), {"max_total_chars": len(encoded(FAKE))}),
            ("decode_depth", encoded(encoded("ordinary message")), {"max_decode_depth": 1}),
            ("view_count", '["first","second"]', {"max_views": 1}),
            ("json_depth", "[" * 17 + "0" + "]" * 17, {}),
            ("json_nodes", '[1,2,3]', {"max_json_nodes": 2}),
            ("json_parses", json.dumps('["safe"]'), {"max_json_parses": 1}),
            ("base64_candidates", " ".join(encoded(f"sample_{i:03}") for i in range(70)), {}),
        ]
        for reason, sample, overrides in constraints:
            limits = dataclasses.replace(DEFAULT_SCAN_LIMITS, **overrides)
            with self.subTest(reason=reason):
                result = inspect_sensitive(sample, limits=limits)
                self.assertEqual(result.limit_reason, reason)
                self.assertTrue(result.blocked)
                self.assertFalse(result.detected)
                self.assertLessEqual(result.chars_scheduled, limits.max_total_chars)
                self.assertLessEqual(result.views_examined, limits.max_views)
                self.assertLessEqual(result.base64_attempts, limits.max_base64_candidates)

    def test_oversized_secret_suffix_is_not_truncated_and_allowed(self) -> None:
        self.assertEqual(inspect_sensitive("x" * 65536 + FAKE).limit_reason, "input_length")
        self.assertTrue(scan_sensitive("x" * 65537))

    def test_pathological_inputs_finish_in_bounded_subprocess(self) -> None:
        source = '''
from security.scanner import inspect_sensitive
assert inspect_sensitive("[" * 30000 + "]" * 30000).limit_reason == "json_depth"
assert inspect_sensitive("PASSWORD" + " " * 64000).blocked is False
assert inspect_sensitive('{"number":' + '9' * 60000 + '}').views_examined <= 128
assert inspect_sensitive("x" * 10000000).limit_reason == "input_length"
'''
        result = subprocess.run([sys.executable, "-c", source], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_seeded_malformed_input_is_bounded(self) -> None:
        generator = random.Random(17)
        alphabet = '[]{}"%abc0123_-=+/\\'
        for _ in range(200):
            sample = "".join(generator.choice(alphabet) for _ in range(generator.randrange(256)))
            result = inspect_sensitive(sample)
            self.assertLessEqual(result.views_examined, 128)
            self.assertLessEqual(result.chars_scheduled, 262144)
            self.assertLessEqual(result.base64_attempts, 64)

    def test_argument_validation_and_compatibility(self) -> None:
        for value in (None, 42, b"text"):
            with self.assertRaises(TypeError):
                inspect_sensitive(value)
        for value in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                ScanLimits(max_decode_depth=value)
        self.assertFalse(scan_sensitive("ordinary message"))
        self.assertTrue(scan_sensitive(FAKE))


if __name__ == "__main__":
    unittest.main()

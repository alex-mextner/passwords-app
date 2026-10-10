"""Offline tests for one-time codes: RFC 6238 vectors, and the Apple sidecar block -> URI.

Run: .venv/bin/python -m unittest tests.test_totp
"""

import base64
import unittest

from passwords_app.icloud import totp
from passwords_app.icloud.vault.host import Credential, CredentialStore, handle

# RFC 6238 Appendix B: ASCII "12345678901234567890", 8 digits, 30s.
RFC_URI = "otpauth://totp/rfc?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8"

APPLE_BLOCK = {
    "secret": bytes(range(1, 21)),
    "algorithm": 0,
    "digits": 6,
    "period": 30,
    "issuer": "Example",
    "accountName": "me@example.com",
}


class GenerateTests(unittest.TestCase):
    def test_rfc6238_vectors(self):
        for at, expected in ((59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924")):
            self.assertEqual(totp.generate(RFC_URI, at=at)["code"], expected)

    def test_expiry_is_the_next_period_boundary(self):
        self.assertEqual(totp.generate(RFC_URI, at=59)["expires"], 60)

    def test_unusable_uri(self):
        self.assertEqual(totp.generate("otpauth://totp/x?secret=not!base32"), {})
        self.assertEqual(totp.generate(""), {})


class SidecarTests(unittest.TestCase):
    def test_block_becomes_a_usable_uri(self):
        uri = totp.uri_from_sidecar(APPLE_BLOCK)
        self.assertIn("secret=" + base64.b32encode(APPLE_BLOCK["secret"]).decode(), uri)
        self.assertEqual(len(totp.generate(uri)["code"]), 6)

    def test_block_without_a_secret(self):
        self.assertEqual(totp.uri_from_sidecar({"digits": 6}), "")
        self.assertEqual(totp.uri_from_sidecar(None), "")


class WireTests(unittest.TestCase):
    """The secret must never reach the browser - only a generated code."""

    def setUp(self):
        self.store = CredentialStore(
            [Credential("example.com", "alice", "pw", totp=totp.uri_from_sidecar(APPLE_BLOCK))]
        )

    def test_match_sends_a_code_not_the_secret(self):
        sent = handle({"cmd": "match", "domain": "example.com"}, self.store)["credentials"][0]
        self.assertNotIn("AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYU", repr(sent))
        self.assertEqual(len(sent["totp"]["code"]), 6)

    def test_totp_command_regenerates(self):
        reply = handle({"cmd": "totp", "domain": "example.com", "username": "alice"}, self.store)
        self.assertEqual(len(reply["totp"]["code"]), 6)
        self.assertFalse(
            handle({"cmd": "totp", "domain": "example.com", "username": "bob"}, self.store)["ok"]
        )


if __name__ == "__main__":
    unittest.main()

"""Offline tests for the keychain decryption core (x9.63 KDF + AES-SIV unwrap)."""

import unittest

from passwords_app.icloud.keychain import crypto as kc


class X963KdfTests(unittest.TestCase):
    def test_known_vector(self):
        # NIST/SEC1 ANSI-X9.63 KDF (SHA-256) vector, no SharedInfo.
        z = bytes.fromhex("96c05619d56c328ab95fe84b18264b08725b85e33fd34f08")
        out = kc.x963_kdf(z, b"", 16)
        self.assertEqual(out.hex(), "443024c3dae66b95e6f5670601558f71")

    def test_length_and_counter(self):
        out = kc.x963_kdf(b"secret", b"info", 48)
        self.assertEqual(len(out), 48)
        self.assertEqual(kc.x963_kdf(b"secret", b"info", 32), out[:32])


if __name__ == "__main__":
    unittest.main()

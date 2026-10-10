"""Offline tests for the encrypted session store's master-key handling (temp config dir).

Covers the key-file fallback path only - no Secret Service is touched.

Run: .venv/bin/python -m unittest tests.test_session
"""

import base64
import os
import tempfile
import unittest


class MasterKeyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old_xdg = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = self._tmp.name
        # no Secret Service: force the 0600 key file fallback
        self._old_dbus = os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)

    def tearDown(self):
        if self._old_xdg is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = self._old_xdg
        if self._old_dbus is not None:
            os.environ["DBUS_SESSION_BUS_ADDRESS"] = self._old_dbus
        self._tmp.cleanup()

    @staticmethod
    def _key_file():
        from passwords_app.icloud import paths
        return paths.fallback_key_file()

    def test_save_then_load(self):
        from passwords_app.icloud.auth import session
        self.assertIsNone(session.load())  # nothing stored yet
        session.save({"username": "alice@example.com", "token": "t"})
        self.assertEqual(session.load()["username"], "alice@example.com")
        f = self._key_file()
        self.assertEqual(len(base64.b64decode(f.read_bytes())), 32)
        self.assertEqual(f.stat().st_mode & 0o777, 0o600)

    def test_raw_32_byte_key_still_accepted(self):
        """Keys written by versions before the base64 change must keep working."""
        from passwords_app.icloud.auth import session
        session.save({"a": 1})
        f = self._key_file()
        f.write_bytes(base64.b64decode(f.read_bytes()))  # downgrade to the legacy raw form
        self.assertEqual(session.load(), {"a": 1})

    def test_unusable_key_is_replaced(self):
        """A key the keyring mangled (wrong length) is regenerated, not fed to SecretBox."""
        from passwords_app.icloud.auth import session
        f = self._key_file()
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"\x00short")
        session.save({"a": 1})  # used to raise ValueError: key must be exactly 32 bytes
        self.assertEqual(len(base64.b64decode(f.read_bytes())), 32)
        self.assertEqual(session.load(), {"a": 1})

    def test_key_change_raises_session_error(self):
        from passwords_app.icloud.auth import session
        session.save({"a": 1})
        self._key_file().write_bytes(base64.b64encode(os.urandom(32)))
        with self.assertRaises(session.SessionError):
            session.load()

    def test_undecryptable_caches_are_discarded(self):
        from passwords_app.icloud.auth import session
        from passwords_app.icloud.vault import store as vault
        from passwords_app.icloud.vault.host import Credential, CredentialStore

        session.save({"a": 1})
        vault.save_vault(CredentialStore([Credential("example.com", "alice", "pw", "Example")]))
        self.assertEqual(len(vault.load_vault()), 1)

        self._key_file().write_bytes(base64.b64encode(os.urandom(32)))
        self.assertEqual(len(vault.load_vault()), 0)  # dropped, rebuilt by the next sync


if __name__ == "__main__":
    unittest.main()

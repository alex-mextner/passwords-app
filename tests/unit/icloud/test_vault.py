"""Offline test for the encrypted credential vault (round-trip via a temp config dir).

Run: .venv/bin/python -m unittest tests.test_vault
"""

import importlib
import os
import tempfile
import unittest


class VaultRoundTripTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old_xdg = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = self._tmp.name
        # ensure the keyring-less fallback key file path is used (no Secret Service in CI)
        self._old_dbus = os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)

    def tearDown(self):
        if self._old_xdg is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = self._old_xdg
        if self._old_dbus is not None:
            os.environ["DBUS_SESSION_BUS_ADDRESS"] = self._old_dbus
        self._tmp.cleanup()

    def test_save_then_load(self):
        from passwords_app.icloud.vault import store as vault
        from passwords_app.icloud.vault.host import Credential, CredentialStore
        importlib.reload(vault)  # pick up XDG override

        self.assertEqual(len(vault.load_vault()), 0)  # empty before save

        store = CredentialStore([
            Credential("example.com", "alice", "pw1", "Example"),
            Credential("login.bank.test", "bob", "pw2", "Bank"),
        ])
        vault.save_vault(store)

        loaded = vault.load_vault()
        self.assertEqual(len(loaded), 2)
        hit = loaded.match("www.example.com")
        self.assertEqual(hit[0].password, "pw1")
        self.assertEqual(loaded.match("bank.test")[0].username, "bob")


if __name__ == "__main__":
    unittest.main()

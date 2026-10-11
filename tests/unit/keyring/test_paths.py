# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""How D-Bus object paths map to gnome-keyring's on-disk ids and files."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from passwords_app.keyring.client import object_id
from passwords_app.keyring.collection import keyring_location
from passwords_app.keyring.secret_service import keyring_file

if TYPE_CHECKING:
    from pathlib import Path

BASE = "/org/freedesktop/secrets/collection/"


@pytest.mark.parametrize(
    ("path", "identifier"),
    [
        (BASE + "login", "login"),
        (BASE + "iCloud_5fPasswords", "iCloud_Passwords"),
        (BASE + "iCloud_5fPasswords_5f1", "iCloud_Passwords_1"),
        (BASE + "_d0_9f_d0_b0_d1_80_d0_be_d0_bb_d0_b8", "Пароли"),
        (BASE + "a_2eb", "a.b"),
        (BASE + "upper_5FCASE", "upper_CASE"),
        (BASE + "iCloud_5fPasswords/12", "12"),
    ],
)
def test_object_id_undoes_gnome_keyring_escaping(path: str, identifier: str) -> None:
    assert object_id(path) == identifier


def test_keyring_location_matches_gnome_keyrings_auto_unlock_key() -> None:
    # The exact string gkm-wrap-prompt.c builds: "LOCAL:/keyrings/%s.keyring".
    assert (
        keyring_location(BASE + "iCloud_5fPasswords") == "LOCAL:/keyrings/iCloud_Passwords.keyring"
    )


def test_keyring_file_follows_xdg_data_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert (
        keyring_file(BASE + "iCloud_5fPasswords")
        == tmp_path / "keyrings" / "iCloud_Passwords.keyring"
    )


@pytest.mark.parametrize("value", [None, ""])
def test_keyring_file_defaults_to_local_share(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, value: str | None
) -> None:
    if value is None:
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    else:
        monkeypatch.setenv("XDG_DATA_HOME", value)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert keyring_file(BASE + "x") == tmp_path / ".local" / "share" / "keyrings" / "x.keyring"

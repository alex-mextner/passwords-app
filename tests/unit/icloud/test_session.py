# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Encrypted session store and device identity, including files written by earlier versions."""

from __future__ import annotations

import base64
import errno
import json
import os
import stat
from typing import TYPE_CHECKING, Self

import nacl.secret
import pytest

from passwords_app.icloud.auth import session as sess
from passwords_app.icloud.auth.device import Device, DeviceError
from passwords_app.icloud.paths import ConfigPaths, default_config_dir

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from pathlib import Path
    from typing import BinaryIO


@pytest.fixture(autouse=True)
def _fresh_key_cache() -> Iterator[None]:
    sess.forget_cached_keys()
    yield
    sess.forget_cached_keys()


class _Item:
    def __init__(self, secret: bytes) -> None:
        self.secret = secret

    def get_secret(self) -> bytes:
        return self.secret


class FakeCollection:
    """A login keyring collection, as secretstorage exposes it."""

    def __init__(
        self, *, locked: bool = False, dismiss: bool = False, broken: bool = False
    ) -> None:
        self.items: list[_Item] = []
        self.locked, self.dismiss, self.broken = locked, dismiss, broken
        self.lookups = 0

    def is_locked(self) -> bool:
        if self.broken:
            msg = "bus gone"
            raise RuntimeError(msg)
        return self.locked

    def unlock(self) -> bool:
        if not self.dismiss:
            self.locked = False
        return self.dismiss

    def search_items(self, attributes: dict[str, str]) -> Iterable[_Item]:
        assert attributes == sess.ATTRIBUTES
        self.lookups += 1
        return list(self.items)

    def create_item(
        self, label: str, attributes: dict[str, str], secret: bytes, *, replace: bool
    ) -> object:
        assert replace
        assert attributes == sess.ATTRIBUTES
        assert label
        self.items = [_Item(secret)]
        return self.items[0]


def _store(tmp_path: Path, coll: FakeCollection | None = None) -> sess.SessionStore:
    return sess.SessionStore(ConfigPaths(tmp_path / "cfg"), collection=lambda: coll)


# --- key handling ----------------------------------------------------------------------------


def test_round_trip_with_the_key_file(tmp_path: Path) -> None:
    store = _store(tmp_path)
    assert store.load() is None
    store.save({"username": "alice@example.com"})
    assert store.load() == {"username": "alice@example.com"}
    key_file = store.paths.fallback_key
    assert len(base64.b64decode(key_file.read_bytes())) == 32
    for path in (key_file, store.paths.session):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.paths.root.stat().st_mode) == 0o700


def test_keyring_key_is_created_once_and_reused(tmp_path: Path) -> None:
    coll = FakeCollection()
    store = _store(tmp_path, coll)
    store.save({"a": 1})
    assert len(coll.items) == 1
    assert len(base64.b64decode(coll.items[0].secret)) == 32
    sess.forget_cached_keys()
    assert _store(tmp_path, coll).load() == {"a": 1}
    assert not store.paths.fallback_key.exists()


def test_key_is_looked_up_once_per_process(tmp_path: Path) -> None:
    coll = FakeCollection()
    store = _store(tmp_path, coll)
    for _ in range(3):
        store.save({"a": 1})
        store.load()
    assert coll.lookups == 1


def test_locked_keyring_is_unlocked(tmp_path: Path) -> None:
    coll = FakeCollection(locked=True)
    _store(tmp_path, coll).save({"a": 1})
    assert coll.items


@pytest.mark.parametrize(
    "coll", [FakeCollection(locked=True, dismiss=True), FakeCollection(broken=True), None]
)
def test_unusable_keyring_falls_back_to_the_key_file(
    tmp_path: Path, coll: FakeCollection | None
) -> None:
    store = _store(tmp_path, coll)
    store.save({"a": 1})
    assert store.paths.fallback_key.exists()
    assert store.load() == {"a": 1}


def test_raw_32_byte_key_from_older_versions_is_accepted(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.save({"a": 1})
    key_file = store.paths.fallback_key
    key_file.write_bytes(base64.b64decode(key_file.read_bytes()))
    sess.forget_cached_keys()
    assert store.load() == {"a": 1}


def test_mangled_keyring_items_are_replaced(tmp_path: Path) -> None:
    coll = FakeCollection()
    coll.items = [_Item(b"short")]
    _store(tmp_path, coll).save({"a": 1})
    [item] = coll.items
    assert len(base64.b64decode(item.secret)) == 32


def test_unusable_key_file_is_replaced(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.paths.ensure()
    store.paths.fallback_key.write_bytes(b"\x00short")
    store.save({"a": 1})
    assert len(base64.b64decode(store.paths.fallback_key.read_bytes())) == 32


def test_changed_key_makes_the_session_unreadable(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.save({"a": 1})
    store.paths.fallback_key.write_bytes(base64.b64encode(os.urandom(32)))
    sess.forget_cached_keys()
    with pytest.raises(sess.SessionError, match="no longer matches"):
        store.load()


def test_session_that_is_not_an_object_is_an_error(tmp_path: Path) -> None:
    store = _store(tmp_path)
    key = store.master_key()
    store.paths.session.write_bytes(nacl.secret.SecretBox(key).encrypt(b"[1, 2]"))
    with pytest.raises(sess.SessionError, match="does not hold a session"):
        store.load()


def test_clear_removes_only_the_session(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.save({"a": 1})
    store.clear()
    store.clear()
    assert store.load() is None
    assert store.paths.fallback_key.exists()


@pytest.mark.parametrize(
    ("stored", "usable"),
    [
        (b"k" * 32, True),
        (base64.b64encode(b"k" * 32), True),
        (base64.b64encode(b"k" * 32).decode(), True),
        (b"short", False),
        (b"!!!notbase64!!!", False),
        (None, False),
        (base64.b64encode(b"k" * 31), False),
    ],
)
def test_decode_key_forms(stored: bytes | str | None, usable: bool) -> None:
    assert (sess.decode_key(stored) == b"k" * 32) is usable


def test_written_files_are_never_world_readable(tmp_path: Path) -> None:
    path = tmp_path / "secret"
    path.write_bytes(b"old")
    path.chmod(0o644)
    sess.write_private(path, b"new")
    assert path.read_bytes() == b"new"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


class _FailsHalfway:
    """A file object whose write lands half the bytes and then fails, like a full disk."""

    def __init__(self, inner: BinaryIO) -> None:
        self.inner = inner

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.inner.close()

    def write(self, data: bytes) -> int:
        self.inner.write(data[: len(data) // 2])
        self.inner.flush()
        raise OSError(errno.ENOSPC, "No space left on device")

    def __getattr__(self, name: str) -> object:
        return getattr(self.inner, name)


def test_a_save_that_fails_halfway_leaves_the_earlier_session_readable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    store.save({"username": "alice@example.com", "mme": {"mmeAuthToken": "first"}})
    before = sorted(p.name for p in store.paths.root.iterdir())
    real_fdopen = os.fdopen
    with monkeypatch.context() as patch:
        patch.setattr(os, "fdopen", lambda fd, _mode: _FailsHalfway(real_fdopen(fd, "wb")))
        with pytest.raises(OSError, match="No space"):
            store.save({"username": "alice@example.com", "mme": {"mmeAuthToken": "second"}})
    assert store.load() == {"username": "alice@example.com", "mme": {"mmeAuthToken": "first"}}
    assert sorted(p.name for p in store.paths.root.iterdir()) == before  # no temporary file stays


def test_a_new_process_reads_the_session_the_old_one_saved(tmp_path: Path) -> None:
    coll = FakeCollection()
    _store(tmp_path, coll).save({"username": "alice@example.com"})
    sess.forget_cached_keys()  # a restarted daemon, or one from a reinstalled venv
    assert _store(tmp_path, coll).load() == {"username": "alice@example.com"}
    assert len(coll.items) == 1  # the key was found again, not replaced


# --- files from earlier versions ---------------------------------------------------------------


def test_legacy_session_file_still_loads(tmp_path: Path) -> None:
    """session.enc as the vendored client wrote it: SecretBox(JSON) under a base64 key file."""
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    key = os.urandom(32)
    (cfg / "master.key").write_bytes(base64.b64encode(key))
    legacy = {
        "username": "owner@example.com",
        "dsid": "000-adsid",
        "password": "pw",
        "mme": {
            "dsid": "123",
            "mmeAuthToken": "t",
            "tokens": {"cloudKitToken": "ck"},
            "cloudKitUserId": "_u",
        },
        "webservices": {"keychainsync": "https://p1-escrowproxy.icloud.com"},
        "octagon": {"peer_id": "SHA256:x", "joined": True},
    }
    (cfg / "session.enc").write_bytes(
        nacl.secret.SecretBox(key).encrypt(json.dumps(legacy).encode())
    )
    assert sess.SessionStore(ConfigPaths(cfg), collection=lambda: None).load() == legacy


def test_legacy_device_file_still_loads(tmp_path: Path) -> None:
    path = tmp_path / "device.json"
    path.write_text(
        json.dumps({"device_id": "D-1", "serial": "C02X", "local_user_uuid": "L-1"}, indent=2)
    )
    assert Device.load_or_create(path) == Device("D-1", "C02X", "L-1")


def test_new_device_is_generated_once_and_kept(tmp_path: Path) -> None:
    path = tmp_path / "device.json"
    first = Device.load_or_create(path)
    assert Device.load_or_create(path) == first
    assert first.device_id == first.device_id.upper()
    assert first.serial.startswith("C02")
    assert len(first.serial) == 12
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert set(json.loads(path.read_text())) == {"device_id", "serial", "local_user_uuid"}


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        json.dumps({"device_id": "x"}),
        json.dumps({"device_id": 1, "serial": "s", "local_user_uuid": "l"}),
    ],
)
def test_damaged_device_file_is_an_error(tmp_path: Path, content: str) -> None:
    path = tmp_path / "device.json"
    path.write_text(content)
    with pytest.raises(DeviceError):
        Device.load_or_create(path)


def test_device_headers_carry_identity() -> None:
    h = Device("abc-def", "C02X", "local-uuid").meta_headers()
    assert h["X-Mme-Device-Id"] == "ABC-DEF"
    assert h["X-Apple-I-SRL-NO"] == "C02X"
    assert base64.b64decode(h["X-Apple-I-MD-LU"]) == b"LOCAL-UUID"
    assert h["X-Apple-I-Client-Time"].endswith("Z")


# --- paths -------------------------------------------------------------------------------------


def test_default_config_dir_follows_xdg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert default_config_dir() == tmp_path / "passwords-app"
    assert ConfigPaths.default().session == tmp_path / "passwords-app" / "session.enc"


def test_path_lookups_do_not_touch_the_disk(tmp_path: Path) -> None:
    paths = ConfigPaths(tmp_path / "nothing")
    assert paths.device.name == "device.json"
    assert paths.zone_cache.name == "icloud-zones.json"
    assert not paths.root.exists()

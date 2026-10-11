# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""`ICloudRemoteStore`: the sync engine's view of iCloud, over the fake gateway."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
import requests

from passwords_app.core.model import Credential
from passwords_app.icloud.account import SignInRequired
from passwords_app.icloud.keychain.client import (
    KeychainClient,
    RecordConflictError,
    StoredLogin,
    UnreadableZoneError,
)
from passwords_app.icloud.passwords import UnsupportedCredentialError
from passwords_app.icloud.transport.cloudkit import CloudKitError
from passwords_app.sync.ports import (
    AuthRequired,
    ConflictError,
    RemoteSnapshot,
    RemoteStore,
    RemoteUnavailable,
)
from passwords_app.sync.remote_icloud import ICloudRemoteStore

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from tests.fakes.cloudkit_server import FakeCloudKit

T0 = datetime(2024, 3, 4, 5, 6, 7, tzinfo=UTC)
CRED = Credential("00000000-0000-4000-8000-000000000001", "https://a.example", "u", "p", T0, T0)


@pytest.fixture
def store(open_keychain: Callable[[], KeychainClient]) -> ICloudRemoteStore:
    return ICloudRemoteStore(open_keychain)


def test_satisfies_the_remote_store_protocol(store: ICloudRemoteStore) -> None:
    remote: RemoteStore = store
    assert remote is store


async def test_fetch_returns_credentials_with_their_etags(
    fake: FakeCloudKit, store: ICloudRemoteStore
) -> None:
    tag, _ = fake.put_login(CRED)
    snap = await store.fetch()
    assert isinstance(snap, RemoteSnapshot)
    item = snap.items[CRED.id]
    assert item.credential.content_hash() == CRED.content_hash()
    assert item.etag == tag


async def test_upsert_create_edit_delete_cycle(
    fake: FakeCloudKit, store: ICloudRemoteStore
) -> None:
    await store.fetch()
    etag = await store.upsert(CRED, None)
    assert (await store.fetch()).items[CRED.id].etag == etag
    etag2 = await store.upsert(dataclasses.replace(CRED, password="new"), etag)
    assert fake.logins()[CRED.id].password == "new"
    await store.delete(CRED.id, etag2)
    assert (await store.fetch()).items == {}


async def test_stale_write_is_a_conflict(fake: FakeCloudKit, store: ICloudRemoteStore) -> None:
    fake.put_login(CRED)
    etag = (await store.fetch()).items[CRED.id].etag
    fake.put_item(CRED.id, {**fake.item(CRED.id), "v_Data": b"iphone"})
    with pytest.raises(ConflictError):
        await store.upsert(dataclasses.replace(CRED, password="linux"), etag)
    with pytest.raises(ConflictError):
        await store.delete(CRED.id, "stale")


async def test_server_failure_is_remote_unavailable_never_a_short_snapshot(
    fake: FakeCloudKit, store: ICloudRemoteStore
) -> None:
    fake.put_login(CRED)
    await store.fetch()
    fake.fail("/record/sync", http_status=500)
    with pytest.raises(RemoteUnavailable) as info:
        await store.fetch()
    assert not isinstance(info.value, AuthRequired)


async def test_rejected_token_reconnects_once(
    fake: FakeCloudKit, open_keychain: Callable[[], KeychainClient]
) -> None:
    opened: list[int] = []

    def connect() -> KeychainClient:
        opened.append(1)
        return open_keychain()

    store = ICloudRemoteStore(connect)
    fake.put_login(CRED)
    await store.fetch()
    fake.fail("/record/sync", http_status=401)
    assert CRED.id in (await store.fetch()).items
    assert len(opened) == 2


async def test_token_rejected_twice_needs_sign_in(
    fake: FakeCloudKit, store: ICloudRemoteStore
) -> None:
    await store.fetch()
    fake.fail("/record/sync", http_status=401, times=2)
    with pytest.raises(AuthRequired):
        await store.fetch()


async def test_connection_is_reused(open_keychain: Callable[[], KeychainClient]) -> None:
    opened: list[int] = []

    def connect() -> KeychainClient:
        opened.append(1)
        return open_keychain()

    store = ICloudRemoteStore(connect)
    await store.fetch()
    await store.fetch()
    assert len(opened) == 1


async def test_changed_generation_reopens_the_keychain(
    open_keychain: Callable[[], KeychainClient],
) -> None:
    opened: list[int] = []
    generation = [0]

    def connect() -> KeychainClient:
        opened.append(1)
        return open_keychain()

    store = ICloudRemoteStore(connect, lambda: generation[0])
    await store.fetch()
    generation[0] += 1
    await store.fetch()
    await store.fetch()
    assert len(opened) == 2


class _Raising:
    def __init__(self, error: Exception) -> None:
        self.error = error

    def fetch(self) -> Mapping[str, StoredLogin]:
        raise self.error

    def save(self, cred: Credential, etag: str | None) -> str:
        del cred, etag
        raise self.error

    def delete(self, item_id: str, etag: str | None) -> None:
        del item_id, etag
        raise self.error


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (RecordConflictError("x"), ConflictError),
        (SignInRequired("x"), AuthRequired),
        (UnreadableZoneError("x"), RemoteUnavailable),
        (CloudKitError("x", http_status=500), RemoteUnavailable),
        (UnsupportedCredentialError("x"), RemoteUnavailable),
        (requests.ConnectionError("x"), RemoteUnavailable),
        (OSError("disk"), RemoteUnavailable),
    ],
)
async def test_errors_map_to_engine_errors(error: Exception, expected: type[Exception]) -> None:
    store = ICloudRemoteStore(lambda: _Raising(error))
    for call in (store.fetch(), store.upsert(CRED, None), store.delete(CRED.id, None)):
        with pytest.raises(expected):
            await call


async def test_sign_in_required_while_connecting_is_auth_required() -> None:
    def connect() -> KeychainClient:
        msg = "verification code needed"
        raise SignInRequired(msg)

    with pytest.raises(AuthRequired, match="verification code"):
        await ICloudRemoteStore(connect).fetch()


async def test_unexpected_errors_are_not_swallowed() -> None:
    store = ICloudRemoteStore(lambda: _Raising(KeyError("bug")))
    with pytest.raises(KeyError):
        await store.fetch()

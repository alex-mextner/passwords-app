# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""`app_secret`: random app keys (state.db key) kept in the default keyring."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest
from tests.harness.dbus_session import LOGIN_COLLECTION, PrivateSession, lock_collection
from tests.integration.keyring.support import kill_keyring_daemon

from passwords_app.keyring.app_key import SCHEMA, app_secret
from passwords_app.sync.ports import LocalUnavailable

if TYPE_CHECKING:
    from dbus_fast.aio import MessageBus

    from passwords_app.keyring.client import SecretServiceClient

pytestmark = pytest.mark.integration


async def test_first_call_creates_a_random_key(bus: MessageBus) -> None:
    key = await app_secret(bus, "state-db")
    assert len(key) == 32
    assert key != bytes(32)


async def test_later_calls_return_the_same_key(bus: MessageBus, other_bus: MessageBus) -> None:
    first = await app_secret(bus, "state-db")
    assert await app_secret(bus, "state-db") == first
    assert await app_secret(other_bus, "state-db") == first  # another process, same key


async def test_names_are_independent(bus: MessageBus) -> None:
    assert await app_secret(bus, "state-db") != await app_secret(bus, "session")


@pytest.mark.parametrize("size", [1, 16, 64, 128])
async def test_requested_size(bus: MessageBus, size: int) -> None:
    assert len(await app_secret(bus, f"key-{size}", size)) == size


async def test_key_is_stored_where_the_plan_says(
    bus: MessageBus, seahorse: SecretServiceClient
) -> None:
    key = await app_secret(bus, "state-db")
    (item,) = await seahorse.search(
        LOGIN_COLLECTION, {"application": "passwords-app", "type": "state-db"}
    )
    attributes = await seahorse.get_property(item, "org.freedesktop.Secret.Item", "Attributes")
    assert attributes["xdg:schema"] == SCHEMA
    assert (await seahorse.get_secrets([item]))[item] == key


async def test_concurrent_first_calls_agree(bus: MessageBus, other_bus: MessageBus) -> None:
    keys = await asyncio.gather(
        app_secret(bus, "raced"), app_secret(other_bus, "raced"), app_secret(bus, "raced")
    )
    assert len(set(keys)) == 1
    assert await app_secret(bus, "raced") == keys[0]


async def test_wrong_stored_size_is_an_error_not_a_silent_replacement(bus: MessageBus) -> None:
    original = await app_secret(bus, "state-db", 32)
    with pytest.raises(ValueError, match="32 bytes, expected 16"):
        await app_secret(bus, "state-db", 16)
    assert await app_secret(bus, "state-db", 32) == original


async def test_locked_default_keyring_is_unavailable(bus: MessageBus, private_bus: str) -> None:
    await lock_collection(private_bus, LOGIN_COLLECTION)
    with pytest.raises(LocalUnavailable, match="locked"):
        await app_secret(bus, "state-db")


async def test_missing_service_is_unavailable(
    bus: MessageBus, private_session: PrivateSession
) -> None:
    kill_keyring_daemon(private_session.root)
    with pytest.raises(LocalUnavailable):
        await app_secret(bus, "state-db")


@pytest.mark.parametrize(("name", "size"), [("", 32), ("x", 0), ("x", -1)])
async def test_bad_arguments(bus: MessageBus, name: str, size: int) -> None:
    with pytest.raises(ValueError, match="key"):
        await app_secret(bus, name, size)

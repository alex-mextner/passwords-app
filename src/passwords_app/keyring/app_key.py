# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Random keys the app keeps in the user's default keyring (e.g. the state.db key).

Get-or-create: the first call stores fresh random bytes, later calls return them. If two
processes race on the first call, both read back every matching item and pick the oldest,
so they agree on one key instead of each keeping its own. A locked default collection is
`LocalUnavailable` — the daemon must not prompt — and a stored key of the wrong size is an
error rather than silently replaced, since data may already be encrypted with it.
"""

from __future__ import annotations

import contextlib
import secrets
import sys
from typing import TYPE_CHECKING

from passwords_app.keyring.client import BINARY, ITEM, SecretServiceClient, SecretServiceError
from passwords_app.sync.ports import LocalUnavailable

if TYPE_CHECKING:
    from dbus_fast.aio import MessageBus

APPLICATION = "passwords-app"
SCHEMA = "io.github.alex_mextner.Passwords.AppKey"


async def _oldest(client: SecretServiceClient, items: list[str]) -> str:
    # `Created` has one-second resolution, so racers created in the same second tie; the
    # item number (gnome-keyring counts up per collection) then decides, numerically —
    # comparing the paths as text would put ".../10" before ".../9".
    created = [
        (int(await client.get_property(path, ITEM, "Created")), _item_number(path), path)
        for path in items
    ]
    return min(created)[2]


def _item_number(path: str) -> int:
    number = path.rsplit("/", 1)[-1]
    return int(number) if number.isdigit() else sys.maxsize


async def _app_secret(client: SecretServiceClient, name: str, size: int) -> bytes:
    default = await client.read_alias("default")
    if default is None:
        msg = "there is no default keyring"
        raise LocalUnavailable(msg)
    if await client.is_locked(default):
        msg = "the default keyring is locked"
        raise LocalUnavailable(msg)
    attributes = {"xdg:schema": SCHEMA, "application": APPLICATION, "type": name}
    found = await client.search(default, attributes)
    if not found:
        await client.create_item(
            default,
            f"Passwords app: {name}",
            attributes,
            secrets.token_bytes(size),
            replace=False,
            content_type=BINARY,
        )
        found = await client.search(default, attributes)
    chosen = await _oldest(client, found)
    value = (await client.get_secrets([chosen])).get(chosen)
    if value is None:
        msg = "the stored key could not be read"
        raise LocalUnavailable(msg)
    if len(value) != size:
        msg = f"stored key {name!r} has {len(value)} bytes, expected {size}"
        raise ValueError(msg)
    return value


async def app_secret(bus: MessageBus, name: str, size: int = 32) -> bytes:
    """Return the app key `name` (`size` random bytes), creating it on first use."""
    if not name:
        msg = "key name must be non-empty"
        raise ValueError(msg)
    if size <= 0:
        msg = "key size must be positive"
        raise ValueError(msg)
    try:
        client = await SecretServiceClient.open(bus)
    except SecretServiceError as exc:
        raise LocalUnavailable(str(exc)) from exc
    try:
        return await _app_secret(client, name, size)
    except SecretServiceError as exc:
        raise LocalUnavailable(str(exc)) from exc
    finally:
        # Closing a session on a vanished service changes nothing for the caller.
        with contextlib.suppress(SecretServiceError):
            await client.close()

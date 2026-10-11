# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The dedicated, password-protected "iCloud Passwords" collection (ADR 0001).

The collection is created with a random password we generate (never an empty one — that
would write an unencrypted keyring), through gnome-keyring's
``CreateWithMasterPassword`` so no prompt appears. The password lives in the login keyring
as gnome-keyring's own "automatically unlock this keyring" item (attribute
``keyring=LOCAL:/keyrings/<id>.keyring``), which gives two unlock paths without any dialog:

- we read it and call ``UnlockWithMasterPassword`` (the service never prompts), and
- Seahorse or any libsecret client asking to unlock finds it via gnome-keyring's
  login-keyring lookup, so the user is not asked for a password they never chose.

The password item is written *before* the collection exists and only then pointed at the
new collection, so a crash in between leaves an orphan password item, never a collection
whose password is lost.
"""

from __future__ import annotations

import secrets
import time
from typing import TYPE_CHECKING

from passwords_app.keyring.client import (
    COLLECTION,
    ITEM,
    SecretServiceClient,
    SecretServiceError,
    object_id,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

APPLICATION = "passwords-app"
UNLOCK_ITEM_TYPE = "keyring-password"
_LOGIN_ALIAS = "login"
_SESSION_COLLECTION = "session"
# Far beyond one CreateWithMasterPassword call (bounded by the 25 s D-Bus timeout).
PENDING_GRACE_SECONDS = 300


class CollectionUnavailableError(Exception):
    """The collection cannot be found, created, or unlocked without a prompt."""


def keyring_location(collection: str) -> str:
    """gnome-keyring's key for a collection's auto-unlock password in the login keyring."""
    return f"LOCAL:/keyrings/{object_id(collection)}.keyring"


def _pending_attributes(label: str) -> dict[str, str]:
    return {"application": APPLICATION, "type": UNLOCK_ITEM_TYPE, "pa-keyring": label}


async def _login_collection(client: SecretServiceClient) -> str:
    login = await client.read_alias(_LOGIN_ALIAS)
    if login is None:
        msg = "there is no login keyring to keep the collection password in"
        raise CollectionUnavailableError(msg)
    if await client.is_locked(login):
        msg = "the login keyring is locked"
        raise CollectionUnavailableError(msg)
    return login


async def _same_label(client: SecretServiceClient, label: str) -> list[str]:
    return [
        path
        for path in await client.collections()
        if object_id(path) != _SESSION_COLLECTION
        and await client.get_property(path, COLLECTION, "Label") == label
    ]


async def find_collection(client: SecretServiceClient, label: str) -> str | None:
    """Find the collection labelled `label`; ours (with a stored password) wins a tie."""
    matches = await _same_label(client, label)
    if len(matches) > 1:
        login = await client.read_alias(_LOGIN_ALIAS)
        if login is not None:
            for path in sorted(matches):
                found = await client.search(
                    login, {"application": APPLICATION, "keyring": keyring_location(path)}
                )
                if found:
                    return path
    return min(matches) if matches else None


async def _drop_stale_passwords(client: SecretServiceClient, login: str, label: str) -> None:
    """Delete password items whose collection is gone; keep those of renamed collections.

    An item with no location yet may belong to a creation running right now in another
    process (between storing the password and pointing it at the new collection); it is
    only deleted once it is older than any creation could take.
    """
    live = {keyring_location(path) for path in await client.collections()}
    now = time.time()
    for item in await client.search(login, _pending_attributes(label)):
        attributes = await client.get_property(item, ITEM, "Attributes")
        location = attributes.get("keyring")
        if location is None:
            created = int(await client.get_property(item, ITEM, "Created"))
            if now - created < PENDING_GRACE_SECONDS:
                continue
        elif location in live:
            continue
        await client.delete_item(item)


async def create_collection(client: SecretServiceClient, label: str) -> tuple[str, str]:
    """Create the collection; return its password item and its path."""
    login = await _login_collection(client)
    await _drop_stale_passwords(client, login, label)
    password = secrets.token_urlsafe(32)
    pending = _pending_attributes(label)
    # replace=False: gnome-keyring "replaces" any item whose attributes are a superset,
    # which could overwrite the password of a same-labelled collection the user renamed.
    item = await client.create_item(
        login, f"Unlock password for: {label}", pending, password.encode(), replace=False
    )
    collection = await client.create_with_master_password(label, password)
    await client.update_item(
        item,
        f"Unlock password for: {label}",
        {**pending, "keyring": keyring_location(collection)},
        None,
    )
    return item, collection


async def ensure_collection(client: SecretServiceClient, label: str) -> str:
    try:
        existing = await find_collection(client, label)
        if existing is not None:
            return existing
        password_item, created = await create_collection(client, label)
        # Two first opens (daemon and app) can both find nothing and both create. Every
        # racer keeps the collection whose path sorts first and removes its own if that
        # is not it, so all of them end up on the same, single collection.
        winner = min(await _same_label(client, label))
        if winner != created:
            await client.call(created, COLLECTION, "Delete")
            await client.delete_item(password_item)
    except SecretServiceError as exc:
        raise CollectionUnavailableError(str(exc)) from exc
    return winner


async def _password_items(
    client: SecretServiceClient, login: str, collection: str, label: str
) -> list[tuple[str, Mapping[str, str]]]:
    by_location = await client.search(
        login, {"application": APPLICATION, "keyring": keyring_location(collection)}
    )
    # An item still lacking the location: we crashed between creating it and the collection.
    pending = await client.search(login, _pending_attributes(label))
    items: list[tuple[str, Mapping[str, str]]] = []
    for path in dict.fromkeys([*by_location, *pending]):
        attributes = await client.get_property(path, ITEM, "Attributes")
        items.append((path, attributes))
    return items


async def ensure_unlocked(client: SecretServiceClient, collection: str, label: str) -> None:
    """Unlock silently with the stored password, or raise; never prompts."""
    try:
        if not await client.is_locked(collection):
            return
        login = await _login_collection(client)
        candidates = await _password_items(client, login, collection, label)
        stored = await client.get_secrets([path for path, _ in candidates])
        location = keyring_location(collection)
        for path, attributes in candidates:
            password = stored.get(path)
            if password is None:
                continue
            try:
                await client.unlock_with_master_password(collection, password.decode())
            except (SecretServiceError, UnicodeDecodeError):
                continue
            if attributes.get("keyring") != location:
                await client.update_item(
                    path,
                    f"Unlock password for: {label}",
                    {**attributes, "keyring": location},
                    None,
                )
            if not await client.is_locked(collection):
                return
    except SecretServiceError as exc:
        raise CollectionUnavailableError(str(exc)) from exc
    msg = "the collection is locked and no stored password unlocks it"
    raise CollectionUnavailableError(msg)

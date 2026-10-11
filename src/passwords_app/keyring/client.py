# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Thin async Secret Service client over dbus-fast, with one DH-encrypted session.

Raw messages instead of introspected proxies: a 2 000-item fetch issues thousands of
property reads, and proxies would add an introspection round trip and per-call overhead.
Every call is bounded by a timeout, because a Secret Service waiting on something (a
stuck daemon, a prompt nobody answers) must surface as "unavailable", not hang the sync.

Prompts are never shown: any method that answers with a prompt object raises
`PromptRequiredError` — a background service must not pop dialogs at the user.
"""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING, Any

from dbus_fast import Message, MessageType, Variant
from dbus_fast.errors import DBusFastError

from passwords_app.keyring.dh import ALGORITHM, DhKeyExchange, SessionCipher, SessionCryptoError

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from dbus_fast.aio import MessageBus

BUS_NAME = "org.freedesktop.secrets"
SERVICE_PATH = "/org/freedesktop/secrets"
SERVICE = "org.freedesktop.Secret.Service"
COLLECTION = "org.freedesktop.Secret.Collection"
ITEM = "org.freedesktop.Secret.Item"
SESSION = "org.freedesktop.Secret.Session"
PROPERTIES = "org.freedesktop.DBus.Properties"
# gnome-keyring's only way to create/unlock a collection with a password we supply instead
# of a prompt. Unsupported by name, but stable since 2011 and used by its own test suite.
GNOME_KEYRING = "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface"
NO_PROMPT = "/"
TEXT = "text/plain; charset=utf8"
BINARY = "application/octet-stream"
CALL_TIMEOUT = 25.0  # the D-Bus default reply timeout

_ESCAPED_BYTE = re.compile(rb"_([0-9a-fA-F]{2})")


class SecretServiceError(Exception):
    """A Secret Service call failed; `name` is the D-Bus error name when there is one."""

    def __init__(self, message: str, name: str | None = None) -> None:
        super().__init__(message)
        self.name = name


class PromptRequiredError(SecretServiceError):
    """The service wants to show a prompt; we never let it from a background service."""


def object_id(path: str) -> str:
    """Undo the ``_XX`` escaping gnome-keyring applies to ids in object paths."""
    raw = path.rsplit("/", 1)[-1].encode()
    return _ESCAPED_BYTE.sub(lambda m: bytes([int(m.group(1), 16)]), raw).decode()


class SecretServiceClient:
    __slots__ = ("_cipher", "bus", "session")

    def __init__(self, bus: MessageBus, session: str, cipher: SessionCipher) -> None:
        self.bus = bus
        self.session = session
        self._cipher = cipher

    @classmethod
    async def open(cls, bus: MessageBus) -> SecretServiceClient:
        """Negotiate an encrypted session; there is deliberately no ``plain`` fallback."""
        exchange = DhKeyExchange()
        output, session = await _call(
            bus,
            SERVICE_PATH,
            SERVICE,
            "OpenSession",
            signature="sv",
            body=[ALGORITHM, Variant("ay", exchange.public_key)],
        )
        if not isinstance(output, Variant) or not isinstance(output.value, bytes):
            msg = "OpenSession returned no DH public key"
            raise SecretServiceError(msg)
        try:
            cipher = exchange.agree(output.value)
        except SessionCryptoError as exc:
            raise SecretServiceError(str(exc)) from exc
        return cls(bus, str(session), cipher)

    async def close(self) -> None:
        await self.call(self.session, SESSION, "Close")

    async def call(
        self,
        path: str,
        interface: str,
        member: str,
        signature: str = "",
        body: list[Any] | None = None,
    ) -> list[Any]:
        return await _call(self.bus, path, interface, member, signature=signature, body=body)

    # --- secrets ----------------------------------------------------------------------

    def encode_secret(self, value: bytes, content_type: str = TEXT) -> list[Any]:
        iv, ciphertext = self._cipher.encrypt(value)
        return [self.session, iv, ciphertext, content_type]

    def decode_secret(self, secret: list[Any]) -> bytes:
        _session, iv, ciphertext, _content_type = secret
        try:
            return self._cipher.decrypt(bytes(iv), bytes(ciphertext))
        except SessionCryptoError as exc:
            raise SecretServiceError(str(exc)) from exc

    async def get_secrets(self, items: list[str]) -> dict[str, bytes]:
        """Secrets of unlocked items, in one round trip; locked items are simply absent."""
        if not items:
            return {}
        (secrets,) = await self.call(
            SERVICE_PATH, SERVICE, "GetSecrets", "aoo", [items, self.session]
        )
        return {path: self.decode_secret(secret) for path, secret in secrets.items()}

    async def set_secret(self, item: str, value: bytes, content_type: str = TEXT) -> None:
        await self.call(
            item, ITEM, "SetSecret", "(oayays)", [self.encode_secret(value, content_type)]
        )

    # --- properties -------------------------------------------------------------------

    async def get_property(self, path: str, interface: str, name: str) -> Any:  # noqa: ANN401
        (value,) = await self.call(path, PROPERTIES, "Get", "ss", [interface, name])
        return value.value

    async def get_all(self, path: str, interface: str) -> dict[str, Any]:
        (values,) = await self.call(path, PROPERTIES, "GetAll", "s", [interface])
        return {name: variant.value for name, variant in values.items()}

    async def set_property(self, path: str, interface: str, name: str, value: Variant) -> None:
        await self.call(path, PROPERTIES, "Set", "ssv", [interface, name, value])

    # --- collections and items --------------------------------------------------------

    async def read_alias(self, alias: str) -> str | None:
        (path,) = await self.call(SERVICE_PATH, SERVICE, "ReadAlias", "s", [alias])
        return None if path == NO_PROMPT else str(path)

    async def collections(self) -> list[str]:
        return list(await self.get_property(SERVICE_PATH, SERVICE, "Collections"))

    async def is_locked(self, path: str) -> bool:
        return bool(await self.get_property(path, COLLECTION, "Locked"))

    async def search(self, collection: str, attributes: Mapping[str, str]) -> list[str]:
        (found,) = await self.call(
            collection, COLLECTION, "SearchItems", "a{ss}", [dict(attributes)]
        )
        return list(found)

    async def create_item(  # noqa: PLR0913 - mirrors the D-Bus method
        self,
        collection: str,
        label: str,
        attributes: Mapping[str, str],
        value: bytes,
        *,
        replace: bool,
        content_type: str = TEXT,
    ) -> str:
        properties = {
            f"{ITEM}.Label": Variant("s", label),
            f"{ITEM}.Attributes": Variant("a{ss}", dict(attributes)),
        }
        item, prompt = await self.call(
            collection,
            COLLECTION,
            "CreateItem",
            "a{sv}(oayays)b",
            [properties, self.encode_secret(value, content_type), replace],
        )
        _no_prompt(prompt, "CreateItem")
        return str(item)

    async def update_item(
        self, item: str, label: str, attributes: Mapping[str, str], value: bytes | None
    ) -> None:
        if value is not None:
            await self.set_secret(item, value)
        await self.set_property(item, ITEM, "Attributes", Variant("a{ss}", dict(attributes)))
        await self.set_property(item, ITEM, "Label", Variant("s", label))

    async def delete_item(self, item: str) -> None:
        (prompt,) = await self.call(item, ITEM, "Delete")
        _no_prompt(prompt, "Delete")

    async def lock(self, paths: Iterable[str]) -> None:
        _locked, prompt = await self.call(SERVICE_PATH, SERVICE, "Lock", "ao", [list(paths)])
        _no_prompt(prompt, "Lock")

    async def create_with_master_password(self, label: str, password: str) -> str:
        properties = {f"{COLLECTION}.Label": Variant("s", label)}
        (path,) = await self.call(
            SERVICE_PATH,
            GNOME_KEYRING,
            "CreateWithMasterPassword",
            "a{sv}(oayays)",
            [properties, self.encode_secret(password.encode())],
        )
        return str(path)

    async def unlock_with_master_password(self, collection: str, password: str) -> None:
        await self.call(
            SERVICE_PATH,
            GNOME_KEYRING,
            "UnlockWithMasterPassword",
            "o(oayays)",
            [collection, self.encode_secret(password.encode())],
        )


def _no_prompt(prompt: object, member: str) -> None:
    if prompt != NO_PROMPT:
        msg = f"{member} needs a user prompt"
        raise PromptRequiredError(msg)


async def _call(  # noqa: PLR0913 - one D-Bus method call
    bus: MessageBus,
    path: str,
    interface: str,
    member: str,
    *,
    signature: str = "",
    body: list[Any] | None = None,
) -> list[Any]:
    message = Message(
        destination=BUS_NAME,
        path=path,
        interface=interface,
        member=member,
        signature=signature,
        body=body or [],
    )
    try:
        reply = await asyncio.wait_for(bus.call(message), CALL_TIMEOUT)
    except TimeoutError as exc:
        msg = f"{member} timed out"
        raise SecretServiceError(msg) from exc
    except (DBusFastError, OSError, EOFError) as exc:
        msg = f"{member} failed: {exc}"
        raise SecretServiceError(msg) from exc
    if reply.message_type == MessageType.ERROR:
        detail = reply.body[0] if reply.body else ""
        msg = f"{member} on {path}: {reply.error_name}: {detail}"
        raise SecretServiceError(msg, reply.error_name)
    return list(reply.body)

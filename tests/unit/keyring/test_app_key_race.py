# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Racing first calls of `app_secret` agree on one key, even across item ".../9" → ".../10"."""

from __future__ import annotations

from typing import TYPE_CHECKING

from passwords_app.keyring.app_key import _app_secret  # pyright: ignore[reportPrivateUsage]

if TYPE_CHECKING:
    from collections.abc import Mapping

DEFAULT = "/org/freedesktop/secrets/collection/login"
SAME_SECOND = 1_790_000_000


class RacingClient:
    """In-memory default collection whose next item is number 9; every Created ties."""

    def __init__(self) -> None:
        self.items: dict[str, bytes] = {}
        self.next_number = 9

    async def read_alias(self, alias: str) -> str:
        assert alias == "default"
        return DEFAULT

    async def is_locked(self, path: str) -> bool:
        assert path == DEFAULT
        return False

    async def search(self, collection: str, attributes: Mapping[str, str]) -> list[str]:
        assert collection == DEFAULT
        assert attributes["type"] == "state-db"
        return list(self.items)

    async def create_item(  # noqa: PLR0913 - mirrors SecretServiceClient.create_item
        self,
        collection: str,
        label: str,
        attributes: Mapping[str, str],
        secret: bytes,
        *,
        replace: bool,
        content_type: str,
    ) -> str:
        del collection, label, attributes, replace, content_type
        path = f"{DEFAULT}/{self.next_number}"
        self.next_number += 1
        self.items[path] = secret
        return path

    async def get_property(self, path: str, interface: str, name: str) -> int:
        del path, interface
        assert name == "Created"
        return SAME_SECOND

    async def get_secrets(self, items: list[str]) -> dict[str, bytes]:
        return {path: self.items[path] for path in items}


async def test_second_racer_in_the_same_second_gets_the_first_key() -> None:
    client = RacingClient()
    first = await _app_secret(client, "state-db", 32)  # type: ignore[arg-type]
    # The second racer searched before the first item existed, so it creates ".../10".
    await client.create_item(
        DEFAULT, "", {}, b"\x01" * 32, replace=False, content_type="application/octet-stream"
    )
    second = await _app_secret(client, "state-db", 32)  # type: ignore[arg-type]
    assert sorted(client.items) == [f"{DEFAULT}/10", f"{DEFAULT}/9"]
    assert second == first == client.items[f"{DEFAULT}/9"]

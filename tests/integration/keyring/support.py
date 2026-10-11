# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Helpers shared by the keyring integration tests."""

from __future__ import annotations

import os
import signal
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from passwords_app.core.model import Credential
from passwords_app.keyring.client import COLLECTION, ITEM, SecretServiceClient

if TYPE_CHECKING:
    from collections.abc import Mapping

T0 = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
T1 = datetime(2026, 6, 7, 8, 9, 10, 123456, tzinfo=UTC)
NOTE_SCHEMA = "org.gnome.keyring.Note"


def cred(n: int = 1, *, pw: str | None = None, **changes: object) -> Credential:
    """Credential number `n`; `pw` overrides the (fake) password."""
    base = Credential(
        id=f"00000000-0000-4000-8000-{n:012d}",
        url=f"https://site{n}.example.com",
        username=f"user{n}",
        password=f"FAKE-PW-{n}" if pw is None else pw,
        created=T0,
        modified=T1,
    )
    return replace(base, **changes)  # type: ignore[arg-type]


async def raw_item(client: SecretServiceClient, path: str) -> tuple[str, dict[str, str], bytes]:
    """(label, attributes, secret) exactly as stored."""
    props = await client.get_all(path, ITEM)
    secrets = await client.get_secrets([path])
    return str(props["Label"]), dict(props["Attributes"]), secrets[path]


async def items_of(client: SecretServiceClient, collection: str) -> list[str]:
    return list(await client.get_property(collection, COLLECTION, "Items"))


async def seahorse_create(
    client: SecretServiceClient,
    collection: str,
    label: str,
    value: str = "FAKE-SEAHORSE",
    attributes: Mapping[str, str] | None = None,
) -> str:
    """Create an item the way Seahorse's "New password" does: a Note with just a label."""
    return await client.create_item(
        collection,
        label,
        {"xdg:schema": NOTE_SCHEMA, **(attributes or {})},
        value.encode(),
        replace=False,
    )


def kill_keyring_daemon(root: Path) -> None:
    """Stop the sandbox's gnome-keyring-daemon (found by its sandbox environment)."""
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            comm = (proc / "comm").read_text().strip()
            environ = (proc / "environ").read_bytes()
        except OSError:
            continue
        if comm.startswith("gnome-keyring") and f"XDG_RUNTIME_DIR={root}/".encode() in environ:
            os.kill(int(proc.name), signal.SIGKILL)
            return
    msg = "sandbox gnome-keyring-daemon not found"
    raise AssertionError(msg)

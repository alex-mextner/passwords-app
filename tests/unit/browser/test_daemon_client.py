# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
from __future__ import annotations

from typing import TYPE_CHECKING, override

import pytest
from dbus_fast import Variant

from passwords_app.browser.daemon import (
    BUS_NAME,
    INTERFACE,
    OBJECT_PATH,
    DaemonClient,
    error_code,
    session_bus_address,
)
from passwords_app.browser.protocol import ProtocolError

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from passwords_app.browser.protocol import ErrorCode


def test_names_match_the_dbus_contract() -> None:
    assert BUS_NAME == "io.github.alex_mextner.Passwords"
    assert OBJECT_PATH == "/io/github/alex_mextner/Passwords"
    assert INTERFACE == "io.github.alex_mextner.Passwords1"


@pytest.mark.parametrize(
    ("name", "code"),
    [
        ("io.github.alex_mextner.Passwords1.Error.NotFound", "not-found"),
        ("io.github.alex_mextner.Passwords1.Error.Invalid", "invalid"),
        ("io.github.alex_mextner.Passwords1.Error.Unavailable", "unavailable"),
        ("io.github.alex_mextner.Passwords1.Error.AuthRequired", "auth-required"),
        ("io.github.alex_mextner.Passwords1.Error.Locked", "locked"),
        ("org.freedesktop.DBus.Error.ServiceUnknown", "daemon-unavailable"),
        ("org.freedesktop.DBus.Error.NameHasNoOwner", "daemon-unavailable"),
        ("org.freedesktop.DBus.Error.NoReply", "daemon-unavailable"),
        ("org.freedesktop.DBus.Error.Disconnected", "daemon-unavailable"),
        ("org.freedesktop.DBus.Error.Timeout", "daemon-unavailable"),
        ("org.freedesktop.DBus.Error.TimedOut", "daemon-unavailable"),
        ("org.freedesktop.DBus.Error.NoServer", "daemon-unavailable"),
        ("org.freedesktop.DBus.Error.SpawnFailed", "daemon-unavailable"),
        # Errors the browser methods never raise, or a daemon newer than this host:
        ("io.github.alex_mextner.Passwords1.Error.WrongCode", "internal"),
        ("io.github.alex_mextner.Passwords1.Error.WrongPasscode", "internal"),
        ("io.github.alex_mextner.Passwords1.Error.Whatever", "internal"),
        ("org.freedesktop.DBus.Error.UnknownMethod", "internal"),
        ("org.freedesktop.DBus.Error.InvalidArgs", "internal"),
        ("org.freedesktop.DBus.Error.AccessDenied", "internal"),
        ("NotFound", "internal"),  # only the full name counts
        ("", "internal"),
    ],
)
def test_error_mapping(name: str, code: ErrorCode) -> None:
    assert error_code(name) == code


def test_bus_address_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/tmp/test-bus.example")
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/4242")
    assert session_bus_address() == "unix:path=/tmp/test-bus.example"


def test_bus_address_falls_back_to_runtime_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/4242")
    assert session_bus_address() == "unix:path=/run/user/4242/bus"


def test_bus_address_is_read_at_call_time(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/tmp/first.example")
    assert session_bus_address() == "unix:path=/tmp/first.example"
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/tmp/second.example")
    assert session_bus_address() == "unix:path=/tmp/second.example"


def test_no_bus_address_at_all(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    assert session_bus_address() is None


async def unavailable(client: DaemonClient) -> ProtocolError:
    with pytest.raises(ProtocolError) as caught:
        await client.status()
    await client.close()
    return caught.value


@pytest.mark.timeout(10)
async def test_missing_bus_is_daemon_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    error = await unavailable(DaemonClient())
    assert error.code == "daemon-unavailable"


@pytest.mark.timeout(10)
async def test_absent_socket_is_daemon_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", f"unix:path={tmp_path}/no-bus")
    error = await unavailable(DaemonClient())
    assert error.code == "daemon-unavailable"


@pytest.mark.timeout(10)
async def test_garbage_address_is_daemon_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "this is not an address")
    error = await unavailable(DaemonClient())
    assert error.code == "daemon-unavailable"


@pytest.mark.timeout(10)
async def test_socket_that_never_answers_times_out(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import socket  # noqa: PLC0415 - only this test needs a listening socket

    path = tmp_path / "silent-bus"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        server.listen(1)
        monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", f"unix:path={path}")
        error = await unavailable(DaemonClient(connect_timeout=0.3))
    assert error.code == "daemon-unavailable"
    assert "timed out" in error.message


class CannedReply(DaemonClient):
    """Answers every D-Bus call with one fixed body, bypassing the bus."""

    def __init__(self, body: Sequence[object]) -> None:
        super().__init__()
        self.body = list(body)

    @override
    async def _call(
        self, member: str, signature: str = "", body: Sequence[object] = ()
    ) -> list[object]:
        return self.body


def _item(**fields: Variant) -> dict[str, Variant]:
    return {"id": Variant("s", "item-1"), **fields}


async def test_well_formed_match_reply_is_parsed() -> None:
    item = _item(
        username=Variant("s", "alice"),
        alt_urls=Variant("as", ["https://b.example"]),
        has_code=Variant("b", True),  # noqa: FBT003 - D-Bus boolean
    )
    [candidate] = await CannedReply([[item]]).match("https://a.example")
    assert candidate.id == "item-1"
    assert candidate.username == "alice"
    assert candidate.alt_urls == ("https://b.example",)
    assert candidate.has_code is True


@pytest.mark.parametrize(
    "body",
    [
        [],
        ["not a list"],
        [[{"username": Variant("s", "no id")}]],
        [[_item(username=Variant("i", 7))]],
        [[_item(alt_urls=Variant("ai", [1]))]],
        [[{"id": "not a variant"}]],
    ],
    ids=["empty", "not-list", "no-id", "wrong-type", "alt-url-type", "bare-value"],
)
async def test_malformed_match_reply_is_internal(body: list[object]) -> None:
    with pytest.raises(ProtocolError) as error:
        await CannedReply(body).match("https://a.example")
    assert error.value.code == "internal"


@pytest.mark.parametrize("body", [[], ["123456"], [123456, 30], ["123456", "30"], ["123456", True]])
async def test_malformed_code_reply_is_internal(body: list[object]) -> None:
    with pytest.raises(ProtocolError) as error:
        await CannedReply(body).code("item-1")
    assert error.value.code == "internal"


async def test_status_with_string_item_count_is_internal() -> None:
    reply = [{"state": Variant("s", "ready"), "item_count": Variant("s", "3")}]
    with pytest.raises(ProtocolError) as error:
        await CannedReply(reply).status()
    assert error.value.code == "internal"

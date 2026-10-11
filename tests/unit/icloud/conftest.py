# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Fixtures shared by the iCloud client tests."""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING

import pytest
from tests.fakes.cloudkit_server import FakeCloudKit
from tests.fakes.icloud_session import DEVICE, make_session
from tests.unit.icloud.tls_server import HttpsServer, Pki, Route, build_pki, serve

from passwords_app.icloud.account import connect_keychain
from passwords_app.icloud.auth import session as sess
from passwords_app.icloud.keychain.zones import ZoneCache

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from http.server import ThreadingHTTPServer
    from pathlib import Path

    from passwords_app.icloud.keychain.client import KeychainClient


class NoAnisette:
    def headers(self) -> dict[str, str]:
        return {"X-Apple-I-MD": "md", "X-Apple-I-MD-M": "mdm"}


@pytest.fixture
def fake() -> Iterator[FakeCloudKit]:
    with FakeCloudKit() as server:
        yield server


@pytest.fixture
def session(fake: FakeCloudKit) -> dict[str, object]:
    return make_session(fake)


@pytest.fixture
def open_keychain(session: dict[str, object], tmp_path: Path) -> Callable[[], KeychainClient]:
    """Open a fresh client on the same session and cache file (a new process, in effect)."""
    cache_path = tmp_path / "zones.json"

    def open_() -> KeychainClient:
        return connect_keychain(session, DEVICE, NoAnisette(), ZoneCache(cache_path))

    return open_


@pytest.fixture
def keychain(open_keychain: Callable[[], KeychainClient]) -> KeychainClient:
    return open_keychain()


_LOCAL_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


@pytest.fixture(autouse=True)
def _no_internet(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any test that tries to resolve a real host: no test may ever reach Apple."""
    real = socket.getaddrinfo

    def local_only(host: str | bytes | None, *args: object, **kwargs: object) -> object:
        name = host.decode() if isinstance(host, bytes) else host
        if name not in _LOCAL_HOSTS:
            msg = f"test tried to reach {name!r}; only localhost is allowed"
            raise AssertionError(msg)
        return real(host, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(socket, "getaddrinfo", local_only)


@pytest.fixture(autouse=True)
def _no_real_keyring(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Keep every test off the owner's login keyring and config directory.

    The Secret Service lookup is replaced, the session bus address points nowhere, and the
    default config directory is a temporary one.
    """

    def refuse() -> None:
        msg = "a test tried to open the real login keyring"
        raise AssertionError(msg)

    monkeypatch.setattr(sess, "_default_collection", refuse)
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/passwords-app-test-bus")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path_factory.mktemp("xdg-config")))
    sess.forget_cached_keys()


@pytest.fixture(scope="session")
def pki(tmp_path_factory: pytest.TempPathFactory) -> Pki:
    return build_pki(tmp_path_factory.mktemp("pki"))


@pytest.fixture
def https_server(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Callable[[Route], HttpsServer]]:
    """Start local HTTPS servers answering through a route function; all stop at teardown."""
    servers: list[ThreadingHTTPServer] = []
    # A proxy or CA override in the developer's environment would skew what is trusted.
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
    monkeypatch.delenv("CURL_CA_BUNDLE", raising=False)

    def start(route: Route) -> HttpsServer:
        server, handle = serve(pki, route)
        servers.append(server)
        return handle

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()

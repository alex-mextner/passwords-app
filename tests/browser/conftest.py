# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Fixtures for the browser tests: fixture web server, seeded FakeDaemon, real browsers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest
from tests.browser.e2e_support import (
    FABRIKAM,
    NORTHWIND,
    ChromiumSession,
    FirefoxSession,
    SiteServer,
)
from tests.fakes.fake_daemon import FakeDaemon, FakeDaemonThread
from tests.harness.dbus_session import private_bus, private_session

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

__all__ = ["chromium", "daemon", "firefox", "private_bus", "private_session", "site", "vault"]

# Fictional logins; the seed is RFC 6238's documentation example, not anyone's account.
OTP_SEED: Final = "JBSWY3DPEHPK3PXP"
ALEX = ("alex.doe@example.com", "nw-Fictional-Pass-1")
OPS = ("ops@example.com", "nw-Fictional-Pass-2")
SAM = ("sam@example.com", "fb-Old-Fictional-3")


class Vault:
    """Ids and credentials of the items the FakeDaemon starts with, for assertions."""

    def __init__(self, daemon: FakeDaemonThread, site: SiteServer) -> None:
        self.daemon = daemon
        self.northwind = site.origin(NORTHWIND)
        self.fabrikam = site.origin(FABRIKAM)
        self.alex = daemon.call(
            lambda d: d.add_item(
                self.northwind,
                *ALEX,
                title="Northwind",
                otpauth=f"otpauth://totp/Northwind:alex?secret={OTP_SEED}&issuer=Northwind",
            )
        )
        self.ops = daemon.call(lambda d: d.add_item(self.northwind, *OPS, title="Northwind Ops"))
        self.sam = daemon.call(lambda d: d.add_item(self.fabrikam, *SAM, title="Fabrikam"))

    def items(self) -> list[tuple[str, str, str, str]]:
        """(url, username, password, id) of every item, as the daemon holds them now."""
        return self.daemon.call(
            lambda d: [(c.url, c.username, c.password, c.id) for c in d.items.values()]
        )

    def calls(self) -> list[str]:
        return self.daemon.call(lambda d: list(d.calls))


@pytest.fixture(scope="session")
def site(tmp_path_factory: pytest.TempPathFactory) -> Iterator[SiteServer]:
    with SiteServer(tmp_path_factory.mktemp("site")) as server:
        yield server


@pytest.fixture
def daemon(private_bus: str) -> Iterator[FakeDaemonThread]:
    with FakeDaemonThread(
        private_bus, FakeDaemon(state="idle", apple_id="alex.doe@example.com")
    ) as thread:
        yield thread


@pytest.fixture
def vault(daemon: FakeDaemonThread, site: SiteServer) -> Vault:
    return Vault(daemon, site)


@pytest.fixture
def firefox(
    tmp_path: Path, private_bus: str, site: SiteServer, vault: Vault
) -> Iterator[FirefoxSession]:
    del vault  # seeded before the browser can ask
    session = FirefoxSession(tmp_path / "home", private_bus, site)
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def chromium(
    tmp_path: Path, private_bus: str, site: SiteServer, vault: Vault
) -> Iterator[ChromiumSession]:
    del vault
    session = ChromiumSession(tmp_path / "home", private_bus, site)
    try:
        yield session
    finally:
        session.close()

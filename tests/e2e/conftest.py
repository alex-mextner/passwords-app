# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Fixtures for the end-to-end scenarios (spec §11): one `stack` per test.

`stack` (tests/e2e/stack.py) is the whole product on a throwaway desktop: private bus and
keyring, fake iCloud seeded with `data.seed`, the account signed in, the real daemon synced.
A test changes that start with `@pytest.mark.stack(seed=False, signed_in=False, daemon=False)`.
The GTK app (`stack.app`) and the browsers (`stack.firefox`, `stack.chromium`) start on first
use; the headless gnome-shell behind the app is shared by the session (`desktop`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from tests.browser.e2e_support import SiteServer
from tests.e2e.data import seed
from tests.e2e.stack import running_stack
from tests.gui import support

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from tests.e2e.stack import Stack

# Runs at collection, before anything in this process can import Gtk.
support.safe_environment()


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "stack(seed, signed_in, daemon): how the e2e `stack` fixture starts"
    )


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if "tests/e2e/" in str(item.path).replace("\\", "/"):
            item.add_marker(pytest.mark.e2e)
            # One machine-wide gnome-shell at a time: keep the scenarios on one worker.
            item.add_marker(pytest.mark.xdist_group("gnome-shell"))
            # PyGObject's main-loop override touches asyncio policy APIs Python 3.14
            # deprecates; that is the library's concern, not a defect in the app.
            item.add_marker(
                pytest.mark.filterwarnings(
                    r"ignore:'asyncio\.\w+' is deprecated:DeprecationWarning"
                )
            )


@pytest.fixture(scope="session")
def site(tmp_path_factory: pytest.TempPathFactory) -> Iterator[SiteServer]:
    """Every fictional website, on one loopback port (see tests/browser/e2e_support.py)."""
    with SiteServer(tmp_path_factory.mktemp("site")) as server:
        yield server


@pytest.fixture(scope="session")
def desktop(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Any]:
    """A private headless gnome-shell with the app registered, drawn by this process."""
    from tests.e2e.desktop import Desktop  # noqa: PLC0415

    base = tmp_path_factory.mktemp("desktop")
    schemas = support.compile_schemas(base / "schemas")
    locales = support.compile_catalogs(base / "locale")
    with support.app_shell_session("1440x900") as shell:
        support.add_virtual_keyboard(shell)
        support.point_process_at(shell, schemas, locales)
        support.import_gtk()
        from gi.repository import Gio  # noqa: PLC0415

        from passwords_app.app.ui.application import (  # noqa: PLC0415
            PasswordsApplication,
            make_settings,
        )

        application = PasswordsApplication(settings=make_settings(), lock_probe=False)
        application._connection = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        application.register(None)
        application.detach()
        yield Desktop(shell, application)
        application.detach()


@pytest.fixture
def stack(request: pytest.FixtureRequest, site: SiteServer, tmp_path: Path) -> Iterator[Stack]:
    marker = request.node.get_closest_marker("stack")
    options = {"seed": True, "signed_in": True, "daemon": True, **(marker.kwargs if marker else {})}
    with running_stack(tmp_path, request) as built:
        if options["seed"]:
            built.seeded = seed(site)
            for cred in built.seeded.values():
                built.apple.create(cred)
        if options["signed_in"]:
            built.sign_in()
        if options["daemon"]:
            built.start_daemon(wait_synced=bool(options["signed_in"]))
        yield built

# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Fixtures: one headless GNOME Shell per worker, one fresh app window per test."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest
from tests.gui import support

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

# Runs at collection, before any test in this process can import Gtk.
support.safe_environment()


# tryfirst: xdist's loadgroup reads the xdist_group marker in its own modifyitems hook.
@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    # Sessions are serialized machine-wide; keep every GUI test on one xdist worker.
    for item in items:
        if "tests/gui/" in str(item.path).replace("\\", "/"):
            item.add_marker(pytest.mark.gui)
            item.add_marker(pytest.mark.xdist_group("gnome-shell"))
            # PyGObject's main-loop override touches asyncio policy APIs that Python 3.14
            # deprecates; that is the library's concern, not a defect in the app.
            item.add_marker(
                pytest.mark.filterwarnings(
                    r"ignore:'asyncio\.\w+' is deprecated:DeprecationWarning"
                )
            )


@pytest.fixture(scope="session")
def shell(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Any]:
    base = tmp_path_factory.mktemp("gui")
    schemas = support.compile_schemas(base / "schemas")
    locales = support.compile_catalogs(base / "locale")
    with support.app_shell_session("1440x900") as session:
        support.add_virtual_keyboard(session)
        support.point_process_at(session, schemas, locales)
        support.import_gtk()
        yield session


@pytest.fixture(scope="session")
def application(shell: Any) -> Iterator[Any]:
    from gi.repository import Gio  # noqa: PLC0415

    from passwords_app.app.ui.application import PasswordsApplication, make_settings  # noqa: PLC0415

    app = PasswordsApplication(settings=make_settings(), lock_probe=False)
    connection = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    app._connection = connection
    # register() runs startup, which attaches to the bus; tests re-attach per test.
    app.register(None)
    app.detach()
    yield app
    app.detach()


@pytest.fixture
def lang() -> str:
    return "en"


@pytest.fixture
def daemon_factory() -> Any:
    """Override in a test module to seed the fake differently."""
    from tests.fakes.fake_daemon import FakeDaemon  # noqa: PLC0415

    return lambda: FakeDaemon.demo(datetime.now(UTC))


@pytest.fixture
def app(
    shell: Any,
    application: Any,
    daemon_factory: Any,
    lang: str,
    tmp_path: Path,
) -> Iterator[support.AppUnderTest]:
    from gi.repository import Adw, Gio  # noqa: PLC0415
    from tests.fakes.fake_daemon import FakeDaemonThread  # noqa: PLC0415

    from passwords_app.app import i18n  # noqa: PLC0415
    from passwords_app.app.ui.application import settings_schema_source  # noqa: PLC0415

    i18n.setup([lang])
    source = settings_schema_source()
    assert source is not None
    schema = source.lookup(support.APP_ID, True)  # noqa: FBT003
    assert schema is not None
    settings = Gio.Settings.new_full(schema, Gio.memory_settings_backend_new(), None)
    authorizations: list[bool] = []

    def authorizer(done: Any) -> None:
        done(authorizations.pop(0) if authorizations else False)

    connection = Gio.DBusConnection.new_for_address_sync(
        shell.bus_address,
        Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT
        | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
        None,
        None,
    )
    Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_LIGHT)
    with FakeDaemonThread(shell.bus_address, daemon_factory()) as fake:
        application._connection = connection
        application._settings = settings
        application._authorizer = authorizer
        application.attach()
        window = application.ensure_window()
        window.present()
        under_test = support.AppUnderTest(application, window, fake, settings, authorizations)
        try:
            support.wait_until(window.get_mapped, what="window mapped")
            yield under_test
        finally:
            # Drop keyboard focus and let the compositor's leave/text-input events arrive
            # while the widgets still exist; destroying a focused entry first lets a late
            # Wayland event reach a freed widget inside GTK.
            window.set_focus(None)
            support.pump(0.2)
            application.detach()
            support.pump(0.05)
            connection.close_sync(None)
    i18n.setup(["en"])

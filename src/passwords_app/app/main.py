# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Entry point of the Passwords app (`passwords-app` with no subcommand)."""

from __future__ import annotations

import contextlib
import locale
import sys

from passwords_app.app import i18n


def main(argv: list[str] | None = None) -> int:
    """Run the app; returns the process exit status."""
    # An unsupported LANG falls back to the C locale, like any GTK app.
    with contextlib.suppress(locale.Error):
        locale.setlocale(locale.LC_ALL, "")
    i18n.setup()
    import gi  # noqa: PLC0415 - Gtk connects to the display on import; only the GUI path needs it

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from passwords_app.app.ui.application import PasswordsApplication  # noqa: PLC0415

    app = PasswordsApplication()
    return app.run(sys.argv if argv is None else argv)


if __name__ == "__main__":
    sys.exit(main())

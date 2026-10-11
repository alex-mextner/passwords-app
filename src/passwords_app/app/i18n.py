# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""gettext for the app (domain ``passwords-app``).

Strings are translated in Python rather than by GTK, so one translation object serves every
widget; `setup()` swaps it, which is how tests render the UI in Russian without restarting.
"""

from __future__ import annotations

import gettext
import os
import sys
from pathlib import Path

from passwords_app.app.constants import GETTEXT_DOMAIN

LOCALEDIR_ENV = "PASSWORDS_APP_LOCALEDIR"

_translation: gettext.NullTranslations = gettext.NullTranslations()


def locale_dir() -> Path | None:
    """Where compiled catalogs live: the env override, the venv/prefix, or the system default."""
    override = os.environ.get(LOCALEDIR_ENV)
    if override:
        return Path(override)
    prefixed = Path(sys.prefix) / "share" / "locale"
    if any(prefixed.glob(f"*/LC_MESSAGES/{GETTEXT_DOMAIN}.mo")):
        return prefixed
    return None


def setup(languages: list[str] | None = None) -> None:
    """Load the catalog for `languages` (default: from LANGUAGE/LC_ALL/LC_MESSAGES/LANG)."""
    global _translation  # noqa: PLW0603 - one process-wide catalog, swapped by tests
    directory = locale_dir()
    _translation = gettext.translation(
        GETTEXT_DOMAIN,
        localedir=str(directory) if directory else None,
        languages=languages,
        fallback=True,
    )


def _(message: str) -> str:
    return _translation.gettext(message)


def ngettext(singular: str, plural: str, n: int) -> str:
    return _translation.ngettext(singular, plural, n)


def pgettext(context: str, message: str) -> str:
    return _translation.pgettext(context, message)


def is_translated() -> bool:
    """Tell whether a real catalog (not the English fallback) is active."""
    return type(_translation) is not gettext.NullTranslations

# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Identifiers shared by the app, its data files and its tests."""

from __future__ import annotations

from typing import Final

APP_ID: Final = "io.github.alex_mextner.Passwords"
GETTEXT_DOMAIN: Final = "passwords-app"

DAEMON_BUS_NAME: Final = "io.github.alex_mextner.Passwords"
DAEMON_OBJECT_PATH: Final = "/io/github/alex_mextner/Passwords"
DAEMON_INTERFACE: Final = "io.github.alex_mextner.Passwords1"
DAEMON_ERROR_PREFIX: Final = "io.github.alex_mextner.Passwords1.Error."

# The daemon owns APP_ID as its bus name, so the GApplication runs NON_UNIQUE and the app
# claims this separate name for single-instance activation and the Shell search provider.
APP_BUS_NAME: Final = "io.github.alex_mextner.Passwords.App"
APP_OBJECT_PATH: Final = "/io/github/alex_mextner/Passwords/App"
SEARCH_PROVIDER_PATH: Final = "/io/github/alex_mextner/Passwords/SearchProvider"

POLKIT_UNLOCK_ACTION: Final = "io.github.alex_mextner.Passwords.unlock"

# Daemon-side retention (spec §5); shown read-only in Preferences.
TRASH_RETENTION_DAYS: Final = 90

# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""GTK4 + libadwaita Passwords app; a pure D-Bus client of passwords-appd.

Modules at this level never import Gtk: importing Gtk opens a display, and unit tests must
never reach the developer's real desktop. Widgets live in `passwords_app.app.ui`.
"""

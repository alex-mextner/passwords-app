# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Certificate trust for Apple endpoints.

gsa.apple.com chains to Apple's own root, which public trust stores do not ship, so GrandSlam
calls verify against the bundled Apple roots - and only those, which also pins that host to
Apple's PKI. Every other Apple host (setup, gateway, escrowproxy) chains to a public root and
uses the default trust store. Verification is never turned off.
"""

from __future__ import annotations

from importlib import resources

_BUNDLE = resources.files(__package__) / "certs" / "apple-roots.pem"


def apple_ca_bundle() -> str:
    """Return the filesystem path of the Apple root certificates (for `requests`' `verify=`)."""
    # The wheel installs package data as plain files, so the traversable is a real path.
    return str(_BUNDLE)

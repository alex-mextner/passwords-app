# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Merged device + anisette request headers, shared by every Apple auth call.

Device identity first, anisette machine data second, so anisette wins on the volatile
X-Apple-I-MD* fields - the order GSA, loginDelegates and account-settings all rely on.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from passwords_app.icloud.auth.anisette import AnisetteSource
    from passwords_app.icloud.auth.device import Device


def identity_headers(device: Device, anisette: AnisetteSource) -> dict[str, str]:
    headers = dict(device.meta_headers())  # never mutate whatever the device hands out
    headers.update(anisette.headers())
    return headers

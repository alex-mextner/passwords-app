# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""otpauth URIs for tests, built from the RFC 6238 test seed rather than spelled out inline."""

from __future__ import annotations

import base64
from urllib.parse import quote, urlencode

# RFC 6238 appendix B SHA-1 seed; public test vector, not a credential.
RFC_SEED = base64.b32encode(b"12345678901234567890").decode()


def otpauth_uri(
    label: str = "Example:alice", *, kind: str = "totp", seed: str | None = RFC_SEED, **params: str
) -> str:
    query = {} if seed is None else {"secret": seed}
    query.update(params)
    return f"otpauth://{kind}/{quote(label)}?{urlencode(query)}"

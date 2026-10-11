# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Typed reads from decoded plists and JSON, whose shape the server controls.

Apple's answers are dictionaries of anything; a field of the wrong type must read as missing
instead of raising `AttributeError` deep inside a caller, and the type checker needs one
place that turns `object` into concrete types.
"""

from __future__ import annotations

import plistlib
from typing import TypeIs, cast
from xml.parsers.expat import ExpatError

Record = dict[str, object]

# Everything `plistlib.loads` raises on a malformed body. Truncated XML surfaces as expat's
# own error, which is not a ValueError, so catching only the first two lets it escape.
PLIST_ERRORS = (plistlib.InvalidFileException, ValueError, ExpatError)


def is_dict(value: object) -> TypeIs[dict[object, object]]:
    """Tell whether `value` is a dictionary, keeping its contents typed as `object`."""
    return isinstance(value, dict)


def mapping(value: object) -> Record:
    """`value` as a string-keyed dictionary, or an empty one if it is anything else."""
    if is_dict(value):
        return {str(k): v for k, v in value.items()}
    return {}


def child(record: Record, key: str) -> Record:
    return mapping(record.get(key))


def text(record: Record, key: str) -> str | None:
    value = record.get(key)
    return value if isinstance(value, str) else None


def blob(record: Record, key: str) -> bytes | None:
    value = record.get(key)
    return bytes(value) if isinstance(value, (bytes, bytearray)) else None


def integer(record: Record, key: str) -> int | None:
    value = record.get(key)
    # bool is an int subclass; a flag is never a count or an id.
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def items(value: object) -> list[object]:
    """`value` as a list, or an empty one if it is anything else."""
    return list(cast("list[object]", value)) if isinstance(value, list) else []

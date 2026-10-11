# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The saved keyring properties read back exactly, and a damaged row is dropped whole (#64)."""

from __future__ import annotations

import json

import pytest

from passwords_app.keyring.secret_service import (
    _decode_saved,  # pyright: ignore[reportPrivateUsage]
    _encode_saved,  # pyright: ignore[reportPrivateUsage]
    _Properties,  # pyright: ignore[reportPrivateUsage]
)

ITEM = "/org/freedesktop/secrets/collection/iCloud_20Passwords/7"
KNOWN = {
    ITEM: _Properties("Work VPN \u2014 alice", {"pa-id": "X", "url": "ü.example"}, 1_700_000, 9),
    f"{ITEM}0": _Properties("Note", {}, None, 10),
}


def test_saved_properties_read_back_exactly() -> None:
    assert _decode_saved(_encode_saved(KNOWN, 42)) == (KNOWN, 42)


def test_an_empty_cache_keeps_its_second() -> None:
    assert _decode_saved(_encode_saved({}, 42)) == ({}, 42)


def entry(**changes: object) -> list[object]:
    fields: dict[str, object] = {
        "label": "L",
        "attributes": {"a": "b"},
        "created": None,
        "modified": 9,
    }
    fields.update(changes)
    return list(fields.values())


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        "not json",
        "[]",
        json.dumps({"version": 2, "since": 1, "items": {}}),
        json.dumps({"version": 1, "since": "1", "items": {}}),
        json.dumps({"version": 1, "since": 1, "items": []}),
        json.dumps({"version": 1, "since": 1, "items": {ITEM: entry()[:3]}}),
        json.dumps({"version": 1, "since": 1, "items": {ITEM: entry(label=5)}}),
        json.dumps({"version": 1, "since": 1, "items": {ITEM: entry(attributes={"a": 1})}}),
        json.dumps({"version": 1, "since": 1, "items": {ITEM: entry(attributes=["a"])}}),
        json.dumps({"version": 1, "since": 1, "items": {ITEM: entry(created="x")}}),
        json.dumps({"version": 1, "since": 1, "items": {ITEM: entry(modified=None)}}),
        json.dumps({"version": 1, "since": 1, "items": {ITEM: entry(), "x": "y"}}),
    ],
)
def test_unusable_saved_properties_are_dropped_whole(raw: str | None) -> None:
    assert _decode_saved(raw) == ({}, 0)

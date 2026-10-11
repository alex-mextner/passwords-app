# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""NSKeyedArchiver expansion of TLK share ciphertexts."""

from __future__ import annotations

import plistlib

import pytest
from tests.fakes.cloudkit_server import keyed_archive

from passwords_app.icloud.keychain import nska


def _archive(objects: list[object], root: int = 1) -> bytes:
    return plistlib.dumps(
        {"$archiver": "NSKeyedArchiver", "$top": {"root": plistlib.UID(root)}, "$objects": objects},
        fmt=plistlib.FMT_BINARY,
    )


def _nsdata_archive(values: dict[str, bytes]) -> bytes:
    """Each value archived as an NSMutableData object, as Apple stores the ephemeral key."""
    objects: list[object] = ["$null"]

    def add(o: object) -> plistlib.UID:
        objects.append(o)
        return plistlib.UID(len(objects) - 1)

    cls = add({"$classname": "NSMutableData", "$classes": ["NSMutableData", "NSData", "NSObject"]})
    top: dict[str, object] = {}
    for k, v in values.items():
        top[k] = add({"$class": cls, "NS.data": add(v)})
    root = add(top)
    return _archive(objects, root.data)


def test_unwraps_nsdata_objects_to_bytes() -> None:
    out = nska.expand(_nsdata_archive({"SFIESAuthenticationCode": b"\x11" * 16, "K": b"\x04"}))
    assert out == {"SFIESAuthenticationCode": b"\x11" * 16, "K": b"\x04"}


def test_plain_dictionary_is_left_as_is() -> None:
    assert nska.expand(_archive(["$null", {"hello": "world"}])) == {"hello": "world"}


def test_null_reference_becomes_none() -> None:
    assert nska.expand(_archive(["$null", {"a": plistlib.UID(0)}])) == {"a": None}


def test_nsstring_and_array_unwrap() -> None:
    objects: list[object] = [
        "$null",
        {"s": plistlib.UID(2), "l": plistlib.UID(3)},
        {"$class": plistlib.UID(4), "NS.string": "text"},
        {"$class": plistlib.UID(4), "NS.objects": [plistlib.UID(5)]},
        {"$classname": "X"},
        b"item",
    ]
    assert nska.expand(_archive(objects)) == {"s": "text", "l": [b"item"]}


def test_fake_share_archive_expands() -> None:
    assert nska.expand(keyed_archive({"A": b"1", "B": b"2"})) == {"A": b"1", "B": b"2"}


@pytest.mark.parametrize(
    "data",
    [
        b"not a plist",
        plistlib.dumps([1, 2]),
        plistlib.dumps({"$objects": "x", "$top": {}}),
        _archive(["$null", "a string root"]),
    ],
)
def test_malformed_archives_raise(data: bytes) -> None:
    with pytest.raises(nska.ArchiveError):
        nska.expand(data)


def test_dangling_reference_raises() -> None:
    with pytest.raises(nska.ArchiveError, match="out of range"):
        nska.expand(_archive(["$null", {"a": plistlib.UID(9)}]))


def test_reference_cycle_raises_instead_of_recursing() -> None:
    with pytest.raises(nska.ArchiveError, match="deeply"):
        nska.expand(_archive(["$null", {"self": plistlib.UID(1)}]))


def test_shared_reference_fan_out_is_cut_off() -> None:
    # 31 objects each pointing twice at the next stay under the depth cap but expand to 2^31.
    objects: list[object] = ["$null"]
    objects += [{"a": plistlib.UID(k + 1), "b": plistlib.UID(k + 1)} for k in range(1, 31)]
    objects.append("leaf")
    with pytest.raises(nska.ArchiveError, match="too many objects"):
        nska.expand(_archive(objects))


def test_non_string_object_key_is_an_archive_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # plistlib refuses to write such a key, but a binary plist from the wire can hold one.
    archive: dict[str, object] = {"$top": {"root": plistlib.UID(1)}, "$objects": ["$null", {1: 0}]}

    def loads(_data: bytes, **_kw: object) -> object:
        return archive

    monkeypatch.setattr(nska.plistlib, "loads", loads)
    with pytest.raises(nska.ArchiveError, match="not a string"):
        nska.expand(b"ignored")

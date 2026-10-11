# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Minimal NSKeyedArchiver expander for the `IESCiphertext` inside a TLKShare.

Resolves the archive's `plistlib.UID` object graph into plain Python and unwraps the
Foundation containers (NSData, NSString, NSArray) to their payloads.
"""

from __future__ import annotations

import plistlib
from typing import cast

from passwords_app.icloud.values import PLIST_ERRORS

_MAX_DEPTH = 64  # archives here are a few levels deep; a cycle must not recurse forever
_MAX_NODES = 100_000  # a TLK share expands to a few dozen nodes


class ArchiveError(ValueError):
    """The bytes are not a keyed archive this expander understands."""


def expand(data: bytes) -> dict[str, object]:
    """Expand an NSKeyedArchiver bplist whose root is an object into a dictionary."""
    try:
        plist = plistlib.loads(data)
    except PLIST_ERRORS as e:
        msg = "not a property list"
        raise ArchiveError(msg) from e
    if not isinstance(plist, dict):
        msg = "not a keyed archive"
        raise ArchiveError(msg)
    archive = cast("dict[str, object]", plist)
    objects = archive.get("$objects")
    top = archive.get("$top")
    if not isinstance(objects, list) or not isinstance(top, dict):
        msg = "not a keyed archive"
        raise ArchiveError(msg)
    resolver = _Resolver(cast("list[object]", objects))
    top_dict = cast("dict[str, object]", top)
    root = resolver.resolve(top_dict.get("root", top_dict), 0)
    if not isinstance(root, dict):
        msg = "archive root is not an object"
        raise ArchiveError(msg)
    return cast("dict[str, object]", root)


class _Resolver:
    def __init__(self, objects: list[object]) -> None:
        self.objects = objects
        self.budget = _MAX_NODES

    def _step(self, depth: int) -> None:
        if depth > _MAX_DEPTH:
            msg = "archive nests too deeply"
            raise ArchiveError(msg)
        # Shared references re-expand on every use, so a small archive of objects that each
        # point twice at the next can demand billions of steps without ever nesting deeply.
        self.budget -= 1
        if self.budget < 0:
            msg = "archive expands to too many objects"
            raise ArchiveError(msg)

    def resolve(self, node: object, depth: int) -> object:
        self._step(depth)
        if isinstance(node, plistlib.UID):
            return self._dereference(node, depth)
        if node == "$null":
            return None
        if isinstance(node, dict):
            return self._resolve_object(cast("dict[object, object]", node), depth)
        if isinstance(node, list):
            return [self.resolve(v, depth + 1) for v in cast("list[object]", node)]
        return node

    def _dereference(self, uid: plistlib.UID, depth: int) -> object:
        if not 0 <= uid.data < len(self.objects):
            msg = "archive reference out of range"
            raise ArchiveError(msg)
        return self.resolve(self.objects[uid.data], depth + 1)

    def _resolve_object(self, node: dict[object, object], depth: int) -> object:
        if not all(isinstance(k, str) for k in node):
            msg = "archive object has a key that is not a string"
            raise ArchiveError(msg)
        fields = cast("dict[str, object]", node)
        out = {k: self.resolve(v, depth + 1) for k, v in fields.items() if not k.startswith("$")}
        if "$class" in fields:  # an archived object: unwrap Foundation containers
            return _foundation_payload(out)
        return out


def _foundation_payload(out: dict[str, object]) -> object:
    """Return an NSData/NSString/NSArray's payload; any other archived object stays as is."""
    for key in ("NS.data", "NS.string", "NS.objects"):
        if key in out:
            return out[key]
    return out

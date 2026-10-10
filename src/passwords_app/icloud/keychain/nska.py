"""Minimal NSKeyedArchiver expander: resolve the `plistlib.UID` object graph Apple uses for
the per-TLKShare `IESCiphertext` into plain Python."""

from __future__ import annotations

import plistlib


def expand(data: bytes):
    """Expand an NSKeyedArchiver bplist into plain Python (dicts/lists/bytes/str/None)."""
    plist = plistlib.loads(data)
    objects = plist["$objects"]

    def resolve(node):
        if isinstance(node, plistlib.UID):
            return resolve(objects[node.data])
        if node == "$null":
            return None
        if isinstance(node, dict):
            is_object = "$class" in node          # an archived NSObject (vs a plain dict)
            out = {k: resolve(v) for k, v in node.items() if not k.startswith("$")}
            # Unwrap the common Foundation container objects to their payload, so e.g. an
            # NSData/NSMutableData value (the IESCiphertext ephemeral key) yields raw bytes,
            # not {"NS.data": ...}.
            if is_object:
                if "NS.data" in out:
                    return out["NS.data"]
                if "NS.string" in out:
                    return out["NS.string"]
                if "NS.objects" in out:
                    return out["NS.objects"]
            return out
        if isinstance(node, list):
            return [resolve(v) for v in node]
        return node

    top = plist["$top"]
    if isinstance(top, dict) and "root" in top:
        return resolve(top["root"])
    return resolve(top)

"""NSKeyedArchiver expander tests, incl. NSData object unwrapping (the IESCiphertext case).

Run: .venv/bin/python -m unittest tests.test_nska
"""

import plistlib
import unittest

from passwords_app.icloud.keychain import nska


def _nsdata_archive(values: dict) -> bytes:
    """Build a realistic NSKeyedArchiver where each value is an NSMutableData OBJECT
    ({$class -> NSMutableData, NS.data -> bytes}) - as Apple archives the IESCiphertext
    ephemeral sender key - rather than a bare plist Data."""
    objects = ["$null"]

    def add(o):
        objects.append(o)
        return plistlib.UID(len(objects) - 1)

    cls = add({"$classname": "NSMutableData", "$classes": ["NSMutableData", "NSData", "NSObject"]})
    top = {}
    for k, v in values.items():
        data_uid = add(v)
        top[k] = add({"$class": cls, "NS.data": data_uid})
    root = add(top)
    return plistlib.dumps({"$version": 100000, "$archiver": "NSKeyedArchiver",
                           "$top": {"root": root}, "$objects": objects},
                          fmt=plistlib.FMT_BINARY)


class NsdataUnwrapTests(unittest.TestCase):
    def test_unwraps_nsdata_object_to_bytes(self):
        raw = _nsdata_archive({
            "SFEphemeralSenderPublicKeyExternaRepresentation": b"\x04" + b"\xab" * 96,
            "SFIESAuthenticationCode": b"\x11" * 16,
        })
        out = nska.expand(raw)
        # the wrapped NSData yields raw bytes, NOT {"NS.data": ...}
        self.assertEqual(out["SFEphemeralSenderPublicKeyExternaRepresentation"],
                         b"\x04" + b"\xab" * 96)
        self.assertEqual(out["SFIESAuthenticationCode"], b"\x11" * 16)

    def test_plain_dict_not_unwrapped(self):
        # a dict WITHOUT $class (not an archived object) is left as-is
        objects = ["$null", {"hello": "world"}]
        raw = plistlib.dumps({"$archiver": "NSKeyedArchiver", "$top": {"root": plistlib.UID(1)},
                              "$objects": objects}, fmt=plistlib.FMT_BINARY)
        self.assertEqual(nska.expand(raw), {"hello": "world"})


if __name__ == "__main__":
    unittest.main()

"""Offline tests for the decryption pipeline's live building blocks: item AAD
construction, and CKKS value parsing."""

import unittest

from passwords_app.icloud.keychain import pipeline


class AadTests(unittest.TestCase):
    def test_aad_includes_pcs_fields(self):
        fields = {"parentkeyref": "CLASSC", "encver": 2, "gen": 0,
                  "pcsservice": 5, "pcspublicidentity": b"ident", "pcspublickey": b"pub",
                  "wrappedkey": "ignored", "data": b"ignored"}
        aad = pipeline.authenticated_data_v2("UUID-x", fields, encver=2, gen=0,
                                             parent_key_id="CLASSC")
        self.assertIn(b"ident", aad)
        self.assertIn(b"pub", aad)
        self.assertIn((5).to_bytes(8, "little", signed=True), aad)

    def test_le8_two_complement_no_overflow(self):
        # proto int64 negatives arrive as large unsigned varints; must give the 64-bit
        # two's-complement LE, not raise OverflowError.
        self.assertEqual(pipeline._le8(0xFFFFFFFFFFFFFFFF), b"\xff" * 8)   # -1 as i64
        self.assertEqual(pipeline._le8(2), b"\x02" + b"\x00" * 7)
        aad = pipeline.authenticated_data_v2(
            "U", {"n": 0xFFFFFFFFFFFFFFFF, "parentkeyref": "C"}, encver=2, gen=0, parent_key_id="C")
        self.assertIn(b"\xff" * 8, aad)

    def test_aad_encodes_date_and_double(self):
        from passwords_app.icloud.transport.ckks import CKDate
        fields = {"parentkeyref": "C", "cdat": CKDate(1687305600.0), "score": 3.9}
        aad = pipeline.authenticated_data_v2("U", fields, encver=2, gen=0, parent_key_id="C")
        self.assertIn(b"2023-06-21T00:00:00Z", aad)       # RFC3339 seconds Z
        self.assertIn((3).to_bytes(8, "little"), aad)     # double truncated -> (u64) LE


class ParseValueTests(unittest.TestCase):
    def test_parse_value_decodes_double_and_date(self):
        import struct
        from passwords_app.icloud.transport.ckks import CKDate, _parse_value
        raw_double = bytes([(5 << 3) | 1]) + struct.pack("<d", 2.5)
        self.assertEqual(_parse_value(raw_double), 2.5)
        date_inner = bytes([(1 << 3) | 1]) + struct.pack("<d", 1687305600.0)
        raw_date = bytes([(6 << 3) | 2, len(date_inner)]) + date_inner
        self.assertEqual(_parse_value(raw_date), CKDate(1687305600.0))


class UnionTlkTests(unittest.TestCase):
    def test_plain_and_recoverable_tlks_are_unioned(self):
        # The recoverable TLKs (user-controllable views like Passwords) are UNIONed with the
        # plain-zone tlkshare TLKs (always-on views like WiFi), not substituted.
        seen = {}
        orig = (pipeline.unwrap_tlkshares, pipeline.unwrap_class_keys, pipeline.decrypt_items)
        pipeline.unwrap_tlkshares = lambda *a, **k: {"TLK-WIFI": b"w" * 64}
        pipeline.unwrap_class_keys = (
            lambda synckeys, tlks, access_key=None: seen.update(tlks=dict(tlks)) or {})
        pipeline.decrypt_items = lambda items, class_keys: []
        try:
            pipeline.build_credential_store({}, "SHA256:me", None, tlks={"TLK-PW": b"p" * 64})
        finally:
            (pipeline.unwrap_tlkshares, pipeline.unwrap_class_keys,
             pipeline.decrypt_items) = orig
        self.assertEqual(seen["tlks"], {"TLK-WIFI": b"w" * 64, "TLK-PW": b"p" * 64})


if __name__ == "__main__":
    unittest.main()

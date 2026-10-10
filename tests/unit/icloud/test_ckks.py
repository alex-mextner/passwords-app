"""Offline tests for CKKS record-fetch request building + Record parsing.

Run: .venv/bin/python -m unittest tests.test_ckks
"""

import unittest

from passwords_app.icloud.transport import ckks
from passwords_app.icloud.proto import codec as _proto


def _identifier(name, type_):
    return _proto.Writer().string(1, name).uint64(2, type_).finish()


def _value(bytes_value=None, string_value=None, int_value=None):
    w = _proto.Writer()
    if bytes_value is not None:
        w.uint64(1, 1).bytes(2, bytes_value)      # bytesValue
    elif string_value is not None:
        w.uint64(1, 3).string(7, string_value)    # stringValue
    elif int_value is not None:
        w.uint64(1, 7).uint64(4, int_value)       # signedValue
    return w.finish()


def _ref_value(name):
    # Value{ type(1)=REFERENCE, referenceValue(9): Reference{ recordIdentifier(2):
    #   RecordIdentifier{ value(1): Identifier{ name(1) } } } }
    ident = _proto.Writer().string(1, name).finish()
    rec_id = _proto.Writer().message(1, ident).finish()
    ref = _proto.Writer().message(2, rec_id).finish()
    return _proto.Writer().uint64(1, 5).message(9, ref).finish()


def _field(name, value):
    return _proto.Writer().message(1, _identifier(name, 0)).message(2, value).finish()


def _record(record_name, rtype, fields):
    rec_id = _proto.Writer().message(1, _identifier(record_name, 1)).finish()  # ID_TYPE_RECORD
    type_msg = _proto.Writer().string(1, rtype).finish()
    w = _proto.Writer().message(2, rec_id).message(3, type_msg)
    for fname, fval in fields:
        w.message(7, _field(fname, fval))
    return w.finish()


class RequestBuildTests(unittest.TestCase):
    def test_zone_identifier(self):
        raw = ckks.record_zone_identifier("Passwords", "USER-1")
        f = _proto.decode_fields(raw)
        zone = _proto.decode_fields(_proto.first(f, 1))
        self.assertEqual(_proto.first_str(zone, 1), "Passwords")
        self.assertEqual(_proto.first(zone, 2), ckks.ID_TYPE_RECORD_ZONE)
        owner = _proto.decode_fields(_proto.first(f, 2))
        self.assertEqual(_proto.first_str(owner, 1), "USER-1")
        self.assertEqual(_proto.first(owner, 2), ckks.ID_TYPE_USER)

    def test_retrieve_changes_request(self):
        zid = ckks.record_zone_identifier("Manatee", "U")
        raw = ckks.build_retrieve_changes_request(zid, continuation_token=b"TOK", max_changes=10)
        f = _proto.decode_fields(raw)
        self.assertEqual(_proto.first(f, 1), b"TOK")
        self.assertEqual(_proto.first(f, 2), zid)
        self.assertEqual(_proto.first(f, 4), 10)

    def test_request_operation_uses_213(self):
        from passwords_app.icloud.transport import cloudkit as ck
        header = ck.build_header(ck.DeviceConfig("UUID", "SER"))
        req = ckks.build_retrieve_changes_request(
            ckks.record_zone_identifier("Passwords", "U"))
        raw = ck.build_request_operation_generic(
            header, ckks.OP_TYPE_RECORD_RETRIEVE_CHANGES, ckks.FIELD_RETRIEVE_CHANGES, req)
        f = _proto.decode_fields(raw)
        op = _proto.decode_fields(_proto.first(f, 2))
        self.assertEqual(_proto.first(op, 2), 213)            # Operation.type
        self.assertEqual(_proto.first(f, 213), req)           # retrieveChangesRequest


class RecordParseTests(unittest.TestCase):
    def test_parse_item_record(self):
        raw = _record("UUID-item", "item", [
            ("wrappedkey", _value(string_value="d3JhcA==")),
            ("data", _value(bytes_value=b"\x00\x01iv+ct")),
            ("encver", _value(int_value=2)),
            ("parentkeyref", _value(string_value="classC-uuid")),
        ])
        rec = ckks.parse_record(raw)
        self.assertEqual(rec.type, "item")
        self.assertEqual(rec.record_name, "UUID-item")
        self.assertEqual(rec.get_str("wrappedkey"), "d3JhcA==")
        self.assertEqual(rec.get_bytes("data"), b"\x00\x01iv+ct")
        self.assertEqual(rec.fields["encver"], 2)

    def test_parse_reference_field_resolves_to_name(self):
        # `parentkeyref` is a CloudKit Reference, not a string: _parse_value resolves
        # referenceValue -> recordIdentifier -> value -> name to recover the synckey->TLK and
        # item->classkey links.
        raw = _record("synckey-1", "synckey", [
            ("class", _value(string_value="classC")),
            ("parentkeyref", _ref_value("TLK-UUID-42")),
        ])
        rec = ckks.parse_record(raw)
        self.assertEqual(rec.get_str("parentkeyref"), "TLK-UUID-42")

    def test_parse_tlkshare_record(self):
        raw = _record("share-1", "tlkshare", [
            ("receiver", _value(string_value="SHA256:me")),
            ("sender", _value(string_value="SHA256:them")),
            ("wrappedkey", _value(string_value="QkFTRTY0")),
            ("curve", _value(int_value=4)),
        ])
        rec = ckks.parse_record(raw)
        self.assertEqual(rec.type, "tlkshare")
        self.assertEqual(rec.get_str("receiver"), "SHA256:me")
        self.assertEqual(rec.fields["curve"], 4)

    def test_parse_changes_response_groups(self):
        recs = [
            _record("i1", "item", [("wrappedkey", _value(string_value="a"))]),
            _record("k1", "synckey", [("class", _value(string_value="classC"))]),
            _record("s1", "tlkshare", [("receiver", _value(string_value="me"))]),
        ]
        changes = _proto.Writer()
        for r in recs:
            rc = _proto.Writer().message(5, r).finish()   # RecordChange.record(5)
            changes.message(1, rc)
        changes.bytes(2, b"NEXT")
        changes.uint64(4, 1)
        out = ckks.parse_retrieve_changes_response(changes.finish())

        self.assertEqual(out["continuation_token"], b"NEXT")
        self.assertEqual(out["status"], 1)
        grouped = {}
        for r in out["records"]:
            grouped.setdefault(r.type, []).append(r)
        self.assertEqual(len(grouped["item"]), 1)
        self.assertEqual(grouped["synckey"][0].get_str("class"), "classC")
        self.assertEqual(grouped["tlkshare"][0].record_name, "s1")


class ZoneListTests(unittest.TestCase):
    def test_password_zones_present(self):
        self.assertIn("Passwords", ckks.KEYCHAIN_ZONES)
        self.assertIn("Manatee", ckks.KEYCHAIN_ZONES)


if __name__ == "__main__":
    unittest.main()

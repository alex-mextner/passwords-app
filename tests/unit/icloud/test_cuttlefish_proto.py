"""Offline round-trip tests for the protobuf codec + Cuttlefish join-path messages.

Run: .venv/bin/python -m unittest tests.test_cuttlefish_proto
"""

import unittest

import pytest

from passwords_app.icloud.octagon import keys as ok
from passwords_app.icloud.proto import codec as _proto
from passwords_app.icloud.proto import cuttlefish as cf


class ProtoCodecTests(unittest.TestCase):
    def test_varint(self) -> None:
        assert _proto.encode_varint(0) == b"\x00"
        assert _proto.encode_varint(300) == b"\xac\x02"
        assert _proto.encode_varint(1) == b"\x01"

    def test_varint_longer_than_ten_bytes_is_malformed(self) -> None:
        assert _proto.read_varint(_proto.encode_varint(2**64 - 1), 0)[1] == 10
        with pytest.raises(_proto.ProtoError, match="longer than 10"):
            _proto.read_varint(b"\x80" * 10 + b"\x01", 0)

    def test_writer_field_types(self) -> None:
        raw = (
            _proto.Writer()
            .uint64(1, 5)
            .string(2, "hi")
            .bytes(3, b"\x00\xff")
            .bool(4, True)
            .finish()
        )
        f = _proto.decode_fields(raw)
        assert _proto.first(f, 1) == 5
        assert _proto.first_str(f, 2) == "hi"
        assert _proto.first(f, 3) == b"\x00\xff"
        assert _proto.first(f, 4) == 1

    def test_repeated_and_nested(self) -> None:
        sub = _proto.Writer().string(1, "x")
        raw = _proto.Writer().string(1, "a").string(1, "b").message(2, sub).finish()
        f = _proto.decode_fields(raw)
        assert [v.decode() for v in _proto.all_bytes(f, 1)] == ["a", "b"]
        nested = _proto.first_message(f, 2)
        assert nested is not None
        assert _proto.first_str(nested, 1) == "x"

    def test_truncated_raises(self) -> None:
        with pytest.raises(_proto.ProtoError):
            _proto.decode_fields(b"\x0a\x05ab")  # says len 5, only 2 bytes


class SignedInfoTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        raw = cf.encode_signed_info(b"info-bytes", b"sig-bytes")
        assert cf.parse_signed_info(raw) == (b"info-bytes", b"sig-bytes")


class CuttlefishPeerTests(unittest.TestCase):
    def test_peer_carries_octagon_identity(self) -> None:
        """Build a real Octagon peer identity and wrap it as a CuttlefishPeer; parse it back."""
        ks = ok.PeerKeySet.generate()
        perm = ok.build_permanent_info(
            ks, machine_id="ABC", model_id="MacBookPro18,3", epoch=1, creation_time=1700000000
        )
        stable = ok.build_stable_info(
            ks,
            clock=1,
            frozen_policy_version=1,
            frozen_policy_hash="SHA256:x",
            flexible_policy_version=1,
            flexible_policy_hash="SHA256:x",
            device_name="Mac",
            serial_number="C02",
            os_version="13.4",
        )
        dynamic = ok.build_dynamic_info(ks, clock=1, included_peer_ids=[perm.peer_id])

        raw = cf.encode_cuttlefish_peer(
            perm.peer_id,
            cf.SignedBlob(perm.data, perm.sig),
            cf.SignedBlob(stable.data, stable.sig),
            cf.SignedBlob(dynamic.data, dynamic.sig),
        )

        parsed = cf.parse_cuttlefish_peer(raw)
        assert parsed.hash == perm.peer_id
        assert parsed.permanent_info is not None
        assert parsed.stable_info is not None
        assert parsed.dynamic_info is not None
        assert parsed.permanent_info.info == perm.data
        assert parsed.permanent_info.sig == perm.sig
        assert parsed.stable_info.info == stable.data
        assert parsed.dynamic_info.sig == dynamic.sig
        assert parsed.voucher is None


class TlkShareTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        s = cf.TlkShare(
            service="Manatee",
            curve=4,
            epoch=0,
            key_id="UUID-1",
            poisoned=0,
            receiver="peerB",
            receiver_public_encryption_key="c3Bracg=",
            sender="peerA",
            signature="c2ln",
            version=1,
            wrapped_key="d3JhcA==",
        )
        back = cf.TlkShare.parse(s.encode())
        assert back == s


class RequestResponseTests(unittest.TestCase):
    def test_fetch_changes_request(self) -> None:
        f = _proto.decode_fields(cf.encode_fetch_changes_request("tok"))
        assert _proto.first_str(f, 1) == "tok"
        # None token -> empty message
        assert cf.encode_fetch_changes_request(None) == b""

    def test_fetch_changes_response_parses_peers(self) -> None:
        # build a synthetic response: changes{ syncToken, change{ add: peer } }
        peer = cf.encode_cuttlefish_peer(
            "SHA256:p",
            cf.SignedBlob(b"pi", b"ps"),
            cf.SignedBlob(b"si", b"ss"),
            cf.SignedBlob(b"di", b"ds"),
        )
        change = _proto.Writer().message(3, peer).finish()
        changes = _proto.Writer().string(1, "newtok").message(2, change).finish()
        resp = _proto.Writer().message(1, changes).finish()

        out = cf.parse_fetch_changes_response(resp)
        assert out.sync_token == "newtok"  # noqa: S105 - fictional sync token, not a secret
        assert len(out.peers) == 1
        assert out.peers[0].hash == "SHA256:p"
        permanent = out.peers[0].permanent_info
        assert permanent is not None
        assert permanent.info == b"pi"

    def test_function_invoke_envelope(self) -> None:
        params = b"cuttlefish-request-bytes"
        fir = cf.encode_function_invoke_request("Cuttlefish", "fetchChanges", params)
        f = _proto.decode_fields(fir)
        assert _proto.first_str(f, 1) == "Cuttlefish"
        assert _proto.first_str(f, 2) == "fetchChanges"
        assert _proto.first(f, 3) == params

    def test_fetch_recoverable_tlkshares_request(self) -> None:
        f = _proto.decode_fields(cf.encode_fetch_recoverable_tlkshares_request("SHA256:me"))
        assert _proto.first_str(f, 1) == "SHA256:me"

    def test_parse_recoverable_tlkshares_response_unwraps_records(self) -> None:
        # response{ shares(1): repeated RecoverableTlkShare{ service(1), viewkeys(2):
        #   { tlk(1), classA(2), classB(3) }, share(3) } } - each leaf a CuttlefishRecord{inner(2)}.
        def ckrecord(inner: bytes) -> bytes:  # CuttlefishRecord{ inner(2): Record }
            return _proto.Writer().message(2, inner).finish()

        share_rec = b"SHARE-RECORD-BYTES"
        classa, classb = b"CLASSA-REC", b"CLASSB-REC"
        viewkeys = (
            _proto.Writer().message(2, ckrecord(classa)).message(3, ckrecord(classb)).finish()
        )
        grp = (
            _proto.Writer()
            .string(1, "Passwords")
            .message(2, viewkeys)
            .message(3, ckrecord(share_rec))
            .finish()
        )
        resp = _proto.Writer().message(1, grp).message(1, grp).finish()  # two share-groups

        out = cf.parse_recoverable_tlkshares_response(resp)
        assert list(out.share_records) == [share_rec, share_rec]
        # classA + classB synckey records from each group's viewkeys
        assert list(out.synckey_records) == [classa, classb, classa, classb]

    def test_join_with_voucher_request(self) -> None:
        peer = cf.encode_cuttlefish_peer(
            "SHA256:p",
            cf.SignedBlob(b"pi", b"ps"),
            cf.SignedBlob(b"si", b"ss"),
            cf.SignedBlob(b"di", b"ds"),
            voucher=cf.SignedBlob(b"vi", b"vs"),
        )
        share = cf.TlkShare(service="Manatee", key_id="K")
        raw = cf.encode_join_with_voucher_request(peer, shares=[share])
        f = _proto.decode_fields(raw)
        assert _proto.first(f, 2) == peer  # peer field
        assert len(f[4]) == 1  # one share
        peer_field = _proto.first_bytes(f, 2)
        assert peer_field is not None
        voucher = cf.parse_cuttlefish_peer(peer_field).voucher
        assert voucher is not None
        assert voucher.info == b"vi"


if __name__ == "__main__":
    unittest.main()

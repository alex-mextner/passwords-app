"""Offline unit tests for the Octagon peer key material (`passwords_app.icloud.octagon.keys`).

No network.

Run: .venv/bin/python -m unittest tests.test_octagon_keys
"""

import base64
import unittest
from typing import override

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from passwords_app.icloud.octagon import keys as ok
from passwords_app.icloud.values import items


class PeerKeyEncodingTests(unittest.TestCase):
    @override
    def setUp(self) -> None:
        self.key = ok.generate_peer_key()

    def test_curve_is_p384(self) -> None:
        assert isinstance(self.key.private_key.curve, ec.SECP384R1)

    def test_public_x963_shape(self) -> None:
        pub = self.key.public_x963()
        assert len(pub) == 97  # 0x04 || X(48) || Y(48)
        assert pub[0] == 4

    def test_private_x963_shape(self) -> None:
        priv = self.key.private_x963()
        assert len(priv) == 145  # point(97) || D(48)
        assert priv[0] == 4
        assert priv[:97] == self.key.public_x963()

    def test_spki_parses_back_to_same_public_key(self) -> None:
        spki = self.key.public_spki()
        loaded = serialization.load_der_public_key(spki)
        assert (
            loaded.public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
            )
            == self.key.public_x963()
        )

    def test_private_x963_round_trip(self) -> None:
        blob = self.key.private_x963()
        reloaded = ok.load_peer_key_x963(blob)
        assert reloaded.private_x963() == blob
        assert (
            reloaded.private_key.private_numbers().private_value
            == self.key.private_key.private_numbers().private_value
        )


class SigningTests(unittest.TestCase):
    @override
    def setUp(self) -> None:
        self.key = ok.generate_peer_key()
        self.pub = self.key.private_key.public_key()

    def test_sign_sha384_verifies(self) -> None:
        msg = b"octagon permanent info bytes"
        sig = self.key.sign_sha384(msg)
        self.pub.verify(sig, msg, ec.ECDSA(hashes.SHA384()))  # raises if invalid

    def test_bad_signature_fails(self) -> None:
        sig = self.key.sign_sha384(b"a")
        with pytest.raises(InvalidSignature):
            self.pub.verify(sig, b"b", ec.ECDSA(hashes.SHA384()))


class KeySetTests(unittest.TestCase):
    def test_generate_two_distinct_keys(self) -> None:
        ks = ok.PeerKeySet.generate()
        assert ks.signing.private_x963() != ks.encryption.private_x963()

    def test_storage_round_trip(self) -> None:
        ks = ok.PeerKeySet.generate()
        restored = ok.PeerKeySet.from_storage(ks.to_storage())
        assert restored.signing.private_x963() == ks.signing.private_x963()
        assert restored.encryption.private_x963() == ks.encryption.private_x963()


class TPHashTests(unittest.TestCase):
    """Lock the TPHashBuilder format to Apple's own test vector forever.

    From Apple's own TrustedPeersHelper unit-test vector: the policy v1 document
    data base64-decodes and TPHashBuilder.hash(.SHA256, ...) of it equals the literal below.
    """

    POLICY1_B64 = (
        "CAESDgoGaVBob25lEgRmdWxsEgwKBGlQYWQSBGZ1bGwSCwoDTWFjEgRmdWxsEgwKBGlNYWMSBGZ1bGwSDQoHQXBwbGVUVhICdHYS"
        "DgoFV2F0Y2gSBXdhdGNoGhEKCVBDU0VzY3JvdxIEZnVsbBoXCgRXaUZpEgRmdWxsEgJ0dhIFd2F0Y2gaGQoRU2FmYXJpQ3JlZGl0"
        "Q2FyZHMSBGZ1bGwiDAoEZnVsbBIEZnVsbCIUCgV3YXRjaBIEZnVsbBIFd2F0Y2giDgoCdHYSBGZ1bGwSAnR2"
    )
    POLICY1_HASH = "SHA256:TLXrcQmY4ue3oP5pCX1pwsi9BF8cKfohlJBilCroeBs="

    def test_tphash_matches_apple_vector(self) -> None:
        assert ok.tphash(base64.b64decode(self.POLICY1_B64)) == self.POLICY1_HASH

    def test_derive_peer_id_hashes_data_plus_sig(self) -> None:
        # peerID concatenates data then sig before hashing (TPPeerPermanentInfo.mm)
        assert ok.derive_peer_id(b"data", b"sig") == ok.tphash(b"datasig")

    def test_tphash_sha384_prefix(self) -> None:
        assert ok.tphash(b"x", "SHA384").startswith("SHA384:")


class PermanentInfoTests(unittest.TestCase):
    @override
    def setUp(self) -> None:
        self.ks = ok.PeerKeySet.generate()
        self.info = ok.build_permanent_info(
            self.ks,
            machine_id="ABCDEF0123456",
            model_id="MacBookPro18,3",
            epoch=1,
            creation_time=1700000000,
        )

    def test_peer_id_format(self) -> None:
        assert self.info.peer_id.startswith("SHA256:")
        # 32-byte digest -> 44 base64 chars incl. one '=' pad
        assert len(self.info.peer_id) == len("SHA256:") + 44

    def test_peer_id_is_hash_of_data_plus_sig(self) -> None:
        assert self.info.peer_id == ok.tphash(self.info.data + self.info.sig)

    def test_field_order_is_ascending(self) -> None:
        # canonical protobuf: first tag byte is field 1 (epoch), wire 0 -> 0x08
        assert self.info.data[0] == 1 << 3 | 0

    def test_signature_is_over_prefixed_data(self) -> None:
        # the sig must verify over UTF8(type)++data, and NOT over bare data
        pub = self.ks.signing.private_key.public_key()
        prefixed = b"TPPB.PeerPermanentInfo" + self.info.data
        pub.verify(self.info.sig, prefixed, ec.ECDSA(hashes.SHA384()))
        with pytest.raises(InvalidSignature):
            pub.verify(self.info.sig, self.info.data, ec.ECDSA(hashes.SHA384()))

    def test_distinct_peers_get_distinct_ids(self) -> None:
        other = ok.build_permanent_info(
            ok.PeerKeySet.generate(), machine_id="ABCDEF0123456", model_id="MacBookPro18,3", epoch=1
        )
        assert self.info.peer_id != other.peer_id


class StableInfoTests(unittest.TestCase):
    @override
    def setUp(self) -> None:
        self.ks = ok.PeerKeySet.generate()
        self.info = ok.build_stable_info(
            self.ks,
            clock=1,
            frozen_policy_version=1,
            frozen_policy_hash="SHA256:TLXrcQmY4ue3oP5pCX1pwsi9BF8cKfohlJBilCroeBs=",
            flexible_policy_version=1,
            flexible_policy_hash="SHA256:TLXrcQmY4ue3oP5pCX1pwsi9BF8cKfohlJBilCroeBs=",
            device_name="Sank's Mac",
            serial_number="C02XYZ123",
            os_version="Mac OS X;13.4.1",
        )

    def test_signature_over_prefixed_data(self) -> None:
        pub = self.ks.signing.private_key.public_key()
        prefixed = b"TPPB.PeerStableInfo" + self.info.data
        pub.verify(self.info.sig, prefixed, ec.ECDSA(hashes.SHA384()))
        with pytest.raises(InvalidSignature):
            pub.verify(self.info.sig, self.info.data, ec.ECDSA(hashes.SHA384()))

    def test_field_order_is_ascending(self) -> None:
        # first field is clock (1), varint -> tag 0x08
        assert self.info.data[0] == 1 << 3 | 0

    def test_round_trips(self) -> None:
        p = ok.parse_stable_info_data(self.info.data)
        assert p["clock"] == 1
        assert p["frozen_policy_version"] == 1
        assert p["flexible_policy_version"] == 1
        assert p["device_name"] == "Sank's Mac"
        assert p["serial_number"] == "C02XYZ123"
        assert p["os_version"] == "Mac OS X;13.4.1"
        assert p["user_controllable_views"] == ok.UCV_FOLLOWING
        assert p["supports_repudiation"] == 1
        assert str(p["frozen_policy_hash"]).startswith("SHA256:")

    def test_repudiation_can_be_omitted(self) -> None:
        info = ok.build_stable_info(
            self.ks,
            clock=2,
            frozen_policy_version=1,
            frozen_policy_hash="SHA256:x",
            flexible_policy_version=1,
            flexible_policy_hash="SHA256:x",
            device_name="d",
            serial_number="s",
            os_version="o",
            supports_repudiation=False,
        )
        assert "supports_repudiation" not in ok.parse_stable_info_data(info.data)


class DynamicInfoTests(unittest.TestCase):
    @override
    def setUp(self) -> None:
        self.ks = ok.PeerKeySet.generate()
        self.info = ok.build_dynamic_info(
            self.ks,
            clock=1,
            included_peer_ids=["SHA256:" + "A" * 43 + "=", "SHA256:" + "B" * 43 + "="],
            excluded_peer_ids=["SHA256:" + "C" * 43 + "="],
        )

    def test_signature_over_prefixed_data(self) -> None:
        pub = self.ks.signing.private_key.public_key()
        prefixed = b"TPPB.PeerDynamicInfo" + self.info.data
        pub.verify(self.info.sig, prefixed, ec.ECDSA(hashes.SHA384()))
        with pytest.raises(InvalidSignature):
            pub.verify(self.info.sig, self.info.data, ec.ECDSA(hashes.SHA384()))

    def test_round_trips(self) -> None:
        p = ok.parse_dynamic_info_data(self.info.data)
        assert p["clock"] == 1
        included = items(p["included"])
        assert len(included) == 2
        assert len(items(p["excluded"])) == 1
        assert included[0] == "SHA256:" + "A" * 43 + "="

    def test_field_order(self) -> None:
        assert self.info.data[0] == 1 << 3 | 0  # clock first


if __name__ == "__main__":
    unittest.main()

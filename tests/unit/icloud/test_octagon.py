"""Offline tests for the orchestration's non-network parts: identity persistence + join assembly."""

# pyright: reportPrivateUsage=false
# These tests stub the client's private network seams to stay offline.

import unittest
from typing import TYPE_CHECKING, Never, cast, override
from unittest import mock

from passwords_app.icloud.auth.device import Device
from passwords_app.icloud.escrow import srp as escrow_srp
from passwords_app.icloud.octagon import client as octagon
from passwords_app.icloud.octagon import keys as ok
from passwords_app.icloud.proto import cuttlefish as cf
from passwords_app.icloud.proto.codec import Writer
from passwords_app.icloud.values import Record, child, items, text

if TYPE_CHECKING:
    from passwords_app.icloud.auth.anisette import AnisetteSource


def _device() -> Device:
    return Device(device_id="DEVICE-UUID-1", serial="C02SERIAL", local_user_uuid="USER-UUID-1")


class FetchRecoverableUnionTests(unittest.TestCase):
    def _client_with(self, octagon_state: Record) -> octagon.OctagonClient:
        client = octagon.OctagonClient.__new__(octagon.OctagonClient)  # bypass __init__/network
        client._http = None
        record: Record = {"octagon": octagon_state}
        client.record = record
        return client

    def test_unions_self_and_sponsor_recoverable_tlks(self) -> None:
        # The sponsor fetch is what supplies the user-controllable views (Passwords/Manatee)
        # that our own peer is not entitled to; both fetches must be UNIONed.
        sp_key_hex = ok.generate_peer_key().private_x963().hex()
        client = self._client_with(
            {
                "peer_id": "SHA256:me",
                "keys": ok.PeerKeySet.generate().to_storage(),
                "sponsor": {"peer_id": "SHA256:sponsor", "encryption_priv_x963": sp_key_hex},
            }
        )
        calls: list[str] = []

        def fake_fetch(
            for_peer_id: str, _enc_private_key: ok.PeerKey
        ) -> tuple[dict[str, bytes], list[str]]:
            calls.append(for_peer_id)
            if for_peer_id == "SHA256:me":
                return {"TLK-WIFI": b"w" * 64}, ["SK-sys"]
            return {"TLK-PW": b"p" * 64}, ["SK-pw"]

        with mock.patch.object(client, "_fetch_recoverable_for", fake_fetch):
            tlks, synckeys = client.fetch_recoverable_tlks()
        assert tlks == {"TLK-WIFI": b"w" * 64, "TLK-PW": b"p" * 64}
        seen: list[object] = list(synckeys)  # the stub hands back plain strings
        assert seen == ["SK-sys", "SK-pw"]
        assert calls == ["SHA256:me", "SHA256:sponsor"]

    def test_without_sponsor_only_self_is_fetched(self) -> None:
        client = self._client_with(
            {
                "peer_id": "SHA256:me",
                "keys": ok.PeerKeySet.generate().to_storage(),
            }
        )
        calls: list[str] = []

        def fake_fetch(
            for_peer_id: str, _enc_private_key: ok.PeerKey
        ) -> tuple[dict[str, bytes], list[str]]:
            calls.append(for_peer_id)
            return {"T": b"x" * 64}, []

        with mock.patch.object(client, "_fetch_recoverable_for", fake_fetch):
            tlks, _ = client.fetch_recoverable_tlks()
        assert calls == ["SHA256:me"]
        assert tlks == {"T": b"x" * 64}


class EnsureIdentityTests(unittest.TestCase):
    def test_generates_and_persists(self) -> None:
        record: Record = {}
        st = octagon.ensure_peer_identity(record, _device())
        assert (text(st, "peer_id") or "").startswith("SHA256:")
        assert "octagon" in record
        assert "signing_priv_x963" in child(st, "keys")

    def test_idempotent_reuse(self) -> None:
        record: Record = {}
        a = octagon.ensure_peer_identity(record, _device())
        b = octagon.ensure_peer_identity(record, _device())
        assert a["peer_id"] == b["peer_id"]  # same identity reused, not regenerated

    def test_keys_reload(self) -> None:
        record: Record = {}
        st = octagon.ensure_peer_identity(record, _device())
        keys = octagon.load_peer_keys(st)
        assert len(keys.signing.public_spki()) > 0


class JoinPeerAssemblyTests(unittest.TestCase):
    @override
    def setUp(self) -> None:
        self.record: Record = {}
        self.st = octagon.ensure_peer_identity(self.record, _device())
        self.keys = octagon.load_peer_keys(self.st)

    def test_stable_info_uses_prevailing_policy(self) -> None:
        p = ok.parse_stable_info_data(bytes.fromhex(text(child(self.st, "stable"), "data") or ""))
        assert p["frozen_policy_version"] == octagon.FROZEN_POLICY_VERSION
        assert p["frozen_policy_hash"] == octagon.FROZEN_POLICY_HASH
        assert p["flexible_policy_version"] == octagon.FLEXIBLE_POLICY_VERSION
        assert p["flexible_policy_hash"] == octagon.FLEXIBLE_POLICY_HASH
        assert p["user_controllable_views"] == ok.UCV_FOLLOWING

    def _changes(
        self,
        sponsor_id: str,
        sponsor_includes: list[str],
        sponsor_dyn_clock: int,
        stable_clock: int,
    ) -> cf.FetchChanges:
        sponsor_keys = ok.PeerKeySet.generate()
        si = ok.build_stable_info(
            sponsor_keys,
            clock=stable_clock,
            frozen_policy_version=5,
            frozen_policy_hash="SHA256:x",
            flexible_policy_version=20,
            flexible_policy_hash="SHA256:y",
            device_name="d",
            serial_number="s",
            os_version="o",
        )
        di = ok.build_dynamic_info(
            sponsor_keys, clock=sponsor_dyn_clock, included_peer_ids=sponsor_includes
        )
        peer = cf.CuttlefishPeer(
            sponsor_id, None, cf.SignedBlob(si.data, si.sig), cf.SignedBlob(di.data, di.sig), None
        )
        return cf.FetchChanges("tok", (peer,))

    def test_trust_from_changes(self) -> None:
        sponsor = "SHA256:sponsor"
        changes = self._changes(sponsor, [sponsor, "SHA256:other"], 7, 9)
        included_ids, stable_clock, dyn_clock = octagon.trust_from_changes(changes, sponsor)
        assert included_ids == [sponsor, "SHA256:other"]
        assert stable_clock == 10  # max stable (9) + 1
        assert dyn_clock == 8  # sponsor dynamic (7) + 1

    def test_build_join_peer_includes_self_and_sponsor(self) -> None:
        voucher = cf.SignedBlob(b"vinfo", b"vsig")
        peer_bytes = octagon.build_join_peer(
            self.st,
            self.keys,
            voucher,
            ["SHA256:sponsor"],
            stable_clock=10,
            dynamic_clock=8,
            serial="C02",
        )
        peer = cf.parse_cuttlefish_peer(peer_bytes)
        assert peer.hash == self.st["peer_id"]
        assert peer.voucher is not None
        assert peer.dynamic_info is not None
        assert peer.stable_info is not None
        assert peer.voucher.info == b"vinfo"
        # dynamicInfo includes the sponsor AND our own peerID
        dyn = ok.parse_dynamic_info_data(peer.dynamic_info.info)
        included = items(dyn["included"])
        assert "SHA256:sponsor" in included
        assert self.st["peer_id"] in included
        assert dyn["clock"] == 8
        # stableInfo carries the prevailing policy at the new clock
        st = ok.parse_stable_info_data(peer.stable_info.info)
        assert st["clock"] == 10
        assert st["flexible_policy_version"] == 20


class ViableBottlesParseTests(unittest.TestCase):
    def test_parse_viable_bottles(self) -> None:
        otbottle = b"OTBOTTLE-BYTES"
        bottle = Writer().bytes(2, otbottle).finish()  # Bottle{ bottle(2) }
        escrow_data = Writer().string(1, "escrow-id-1").message(2, bottle).finish()
        resp = Writer().message(1, escrow_data).finish()  # response{ valid(1) }
        out = octagon.parse_viable_bottles(resp)
        assert len(out) == 1
        assert out[0]["id"] == "escrow-id-1"
        assert out[0]["otbottle"] == otbottle

    def test_parse_empty(self) -> None:
        assert octagon.parse_viable_bottles(b"") == []


class IsJoinedTests(unittest.TestCase):
    def test_bare_peer_id_is_not_joined(self) -> None:
        assert not octagon.is_joined({"octagon": {"peer_id": "SHA256:abc"}})

    def test_joined_flag_or_sponsor_counts_as_joined(self) -> None:
        assert octagon.is_joined({"octagon": {"peer_id": "p", "joined": True}})
        assert octagon.is_joined({"octagon": {"peer_id": "p", "sponsor": {"peer_id": "s"}}})

    def test_no_octagon_state_is_not_joined(self) -> None:
        assert not octagon.is_joined({})
        assert not octagon.is_joined({"octagon": {}})


class ListRecoverableBottlesTests(unittest.TestCase):
    def _client(self, viable: list[Record]) -> octagon.OctagonClient:
        client = octagon.OctagonClient.__new__(octagon.OctagonClient)  # bypass __init__/network
        client._http = None
        # Never reached: the escrow recovery that would use it is replaced by a fake.
        client.anisette = cast("AnisetteSource", object())
        client.fetch_viable_bottles = lambda: viable  # type: ignore[method-assign]  # offline stub
        return client

    def test_correlates_getrecords_metadata_and_drops_bottleless(self) -> None:
        client = self._client(
            [
                {"id": "b1", "otbottle": b"OT1"},
                {"id": "b2", "otbottle": None},  # no OTBottle -> not recoverable, dropped
                {"id": "b3", "otbottle": b"OT3"},
            ]
        )

        class FakeRecovery:
            def __init__(self, *_args: object, **_kwargs: object) -> None:
                pass

            def list_records(self) -> list[Record]:
                return [
                    {"label": "b1", "meta": {"serial": "S1"}},
                    {"label": "b3", "meta": {"serial": "S3"}},
                ]

        with mock.patch.object(escrow_srp, "EscrowRecovery", FakeRecovery):
            out = client.list_recoverable_bottles("https://h", "e", "pet")
        assert out == [
            {"id": "b1", "otbottle": b"OT1", "meta": {"serial": "S1"}},
            {"id": "b3", "otbottle": b"OT3", "meta": {"serial": "S3"}},
        ]

    def test_metadata_failure_is_best_effort(self) -> None:
        # GETRECORDS erroring must not block the join - bottles still returned with empty meta.
        client = self._client([{"id": "b1", "otbottle": b"OT1"}])

        class BoomRecovery:
            def __init__(self, *_args: object, **_kwargs: object) -> None:
                pass

            def list_records(self) -> Never:
                msg = "escrowproxy down"
                raise escrow_srp.EscrowError(msg)

        with mock.patch.object(escrow_srp, "EscrowRecovery", BoomRecovery):
            out = client.list_recoverable_bottles("https://h", "e", "pet")
        assert out == [{"id": "b1", "otbottle": b"OT1", "meta": {}}]


if __name__ == "__main__":
    unittest.main()

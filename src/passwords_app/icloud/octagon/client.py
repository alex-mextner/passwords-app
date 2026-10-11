# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Octagon trust: this device's keychain peer, the escrow-recovery join, and the view keys.

The peer identity (two P-384 key pairs and its signed permanent/stable/dynamic info) lives in
the session record under "octagon" and never changes once generated: trust membership is tied
to it, not to the short-lived auth tokens. Joining recovers a device's escrow bottle with that
device's passcode and has the recovered identity vouch for ours.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from passwords_app.icloud.errors import AppleError
from passwords_app.icloud.escrow import bottle as escrow
from passwords_app.icloud.escrow import srp as escrow_srp
from passwords_app.icloud.keychain import pipeline
from passwords_app.icloud.octagon import keys as ok
from passwords_app.icloud.proto import cuttlefish as cf
from passwords_app.icloud.proto.codec import all_bytes, decode_fields, first_bytes, first_message
from passwords_app.icloud.proto.codec import first_str as _first_str
from passwords_app.icloud.transport import ckks, cloudkit
from passwords_app.icloud.values import Record, child, integer, items, text

if TYPE_CHECKING:
    from collections.abc import Callable

    import requests

    from passwords_app.icloud.auth.anisette import AnisetteSource
    from passwords_app.icloud.auth.device import Device

# Prevailing builtin Octagon policy version <-> hash, declared in our stableInfo.
FROZEN_POLICY_VERSION = 5
FROZEN_POLICY_HASH = "SHA256:O/ECQlWhvNlLmlDNh2+nal/yekUC87bXpV3k+6kznSo="
FLEXIBLE_POLICY_VERSION = 20
FLEXIBLE_POLICY_HASH = "SHA256:OIzjC3WyLGrM8GAd/EyIfVzTJdYmcGoKPFdQeWeRZTY="

PEER_MODEL_ID = "MacBookPro18,3"
PEER_OS_VERSION = "macOS 13.4.1 (22F8)"
_DEFAULT_SERIAL = "0000000000"


class OctagonError(AppleError):
    pass


def is_joined(record: Record) -> bool:
    oct_state = child(record, "octagon")
    return bool(oct_state.get("joined") or oct_state.get("sponsor"))


def _stable(keys: ok.PeerKeySet, clock: int, serial: str) -> ok.StableInfo:
    return ok.build_stable_info(
        keys,
        clock=clock,
        frozen_policy_version=FROZEN_POLICY_VERSION,
        frozen_policy_hash=FROZEN_POLICY_HASH,
        flexible_policy_version=FLEXIBLE_POLICY_VERSION,
        flexible_policy_hash=FLEXIBLE_POLICY_HASH,
        device_name="",
        serial_number=serial,
        os_version=PEER_OS_VERSION,
        user_controllable_views=ok.UCV_FOLLOWING,
    )


def ensure_peer_identity(record: Record, device: Device, *, clock: int = 1) -> Record:
    """Generate (once) the Octagon self-peer into `record["octagon"]`; return that dict.

    The stored stable/dynamic info is an initial form; the join regenerates and re-signs both
    from the live trust state (`build_join_peer`), as Apple's client does.
    """
    oct_state = child(record, "octagon")
    if text(oct_state, "peer_id"):
        return oct_state
    keys = ok.PeerKeySet.generate()
    now = int(time.time())
    perm = ok.build_permanent_info(
        keys,
        machine_id=device.device_id or str(record.get("dsid_numeric") or ""),
        model_id=PEER_MODEL_ID,
        epoch=1,
        creation_time=now,
    )
    stable = _stable(keys, clock, device.serial or _DEFAULT_SERIAL)
    dynamic = ok.build_dynamic_info(keys, clock=clock, included_peer_ids=[perm.peer_id])
    fresh: Record = {
        "peer_id": perm.peer_id,
        "keys": keys.to_storage(),
        "permanent": {"data": perm.data.hex(), "sig": perm.sig.hex()},
        "stable": stable.to_storage(),
        "dynamic": dynamic.to_storage(),
        "created_at": now,
    }
    record["octagon"] = fresh
    return fresh


def load_peer_keys(oct_state: Record) -> ok.PeerKeySet:
    return ok.PeerKeySet.from_storage(child(oct_state, "keys"))


def trust_from_changes(
    changes: cf.FetchChanges, sponsor_peer_id: str
) -> tuple[list[str], int, int]:
    """(sponsor's included peer ids, next stable clock, next dynamic clock) from fetchChanges."""
    stable_clocks = [0]
    included: list[str] = []
    sponsor_clock = 0
    for peer in changes.peers:
        if peer.stable_info is not None:
            stable = ok.parse_stable_info_data(peer.stable_info.info)
            stable_clocks.append(integer(stable, "clock") or 0)
        if peer.hash == sponsor_peer_id and peer.dynamic_info is not None:
            parsed = ok.parse_dynamic_info_data(peer.dynamic_info.info)
            included = [str(x) for x in items(parsed.get("included"))]
            sponsor_clock = integer(parsed, "clock") or 0
    return included, max(stable_clocks) + 1, sponsor_clock + 1


def build_join_peer(  # noqa: PLR0913, PLR0917 - the peer plus the live trust state it joins into
    oct_state: Record,
    keys: ok.PeerKeySet,
    voucher: cf.SignedBlob,
    included_peer_ids: list[str],
    stable_clock: int,
    dynamic_clock: int,
    serial: str,
) -> bytes:
    """Re-sign stable and dynamic info for the join and encode the CuttlefishPeer."""
    our_peer_id = text(oct_state, "peer_id") or ""
    stable = _stable(keys, stable_clock, serial)
    included_ids = list(dict.fromkeys([*included_peer_ids, our_peer_id]))
    dynamic = ok.build_dynamic_info(keys, clock=dynamic_clock, included_peer_ids=included_ids)
    perm = child(oct_state, "permanent")
    return cf.encode_cuttlefish_peer(
        our_peer_id,
        cf.SignedBlob(
            bytes.fromhex(text(perm, "data") or ""), bytes.fromhex(text(perm, "sig") or "")
        ),
        cf.SignedBlob(stable.data, stable.sig),
        cf.SignedBlob(dynamic.data, dynamic.sig),
        voucher=voucher,
    )


def parse_viable_bottles(raw: bytes) -> list[Record]:
    """FetchViableBottles -> [{id, otbottle}] (otbottle None when not decryptable here)."""
    out: list[Record] = []
    for ed in all_bytes(decode_fields(raw), 1):
        edf = decode_fields(ed)
        bottle_msg = first_message(edf, 2)
        otbottle = first_bytes(bottle_msg, 2) if bottle_msg is not None else None
        out.append({"id": _first_str(edf, 1), "otbottle": otbottle})
    return out


def transport_for(
    record: Record,
    device: Device,
    anisette: AnisetteSource,
    *,
    container: str = cloudkit.CUTTLEFISH_CONTAINER,
    http: requests.Session | None = None,
) -> cloudkit.CloudKitTransport:
    """Build a CloudKit transport authed with the session's tokens (resolving cloudKitUserId once).

    `record["webservices"]["gateway"]`, when present, replaces Apple's gateway (local tests).
    """
    mme = child(record, "mme")
    ck_token = text(child(mme, "tokens"), "cloudKitToken")
    if not ck_token:
        msg = "no cloudKitToken in the session; sign in again"
        raise OctagonError(msg)
    gateway = text(child(record, "webservices"), "gateway") or cloudkit.GATEWAY_URL
    user_id = text(mme, "cloudKitUserId")
    if not user_id:
        mme_token = text(mme, "mmeAuthToken")
        if not mme_token:
            msg = "no mmeAuthToken in the session; sign in again"
            raise OctagonError(msg)
        user_id = cloudkit.ck_app_init(
            cloudkit.CUTTLEFISH_CONTAINER,
            cloudkit.CUTTLEFISH_BUNDLE,
            str(mme.get("dsid") or record.get("dsid_numeric") or ""),
            mme_token,
            anisette,
            url=gateway.rstrip("/") + "/setup/setup/ck/v1/ckAppInit",
            http=http,
        )
        mme["cloudKitUserId"] = user_id
        record["mme"] = mme  # persisted by the caller's next session save
    dev = cloudkit.DeviceConfig(
        device_uuid=device.device_id, serial=device.serial or _DEFAULT_SERIAL
    )
    return cloudkit.CloudKitTransport(
        ck_token, user_id, dev, anisette, container=container, gateway=gateway, http=http
    )


class OctagonClient:
    """The live join and view-key calls of a signed-in session."""

    def __init__(
        self,
        record: Record,
        device: Device,
        anisette: AnisetteSource,
        *,
        transport: cloudkit.CloudKitTransport | None = None,
        http: requests.Session | None = None,
    ) -> None:
        self.record = record
        self.device = device
        self.anisette = anisette
        self.adsid = text(record, "dsid") or ""  # the GUID adsid (escrow key derivation)
        self._http = http
        self.transport = transport or transport_for(record, device, anisette, http=http)
        self.user_id = self.transport.user_id

    def fetch_changes(self, sync_token: str | None = None) -> cf.FetchChanges:
        result = self.transport.invoke("fetchChanges", cf.encode_fetch_changes_request(sync_token))
        return cf.parse_fetch_changes_response(result.serialized_result)

    def fetch_viable_bottles(self) -> list[Record]:
        result = self.transport.invoke(
            "fetchViableBottles", escrow_srp.encode_fetch_viable_bottles_request()
        )
        return parse_viable_bottles(result.serialized_result)

    def list_recoverable_bottles(
        self, escrow_host: str, email: str, pet: str, *, warn: Callable[[str], None] | None = None
    ) -> list[Record]:
        """Viable bottles with the escrow metadata that names each backed-up device."""
        bottles = [b for b in self.fetch_viable_bottles() if b.get("otbottle")]
        meta_by_label: dict[str, Record] = {}
        try:
            recovery = escrow_srp.EscrowRecovery(
                escrow_host, email, pet, self.anisette, http=self._http
            )
            for rec in recovery.list_records():
                meta_by_label[str(rec.get("label") or "")] = child(rec, "meta")
        except escrow_srp.EscrowError as e:
            # The names are a convenience; the bottles themselves are still usable.
            if warn is not None:
                warn(f"device names unavailable: {e}")
        return [
            {"id": b["id"], "otbottle": b["otbottle"], "meta": meta_by_label.get(str(b["id"]), {})}
            for b in bottles
        ]

    def _recover_sponsor(  # noqa: PLR0913 - escrow credentials, the bottle and the consent gate
        self,
        escrow_host: str,
        email: str,
        pet: str,
        passcode: bytes,
        chosen: Record,
        *,
        confirm_irreversible: bool,
    ) -> escrow.RecoveredIdentity:
        """Recover the chosen escrow bottle (IRREVERSIBLE) and remember the sponsor identity.

        The sponsor is entitled to the user-controllable views (Passwords), so its encryption
        key is what later fetches their TLKs. Each call spends one of ~10 escrow attempts.
        """
        otbottle = chosen.get("otbottle")
        bottle_id = text(chosen, "id")
        if not isinstance(otbottle, bytes) or not bottle_id:
            msg = "no viable escrow bottle found for this account"
            raise OctagonError(msg)
        recovery = escrow_srp.EscrowRecovery(
            escrow_host, email, pet, self.anisette, http=self._http
        )
        entropy = recovery.try_recover_escrow(
            bottle_id, passcode, confirm_irreversible=confirm_irreversible
        )
        identity = escrow.recover_identity(escrow.OTBottle.parse(otbottle), entropy, self.adsid)
        oct_state = child(self.record, "octagon")
        oct_state["sponsor"] = {
            "peer_id": identity.peer_id,
            "encryption_priv_x963": identity.encryption_key.private_x963().hex(),
        }
        self.record["octagon"] = oct_state
        return identity

    def join_via_escrow(  # noqa: PLR0913 - escrow credentials, the bottle and the consent gate
        self,
        escrow_host: str,
        email: str,
        pet: str,
        passcode: bytes,
        chosen: Record,
        *,
        confirm_irreversible: bool = False,
    ) -> str:
        """Recover the chosen bottle, have it vouch for us, and join; return the sponsor id."""
        identity = self._recover_sponsor(
            escrow_host, email, pet, passcode, chosen, confirm_irreversible=confirm_irreversible
        )
        oct_state = child(self.record, "octagon")
        voucher = identity.make_voucher(text(oct_state, "peer_id") or "")
        changes = self.fetch_changes()
        included_ids, stable_clock, dyn_clock = trust_from_changes(changes, identity.peer_id)
        peer = build_join_peer(
            oct_state,
            load_peer_keys(oct_state),
            voucher,
            included_ids or [identity.peer_id],
            stable_clock,
            dyn_clock,
            self.device.serial or _DEFAULT_SERIAL,
        )
        token = changes.sync_token
        req = cf.encode_join_with_voucher_request(
            peer, restore_point=token if isinstance(token, str) else None
        )
        self.transport.invoke("joinWithVoucher", req)
        oct_state["joined"] = True
        self.record["octagon"] = oct_state
        return identity.peer_id

    def _fetch_recoverable_for(
        self, peer_id: str, key: ok.PeerKey
    ) -> tuple[dict[str, bytes], list[ckks.CloudKitRecord]]:
        result = self.transport.invoke(
            "fetchRecoverableTLKShares", cf.encode_fetch_recoverable_tlkshares_request(peer_id)
        )
        parsed = cf.parse_recoverable_tlkshares_response(result.serialized_result)
        shares = [ckks.parse_record(r) for r in parsed.share_records]
        synckeys = [ckks.parse_record(r) for r in parsed.synckey_records]
        return pipeline.unwrap_tlkshares(shares, peer_id, key.private_key), synckeys

    def fetch_recoverable_tlks(self) -> tuple[dict[str, bytes], list[ckks.CloudKitRecord]]:
        """Every view's TLK we can recover, for our own peer and for the escrow sponsor.

        A freshly joined peer is entitled only to the always-on views; the sponsor also gets
        the user-controllable ones (Passwords). Both answers are merged.
        """
        oct_state = child(self.record, "octagon")
        keys = load_peer_keys(oct_state)
        tlks, synckeys = self._fetch_recoverable_for(
            text(oct_state, "peer_id") or "", keys.encryption
        )
        sponsor = child(oct_state, "sponsor")
        sponsor_id, sponsor_key = text(sponsor, "peer_id"), text(sponsor, "encryption_priv_x963")
        if sponsor_id and sponsor_key:
            sp_tlks, sp_synckeys = self._fetch_recoverable_for(
                sponsor_id, ok.load_peer_key_x963(bytes.fromhex(sponsor_key))
            )
            tlks = {**tlks, **sp_tlks}
            synckeys = [*synckeys, *sp_synckeys]
        return tlks, synckeys

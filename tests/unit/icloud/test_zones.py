# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Incremental zone fetch and its persistent cache."""

# pyright: reportPrivateUsage=false
# Record decoding and identifier derivation are tested directly as units.

from __future__ import annotations

import json
import stat
from typing import TYPE_CHECKING

import pytest

from passwords_app.icloud.keychain import zones
from passwords_app.icloud.keychain.zones import CacheError, ZoneCache, ZoneState, _decode, sync_zone
from passwords_app.icloud.proto import codec as pb
from passwords_app.icloud.transport import ckks
from passwords_app.icloud.transport.cloudkit import CloudKitError

if TYPE_CHECKING:
    from pathlib import Path

ZONE = ckks.ZoneId("Passwords", "_u")


def _rec(name: str, etag: str, **fields: ckks.FieldValue) -> ckks.CloudKitRecord:
    return ckks.CloudKitRecord(name, "item", fields, etag=etag, zone=ZONE)


def _page(changes: list[tuple[str, ckks.CloudKitRecord | None]], token: bytes, more: bool) -> bytes:
    raw = [
        ckks.build_change(
            name, ZONE, rec.etag if rec else None, ckks.encode_record(rec) if rec else None
        )
        for name, rec in changes
    ]
    return ckks.build_changes_page(raw, token, ckks.STATUS_MORE if more else 3)


class Feed:
    """Answers fetches from a queue of pages, recording the token of each request."""

    def __init__(self, *answers: bytes | Exception) -> None:
        self.answers = list(answers)
        self.tokens: list[bytes | None] = []

    def fetch_records(self, zone_request_bytes: bytes) -> bytes:
        f = pb.decode_fields(zone_request_bytes)
        self.tokens.append(pb.first_bytes(f, 1))
        assert ckks.parse_zone_identifier(pb.first_bytes(f, 2) or b"") == ZONE
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


def test_first_fetch_pages_through_every_change() -> None:
    feed = Feed(
        _page([("A", _rec("A", "1"))], b"t1", more=True),
        _page([("B", _rec("B", "2"))], b"t2", more=False),
    )
    state = sync_zone(feed, ZONE, ZoneState())
    assert feed.tokens == [None, b"t1"]
    assert sorted(state.records) == ["A", "B"]
    assert state.token == b"t2"


def test_incremental_fetch_sends_the_saved_token_and_applies_changes() -> None:
    old = ZoneState(b"t5", {"A": _rec("A", "1"), "B": _rec("B", "1")})
    feed = Feed(
        _page([("A", _rec("A", "2", x=1)), ("B", None), ("C", _rec("C", "1"))], b"t6", more=False)
    )
    state = sync_zone(feed, ZONE, old)
    assert feed.tokens == [b"t5"]
    assert {n: r.etag for n, r in state.records.items()} == {"A": "2", "C": "1"}
    assert state.token == b"t6"


def test_deletion_of_unknown_record_is_harmless() -> None:
    state = sync_zone(Feed(_page([("Z", None)], b"t", more=False)), ZONE, ZoneState())
    assert state.records == {}


def test_failed_fetch_leaves_the_previous_state_untouched() -> None:
    old = ZoneState(b"t1", {"A": _rec("A", "1")})
    feed = Feed(_page([("A", None)], b"t2", more=True), CloudKitError("boom"))
    with pytest.raises(CloudKitError):
        sync_zone(feed, ZONE, old)
    assert old.token == b"t1"
    assert list(old.records) == ["A"]


def test_expired_token_restarts_from_scratch() -> None:
    old = ZoneState(b"old", {"GONE": _rec("GONE", "1")})
    feed = Feed(
        CloudKitError("reset", client_error=40), _page([("A", _rec("A", "1"))], b"t1", more=False)
    )
    state = sync_zone(feed, ZONE, old)
    assert feed.tokens == [b"old", None]
    assert list(state.records) == ["A"]


def test_reset_on_a_first_fetch_is_an_error() -> None:
    with pytest.raises(CloudKitError):
        sync_zone(Feed(CloudKitError("reset", client_error=40)), ZONE, ZoneState())


@pytest.mark.parametrize("client_error", [None, 48, 59])
def test_other_failures_propagate(client_error: int | None) -> None:
    with pytest.raises(CloudKitError):
        sync_zone(Feed(CloudKitError("x", client_error=client_error)), ZONE, ZoneState(b"t"))


def test_malformed_page_is_a_cloudkit_error() -> None:
    with pytest.raises(CloudKitError, match="malformed"):
        sync_zone(Feed(b"\x0a\xff"), ZONE, ZoneState())


def test_page_without_token_keeps_the_previous_one() -> None:
    state = sync_zone(Feed(ckks.build_changes_page([], None, 3)), ZONE, ZoneState(b"keep"))
    assert state.token == b"keep"


def test_more_pages_without_a_token_is_an_error_not_a_complete_snapshot() -> None:
    # Treating this as "caught up" would publish a partial zone, which the sync engine would
    # read as mass deletion of every login not on the first page.
    feed = Feed(ckks.build_changes_page([], None, ckks.STATUS_MORE))
    with pytest.raises(CloudKitError, match="continuation token"):
        sync_zone(feed, ZONE, ZoneState(b"keep"))


def test_wrongly_typed_record_field_is_malformed_not_a_deletion() -> None:
    # Field 5 present but not a sub-message: reading it as "no record" would delete the
    # cached login and advance the token past it for good.
    old = ZoneState(b"t1", {"A": _rec("A", "1")})
    change = pb.Writer().message(1, ckks.record_identifier("A", ZONE)).uint64(5, 7).finish()
    feed = Feed(ckks.build_changes_page([change], b"t2", 3))
    with pytest.raises(CloudKitError, match="malformed"):
        sync_zone(feed, ZONE, old)
    assert old.token == b"t1"
    assert set(old.records) == {"A"}


@pytest.mark.parametrize(
    "change",
    [pb.Writer().string(2, "e2").finish(), pb.Writer().uint64(1, 123).string(2, "e2").finish()],
    ids=["no-id", "non-message-id"],
)
def test_change_naming_no_record_keeps_cache_and_token(change: bytes) -> None:
    old = ZoneState(b"t1", {"A": _rec("A", "1")})
    with pytest.raises(CloudKitError, match="malformed"):
        sync_zone(Feed(ckks.build_changes_page([change], b"t2", 3)), ZONE, old)
    assert (old.token, set(old.records)) == (b"t1", {"A"})


def test_deletion_in_another_zone_keeps_cache_and_token() -> None:
    old = ZoneState(b"t1", {"A": _rec("A", "1")})
    change = ckks.build_change("A", ckks.ZoneId("OtherZone", ZONE.owner), None, None)
    with pytest.raises(CloudKitError, match="malformed"):
        sync_zone(Feed(ckks.build_changes_page([change], b"new", 3)), ZONE, old)
    assert (old.token, set(old.records)) == (b"t1", {"A"})


def test_page_with_contradicting_statuses_is_not_a_finished_sync() -> None:
    page = pb.Writer().uint64(4, 3).uint64(4, ckks.STATUS_MORE).bytes(2, b"next").finish()
    with pytest.raises(CloudKitError, match="malformed"):
        sync_zone(Feed(page), ZONE, ZoneState(b"t1"))


def test_deletion_naming_two_records_keeps_cache_and_token() -> None:
    old = ZoneState(b"t1", {"A": _rec("A", "1"), "B": _rec("B", "1")})
    change = (
        pb.Writer()
        .message(1, ckks.record_identifier("A", ZONE))
        .message(1, ckks.record_identifier("B", ZONE))
        .finish()
    )
    with pytest.raises(CloudKitError, match="malformed"):
        sync_zone(Feed(ckks.build_changes_page([change], b"advanced", 3)), ZONE, old)
    assert (old.token, set(old.records)) == (b"t1", {"A", "B"})


def test_records_without_zone_get_the_fetched_zone() -> None:
    raw = (
        pb.Writer()
        .message(2, pb.Writer().message(1, ckks._identifier("A", 1)))
        .message(3, pb.Writer().string(1, "item"))
    )
    change = pb.Writer().message(5, raw).finish()
    state = sync_zone(Feed(ckks.build_changes_page([change], b"t", 3)), ZONE, ZoneState())
    assert state.records["A"].zone == ZONE


def test_endless_feed_is_cut_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(zones, "_MAX_PAGES", 3)
    feed = Feed(*[_page([], b"t", more=True)] * 3)
    with pytest.raises(CloudKitError, match="never ended"):
        sync_zone(feed, ZONE, ZoneState())


# --- the cache file --------------------------------------------------------------------------


def test_cache_round_trips_tokens_and_records(tmp_path: Path) -> None:
    path = tmp_path / "zones.json"
    cache = ZoneCache(path)
    cache.zones[cache.key(ZONE)] = ZoneState(b"\x00tok", {"A": _rec("A", "e1", x=b"\x01", y="s")})
    cache.save()
    again = ZoneCache(path)
    assert again.get(ZONE).token == b"\x00tok"
    assert again.get(ZONE).records == {"A": _rec("A", "e1", x=b"\x01", y="s")}


def test_cache_file_is_private(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "zones.json"
    cache = ZoneCache(path)
    cache.get(ZONE)
    cache.save()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_save_replaces_atomically_and_leaves_no_temp_files(tmp_path: Path) -> None:
    path = tmp_path / "zones.json"
    for token in (b"a", b"b"):
        cache = ZoneCache(path)
        cache.zones[cache.key(ZONE)] = ZoneState(token, {})
        cache.save()
    assert [p.name for p in tmp_path.iterdir()] == ["zones.json"]
    assert ZoneCache(path).get(ZONE).token == b"b"


@pytest.mark.parametrize(
    "content",
    [
        b"not json",
        b"[]",
        json.dumps({"format": 99, "zones": {}}).encode(),
        json.dumps({"format": 1, "zones": {"k": {"records": {"A": "!!!"}}}}).encode(),
        json.dumps({"format": 1}).encode(),
    ],
)
def test_corrupt_cache_reads_as_empty(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "zones.json"
    path.write_bytes(content)
    assert ZoneCache(path).zones == {}
    with pytest.raises(CacheError):
        _decode(content)


def test_memory_only_cache_never_writes(tmp_path: Path) -> None:
    cache = ZoneCache(None)
    cache.get(ZONE).token = b"x"
    cache.save()
    assert list(tmp_path.iterdir()) == []


def test_zones_of_different_owners_are_separate() -> None:
    cache = ZoneCache(None)
    cache.get(ckks.ZoneId("group-1", "_a")).token = b"a"
    assert cache.get(ckks.ZoneId("group-1", "_b")).token is None


def test_by_type_filters_records() -> None:
    state = ZoneState(
        None, {"A": _rec("A", "1"), "K": ckks.CloudKitRecord("K", "synckey", {}, zone=ZONE)}
    )
    assert [r.record_name for r in state.by_type("synckey")] == ["K"]

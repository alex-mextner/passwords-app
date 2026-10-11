# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Incremental zone fetch and the on-disk cache that makes it possible.

CloudKit's change feed is relative to a continuation token, so after the first full fetch a
zone only reports what changed (records, or names without a record for deletions). The cache
keeps each zone's token and its current records (still encrypted by Apple's keys, with their
change tags) in one 0600 JSON file. A fetch either completes for every requested zone or
raises; a half-read zone never replaces the cached one.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import dataclasses
import json
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from passwords_app.icloud.proto.codec import ProtoError
from passwords_app.icloud.transport import ckks
from passwords_app.icloud.transport.cloudkit import (
    CLIENT_FULL_RESET_NEEDED,
    CloudKitError,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

_FORMAT = 1
_MAX_PAGES = 10_000  # a runaway feed is a server bug, not a big keychain


class ZoneFetcher(Protocol):
    def fetch_records(self, zone_request_bytes: bytes) -> bytes: ...


@dataclasses.dataclass(slots=True)
class ZoneState:
    token: bytes | None = None
    records: dict[str, ckks.CloudKitRecord] = dataclasses.field(
        default_factory=dict[str, ckks.CloudKitRecord]
    )

    def by_type(self, record_type: str) -> list[ckks.CloudKitRecord]:
        return [r for r in self.records.values() if r.type == record_type]


class CacheError(ValueError):
    """The cache file is unreadable; callers start from an empty cache."""


class ZoneCache:
    """Zone states keyed by "<owner>/<zone>", loaded from and saved to one file."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self.zones: dict[str, ZoneState] = {}
        if path is not None and path.exists():
            with contextlib.suppress(CacheError):
                self.zones = _decode(path.read_bytes())

    @staticmethod
    def key(zone: ckks.ZoneId) -> str:
        return f"{zone.owner}/{zone.name}"

    def get(self, zone: ckks.ZoneId) -> ZoneState:
        return self.zones.setdefault(self.key(zone), ZoneState())

    def save(self) -> None:
        if self.path is None:
            return
        data = _encode(self.zones)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".zones-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            Path(tmp).replace(self.path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                Path(tmp).unlink()
            raise


def _encode(zones: Mapping[str, ZoneState]) -> bytes:
    out: dict[str, object] = {}
    for key, state in zones.items():
        out[key] = {
            "token": base64.b64encode(state.token).decode() if state.token else None,
            "records": {
                name: base64.b64encode(ckks.encode_record(rec)).decode()
                for name, rec in state.records.items()
            },
        }
    return json.dumps({"format": _FORMAT, "zones": out}, sort_keys=True).encode()


def _decode(raw: bytes) -> dict[str, ZoneState]:
    try:
        doc = json.loads(raw)
        if not isinstance(doc, dict) or cast("dict[str, object]", doc).get("format") != _FORMAT:
            msg = "unknown cache format"
            raise CacheError(msg)
        zones: dict[str, ZoneState] = {}
        for key, entry in cast("dict[str, dict[str, object]]", doc["zones"]).items():
            token = entry.get("token")
            records = cast("dict[str, str]", entry.get("records") or {})
            zones[key] = ZoneState(
                base64.b64decode(token, validate=True) if isinstance(token, str) else None,
                {n: _cached_record(n, r) for n, r in records.items()},
            )
    except (ValueError, KeyError, TypeError, AttributeError, binascii.Error, ProtoError) as e:
        msg = "zone cache is corrupt"
        raise CacheError(msg) from e
    return zones


def _cached_record(name: str, raw: str) -> ckks.CloudKitRecord:
    record = ckks.parse_record(base64.b64decode(raw, validate=True))
    if record.record_name != name or record.zone is None:
        msg = f"cached record {name} is damaged"
        raise CacheError(msg)
    return record


def _apply(state: ZoneState, zone: ckks.ZoneId, changes: Iterable[ckks.RecordChange]) -> None:
    for change in changes:
        if change.record is None:
            state.records.pop(change.record_name, None)
        else:
            record = change.record
            if record.zone is None:
                record = dataclasses.replace(record, zone=zone)
            state.records[change.record_name] = record


def sync_zone(fetcher: ZoneFetcher, zone: ckks.ZoneId, state: ZoneState) -> ZoneState:
    """Bring `state` up to date with the server; return the new state (the input is untouched).

    An expired token (FULL_RESET_NEEDED) restarts from scratch. Any other failure raises.
    """
    try:
        return _pull(fetcher, zone, ZoneState(state.token, dict(state.records)))
    except CloudKitError as e:
        if e.client_error != CLIENT_FULL_RESET_NEEDED or state.token is None:
            raise
    return _pull(fetcher, zone, ZoneState())


def _pull(fetcher: ZoneFetcher, zone: ckks.ZoneId, state: ZoneState) -> ZoneState:
    zid = ckks.record_zone_identifier(zone.name, zone.owner)
    for _ in range(_MAX_PAGES):
        raw = fetcher.fetch_records(ckks.build_retrieve_changes_request(zid, state.token))
        try:
            page = ckks.parse_retrieve_changes_response(raw, zone)
        except ProtoError as e:
            msg = "CloudKit returned a malformed change page"
            raise CloudKitError(msg) from e
        _apply(state, zone, page.changes)
        if page.status == ckks.STATUS_MORE and page.continuation_token is None:
            # Stopping here would publish a partial zone as complete, which reads as every
            # login on the later pages having been deleted.
            msg = "CloudKit announced more changes without a continuation token"
            raise CloudKitError(msg)
        if page.continuation_token is not None:
            state.token = page.continuation_token
        if not page.more:
            return state
    msg = "the zone's change feed never ended"
    raise CloudKitError(msg)

# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Read and write website logins in the keychain's `Passwords` zone.

Fetching pulls the zone's changes into the cache, unwraps the zone keys and decrypts every
item; any record that cannot be read fails the whole fetch, because a shorter list would look
like deletions to the sync engine. Writes go out as one zone-atomic batch per login (its item
and sidecar together), each record conditional on the change tag it was read with.

Deleting works like the Passwords app: the login and its sidecar move into Apple's Recently
Deleted, where every Apple device can still recover them. Creating a login whose record is
in Recently Deleted moves that record back instead of adding a duplicate next to it.

A login's version token (the sync engine's etag) combines the change tags of its item and its
sidecar, so an edit to either on another device makes a stale write fail.

Apple keeps a login used on several websites as one record per website (see
`passwords.group_logins`); those records read as one login named after the oldest one, whose
token covers every record. Saving it rewrites the records together and never adds one;
deleting it moves them all into Recently Deleted.
"""

from __future__ import annotations

import dataclasses
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol, override

from passwords_app.icloud import passwords
from passwords_app.icloud.errors import AppleError
from passwords_app.icloud.keychain import pipeline
from passwords_app.icloud.keychain.crypto import KeychainCryptoError
from passwords_app.icloud.keychain.zones import ZoneCache, ZoneState, sync_zone
from passwords_app.icloud.transport import ckks
from passwords_app.icloud.transport.cloudkit import CLIENT_ATOMIC_FAILURE, CloudKitResult

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from cryptography.hazmat.primitives.asymmetric import ec

    from passwords_app.core.model import Credential

PASSWORDS_ZONE = "Passwords"


class RecordConflictError(AppleError):
    """The login changed on the server since the version the write was based on."""


class UnreadableZoneError(AppleError):
    """A record in the zone could not be decrypted, so the zone's contents are unknown."""


class RecordTransport(Protocol):
    def fetch_records(self, zone_request_bytes: bytes) -> bytes: ...

    def save_records(
        self, saves: Sequence[tuple[ckks.CloudKitRecord, bool]]
    ) -> list[CloudKitResult]: ...


RecoverableKeys = tuple[dict[str, bytes], list[ckks.CloudKitRecord]]


@dataclasses.dataclass(frozen=True, slots=True)
class Identity:
    """This device's keychain peer: the id TLK shares are addressed to and its decryption key."""

    peer_id: str
    encryption_key: ec.EllipticCurvePrivateKey


@dataclasses.dataclass(frozen=True, slots=True)
class LoginRecords:
    """A login's decrypted attributes and the records they live in."""

    login: passwords.Login
    item: ckks.CloudKitRecord
    sidecar: ckks.CloudKitRecord | None

    @property
    def etag(self) -> str:
        return version_token(self.item, self.sidecar)


@dataclasses.dataclass(frozen=True, slots=True)
class StoredLogin(LoginRecords):
    """A live login as stored, with the credential it maps to.

    `others` are the records of the same login on its other websites, oldest first.
    """

    credential: Credential
    others: tuple[LoginRecords, ...] = ()

    @property
    @override
    def etag(self) -> str:
        token = version_token(self.item, self.sidecar)
        return "".join((token, *(f"|{other.etag}" for other in self.others)))

    @property
    def records(self) -> tuple[LoginRecords, ...]:
        return (self, *self.others)


def version_token(item: ckks.CloudKitRecord, sidecar: ckks.CloudKitRecord | None) -> str:
    tag = item.etag or ""
    if sidecar is not None:
        tag += f"+{sidecar.record_name}:{sidecar.etag or ''}"
    return tag


class KeychainClient:
    """Logins of one keychain zone, over a record transport and a persistent zone cache."""

    def __init__(  # noqa: PLR0913 - collaborators plus the zone and test seams
        self,
        transport: RecordTransport,
        user_id: str,
        identity: Identity,
        recoverable_keys: Callable[[], RecoverableKeys],
        cache: ZoneCache,
        *,
        zone: str = PASSWORDS_ZONE,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._transport = transport
        self.zone = ckks.ZoneId(zone, user_id)
        self._identity = identity
        self._recoverable_keys = recoverable_keys
        self._recovered: RecoverableKeys | None = None
        self._cache = cache
        self._clock = clock
        self._decrypted: dict[tuple[str, str | None], passwords.Attributes] = {}
        self._keyrings: tuple[frozenset[tuple[str, str | None]], pipeline.KeyRing] | None = None

    # --- reading -----------------------------------------------------------------------------

    def fetch(self) -> dict[str, StoredLogin]:
        """Bring the zone up to date and return its logins by id; raise if an item is unreadable."""
        state = sync_zone(self._transport, self.zone, self._cache.get(self.zone))
        logins = self._logins(state)
        self._cache.zones[self._cache.key(self.zone)] = state
        self._cache.save()
        return logins

    def _keyring(self, state: ZoneState) -> pipeline.KeyRing:
        """Return the zone's keys, rebuilt only when a key record changed (unwrapping is ECDH)."""
        key_records = [
            r for r in state.records.values() if r.type in {"tlkshare", "synckey", "currentkey"}
        ]
        version = frozenset((r.record_name, r.etag) for r in key_records)
        if self._keyrings is not None and self._keyrings[0] == version:
            return self._keyrings[1]
        if self._recovered is None:
            self._recovered = self._recoverable_keys()
        tlks, synckeys = self._recovered
        zone_tlks = pipeline.unwrap_tlkshares(
            state.by_type("tlkshare"), self._identity.peer_id, self._identity.encryption_key
        )
        keyring = pipeline.build_keyring(
            [*state.by_type("synckey"), *synckeys],
            state.by_type("currentkey"),
            {**zone_tlks, **tlks},
        )
        self._keyrings = (version, keyring)
        return keyring

    def _decrypt(
        self, record: ckks.CloudKitRecord, keyring: pipeline.KeyRing
    ) -> passwords.Attributes:
        key = (record.record_name, record.etag)
        cached = self._decrypted.get(key)
        if cached is None:
            try:
                cached = pipeline.decrypt_item(record, keyring)
            except KeychainCryptoError as e:
                msg = f"cannot decrypt keychain item {record.record_name}: {e}"
                raise UnreadableZoneError(msg) from e
            self._decrypted[key] = cached
        return cached

    def _paired(self, state: ZoneState, *, deleted: bool = False) -> list[LoginRecords]:
        """Return the zone's logins with their records (`deleted`: those in Recently Deleted)."""
        keyring = self._keyring(state)
        records = {r.record_name: r for r in state.by_type("item")}
        items = [
            passwords.StoredItem(name, self._decrypt(rec, keyring)) for name, rec in records.items()
        ]
        return [
            LoginRecords(
                login,
                records[login.record_name],
                records[login.sidecar.record_name] if login.sidecar is not None else None,
            )
            for login in passwords.pair_logins(items, deleted=deleted)
        ]

    def _logins(self, state: ZoneState) -> dict[str, StoredLogin]:
        pairs = {pair.login.record_name: pair for pair in self._paired(state)}
        out: dict[str, StoredLogin] = {}
        for group in passwords.group_logins(pair.login for pair in pairs.values()):
            cred = passwords.group_credential(group)
            if cred is not None:
                first, *rest = (pairs[login.record_name] for login in group)
                out[cred.id] = StoredLogin(
                    first.login, first.item, first.sidecar, cred, tuple(rest)
                )
        return out

    # --- writing -----------------------------------------------------------------------------

    def _current(self) -> tuple[ZoneState, dict[str, StoredLogin]]:
        """Return the zone as last fetched, fetching it now if this cache has never seen it."""
        state = self._cache.get(self.zone)
        if state.token is None:
            self.fetch()
            state = self._cache.get(self.zone)
        return state, self._logins(state)

    def save(self, cred: Credential, etag: str | None) -> str:
        """Create (`etag` None) or update the login `cred.id`; return its new version token.

        Creating a login whose record sits in Recently Deleted moves that record back.
        """
        state, logins = self._current()
        existing = logins.get(cred.id)
        if (existing.etag if existing is not None else None) != etag:
            msg = f"login {cred.id} changed since it was read"
            raise RecordConflictError(msg)
        if existing is not None and existing.others:
            return self._save_group(state, existing, cred, logins)
        base: LoginRecords | None = existing
        if base is None:
            trashed = {p.login.record_name: p for p in self._paired(state, deleted=True)}
            base = trashed.get(cred.id)
        saves, item_name, side_name = self._plan(cred, base, logins, self._keyring(state))
        if not saves:
            return etag or ""
        results = self._transport.save_records(saves)
        _check(results, "saving the login")
        state = self._record_saved(state, saves, results)
        side = state.records.get(side_name) if side_name is not None else None
        return version_token(state.records[item_name], side)

    def _plan(
        self,
        cred: Credential,
        existing: LoginRecords | None,
        logins: Mapping[str, StoredLogin],
        keyring: pipeline.KeyRing,
    ) -> tuple[list[tuple[ckks.CloudKitRecord, bool]], str, str | None]:
        """Plan the (record, create?) saves turning `existing` into `cred`, and the record names.

        An `existing` login in Recently Deleted is moved back out by the same saves.
        """
        now = self._clock()
        if existing is None:
            attrs = passwords.new_login(cred, now)
            item = passwords.StoredItem(cred.id, {})
            prev_item = prev_side = side_attrs = None
        else:
            stored = existing.login
            live = stored
            if passwords.is_login(stored.item.attrs, deleted=True):
                live = passwords.moved_login(stored, now, deleted=False)
            attrs = passwords.updated_login(live, cred, now)
            item = stored.item
            prev_item, prev_side = existing.item, existing.sidecar
            side_attrs = stored.sidecar.attrs if stored.sidecar else None
        _refuse_duplicate(cred, attrs.item, item.record_name, logins)
        # The version token covers both records, so a save touching either one rewrites the
        # other unchanged too: its change tag then guards the batch against a concurrent edit
        # or deletion of the record this edit would otherwise not mention.
        side_name = _sidecar_name(attrs, prev_side)
        item_changed = attrs.item != item.attrs
        side_changed = attrs.sidecar is not None and attrs.sidecar != side_attrs
        if not (item_changed or side_changed):
            return [], item.record_name, side_name
        saves: list[tuple[ckks.CloudKitRecord, bool]] = [
            (
                pipeline.encrypt_item(
                    attrs.item, item.record_name, self.zone, keyring, previous=prev_item
                ),
                prev_item is None,
            )
        ]
        if side_name is not None and attrs.sidecar is not None:
            rec = pipeline.encrypt_item(
                attrs.sidecar, side_name, self.zone, keyring, previous=prev_side
            )
            saves.append((rec, prev_side is None))
        return saves, item.record_name, side_name

    def _save_group(
        self,
        state: ZoneState,
        existing: StoredLogin,
        cred: Credential,
        logins: Mapping[str, StoredLogin],
    ) -> str:
        """Save a login kept as several records (see `passwords.updated_group`).

        Every record's item goes into the batch, changed or not: the version token covers
        them all, so each change tag guards the batch against an edit to any of them.
        """
        keyring = self._keyring(state)
        group = passwords.updated_group(
            [records.login for records in existing.records], cred, self._clock()
        )
        saves: list[tuple[ckks.CloudKitRecord, bool]] = []
        changed = False
        for records, (login, attrs) in zip(existing.records, group.records, strict=True):
            if login.record_name not in group.dropped:
                _refuse_duplicate(cred, attrs.item, login.record_name, logins, group.dropped)
            changed = self._rewrite(records, attrs, keyring, saves) or changed
        if not changed:
            return existing.etag
        results = self._transport.save_records(saves)
        _check(results, "saving the login")
        state = self._record_saved(state, saves, results)
        saved = self._logins(state).get(cred.id)
        return saved.etag if saved is not None else ""

    def _rewrite(
        self,
        records: LoginRecords,
        attrs: passwords.LoginAttributes,
        keyring: pipeline.KeyRing,
        saves: list[tuple[ckks.CloudKitRecord, bool]],
    ) -> bool:
        """Add the saves turning `records` into `attrs`, every record; True if any changes."""
        login = records.login
        side_attrs = login.sidecar.attrs if login.sidecar is not None else None
        side_changed = attrs.sidecar is not None and attrs.sidecar != side_attrs
        item = pipeline.encrypt_item(
            attrs.item, login.record_name, self.zone, keyring, previous=records.item
        )
        saves.append((item, False))
        side_name = _sidecar_name(attrs, records.sidecar)
        # An unchanged sidecar is rewritten too, so its change tag guards the batch.
        if side_name is not None and attrs.sidecar is not None:
            side = pipeline.encrypt_item(
                attrs.sidecar, side_name, self.zone, keyring, previous=records.sidecar
            )
            saves.append((side, records.sidecar is None))
        return side_changed or attrs.item != login.item.attrs

    def _record_saved(
        self,
        state: ZoneState,
        saves: Sequence[tuple[ckks.CloudKitRecord, bool]],
        results: Sequence[CloudKitResult],
    ) -> ZoneState:
        """Adopt the server's new change tags; refetch when the answer does not carry them."""
        tags = [ckks.parse_save_response(r.field(ckks.FIELD_RECORD_SAVE) or b"") for r in results]
        if all(tags):
            for (rec, _), tag in zip(saves, tags, strict=True):
                state.records[rec.record_name] = dataclasses.replace(rec, etag=tag)
            self._cache.save()
            return state
        self.fetch()
        return self._cache.get(self.zone)

    def delete(self, item_id: str, etag: str | None) -> None:
        """Move a login and its sidecar into Recently Deleted, as the Passwords app deletes.

        `etag` None skips the check against the caller's version; the move itself is still
        conditional on the tags just read, so it never buries an edit it has not seen.
        """
        # The fresh read finds a sidecar added on another device since the last fetch, which
        # no change tag in the batch could guard; each save then carries the tag it was read
        # with, so an edit landing in the round trip fails the batch instead.
        logins = self.fetch()
        state = self._cache.get(self.zone)
        existing = logins.get(item_id)
        if existing is None:
            return
        if etag is not None and existing.etag != etag:
            msg = f"login {item_id} changed since it was read"
            raise RecordConflictError(msg)
        now = self._clock()
        keyring = self._keyring(state)
        saves: list[tuple[ckks.CloudKitRecord, bool]] = []
        for records in existing.records:
            trashed = passwords.moved_login(records.login, now, deleted=True)
            moves = [(trashed.item, records.item)]
            if trashed.sidecar is not None and records.sidecar is not None:
                moves.append((trashed.sidecar, records.sidecar))
            saves.extend(
                (
                    pipeline.encrypt_item(
                        moved.attrs, moved.record_name, self.zone, keyring, previous=previous
                    ),
                    False,
                )
                for moved, previous in moves
            )
        results = self._transport.save_records(saves)
        _check(results, "deleting the login")
        self._record_saved(state, saves, results)


def _refuse_duplicate(
    cred: Credential,
    item: passwords.Attributes,
    record_name: str,
    logins: Mapping[str, StoredLogin],
    leaving: frozenset[str] = frozenset(),
) -> None:
    """Refuse a save giving `item` the primary key of another stored record.

    `leaving` names records the same batch moves to Recently Deleted.
    """
    key = passwords.primary_key(item)
    for login in logins.values():
        for other in login.records:
            name = other.login.record_name
            if (
                name != record_name
                and name not in leaving
                and passwords.primary_key(other.login.item.attrs) == key
            ):
                msg = f"another login for {cred.username!r} on {cred.url} already exists"
                raise passwords.DuplicateLoginError(msg)


def _sidecar_name(
    attrs: passwords.LoginAttributes, prev_side: ckks.CloudKitRecord | None
) -> str | None:
    """Return the sidecar's record name: its current one, or a fresh one for a new sidecar."""
    if attrs.sidecar is None:
        return None
    return prev_side.record_name if prev_side is not None else str(uuid.uuid4()).upper()


def _check(results: Sequence[CloudKitResult], what: str) -> None:
    failed = [r for r in results if not r.ok]
    if not failed:
        return
    if any(r.conflict for r in failed):
        msg = f"{what}: the login changed on the server"
        raise RecordConflictError(msg)
    primary = next((r for r in failed if r.client_error != CLIENT_ATOMIC_FAILURE), failed[0])
    raise primary.error(what)

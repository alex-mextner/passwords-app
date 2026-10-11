# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Read and write website logins in the keychain's `Passwords` zone.

Fetching pulls the zone's changes into the cache, unwraps the zone keys and decrypts every
item; any record that cannot be read fails the whole fetch, because a shorter list would look
like deletions to the sync engine. Writes go out as one zone-atomic batch per login (its item
and sidecar together), each record conditional on the change tag it was read with.

A login's version token (the sync engine's etag) combines the change tags of its item and its
sidecar, so an edit to either on another device makes a stale write fail.
"""

from __future__ import annotations

import dataclasses
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol

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

    def delete_records(self, names: Sequence[tuple[str, ckks.ZoneId]]) -> list[CloudKitResult]: ...


RecoverableKeys = tuple[dict[str, bytes], list[ckks.CloudKitRecord]]


@dataclasses.dataclass(frozen=True, slots=True)
class Identity:
    """This device's keychain peer: the id TLK shares are addressed to and its decryption key."""

    peer_id: str
    encryption_key: ec.EllipticCurvePrivateKey


@dataclasses.dataclass(frozen=True, slots=True)
class StoredLogin:
    """A login as stored: its records, decrypted attributes and the credential they map to."""

    login: passwords.Login
    item: ckks.CloudKitRecord
    sidecar: ckks.CloudKitRecord | None
    credential: Credential

    @property
    def etag(self) -> str:
        return version_token(self.item, self.sidecar)


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

    def _logins(self, state: ZoneState) -> dict[str, StoredLogin]:
        keyring = self._keyring(state)
        records = {r.record_name: r for r in state.by_type("item")}
        items = [
            passwords.StoredItem(name, self._decrypt(rec, keyring)) for name, rec in records.items()
        ]
        out: dict[str, StoredLogin] = {}
        for login in passwords.pair_logins(items):
            cred = passwords.to_credential(login)
            if cred is None:
                continue
            side = records[login.sidecar.record_name] if login.sidecar is not None else None
            out[login.record_name] = StoredLogin(login, records[login.record_name], side, cred)
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
        """Create (`etag` None) or update the login `cred.id`; return its new version token."""
        state, logins = self._current()
        existing = logins.get(cred.id)
        if (existing.etag if existing is not None else None) != etag:
            msg = f"login {cred.id} changed since it was read"
            raise RecordConflictError(msg)
        saves, item_name, side_name = self._plan(cred, existing, logins, self._keyring(state))
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
        existing: StoredLogin | None,
        logins: Mapping[str, StoredLogin],
        keyring: pipeline.KeyRing,
    ) -> tuple[list[tuple[ckks.CloudKitRecord, bool]], str, str | None]:
        """Plan the (record, create?) saves turning `existing` into `cred`, and the record names."""
        now = self._clock()
        if existing is None:
            attrs = passwords.new_login(cred, now)
            item = passwords.StoredItem(cred.id, {})
            prev_item = prev_side = side_attrs = None
        else:
            attrs = passwords.updated_login(existing.login, cred, now)
            item = existing.login.item
            prev_item, prev_side = existing.item, existing.sidecar
            side_attrs = existing.login.sidecar.attrs if existing.login.sidecar else None
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
        """Delete a login and its sidecar together; `etag` None deletes whatever is there."""
        # Unlike a save, the delete request carries no change tag the server could check, so
        # the version is compared against a fresh read; only an edit landing in the round trip
        # between that read and the delete can still slip through.
        logins = self.fetch()
        state = self._cache.get(self.zone)
        existing = logins.get(item_id)
        if existing is None:
            return
        if etag is not None and existing.etag != etag:
            msg = f"login {item_id} changed since it was read"
            raise RecordConflictError(msg)
        names = [(existing.item.record_name, self.zone)]
        if existing.sidecar is not None:
            names.append((existing.sidecar.record_name, self.zone))
        _check(self._transport.delete_records(names), "deleting the login")
        for name, _ in names:
            state.records.pop(name, None)
        self._cache.save()


def _refuse_duplicate(
    cred: Credential,
    item: passwords.Attributes,
    record_name: str,
    logins: Mapping[str, StoredLogin],
) -> None:
    """Refuse a save giving `item` the primary key of another stored login."""
    key = passwords.primary_key(item)
    for other in logins.values():
        if other.item.record_name != record_name and (
            passwords.primary_key(other.login.item.attrs) == key
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

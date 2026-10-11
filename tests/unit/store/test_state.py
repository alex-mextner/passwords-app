# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""state.db: persistence, per-row AES-256-GCM, tamper detection, schema handling."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from contextlib import closing
from datetime import UTC, datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from tests.fakes.memory_stores import make_credential

from passwords_app.core.model import Credential, TrashEntry
from passwords_app.store.state import (
    KEY_SIZE,
    SCHEMA_VERSION,
    StateCorruptedError,
    StateSchemaError,
    StateStore,
)
from passwords_app.sync.plan import BaseEntry
from passwords_app.sync.ports import PendingDeletions

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
T0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "share" / "passwords-app" / "state.db"


@pytest.fixture
def store(db_path: Path) -> Iterator[StateStore]:
    with StateStore(db_path, KEY) as s:
        yield s


def sql(db_path: Path, query: str, *args: object) -> list[tuple[Any, ...]]:
    """Run one statement on a separate connection, the way an attacker or a bug would."""
    with closing(sqlite3.connect(db_path, isolation_level=None)) as conn:
        return conn.execute(query, args).fetchall()


def rich() -> Credential:
    return make_credential(
        "RICH",
        url="https://пример.рф:8443/вход",
        username="ålice 👩‍💻",
        password='fake "quoted" \\ back\nslash',
        title="Título",
        notes="line1\nline2\u0000nul",
        otpauth="otpauth://totp/x?issuer=y",
        alt_urls=("https://a.example", "https://b.example"),
        group="GROUP-1",
        created=datetime(2020, 2, 29, 23, 59, 59, 999999, tzinfo=UTC),
        modified=datetime(2026, 1, 2, 3, 4, 5, 6, tzinfo=UTC),
    )


# ---------------------------------------------------------------- opening


@pytest.mark.parametrize("size", [0, 16, 24, 31, 33, 64])
def test_key_must_be_256_bits(db_path: Path, size: int) -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        StateStore(db_path, bytes(size))


def test_key_size_constant_is_aes_256() -> None:
    assert KEY_SIZE == 32


def test_file_and_directory_are_private(db_path: Path, store: StateStore) -> None:
    assert stat.S_IMODE(db_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(db_path.parent.stat().st_mode) == 0o700


def test_existing_permissive_file_mode_is_not_widened(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    path.touch(mode=0o600)
    with StateStore(path, KEY):
        pass
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_wal_journal_mode(db_path: Path, store: StateStore) -> None:
    assert sql(db_path, "PRAGMA journal_mode")[0][0] == "wal"


def test_fresh_database_is_at_current_schema(store: StateStore) -> None:
    assert store.schema_version == SCHEMA_VERSION


def test_reopen_keeps_data_and_schema(db_path: Path) -> None:
    with StateStore(db_path, KEY) as s:
        s.set_base(BaseEntry(rich(), "e1"))
        s.set("k", "v")
    with StateStore(db_path, KEY) as s:
        assert s.schema_version == SCHEMA_VERSION
        assert s.bases() == {"RICH": BaseEntry(rich(), "e1")}
        assert s.get("k") == "v"


def test_migration_from_empty_v0_file_creates_every_table(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    sql(path, "CREATE TABLE unrelated (x)")
    with StateStore(path, KEY) as s:
        assert s.schema_version == SCHEMA_VERSION
    tables = {r[0] for r in sql(path, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"bases", "trash", "pending", "kv", "unrelated"} <= tables


def test_newer_schema_is_refused_and_left_untouched(tmp_path: Path) -> None:
    path = tmp_path / "future.db"
    sql(path, f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    with pytest.raises(StateSchemaError, match="newer"):
        StateStore(path, KEY)
    assert sql(path, "PRAGMA user_version")[0][0] == SCHEMA_VERSION + 1


def test_failed_migration_rolls_back_completely(tmp_path: Path) -> None:
    # A clashing table makes the v1 script fail half-way; nothing of it may remain.
    path = tmp_path / "clash.db"
    sql(path, "CREATE TABLE kv (k)")
    with pytest.raises(sqlite3.OperationalError):
        StateStore(path, KEY)
    assert sql(path, "PRAGMA user_version") == [(0,)]
    tables = {r[0] for r in sql(path, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert tables == {"kv"}


def test_wrong_key_cannot_read_rows(db_path: Path) -> None:
    with StateStore(db_path, KEY) as s:
        s.set_base(BaseEntry(rich(), "e1"))
    with StateStore(db_path, OTHER_KEY) as s, pytest.raises(StateCorruptedError):
        s.bases()


def test_secrets_never_hit_the_file_in_plaintext(db_path: Path) -> None:
    c = make_credential("PLAIN", password="fake-NEEDLE-in-haystack", notes="NOTE-NEEDLE")
    with StateStore(db_path, KEY) as s:
        s.set_base(BaseEntry(c, None))
        s.add_trash(TrashEntry("T", c, T0, "conflict"))
        s.set("token", "KV-NEEDLE")
    blob = b"".join(p.read_bytes() for p in db_path.parent.iterdir() if p.is_file())
    for needle in (b"NEEDLE", b"fake-", b"KV-NEEDLE"):
        assert needle not in blob


# ---------------------------------------------------------------- bases


def test_bases_round_trip_every_field(store: StateStore) -> None:
    store.set_base(BaseEntry(rich(), "etag-1"))
    assert store.bases()["RICH"] == BaseEntry(rich(), "etag-1")


@pytest.mark.parametrize("etag", [None, "", "e", "x" * 500])
def test_base_etag_round_trips(store: StateStore, etag: str | None) -> None:
    store.set_base(BaseEntry(make_credential("A"), etag))
    assert store.bases()["A"].etag == etag


def test_set_base_replaces(store: StateStore) -> None:
    store.set_base(BaseEntry(make_credential("A", password="fake-1"), "e1"))
    store.set_base(BaseEntry(make_credential("A", password="fake-2"), "e2"))
    bases = store.bases()
    assert len(bases) == 1
    assert bases["A"].credential.password == "fake-2"
    assert bases["A"].etag == "e2"


def test_drop_base(store: StateStore) -> None:
    store.set_base(BaseEntry(make_credential("A"), "e"))
    store.set_base(BaseEntry(make_credential("B"), "e"))
    store.drop_base("A")
    store.drop_base("missing")
    assert set(store.bases()) == {"B"}


def test_non_utc_timestamps_come_back_as_the_same_instant(store: StateStore) -> None:
    tz = datetime(2026, 3, 1, 10, 0, tzinfo=UTC).astimezone(
        timezone(timedelta(hours=5, minutes=30))
    )
    store.set_base(BaseEntry(make_credential("TZ", created=tz, modified=tz), None))
    back = store.bases()["TZ"].credential
    assert back.modified == tz
    assert back.modified.utcoffset() == timedelta(0)


def _tamper(db_path: Path, query: str, *args: object) -> None:
    sql(db_path, query, *args)


def test_flipped_ciphertext_bit_is_an_error_not_garbage(db_path: Path, store: StateStore) -> None:
    store.set_base(BaseEntry(make_credential("A"), "e"))
    ((blob,),) = sql(db_path, "SELECT blob FROM bases")
    flipped = bytes([blob[0]]) + blob[1:-1] + bytes([blob[-1] ^ 1])
    _tamper(db_path, "UPDATE bases SET blob = ?", flipped)
    with pytest.raises(StateCorruptedError, match="authentication"):
        store.bases()


def test_blob_moved_to_another_row_fails_authentication(db_path: Path, store: StateStore) -> None:
    store.set_base(BaseEntry(make_credential("A"), "e"))
    store.set_base(BaseEntry(make_credential("B"), "e"))
    ((blob_a,),) = sql(db_path, "SELECT blob FROM bases WHERE item_id='A'")
    _tamper(db_path, "UPDATE bases SET blob = ? WHERE item_id = 'B'", blob_a)
    with pytest.raises(StateCorruptedError):
        store.bases()


def test_etag_edited_in_place_fails_authentication(db_path: Path, store: StateStore) -> None:
    # A forged etag would make the next conditional write overwrite an unseen iCloud edit.
    store.set_base(BaseEntry(make_credential("A"), "e1"))
    _tamper(db_path, "UPDATE bases SET etag = 'e2'")
    with pytest.raises(StateCorruptedError):
        store.bases()


@pytest.mark.parametrize("length", [0, 1, 11, 12, 27])
def test_truncated_blob_is_corruption(db_path: Path, store: StateStore, length: int) -> None:
    store.set_base(BaseEntry(make_credential("A"), "e"))
    ((blob,),) = sql(db_path, "SELECT blob FROM bases")
    _tamper(db_path, "UPDATE bases SET blob = ?", blob[:length])
    with pytest.raises(StateCorruptedError):
        store.bases()


def test_renamed_row_id_fails_authentication(db_path: Path, store: StateStore) -> None:
    store.set_base(BaseEntry(make_credential("A"), "e"))
    _tamper(db_path, "UPDATE bases SET item_id = 'Z'")
    with pytest.raises(StateCorruptedError):
        store.bases()


# ---------------------------------------------------------------- trash


def entry(
    trash_id: str, *, days_ago: float = 0, reason: str = "conflict", item: str = "A"
) -> TrashEntry:
    return TrashEntry(
        trash_id,
        make_credential(item),
        T0 - timedelta(days=days_ago),
        reason,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(
    "reason", ["deleted-in-icloud", "deleted-on-linux", "deleted-both", "conflict"]
)
def test_trash_round_trips_each_reason(store: StateStore, reason: str) -> None:
    e = TrashEntry("T1", rich(), T0, reason)  # type: ignore[arg-type]
    assert store.add_trash(e) is True
    assert store.get_trash("T1") == e
    assert store.trash() == [e]


def test_add_trash_is_idempotent_per_trash_id(store: StateStore) -> None:
    assert store.add_trash(entry("T1")) is True
    assert store.add_trash(entry("T1", days_ago=3)) is False
    assert [e.deleted_at for e in store.trash()] == [T0]


def test_trash_lists_newest_first(store: StateStore) -> None:
    for i, days in enumerate([5, 0, 89, 1]):
        store.add_trash(entry(f"T{i}", days_ago=days))
    assert [e.trash_id for e in store.trash()] == ["T1", "T3", "T0", "T2"]


def test_get_missing_trash_is_none(store: StateStore) -> None:
    assert store.get_trash("nope") is None


def test_remove_trash(store: StateStore) -> None:
    store.add_trash(entry("T1"))
    assert store.remove_trash("T1") is True
    assert store.remove_trash("T1") is False
    assert store.trash() == []


@pytest.mark.parametrize(
    ("ages_days", "cutoff_days", "removed"),
    [
        ([], 90, 0),
        ([0, 1, 2], 90, 0),
        ([90], 90, 0),
        ([90.0001], 90, 1),
        ([91, 200, 5], 90, 2),
        ([10, 20, 30], 0, 3),
        ([10, 20, 30], 15, 2),
    ],
)
def test_purge_older_than_removes_strictly_older(
    store: StateStore, ages_days: list[float], cutoff_days: int, removed: int
) -> None:
    for i, age in enumerate(ages_days):
        store.add_trash(entry(f"T{i}", days_ago=age))
    assert store.purge_older_than(T0 - timedelta(days=cutoff_days)) == removed
    assert len(store.trash()) == len(ages_days) - removed


def test_purge_compares_instants_across_timezones(store: StateStore) -> None:
    store.add_trash(entry("T", days_ago=1))
    cutoff = (T0 - timedelta(hours=23)).astimezone(timezone(timedelta(hours=-8)))
    assert store.purge_older_than(cutoff) == 1


def test_trash_reason_tamper_is_detected(db_path: Path, store: StateStore) -> None:
    store.add_trash(entry("T1", reason="conflict"))
    _tamper(db_path, "UPDATE trash SET reason = 'deleted-both'")
    with pytest.raises(StateCorruptedError):
        store.trash()


def test_trash_date_tamper_is_detected(db_path: Path, store: StateStore) -> None:
    # Back-dating an entry would let the purge destroy it early.
    store.add_trash(entry("T1"))
    _tamper(db_path, "UPDATE trash SET deleted_at = '2000-01-01T00:00:00.000000Z'")
    with pytest.raises(StateCorruptedError):
        store.get_trash("T1")


def test_trash_blob_swap_between_entries_is_detected(db_path: Path, store: StateStore) -> None:
    store.add_trash(entry("T1", item="A"))
    store.add_trash(entry("T2", item="B"))
    ((b1,),) = sql(db_path, "SELECT blob FROM trash WHERE trash_id='T1'")
    _tamper(db_path, "UPDATE trash SET blob = ? WHERE trash_id = 'T2'", b1)
    with pytest.raises(StateCorruptedError):
        store.get_trash("T2")
    assert store.get_trash("T1") is not None


# ---------------------------------------------------------------- pending


def test_no_pending_by_default(store: StateStore) -> None:
    assert store.pending() is None


@pytest.mark.parametrize(
    "pending",
    [
        PendingDeletions(("A",), ()),
        PendingDeletions((), ("B",)),
        PendingDeletions(("A", "C"), ("B", "D")),
        PendingDeletions(tuple(f"L{i:04d}" for i in range(500)), ()),
    ],
)
def test_pending_round_trip(store: StateStore, pending: PendingDeletions) -> None:
    store.set_pending(pending)
    assert store.pending() == pending


def test_pending_is_replaced_not_merged(store: StateStore) -> None:
    store.set_pending(PendingDeletions(("A",), ("B",)))
    store.set_pending(PendingDeletions(("C",), ()))
    assert store.pending() == PendingDeletions(("C",), ())


@pytest.mark.parametrize("empty", [None, PendingDeletions((), ())])
def test_clearing_pending(store: StateStore, empty: PendingDeletions | None) -> None:
    store.set_pending(PendingDeletions(("A",), ()))
    store.set_pending(empty)
    assert store.pending() is None


def test_same_id_may_be_pending_on_both_sides(store: StateStore) -> None:
    store.set_pending(PendingDeletions(("X",), ("X",)))
    assert store.pending() == PendingDeletions(("X",), ("X",))


def test_pending_survives_reopen(db_path: Path) -> None:
    with StateStore(db_path, KEY) as s:
        s.set_pending(PendingDeletions(("A",), ("B",)))
    with StateStore(db_path, KEY) as s:
        assert s.pending() == PendingDeletions(("A",), ("B",))


def test_failed_pending_write_keeps_the_previous_value(store: StateStore) -> None:
    store.set_pending(PendingDeletions(("A",), ()))
    with pytest.raises(sqlite3.IntegrityError):
        store.set_pending(PendingDeletions(("B", "B"), ()))
    assert store.pending() == PendingDeletions(("A",), ())


# ---------------------------------------------------------------- key-value


@pytest.mark.parametrize("value", ["", "x", "ünïcødé ✓", "a\nb", "z" * 10_000])
def test_kv_round_trip(store: StateStore, value: str) -> None:
    store.set("k", value)
    assert store.get("k") == value


def test_kv_missing_and_delete(store: StateStore) -> None:
    assert store.get("missing") is None
    store.set("k", "v")
    store.delete("k")
    store.delete("k")
    assert store.get("k") is None


def test_kv_overwrite(store: StateStore) -> None:
    store.set("k", "v1")
    store.set("k", "v2")
    assert store.get("k") == "v2"


def test_kv_value_moved_to_other_key_is_detected(db_path: Path, store: StateStore) -> None:
    store.set("a", "1")
    store.set("b", "2")
    ((blob,),) = sql(db_path, "SELECT blob FROM kv WHERE key='a'")
    _tamper(db_path, "UPDATE kv SET blob = ? WHERE key = 'b'", blob)
    with pytest.raises(StateCorruptedError):
        store.get("b")


# ---------------------------------------------------------------- transactions


def test_transaction_commits_together(db_path: Path, store: StateStore) -> None:
    with store.transaction():
        store.set("a", "1")
        store.set_base(BaseEntry(make_credential("A"), "e"))
    with StateStore(db_path, KEY) as other:
        assert other.get("a") == "1"
        assert "A" in other.bases()


def test_transaction_rolls_back_on_error(store: StateStore) -> None:
    store.set("a", "old")

    def failing_batch() -> None:
        with store.transaction():
            store.set("a", "new")
            store.set_base(BaseEntry(make_credential("A"), "e"))
            raise RuntimeError

    with pytest.raises(RuntimeError):
        failing_batch()
    assert store.get("a") == "old"
    assert store.bases() == {}


def test_nested_transaction_joins_the_outer_one(store: StateStore) -> None:
    def failing_outer() -> None:
        with store.transaction():
            store.set("a", "1")
            with store.transaction():
                store.set("b", "2")
            raise RuntimeError

    with pytest.raises(RuntimeError):
        failing_outer()
    assert store.get("a") is None
    assert store.get("b") is None


# ---------------------------------------------------------------- properties

field_text = st.text(max_size=40)
any_credential = st.builds(
    lambda i, u, n, p, t, no, o, alt, g, c, m: Credential(
        id=i,
        url=u,
        username=n,
        password=p,
        title=t,
        notes=no,
        otpauth=o,
        alt_urls=tuple(alt),
        group=g,
        created=c,
        modified=m,
    ),
    st.text(min_size=1, max_size=40),
    st.text(min_size=1, max_size=60),
    field_text,
    field_text,
    st.none() | field_text,
    st.none() | field_text,
    st.none() | field_text,
    st.lists(field_text, max_size=3),
    st.none() | field_text,
    st.datetimes(timezones=st.just(UTC)),
    st.datetimes(timezones=st.just(UTC)),
)


@settings(max_examples=150)
@given(any_credential, st.none() | st.text(max_size=20))
def test_any_credential_round_trips_through_bases(
    tmp_path_factory: pytest.TempPathFactory, c: Credential, etag: str | None
) -> None:
    path = tmp_path_factory.mktemp("prop") / "state.db"
    with StateStore(path, os.urandom(32)) as s:
        s.set_base(BaseEntry(c, etag))
        assert s.bases() == {c.id: BaseEntry(c, etag)}


@settings(max_examples=100)
@given(any_credential)
def test_any_credential_round_trips_through_trash(
    tmp_path_factory: pytest.TempPathFactory, c: Credential
) -> None:
    path = tmp_path_factory.mktemp("prop") / "state.db"
    with StateStore(path, os.urandom(32)) as s:
        e = TrashEntry("T", c, T0, "conflict")
        s.add_trash(e)
        assert s.get_trash("T") == e


# ---------------------------------------------------------------- authentic but malformed rows
# A row sealed with the right key can still hold bad content (bug in an older version, or a
# key reused across files); it must surface as corruption, never as a half-built object.


def test_authentic_base_with_non_json_payload(db_path: Path, store: StateStore) -> None:
    blob = store._seal(b"not json", store._base_aad("A", None))
    sql(db_path, "INSERT INTO bases (item_id, etag, blob) VALUES ('A', NULL, ?)", blob)
    with pytest.raises(StateCorruptedError, match="malformed"):
        store.bases()


@pytest.mark.parametrize("drop", ["id", "url", "created", "alt_urls"])
def test_authentic_base_missing_a_field(db_path: Path, store: StateStore, drop: str) -> None:
    store.set_base(BaseEntry(make_credential("A"), None))
    (blob,) = sql(db_path, "SELECT blob FROM bases")[0]
    payload = json.loads(store._open(blob, store._base_aad("A", None)))
    del payload[drop]
    resealed = store._seal(json.dumps(payload).encode(), store._base_aad("A", None))
    sql(db_path, "UPDATE bases SET blob = ?", resealed)
    with pytest.raises(StateCorruptedError):
        store.bases()


def test_authentic_base_whose_credential_has_another_id(db_path: Path, store: StateStore) -> None:
    store.set_base(BaseEntry(make_credential("B"), None))
    (blob,) = sql(db_path, "SELECT blob FROM bases")[0]
    plaintext = store._open(blob, store._base_aad("B", None))
    sql(
        db_path,
        "UPDATE bases SET item_id = 'A', blob = ?",
        store._seal(plaintext, store._base_aad("A", None)),
    )
    with pytest.raises(StateCorruptedError, match="does not match"):
        store.bases()


def test_authentic_trash_row_with_unknown_reason(db_path: Path, store: StateStore) -> None:
    store.add_trash(entry("T1"))
    ((deleted_at, blob),) = sql(db_path, "SELECT deleted_at, blob FROM trash")
    plaintext = store._open(blob, store._trash_aad("T1", deleted_at, "conflict"))
    resealed = store._seal(plaintext, store._trash_aad("T1", deleted_at, "eaten-by-dog"))
    sql(db_path, "UPDATE trash SET reason = 'eaten-by-dog', blob = ?", resealed)
    with pytest.raises(StateCorruptedError, match="reason"):
        store.trash()


def test_authentic_kv_value_that_is_not_text(db_path: Path, store: StateStore) -> None:
    blob = store._seal(b"\xff\xfe", store._kv_aad("k"))
    sql(db_path, "INSERT INTO kv (key, blob) VALUES ('k', ?)", blob)
    with pytest.raises(StateCorruptedError, match="not text"):
        store.get("k")


def test_authentic_base_with_non_utc_timestamp_is_corruption(
    db_path: Path, store: StateStore
) -> None:
    store.set_base(BaseEntry(make_credential("A"), None))
    ((blob,),) = sql(db_path, "SELECT blob FROM bases")
    payload = json.loads(store._open(blob, store._base_aad("A", None)))
    payload["modified"] = "2026-01-01T00:00:00.000000+02:00"
    resealed = store._seal(json.dumps(payload).encode(), store._base_aad("A", None))
    sql(db_path, "UPDATE bases SET blob = ?", resealed)
    with pytest.raises(StateCorruptedError):
        store.bases()


@pytest.mark.parametrize(
    ("since_days", "expected"), [(None, 3), (100, 3), (50, 2), (10, 1), (0, 0)]
)
def test_trash_since_filters_by_deletion_time(
    store: StateStore, since_days: int | None, expected: int
) -> None:
    for i, age in enumerate([5, 30, 80]):
        store.add_trash(entry(f"T{i}", days_ago=age))
    since = None if since_days is None else T0 - timedelta(days=since_days)
    assert len(store.trash(since=since)) == expected

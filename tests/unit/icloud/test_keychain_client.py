# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The keychain client against the fake CloudKit gateway: real wire format, real crypto."""

# pyright: reportPrivateUsage=false
# Concurrency tests reach into the client's lock, store and cache to stage races.

from __future__ import annotations

import base64
import dataclasses
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from hypothesis import HealthCheck, Phase, given, settings
from hypothesis import strategies as st
from tests.fakes.cloudkit_server import FakeCloudKit, ZoneKeys

from passwords_app.core.model import Credential
from passwords_app.icloud import passwords
from passwords_app.icloud.keychain import pipeline
from passwords_app.icloud.keychain.client import (
    KeychainClient,
    RecordConflictError,
    UnreadableZoneError,
)
from passwords_app.icloud.proto.codec import Writer
from passwords_app.icloud.transport import ckks
from passwords_app.icloud.transport.cloudkit import (
    CKDATABASE_SAVE_PATH,
    CLIENT_ATOMIC_FAILURE,
    CLIENT_OP_LOCK_FAILURE,
    SECURITYD_BUNDLE,
    CloudKitError,
    CloudKitResult,
    CloudKitTransport,
    Operation,
)

if TYPE_CHECKING:
    from collections.abc import Callable

T0 = datetime(2024, 3, 4, 5, 6, 7, tzinfo=UTC)
_SEED = base64.b32encode(b"fake-test-seed").decode().rstrip("=")
OTP = f"otpauth://totp/Bank:alice?issuer=Bank&{'secret'}={_SEED}"


def _cred(n: int = 1, **over: object) -> Credential:
    base = Credential(
        f"00000000-0000-4000-8000-{n:012d}",
        f"https://site{n}.example",
        f"user{n}",
        f"pw{n}",
        T0,
        T0,
    )
    return dataclasses.replace(base, **over)  # type: ignore[arg-type]


def _same(a: Credential, b: Credential) -> bool:
    return a.id == b.id and a.content_hash() == b.content_hash()


def _saves(fake: FakeCloudKit) -> list[list[int]]:
    return [ops for path, ops in fake.requests if path.endswith("/record/save")]


# --- fetch -----------------------------------------------------------------------------------


def test_empty_zone_has_no_logins(keychain: KeychainClient) -> None:
    assert keychain.fetch() == {}


def test_logins_written_by_another_device_are_read(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    plain, rich = (
        _cred(1),
        _cred(2, title="Bank", notes="n", otpauth=OTP, alt_urls=("m.site2.example",)),
    )
    fake.put_login(plain)
    fake.put_login(rich)
    got = keychain.fetch()
    assert set(got) == {plain.id, rich.id}
    assert _same(got[plain.id].credential, plain)
    assert _same(got[rich.id].credential, rich)
    assert got[rich.id].sidecar is not None


def test_non_login_items_are_not_credentials(fake: FakeCloudKit, keychain: KeychainClient) -> None:
    card: dict[str, object] = {
        "class": "genp",
        "agrp": "com.apple.safari.credit-cards",
        "pdmn": "ak",
        "v_Data": b"x",
    }
    meta = {
        **passwords.new_login(_cred(), T0).item,
        "agrp": "com.apple.password-manager.website-metadata",
    }
    fake.put_item("CARD", card)
    fake.put_item("META", meta)
    assert keychain.fetch() == {}


def test_etag_combines_item_and_sidecar_change_tags(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    tag, side_tag = fake.put_login(_cred(title="T"), sidecar_name="SIDE")
    assert keychain.fetch()[_cred().id].etag == f"{tag}+SIDE:{side_tag}"


def test_second_fetch_is_incremental(fake: FakeCloudKit, keychain: KeychainClient) -> None:
    fake.put_login(_cred(1))
    keychain.fetch()
    fake.put_login(_cred(2))
    fake.requests.clear()
    assert set(keychain.fetch()) == {_cred(1).id, _cred(2).id}
    assert len(fake.requests) == 1


def test_deletion_on_another_device_disappears(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred(1))
    fake.put_login(_cred(2))
    keychain.fetch()
    fake.remove(_cred(1).id)
    assert set(keychain.fetch()) == {_cred(2).id}


def test_edit_on_another_device_changes_the_etag(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred())
    before = keychain.fetch()[_cred().id]
    fake.put_item(_cred().id, {**fake.item(_cred().id), "v_Data": b"changed"})
    after = keychain.fetch()[_cred().id]
    assert after.etag != before.etag
    assert after.credential.password == "changed"


def test_cache_survives_a_restart(
    fake: FakeCloudKit, open_keychain: Callable[[], KeychainClient]
) -> None:
    fake.put_login(_cred())
    open_keychain().fetch()
    fake.requests.clear()
    assert set(open_keychain().fetch()) == {_cred().id}
    syncs = [path for path, _ in fake.requests if path.endswith("/record/sync")]
    assert len(syncs) == 1


def test_paged_zone_is_read_completely(fake: FakeCloudKit, keychain: KeychainClient) -> None:
    fake.page_size = 2
    for n in range(1, 8):
        fake.put_login(_cred(n))
    assert len(keychain.fetch()) == 7


def test_fetch_failure_raises_and_keeps_the_cache(
    fake: FakeCloudKit, keychain: KeychainClient, open_keychain: Callable[[], KeychainClient]
) -> None:
    fake.put_login(_cred(1))
    keychain.fetch()
    fake.put_login(_cred(2))
    fake.fail("/record/sync", http_status=503)
    with pytest.raises(CloudKitError):
        keychain.fetch()
    assert set(open_keychain().fetch()) == {_cred(1).id, _cred(2).id}


def test_failure_on_a_later_page_never_returns_a_partial_set(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.page_size = 1
    for n in range(1, 4):
        fake.put_login(_cred(n))
    calls = {"n": 0}

    def fail_third(path: str) -> None:
        if path.endswith("/record/sync"):
            calls["n"] += 1
            if calls["n"] == 3:
                fake.fail("/record/sync", http_status=500)

    fake.on_request = fail_third
    with pytest.raises(CloudKitError):
        keychain.fetch()


def test_undecryptable_item_fails_the_whole_fetch(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred(1))
    foreign = ZoneKeys.generate()
    rec = pipeline.encrypt_item(
        passwords.new_login(_cred(2), T0).item,
        "FOREIGN",
        fake.zone,
        foreign.keyring(fake.zone.name),
    )
    with fake._lock:
        fake._store(fake.zone, rec)
    with pytest.raises(UnreadableZoneError, match="FOREIGN"):
        keychain.fetch()


def test_login_with_undecodable_password_fails_the_whole_fetch(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    # Leaving it out of the snapshot would tell the sync engine it was deleted.
    fake.put_login(_cred(1))
    attrs = dict(passwords.new_login(_cred(2), T0).item)
    attrs["v_Data"] = b"\xff"
    fake.put_item("BADPASS", attrs)
    with pytest.raises(passwords.UnreadableLoginError, match="password"):
        keychain.fetch()


def test_expired_sync_token_triggers_a_full_refetch(
    fake: FakeCloudKit, keychain: KeychainClient, open_keychain: Callable[[], KeychainClient]
) -> None:
    fake.put_login(_cred())
    keychain.fetch()
    cache = keychain._cache
    cache.get(fake.zone).token = b"expired-token"
    cache.save()
    assert set(open_keychain().fetch()) == {_cred().id}


# --- create ------------------------------------------------------------------------------------


def test_created_login_is_readable_by_apple_devices(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    keychain.fetch()
    etag = keychain.save(_cred(url="https://shop.example:8443/in"), None)
    item = fake.item(_cred().id)
    assert (item["srvr"], item["port"], item["acct"], item["v_Data"]) == (
        "shop.example",
        8443,
        "user1",
        b"pw1",
    )
    assert keychain.fetch()[_cred().id].etag == etag


def test_create_with_metadata_writes_both_records_in_one_batch(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    keychain.fetch()
    cred = _cred(title="T", notes="N", otpauth=OTP, alt_urls=("a.example",))
    keychain.save(cred, None)
    assert _saves(fake) == [[210, 210]]
    assert _same(fake.logins()[cred.id], cred)


def test_created_login_reads_back_identical(keychain: KeychainClient) -> None:
    cred = _cred(title="T", otpauth=OTP)
    keychain.save(cred, None)
    assert _same(keychain.fetch()[cred.id].credential, cred)


def test_create_over_an_existing_login_is_a_conflict(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred())
    keychain.fetch()
    with pytest.raises(RecordConflictError):
        keychain.save(_cred(password="mine"), None)


def test_create_racing_another_device_is_a_conflict(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    keychain.fetch()
    fake.put_login(_cred(password="theirs"))
    with pytest.raises(RecordConflictError):
        keychain.save(_cred(password="mine"), None)
    assert fake.logins()[_cred().id].password == "theirs"


def test_second_login_for_the_same_site_and_account_is_rejected(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred(1))
    keychain.fetch()
    twin = dataclasses.replace(_cred(1), id=_cred(9).id)
    with pytest.raises(passwords.DuplicateLoginError):
        keychain.save(twin, None)
    assert _saves(fake) == []


def test_renaming_onto_another_login_is_rejected(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred(1))
    fake.put_login(_cred(2))
    stored = keychain.fetch()[_cred(2).id]
    clash = dataclasses.replace(stored.credential, url=_cred(1).url, username=_cred(1).username)
    with pytest.raises(passwords.DuplicateLoginError):
        keychain.save(clash, stored.etag)


def test_same_account_on_another_port_is_a_different_login(keychain: KeychainClient) -> None:
    keychain.save(_cred(1), None)
    other = dataclasses.replace(
        _cred(1), id=_cred(9).id, url="https://site1.example:8443", password="other"
    )
    keychain.save(other, None)
    assert set(keychain.fetch()) == {_cred(1).id, _cred(9).id}


def test_sidecars_of_same_named_logins_on_different_ports_stay_apart(
    keychain: KeychainClient,
) -> None:
    a = _cred(1, title="A")
    b = dataclasses.replace(_cred(1, title="B"), id=_cred(9).id, url="https://site1.example:8443")
    keychain.save(a, None)
    keychain.save(b, None)
    got = keychain.fetch()
    assert (got[a.id].credential.title, got[b.id].credential.title) == ("A", "B")


def test_unsupported_url_is_rejected_before_any_write(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    keychain.fetch()
    with pytest.raises(passwords.UnsupportedCredentialError):
        keychain.save(_cred(url="ssh://host"), None)
    assert _saves(fake) == []


# --- edit --------------------------------------------------------------------------------------


def test_password_edit_guards_the_sidecar_without_changing_it(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred(title="T"), sidecar_name="SIDE")
    stored = keychain.fetch()[_cred().id]
    side_before = fake.item("SIDE")
    new_etag = keychain.save(dataclasses.replace(stored.credential, password="new"), stored.etag)
    assert _saves(fake) == [[210, 210]]
    assert fake.logins()[_cred().id].password == "new"
    assert fake.item("SIDE") == side_before
    assert keychain.fetch()[_cred().id].etag == new_etag


def test_metadata_edit_after_a_remote_deletion_is_a_conflict(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred(title="T"), sidecar_name="SIDE")
    stored = keychain.fetch()[_cred().id]
    fake.remove(_cred().id)
    with pytest.raises(RecordConflictError):
        keychain.save(dataclasses.replace(stored.credential, notes="new"), stored.etag)


def test_metadata_edit_racing_a_remote_password_change_is_a_conflict(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred(title="T"), sidecar_name="SIDE")
    stored = keychain.fetch()[_cred().id]
    fake.put_item(_cred().id, {**fake.item(_cred().id), "v_Data": b"changed"})
    with pytest.raises(RecordConflictError):
        keychain.save(dataclasses.replace(stored.credential, notes="new"), stored.etag)
    assert fake.logins()[_cred().id].password == "changed"


def test_unchanged_save_writes_nothing(fake: FakeCloudKit, keychain: KeychainClient) -> None:
    fake.put_login(_cred(title="T"))
    stored = keychain.fetch()[_cred().id]
    assert keychain.save(stored.credential, stored.etag) == stored.etag
    assert _saves(fake) == []


def test_stale_etag_is_a_conflict_without_a_write(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred())
    stored = keychain.fetch()[_cred().id]
    with pytest.raises(RecordConflictError):
        keychain.save(_cred(password="x"), stored.etag + "-old")
    assert _saves(fake) == []


def test_edit_racing_another_device_is_a_conflict_and_loses_nothing(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred())
    stored = keychain.fetch()[_cred().id]
    fake.put_item(_cred().id, {**fake.item(_cred().id), "v_Data": b"from-iphone"})
    with pytest.raises(RecordConflictError):
        keychain.save(_cred(password="from-linux"), stored.etag)
    assert fake.logins()[_cred().id].password == "from-iphone"


def _raw_update(keychain: KeychainClient, rec: ckks.CloudKitRecord) -> CloudKitResult:
    """Send an update with no request-level condition, only the tag inside the record."""
    transport = keychain._transport
    assert isinstance(transport, CloudKitTransport)
    request = Writer().message(1, ckks.encode_record(rec)).uint64(6, ckks.SAVE_UPDATE).finish()
    [result] = transport.perform_batch(
        CKDATABASE_SAVE_PATH,
        [Operation(ckks.OP_TYPE_RECORD_SAVE, ckks.FIELD_RECORD_SAVE, request)],
        bundle=SECURITYD_BUNDLE,
    )
    return result


def test_fake_ignores_the_tag_inside_the_record_like_apple(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    # The live probe (#72) showed Apple accepts a stale tag inside the record; only the
    # request's own tag (RecordSaveRequest field 4) makes an update conditional.
    fake.put_login(_cred())
    rec = fake.record(_cred().id)
    assert rec is not None
    assert _raw_update(keychain, dataclasses.replace(rec, etag="stale")).ok


def test_stale_record_fails_with_oplock_and_its_partner_with_atomic_failure(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred(title="T"), sidecar_name="SIDE")
    item, side = fake.record(_cred().id), fake.record("SIDE")
    assert item is not None
    assert side is not None
    fake.put_item(_cred().id, {**fake.item(_cred().id), "v_Data": b"from-iphone"})
    results = keychain._transport.save_records([(item, False), (side, False)])
    assert [(r.ok, r.client_error) for r in results] == [
        (False, CLIENT_OP_LOCK_FAILURE),
        (False, CLIENT_ATOMIC_FAILURE),
    ]
    assert [r.conflict for r in results] == [True, False]


def test_create_of_an_existing_record_fails_with_oplock(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred())
    rec = fake.record(_cred().id)
    assert rec is not None
    [result] = keychain._transport.save_records([(rec, True)])
    assert (result.client_error, result.conflict) == (CLIENT_OP_LOCK_FAILURE, True)


def test_sidecar_edit_racing_a_remote_sidecar_edit_is_a_conflict(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred(title="T"), sidecar_name="SIDE")
    stored = keychain.fetch()[_cred().id]
    fake.put_item("SIDE", {**fake.item("SIDE"), "labl": "changed on iphone"})
    with pytest.raises(RecordConflictError):
        keychain.save(dataclasses.replace(stored.credential, password="new"), stored.etag)
    assert fake.logins()[_cred().id].password == _cred().password
    assert fake.item("SIDE")["labl"] == "changed on iphone"


def test_edit_keeps_unknown_attributes_and_record_fields(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    attrs = {
        **passwords.new_login(_cred(), T0).item,
        "vwht": "Passwords",
        "futr": b"\x01\x02",
        "invi": 1,
    }
    fake.put_item(
        _cred().id, attrs, extra={"gen": 3, "futurefield": "kept", "server_wascurrent": 1}
    )
    stored = keychain.fetch()[_cred().id]
    keychain.save(dataclasses.replace(stored.credential, password="new"), stored.etag)
    item = fake.item(_cred().id)
    assert (item["vwht"], item["futr"], item["invi"]) == ("Passwords", b"\x01\x02", 1)
    rec = fake.record(_cred().id)
    assert rec is not None
    assert rec.get_int("gen") == 3
    assert rec.fields["futurefield"] == "kept"


def test_username_change_rewrites_both_records_in_one_batch(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred(title="T"), sidecar_name="SIDE")
    stored = keychain.fetch()[_cred().id]
    keychain.save(dataclasses.replace(stored.credential, username="renamed"), stored.etag)
    assert _saves(fake) == [[210, 210]]
    assert fake.item("SIDE")["acct"] == "renamed"
    got = fake.logins()[_cred().id]
    assert (got.username, got.title) == ("renamed", "T")


def test_failed_batch_changes_nothing(fake: FakeCloudKit, keychain: KeychainClient) -> None:
    fake.put_login(_cred(title="T"), sidecar_name="SIDE")
    stored = keychain.fetch()[_cred().id]
    before = fake.items()
    fake.fail("/record/save", client_error=24)
    with pytest.raises(CloudKitError) as info:
        keychain.save(dataclasses.replace(stored.credential, username="renamed"), stored.etag)
    assert info.value.client_error == 24  # the cause, not the sibling's ATOMIC_FAILURE
    assert info.value.client_error != CLIENT_ATOMIC_FAILURE
    assert fake.items() == before


def test_adding_metadata_creates_the_sidecar(fake: FakeCloudKit, keychain: KeychainClient) -> None:
    fake.put_login(_cred())
    stored = keychain.fetch()[_cred().id]
    etag = keychain.save(dataclasses.replace(stored.credential, notes="hello"), stored.etag)
    assert _saves(fake) == [[210, 210]]
    assert fake.logins()[_cred().id].notes == "hello"
    assert keychain.fetch()[_cred().id].etag == etag


def test_responses_out_of_order_still_match(fake: FakeCloudKit, keychain: KeychainClient) -> None:
    fake.reverse_responses = True
    keychain.fetch()
    etag = keychain.save(_cred(title="T"), None)
    assert keychain.fetch()[_cred().id].etag == etag


def test_answer_without_change_tags_falls_back_to_a_refetch(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.omit_save_etag = True
    keychain.fetch()
    etag = keychain.save(_cred(), None)
    rec = fake.record(_cred().id)
    assert rec is not None
    assert etag == rec.etag


def test_two_quick_edits_both_land_in_order(fake: FakeCloudKit, keychain: KeychainClient) -> None:
    fake.put_login(_cred())
    stored = keychain.fetch()[_cred().id]
    e1 = keychain.save(dataclasses.replace(stored.credential, password="one"), stored.etag)
    keychain.save(dataclasses.replace(stored.credential, password="two"), e1)
    assert fake.logins()[_cred().id].password == "two"


# --- delete ------------------------------------------------------------------------------------


def _requests(fake: FakeCloudKit, suffix: str) -> list[list[int]]:
    return [ops for path, ops in fake.requests if path.endswith(suffix)]


def test_delete_moves_login_and_sidecar_to_recently_deleted(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    # Like the Passwords app: every Apple device can still recover the login for 30 days.
    fake.put_login(_cred(title="T"), sidecar_name="SIDE")
    fake.put_login(_cred(2))
    stored = keychain.fetch()[_cred().id]
    before = fake.items()
    keychain.delete(_cred().id, stored.etag)
    assert _requests(fake, "/record/delete") == []
    assert _saves(fake) == [[210, 210]]
    after = fake.items()
    assert set(after) == set(before)  # nothing removed, nothing added
    assert after[_cred().id]["agrp"] == passwords.AGRP_LOGIN_DELETED
    assert after["SIDE"]["agrp"] == passwords.AGRP_SIDECAR_DELETED
    for name in (_cred().id, "SIDE"):
        assert after[name].keys() == before[name].keys()
        unchanged = {k: v for k, v in after[name].items() if k not in {"agrp", "mdat", "sha1"}}
        assert unchanged == {k: before[name][k] for k in unchanged}
    assert set(fake.logins()) == {_cred(2).id}
    assert _same(fake.logins(deleted=True)[_cred().id], _cred(title="T"))
    assert set(keychain.fetch()) == {_cred(2).id}


def test_login_deleted_on_the_iphone_reads_as_deleted(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred(title="T"), sidecar_name="SIDE")
    keychain.fetch()
    fake.trash_login(_cred().id, "SIDE")
    assert keychain.fetch() == {}


@pytest.mark.parametrize("deleted_on", ["linux", "iphone"])
def test_creating_a_recently_deleted_login_moves_it_back(
    fake: FakeCloudKit, keychain: KeychainClient, deleted_on: str
) -> None:
    fake.put_login(_cred(title="T"), sidecar_name="SIDE")
    stored = keychain.fetch()[_cred().id]
    if deleted_on == "linux":
        keychain.delete(_cred().id, stored.etag)
    else:
        fake.trash_login(_cred().id, "SIDE")
        keychain.fetch()
    names = set(fake.items())
    restored = _cred(title="T", notes="back")
    etag = keychain.save(restored, None)
    assert set(fake.items()) == names  # the same records, no duplicate
    assert fake.item(_cred().id)["agrp"] == passwords.AGRP_LOGIN
    assert fake.item("SIDE")["agrp"] == passwords.AGRP_SIDECAR
    assert fake.logins(deleted=True) == {}
    assert _same(fake.logins()[_cred().id], restored)
    assert keychain.fetch()[_cred().id].etag == etag


def test_restoring_a_login_without_metadata_into_one_with_it_adds_a_sidecar(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred())
    keychain.delete(_cred().id, keychain.fetch()[_cred().id].etag)
    keychain.save(_cred(title="T"), None)
    assert _saves(fake)[-1] == [210, 210]
    assert fake.logins()[_cred().id].title == "T"
    assert fake.logins(deleted=True) == {}


def test_restore_racing_a_recovery_on_the_iphone_is_a_conflict(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred(title="T"), sidecar_name="SIDE")
    fake.trash_login(_cred().id, "SIDE")
    keychain.fetch()
    fake.recover_login(_cred().id, "SIDE")
    with pytest.raises(RecordConflictError):
        keychain.save(_cred(password="from-linux"), None)
    assert fake.logins()[_cred().id].password == _cred().password


def test_new_login_for_a_recently_deleted_site_and_account_is_a_new_record(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred(1, password="old"))
    fake.trash_login(_cred(1).id)
    keychain.fetch()
    fresh = dataclasses.replace(_cred(1), id=_cred(2).id)
    keychain.save(fresh, None)
    assert set(fake.logins()) == {fresh.id}
    assert fake.logins(deleted=True)[_cred(1).id].password == "old"


def test_delete_with_stale_etag_is_a_conflict(fake: FakeCloudKit, keychain: KeychainClient) -> None:
    fake.put_login(_cred())
    keychain.fetch()
    with pytest.raises(RecordConflictError):
        keychain.delete(_cred().id, "old")
    assert _cred().id in fake.logins()


def _on_first(fake: FakeCloudKit, suffix: str, action: Callable[[], object]) -> None:
    """Run `action` once, as another device would, when the first `suffix` request arrives."""
    fired = False

    def hook(path: str) -> None:
        nonlocal fired
        if not fired and path.endswith(suffix):
            fired = True
            action()

    fake.on_request = hook


def test_delete_racing_an_edit_on_another_device_is_a_conflict(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    # The edit lands between the fresh read and the delete, so only the server's check of
    # the tag the delete carries catches it; deleting anyway would destroy a new password.
    fake.put_login(_cred())
    stored = keychain.fetch()[_cred().id]
    _on_first(
        fake,
        "/record/save",
        lambda: fake.put_item(_cred().id, {**fake.item(_cred().id), "v_Data": b"from-iphone"}),
    )
    with pytest.raises(RecordConflictError):
        keychain.delete(_cred().id, stored.etag)
    assert fake.logins()[_cred().id].password == "from-iphone"


def test_delete_racing_a_sidecar_edit_deletes_nothing(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred(title="T"), sidecar_name="SIDE")
    stored = keychain.fetch()[_cred().id]
    _on_first(
        fake,
        "/record/save",
        lambda: fake.put_item("SIDE", {**fake.item("SIDE"), "labl": "changed on iphone"}),
    )
    with pytest.raises(RecordConflictError):
        keychain.delete(_cred().id, stored.etag)
    assert fake.logins()[_cred().id].title == "T"
    assert fake.item("SIDE")["labl"] == "changed on iphone"


def test_delete_after_another_device_added_a_sidecar_is_a_conflict(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    # The login record keeps its tag, so no condition in the batch would notice the new
    # sidecar; deleting would leave its notes behind with no login.
    fake.put_login(_cred())
    stored = keychain.fetch()[_cred().id]
    sidecar = passwords.updated_login(stored.login, _cred(notes="n"), T0).sidecar
    assert sidecar is not None
    fake.put_item("SIDE", sidecar)
    with pytest.raises(RecordConflictError):
        keychain.delete(_cred().id, stored.etag)
    assert fake.logins()[_cred().id].notes == "n"


def test_unconditional_delete(fake: FakeCloudKit, keychain: KeychainClient) -> None:
    fake.put_login(_cred())
    keychain.fetch()
    keychain.delete(_cred().id, None)
    assert fake.logins() == {}


def test_unconditional_delete_reaches_a_login_created_since_the_last_fetch(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    keychain.fetch()
    fake.put_login(_cred())
    keychain.delete(_cred().id, None)
    assert fake.logins() == {}


def test_deleting_an_absent_login_is_a_no_op(fake: FakeCloudKit, keychain: KeychainClient) -> None:
    keychain.fetch()
    keychain.delete("nothing-here", "x")
    assert _saves(fake) == []


def test_failed_delete_raises_and_keeps_the_login(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_cred())
    stored = keychain.fetch()[_cred().id]
    fake.fail("/record/save", client_error=8)
    with pytest.raises(CloudKitError):
        keychain.delete(_cred().id, stored.etag)
    assert _cred().id in keychain.fetch()


# --- round-trip property -------------------------------------------------------------------------

_text = st.text(st.characters(codec="utf-8", exclude_categories=("Cs", "Cc")), max_size=30)
_host = st.from_regex(r"[a-z][a-z0-9]{0,10}(\.[a-z]{2,6}){1,2}", fullmatch=True)


def _credential(  # noqa: PLR0913, PLR0917 - one argument per generated credential field
    host: str,
    port: int | None,
    path: str,
    user: str,
    pw: str,
    title: str,
    notes: str,
    alts: list[str],
) -> Credential:
    return Credential(
        str(uuid.uuid4()).upper(),
        f"https://{host}{f':{port}' if port else ''}{path}",
        user,
        pw,
        T0,
        T0,
        title=title or None,
        notes=notes or None,
        alt_urls=tuple(alts),
    )


_creds = st.builds(
    _credential,
    _host,
    st.sampled_from([None, 8080, 8443]),
    st.sampled_from(["", "/login", "/a/b"]),
    _text,
    _text,
    _text,
    _text,
    st.lists(_host, max_size=3),
)


@pytest.mark.timeout(60)
@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    phases=[Phase.explicit, Phase.generate],  # shrinking replays many network round trips
)
@given(cred=_creds)
def test_any_saved_login_reads_back_unchanged(
    fake: FakeCloudKit, keychain: KeychainClient, cred: Credential
) -> None:
    for stored in keychain.fetch().values():  # examples share the zone; start each one empty
        keychain.delete(stored.credential.id, None)
    etag = keychain.save(cred, None)
    stored = keychain.fetch()[cred.id]
    assert stored.etag == etag
    assert _same(stored.credential, cred)
    assert _same(fake.logins()[cred.id], cred)


# --- one login on several websites ---------------------------------------------------------------
# Apple keeps a login used on several websites of one domain as one record per website (same
# account and password); the Passwords app shows them as one entry with several websites.

T1 = datetime(2024, 5, 6, 7, 8, 9, tzinfo=UTC)


def _site(n: int, url: str, **over: object) -> Credential:
    """Records of one login: same account and password, each on its own website."""
    created = over.pop("created", T0 if n == 1 else T1)
    fields: dict[str, object] = {"username": "kim", "password": "same", **over}
    return _cred(n, url=url, created=created, modified=created, **fields)


def _group(fake: FakeCloudKit) -> tuple[Credential, Credential]:
    main, other = _site(1, "https://example.com"), _site(2, "https://login.example.com")
    fake.put_login(other)
    fake.put_login(main)
    return main, other


def test_records_of_one_login_on_one_domain_read_as_one_credential(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    main, other = _group(fake)
    got = keychain.fetch()
    assert set(got) == {main.id}  # the oldest record names the login
    cred = got[main.id].credential
    assert (cred.url, cred.alt_urls) == ("https://example.com", ("https://login.example.com",))
    assert [o.login.record_name for o in got[main.id].others] == [other.id]


def test_records_on_different_domains_stay_separate_logins(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_site(1, "https://example.com"))
    fake.put_login(_site(2, "https://example.org"))
    fake.put_login(_site(3, "https://login.example.com", password="other"))
    fake.put_login(_site(4, "https://www.example.com", username="kim2"))
    assert len(keychain.fetch()) == 4


def test_alternate_sites_join_the_record_kept_for_that_site(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    main = _site(1, "https://example.com", alt_urls=("example.org",))
    fake.put_login(main)
    fake.put_login(_site(2, "https://example.org"))
    got = keychain.fetch()
    assert set(got) == {main.id}
    assert got[main.id].credential.alt_urls == ("https://example.org",)


def test_group_etag_covers_every_record(fake: FakeCloudKit, keychain: KeychainClient) -> None:
    main, other = _group(fake)
    before = keychain.fetch()[main.id].etag
    fake.put_item(other.id, {**fake.item(other.id), "mdat": T1, "labl": "renamed"})
    assert keychain.fetch()[main.id].etag != before


def test_password_change_rewrites_every_record_and_creates_none(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    main, other = _group(fake)
    stored = keychain.fetch()[main.id]
    names = set(fake.items())
    etag = keychain.save(dataclasses.replace(stored.credential, password="new"), stored.etag)
    assert set(fake.items()) == names
    assert {fake.logins()[i].password for i in (main.id, other.id)} == {"new"}
    again = keychain.fetch()
    assert set(again) == {main.id}
    assert again[main.id].etag == etag


def test_stale_group_etag_is_a_conflict(fake: FakeCloudKit, keychain: KeychainClient) -> None:
    main, other = _group(fake)
    stored = keychain.fetch()[main.id]
    fake.put_item(other.id, {**fake.item(other.id), "mdat": T1, "labl": "renamed"})
    keychain.fetch()
    with pytest.raises(RecordConflictError):
        keychain.save(dataclasses.replace(stored.credential, password="new"), stored.etag)


def test_removing_a_website_moves_only_its_record_to_recently_deleted(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    main, other = _group(fake)
    stored = keychain.fetch()[main.id]
    keychain.save(dataclasses.replace(stored.credential, alt_urls=()), stored.etag)
    assert set(fake.logins()) == {main.id}
    assert set(fake.logins(deleted=True)) == {other.id}
    assert keychain.fetch()[main.id].credential.alt_urls == ()


def test_adding_a_website_to_a_group_creates_no_record(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    main, _ = _group(fake)
    stored = keychain.fetch()[main.id]
    logins = set(fake.logins())
    alt = (*stored.credential.alt_urls, "https://example.net")
    etag = keychain.save(dataclasses.replace(stored.credential, alt_urls=alt), stored.etag)
    assert set(fake.logins()) == logins
    again = keychain.fetch()[main.id]
    assert again.credential.alt_urls == alt
    assert again.etag == etag


def test_metadata_edit_reads_back_from_a_group(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    main = _site(1, "https://example.com")
    other = _site(2, "https://login.example.com", notes="old note")
    fake.put_login(main)
    fake.put_login(other)
    stored = keychain.fetch()[main.id]
    assert stored.credential.notes == "old note"
    keychain.save(dataclasses.replace(stored.credential, notes=None, title="T"), stored.etag)
    cred = keychain.fetch()[main.id].credential
    assert (cred.title, cred.notes) == ("T", None)


def test_deleting_a_group_moves_every_record_to_recently_deleted(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    main, other = _group(fake)
    stored = keychain.fetch()[main.id]
    keychain.delete(main.id, stored.etag)
    assert fake.logins() == {}
    assert set(fake.logins(deleted=True)) == {main.id, other.id}


def test_a_new_login_for_another_site_of_a_group_joins_it(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    main, other = _group(fake)
    keychain.fetch()
    third = _site(3, "https://m.example.com", created=T1.replace(year=2025))
    keychain.save(third, None)
    got = keychain.fetch()
    assert set(got) == {main.id}
    assert set(got[main.id].credential.alt_urls) == {other.url, third.url}


def test_records_with_different_notes_stay_separate_logins(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    fake.put_login(_site(1, "https://example.com", notes="one"))
    fake.put_login(_site(2, "https://login.example.com", notes="two"))
    assert len(keychain.fetch()) == 2


def test_group_save_is_conditional_on_every_sidecar(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    main = _site(1, "https://example.com")
    other = _site(2, "https://login.example.com", notes="note")
    fake.put_login(main)
    fake.put_login(other, sidecar_name="SIDE2")
    stored = keychain.fetch()[main.id]
    fake.put_item("SIDE2", {**fake.item("SIDE2"), "mdat": T1, "labl": "edited elsewhere"})
    with pytest.raises(RecordConflictError):
        keychain.save(dataclasses.replace(stored.credential, password="new"), stored.etag)
    assert fake.logins()[main.id].password == "same"


def test_moving_the_main_website_to_another_domain_keeps_the_group(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    main, other = _group(fake)
    stored = keychain.fetch()[main.id]
    moved = dataclasses.replace(stored.credential, url="https://example.org")
    keychain.save(moved, stored.etag)
    got = keychain.fetch()
    assert set(got) == {main.id}
    assert (got[main.id].credential.url, got[main.id].credential.alt_urls) == (
        "https://example.org",
        (other.url,),
    )


def test_moving_the_main_website_keeps_a_group_whose_records_list_alternate_sites(
    fake: FakeCloudKit, keychain: KeychainClient
) -> None:
    main = _site(1, "https://example.com")
    other = _site(2, "https://login.example.com", alt_urls=("www.example.com",))
    fake.put_login(main)
    fake.put_login(other)
    stored = keychain.fetch()[main.id]
    keychain.save(dataclasses.replace(stored.credential, url="https://example.org"), stored.etag)
    got = keychain.fetch()
    assert set(got) == {main.id}
    assert set(got[main.id].credential.alt_urls) == {other.url, "www.example.com"}

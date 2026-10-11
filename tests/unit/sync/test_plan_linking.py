# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""First-sync linking: keyring items that already exist in iCloud are adopted, not doubled."""

from __future__ import annotations

from typing import Any

import pytest
from tests.fakes.memory_stores import make_credential

from passwords_app.sync.plan import (
    BaseEntry,
    CreateLocal,
    CreateRemote,
    DeleteLocal,
    Link,
    SyncPlan,
    Trash,
    plan,
)
from passwords_app.sync.ports import LocalSnapshot, RemoteItem, RemoteSnapshot, SyncPolicy

POLICY = SyncPolicy()


def first_sync(remote: dict[str, dict[str, Any]], local: dict[str, dict[str, Any]]) -> SyncPlan:
    return plan(
        {},
        RemoteSnapshot(
            {i: RemoteItem(make_credential(i, **f), f"e-{i}") for i, f in remote.items()}
        ),
        LocalSnapshot({i: make_credential(i, **f) for i, f in local.items()}),
        POLICY,
    )


def login(url: str, user: str = "alice", secret: str = "fake-pw") -> dict[str, Any]:
    return {"url": url, "username": user, "password": secret}


# Keyring URL vs iCloud URL: the same site written differently must link.
SAME_HOST = [
    ("https://example.com", "https://example.com"),
    ("example.com", "https://example.com"),
    ("https://www.example.com", "https://example.com"),
    ("https://example.com", "https://www.example.com/login"),
    ("https://EXAMPLE.com", "https://example.com"),
    ("https://example.com./", "https://example.com"),
    ("http://example.com", "https://example.com"),
    ("https://example.com/a?b=c", "https://example.com/other"),
    ("https://example.com:443", "https://example.com"),
    ("https://xn--e1afmkfd.xn--p1ai", "https://пример.рф"),
    ("https://Пример.РФ", "https://xn--e1afmkfd.xn--p1ai/"),
    ("https://mail.example.co.uk", "https://mail.example.co.uk/inbox"),
    ("https://192.168.1.1", "https://192.168.1.1/admin"),
]


@pytest.mark.parametrize(("local_url", "remote_url"), SAME_HOST)
def test_same_login_written_differently_is_linked(local_url: str, remote_url: str) -> None:
    result = first_sync({"R": login(remote_url)}, {"L": login(local_url)})
    links = [a for a in result.actions if isinstance(a, Link)]
    assert [(lk.local_id, lk.credential.id) for lk in links] == [("L", "R")]
    assert not any(isinstance(a, (CreateLocal, CreateRemote)) for a in result.actions)


# Different site or username: these are different logins and both survive.
NOT_SAME = [
    (login("https://example.com"), login("https://example.org")),
    (login("https://example.com"), login("https://mail.example.com")),
    (login("https://a.github.io"), login("https://b.github.io")),
    (login("https://example.com"), login("https://example.com.evil.com")),
    (login("https://example.com"), login("https://notexample.com")),
    (login("https://example.com", user="alice"), login("https://example.com", user="bob")),
    (login("https://example.com", user=""), login("https://example.com", user="alice")),
    (login("https://192.168.1.1"), login("https://192.168.1.2")),
    (login("https://fass.de"), login("https://faß.de")),
    (login("https://evil.com\\@example.com"), login("https://example.com")),
]


@pytest.mark.parametrize(("local_fields", "remote_fields"), NOT_SAME)
def test_different_logins_are_both_kept(
    local_fields: dict[str, Any], remote_fields: dict[str, Any]
) -> None:
    result = first_sync({"R": remote_fields}, {"L": local_fields})
    assert not any(isinstance(a, Link) for a in result.actions)
    assert {type(a) for a in result.actions} == {CreateLocal, CreateRemote}


# Same site and username (compared case-insensitively, as iCloud Keychain does) with
# another password: iCloud keeps one of them, so they are not linked but merged (#71).
SAME_LOGIN_OTHER_PASSWORD = [
    (login("https://example.com", user="alice"), login("https://example.com", user="Alice")),
    (login("https://example.com", secret="fake-a"), login("https://example.com", secret="fake-b")),
    (login("https://example.com", secret="fake-a"), login("https://example.com", secret="fake-a ")),
]


@pytest.mark.parametrize(("local_fields", "remote_fields"), SAME_LOGIN_OTHER_PASSWORD)
def test_a_keyring_twin_of_an_icloud_login_is_merged_not_kept(
    local_fields: dict[str, Any], remote_fields: dict[str, Any]
) -> None:
    result = first_sync({"R": remote_fields}, {"L": local_fields})
    # Equal timestamps: the version iCloud already holds wins.
    assert set(result.actions) == {
        Trash(make_credential("L", **local_fields), "conflict"),
        DeleteLocal("L"),
        CreateLocal(make_credential("R", **remote_fields), "e-R"),
    }


def test_link_with_differing_extras_keeps_the_keyring_version_in_trash() -> None:
    result = first_sync(
        {"R": login("https://www.example.com/login") | {"title": "Example", "notes": "n"}},
        {"L": login("https://example.com")},
    )
    trash = [a for a in result.actions if isinstance(a, Trash)]
    assert [(t.credential.id, t.reason) for t in trash] == [("L", "conflict")]
    link = next(a for a in result.actions if isinstance(a, Link))
    assert link.credential.title == "Example"
    assert result.actions.index(trash[0]) < result.actions.index(link)


def test_identical_content_links_without_trash() -> None:
    fields = login("https://example.com")
    result = first_sync({"R": fields}, {"L": fields})
    assert not any(isinstance(a, Trash) for a in result.actions)


def test_link_carries_the_remote_etag() -> None:
    result = first_sync({"R": login("https://example.com")}, {"L": login("https://example.com")})
    assert result.actions == (
        Link("L", make_credential("R", **login("https://example.com")), "e-R"),
    )


def test_duplicates_link_one_to_one_in_id_order() -> None:
    same = login("https://example.com")
    result = first_sync({"R1": same, "R2": same}, {"L1": same, "L2": same, "L3": same})
    pairs = [(a.local_id, a.credential.id) for a in result.actions if isinstance(a, Link)]
    assert pairs == [("L1", "R1"), ("L2", "R2")]
    assert [a.item_id for a in result.actions if isinstance(a, CreateRemote)] == ["L3"]


def test_one_remote_matches_only_one_local() -> None:
    same = login("https://example.com")
    result = first_sync({"R": same}, {"A": same, "B": same})
    assert sum(isinstance(a, Link) for a in result.actions) == 1
    # B duplicates the login A is linked to: it waits for the next cycle, not an upload.
    assert not any(a.item_id == "B" for a in result.actions)


def test_already_synced_remote_items_are_not_link_candidates() -> None:
    same = login("https://example.com")
    synced = make_credential("R", **same)
    result = plan(
        {"R": BaseEntry(synced, "e")},
        RemoteSnapshot({"R": RemoteItem(synced, "e")}),
        LocalSnapshot({"R": synced, "L": make_credential("L", **same)}),
        POLICY,
    )
    # Not linked, and not uploaded either: iCloud would refuse a second login (#71).
    assert result.actions == (
        Trash(make_credential("L", **same), "conflict"),
        DeleteLocal("L"),
    )


def test_items_with_unparsable_urls_never_link() -> None:
    result = first_sync({"R": login("https://")}, {"L": login("https://")})
    assert not any(isinstance(a, Link) for a in result.actions)


def test_linking_is_not_limited_to_the_very_first_sync() -> None:
    # A login added in Seahorse that already exists in iCloud is adopted at any time.
    same = login("https://example.com")
    other = make_credential("OTHER")
    result = plan(
        {"OTHER": BaseEntry(other, "e")},
        RemoteSnapshot(
            {"OTHER": RemoteItem(other, "e"), "R": RemoteItem(make_credential("R", **same), "r")}
        ),
        LocalSnapshot({"OTHER": other, "L": make_credential("L", **same)}),
        POLICY,
    )
    assert [type(a) for a in result.actions] == [Link]


def test_large_first_sync_links_everything() -> None:
    n = 500
    remote = {f"R{i:04d}": login(f"https://site{i}.example.com", user=f"u{i}") for i in range(n)}
    local = {f"L{i:04d}": login(f"site{i}.example.com", user=f"u{i}") for i in range(n)}
    result = first_sync(remote, local)
    assert sum(isinstance(a, Link) for a in result.actions) == n
    assert all(isinstance(a, (Link, Trash)) for a in result.actions)


def test_half_applied_link_is_completed_not_duplicated() -> None:
    # The remote item was already written under its id; the old keyring item still exists.
    same = login("https://example.com")
    r = make_credential("R", **same)
    result = plan(
        {},
        RemoteSnapshot({"R": RemoteItem(r, "e")}),
        LocalSnapshot({"R": r, "L": make_credential("L", **same)}),
        POLICY,
    )
    assert result.actions == (Link("L", r, "e"),)


def test_same_id_local_with_other_content_is_not_a_link_target() -> None:
    same = login("https://example.com")
    r = make_credential("R", **same)
    local_r = make_credential("R", **same, title="edited before first sync")
    result = plan(
        {},
        RemoteSnapshot({"R": RemoteItem(r, "e")}),
        LocalSnapshot({"R": local_r, "L": make_credential("L", **same)}),
        POLICY,
    )
    assert not any(isinstance(a, Link) and a.local_id == "L" for a in result.actions)
    assert not any(isinstance(a, CreateRemote) for a in result.actions)

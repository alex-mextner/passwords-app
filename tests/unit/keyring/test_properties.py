# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Property tests: no keyring item, however odd, can crash a sync (Review Focus 3)."""

from __future__ import annotations

import string
from datetime import UTC, datetime

from hypothesis import given, settings
from hypothesis import strategies as st

from passwords_app.core.model import Credential
from passwords_app.keyring.labels import UnparseableLabelError, parse_label
from passwords_app.keyring.mapping import (
    ItemRejectedError,
    StoredItem,
    item_content,
    make_label,
    read_item,
)

SETTINGS = settings(max_examples=300, deadline=None)

ldh_label = st.from_regex(r"\A[a-z0-9](?:[a-z0-9-]{0,20}[a-z0-9])?\Z")
tld = st.from_regex(r"\A[a-z]{2,10}\Z")
hosts = st.builds(
    lambda labels, top: ".".join([*labels, top]), st.lists(ldh_label, min_size=1, max_size=3), tld
)
ports = st.one_of(st.none(), st.integers(min_value=1, max_value=65535))
safe_text = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cc", "Cs", "Zl", "Zp"),
        blacklist_characters="\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069",
    ),
    max_size=30,
)
usernames = safe_text.map(str.strip)
timestamps = st.integers(min_value=0, max_value=4_000_000_000)


@SETTINGS
@given(st.text(max_size=200))
def test_any_label_parses_or_is_refused(label: str) -> None:
    try:
        parsed = parse_label(label)
    except UnparseableLabelError:
        return
    assert parsed.url.startswith(("http://", "https://"))


@SETTINGS
@given(hosts, ports, usernames)
def test_our_label_shape_parses_back(host: str, port: int | None, username: str) -> None:
    url = f"https://{host}" if port is None else f"https://{host}:{port}"
    parsed = parse_label(make_label(None, url, username))
    assert (parsed.url, parsed.username) == (url, username)


@SETTINGS
@given(hosts, usernames)
def test_seahorse_at_shape_parses(host: str, username: str) -> None:
    parsed = parse_label(f"{username} @ {host}")
    assert (parsed.url, parsed.username) == (f"https://{host}", username.strip())


attribute_names = st.sampled_from(
    [
        "xdg:schema",
        "pa-id",
        "url",
        "username",
        "title",
        "notes",
        "otpauth",
        "alt-urls",
        "group",
        "created",
        "modified",
        "pa-synced",
        "server",
        "other",
    ]
)
attribute_values = st.one_of(
    st.text(max_size=40),
    st.just("io.github.alex_mextner.Passwords"),
    st.just("2026-01-01T00:00:00+00:00"),
    st.just("https://example.com"),
)


@SETTINGS
@given(
    label=st.text(max_size=60),
    attributes=st.dictionaries(attribute_names, attribute_values, max_size=10),
    secret=st.binary(max_size=40),
    created=st.one_of(st.none(), timestamps),
    modified=timestamps,
)
def test_any_item_maps_or_is_rejected(
    label: str,
    attributes: dict[str, str],
    secret: bytes,
    created: int | None,
    modified: int,
) -> None:
    item = StoredItem("/x/1", label, attributes, secret, created, modified)
    try:
        read = read_item(item, new_id=lambda: "NEW")
    except ItemRejectedError:
        return
    assert read.credential.url
    assert read.credential.id == (attributes.get("pa-id") or "NEW")


# What D-Bus can carry in a string (no NUL); item_content refuses the rest, tested separately.
dbus_text = st.characters(blacklist_characters="\x00")


@SETTINGS
@given(
    url=st.builds(lambda h: f"https://{h}", hosts),
    username=st.text(dbus_text, max_size=30),
    password=st.text(max_size=60),
    title=st.one_of(st.none(), st.text(dbus_text, max_size=30)),
    notes=st.one_of(st.none(), st.text(dbus_text, max_size=60)),
    alt_urls=st.lists(
        st.text(alphabet=string.ascii_letters + ":/.", min_size=1, max_size=20), max_size=3
    ),
    created=timestamps,
    modified=timestamps,
)
def test_any_credential_round_trips(  # noqa: PLR0913, PLR0917 - one field per strategy
    url: str,
    username: str,
    password: str,
    title: str | None,
    notes: str | None,
    alt_urls: list[str],
    created: int,
    modified: int,
) -> None:
    credential = Credential(
        id="ID",
        url=url,
        username=username,
        password=password,
        created=datetime.fromtimestamp(created, UTC),
        modified=datetime.fromtimestamp(modified, UTC),
        title=title,
        notes=notes,
        alt_urls=tuple(alt_urls),
    )
    content = item_content(credential, written_at=modified)
    item = StoredItem("/x/1", content.label, content.attributes, content.secret, None, modified)
    assert read_item(item, new_id=lambda: "unused").credential == credential

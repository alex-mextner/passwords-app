# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Login item + sidecar <-> Credential mapping, over real-shaped keychain attributes."""

# pyright: reportPrivateUsage=false
# The URL-attribute mapping is exercised directly as a unit.

from __future__ import annotations

import base64
import dataclasses
import plistlib
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from passwords_app.core.model import Credential
from passwords_app.core.urls import login_identity
from passwords_app.icloud import passwords as pw

if TYPE_CHECKING:
    from collections.abc import Mapping

T0 = datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)
T1 = T0 + timedelta(days=3)
NOW = T0 + timedelta(days=30)
SECRET = b"12345678901234567890"
SECRET_B32 = base64.b32encode(SECRET).decode().rstrip("=")


def _login_attrs(**over: object) -> dict[str, object]:
    """A login as an iPhone writes it (shape per Apple's inet schema)."""
    attrs: dict[str, object] = {
        "class": "inet",
        "agrp": "com.apple.cfnetwork",
        "acct": "alice",
        "srvr": "example.com",
        "ptcl": "htps",
        "port": 0,
        "path": "",
        "sdmn": "",
        "atyp": "form",
        "labl": "example.com (alice)",
        "desc": "Web form password",
        "pdmn": "ak",
        "v_Data": b"hunter2",
        "cdat": T0,
        "mdat": T0,
        "tomb": 0,
        "musr": b"",
        "sha1": b"\x01" * 20,
        "vwht": "Passwords",  # an attribute this client does not model
    }
    attrs.update(over)
    return attrs


def _sidecar(payload: Mapping[str, object], **over: object) -> dict[str, object]:
    attrs = _login_attrs(
        agrp="com.apple.password-manager",
        labl="Password Manager Metadata: example.com (alice)",
        desc="Password Manager Metadata",
        type=pw.SIDECAR_TYPE,
        v_Data=plistlib.dumps(payload, fmt=plistlib.FMT_BINARY, aware_datetime=True),
        mdat=T1,
    )
    attrs.update(over)
    return attrs


def _cred(**over: object) -> Credential:
    base = Credential("ID-1", "https://example.com", "alice", "hunter2", T0, T0)
    return dataclasses.replace(base, **over)  # type: ignore[arg-type]


def _login(item: dict[str, object], sidecar: dict[str, object] | None = None) -> pw.Login:
    return pw.Login(
        pw.StoredItem("ID-1", item),
        pw.StoredItem("SIDE-1", sidecar) if sidecar is not None else None,
    )


# --- urls ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("attrs", "url"),
    [
        ({"srvr": "example.com", "ptcl": "htps"}, "https://example.com"),
        ({"srvr": "example.com", "ptcl": "http"}, "http://example.com"),
        ({"srvr": "example.com"}, "https://example.com"),
        ({"srvr": "example.com", "ptcl": int.from_bytes(b"htps", "big")}, "https://example.com"),
        ({"srvr": "example.com", "ptcl": "htps", "port": 443}, "https://example.com"),
        ({"srvr": "example.com", "ptcl": "htps", "port": 8443}, "https://example.com:8443"),
        ({"srvr": "example.com", "ptcl": "http", "port": 80}, "http://example.com"),
        ({"srvr": "example.com", "path": "/login"}, "https://example.com/login"),
        ({"srvr": "example.com", "path": "login"}, "https://example.com/login"),
        ({"srvr": "192.168.1.1", "port": 8080}, "https://192.168.1.1:8080"),
        ({"srvr": "fe80::1"}, "https://[fe80::1]"),
        ({"srvr": "bücher.example"}, "https://bücher.example"),
        ({"srvr": " example.com "}, "https://example.com"),
        ({"srvr": b"example.com"}, "https://example.com"),
        ({"srvr": "example.com", "ptcl": "ftp "}, "ftp://example.com"),
        ({"srvr": "example.com", "ptcl": "zzzz"}, "https://example.com"),
        ({"srvr": "example.com", "port": True}, "https://example.com"),
    ],
)
def test_url_from_server_attributes(attrs: dict[str, object], url: str) -> None:
    assert pw.url_of(attrs) == url


@pytest.mark.parametrize("attrs", [{}, {"srvr": ""}, {"srvr": "   "}, {"srvr": 5}])
def test_no_server_means_no_url(attrs: dict[str, object]) -> None:
    assert pw.url_of(attrs) is None


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com", {"srvr": "example.com", "ptcl": "htps", "port": 0, "path": ""}),
        (
            "http://example.com:8080/a",
            {"srvr": "example.com", "ptcl": "http", "port": 8080, "path": "/a"},
        ),
        (
            "https://Example.COM/x?y=1",
            {"srvr": "example.com", "ptcl": "htps", "port": 0, "path": "/x?y=1"},
        ),
        ("https://[fe80::1]:444", {"srvr": "fe80::1", "ptcl": "htps", "port": 444, "path": ""}),
        ("ftp://files.example", {"srvr": "files.example", "ptcl": "ftp ", "port": 0, "path": ""}),
    ],
)
def test_url_to_server_attributes(url: str, expected: dict[str, object]) -> None:
    assert pw._url_attrs(url) == expected


@pytest.mark.parametrize(
    "url", ["mailto:a@b", "example.com", "https://", "android://x", "https://a:99999"]
)
def test_non_web_urls_are_unsupported(url: str) -> None:
    with pytest.raises(pw.UnsupportedCredentialError):
        pw._url_attrs(url)


@pytest.mark.parametrize(
    "url", ["https://example.com", "http://example.com:8080/login", "https://[fe80::1]:444/p"]
)
def test_url_attributes_round_trip(url: str) -> None:
    assert pw.url_of(pw._url_attrs(url)) == url


# --- one-time codes --------------------------------------------------------------------------


def test_totp_dictionary_becomes_otpauth_uri() -> None:
    uri = pw.otpauth_from_totp(
        {
            "secret": SECRET,
            "issuer": "ACME",
            "accountName": "alice",
            "digits": 8,
            "period": 60,
            "algorithm": 1,
        }
    )
    assert uri == (
        f"otpauth://totp/ACME%3Aalice?secret={SECRET_B32}&algorithm=SHA256&digits=8&period=60&issuer=ACME"
    )


def test_totp_label_falls_back_to_the_login_account() -> None:
    uri = pw.otpauth_from_totp({"secret": SECRET}, account="bob")
    assert uri == f"otpauth://totp/bob?secret={SECRET_B32}"


@pytest.mark.parametrize("block", [None, "x", {}, {"secret": b""}, {"secret": "text"}])
def test_totp_without_secret_has_no_uri(block: object) -> None:
    assert pw.otpauth_from_totp(block) is None


def test_otpauth_becomes_totp_dictionary() -> None:
    uri = f"otpauth://totp/ACME:alice?secret={SECRET_B32}&issuer=ACME&digits=8&period=60&algorithm=SHA512"
    assert pw.totp_from_otpauth(uri) == {
        "secret": SECRET,
        "algorithm": 2,
        "digits": 8,
        "period": 60,
        "issuer": "ACME",
        "accountName": "alice",
        "originalURL": uri,
    }


def test_otpauth_defaults_and_lowercase_padded_secret() -> None:
    lower = base64.b32encode(b"abc").decode().lower()
    totp = pw.totp_from_otpauth(f"otpauth://totp/x?secret={lower}")
    assert totp["secret"] == b"abc"
    assert (totp["digits"], totp["period"], totp["algorithm"]) == (6, 30, 0)


def test_otpauth_keeps_fields_the_uri_cannot_carry() -> None:
    previous = {
        "secret": b"old",
        "_initialDate": T0,
        "originalURL": "otpauth://...",
        "issuer": "Old",
    }
    uri = f"otpauth://totp/x?secret={SECRET_B32}"
    totp = pw.totp_from_otpauth(uri, previous)
    assert totp["_initialDate"] == T0
    assert totp["originalURL"] == uri
    assert totp["secret"] == SECRET
    assert "issuer" not in totp  # the new URI has none, so the stale one goes


@pytest.mark.parametrize(
    "uri",
    [
        "otpauth://hotp/x?secret=AAAA",
        "https://x",
        "otpauth://totp/x?secret=!!!!",
        "otpauth://totp/x",
    ],
)
def test_unusable_otpauth_is_unsupported(uri: str) -> None:
    with pytest.raises(pw.UnsupportedCredentialError):
        pw.totp_from_otpauth(uri)


def test_totp_round_trips_through_uri() -> None:
    block = {
        "secret": SECRET,
        "issuer": "ACME",
        "accountName": "alice",
        "digits": 6,
        "period": 30,
        "algorithm": 0,
    }
    uri = pw.otpauth_from_totp(block)
    assert uri is not None
    assert pw.totp_from_otpauth(uri) == {**block, "originalURL": uri}


@pytest.mark.parametrize(
    "uri",
    [
        f"otpauth://totp/x?secret={SECRET_B32}",
        f"otpauth://totp/Big%20Co:me%40x.com?secret={SECRET_B32}&period=30",
        f"otpauth://totp/a?issuer=I&secret={SECRET_B32.lower()}&digits=8",
    ],
)
def test_written_uri_reads_back_verbatim(uri: str) -> None:
    assert pw.otpauth_from_totp(pw.totp_from_otpauth(uri)) == uri


def test_stale_original_url_is_not_trusted() -> None:
    block = {"secret": b"new-secret", "originalURL": f"otpauth://totp/x?secret={SECRET_B32}"}
    uri = pw.otpauth_from_totp(block)
    assert uri is not None
    assert SECRET_B32 not in uri


# --- reading ---------------------------------------------------------------------------------


def test_login_and_sidecar_join_case_insensitively() -> None:
    items = [
        pw.StoredItem("L", _login_attrs(srvr="Example.com", acct="Alice")),
        pw.StoredItem("S", _sidecar({"title": b"T"}, srvr="example.COM", acct="alice")),
        pw.StoredItem("X", _login_attrs(agrp="com.apple.safari.credit-cards")),
        pw.StoredItem("W", _login_attrs(agrp="com.apple.password-manager.website-metadata")),
    ]
    [login] = pw.pair_logins(items)
    assert login.record_name == "L"
    assert login.sidecar is not None
    assert login.sidecar.record_name == "S"


def test_sidecar_for_another_account_is_not_joined() -> None:
    items = [pw.StoredItem("L", _login_attrs()), pw.StoredItem("S", _sidecar({}, acct="bob"))]
    [login] = pw.pair_logins(items)
    assert login.sidecar is None


def test_two_logins_on_one_site_keep_their_own_sidecars() -> None:
    items = [
        pw.StoredItem("L1", _login_attrs()),
        pw.StoredItem("L2", _login_attrs(acct="bob")),
        pw.StoredItem("S2", _sidecar({"title": b"Bob"}, acct="bob")),
    ]
    logins = {lg.record_name: lg for lg in pw.pair_logins(items)}
    assert logins["L1"].sidecar is None
    assert logins["L2"].sidecar is not None


def test_full_credential_from_login_and_sidecar() -> None:
    payload = {
        "title": b"My Bank",
        "notes": b"pin is elsewhere",
        "totp": {"secret": SECRET, "issuer": "Bank"},
        "s_as": [{"s": "bank.example"}, {"s": "m.bank.example"}],
        "s_hi": [{"p": "old", "d": T0}],
    }
    cred = pw.to_credential(_login(_login_attrs(), _sidecar(payload)))
    assert cred is not None
    assert (cred.id, cred.url, cred.username, cred.password) == (
        "ID-1",
        "https://example.com",
        "alice",
        "hunter2",
    )
    assert (cred.title, cred.notes) == ("My Bank", "pin is elsewhere")
    assert cred.otpauth == f"otpauth://totp/Bank%3Aalice?secret={SECRET_B32}&issuer=Bank"
    assert cred.alt_urls == ("bank.example", "m.bank.example")
    assert cred.created == T0
    assert cred.modified == T1  # the sidecar changed later
    assert cred.group is None


def test_credential_without_sidecar_has_no_metadata() -> None:
    cred = pw.to_credential(_login(_login_attrs()))
    assert cred is not None
    assert (cred.title, cred.notes, cred.otpauth, cred.alt_urls) == (None, None, None, ())


def test_naive_dates_are_read_as_utc_and_missing_ones_default() -> None:
    cred = pw.to_credential(_login(_login_attrs(cdat=datetime(2020, 1, 1), mdat=None)))  # noqa: DTZ001
    assert cred is not None
    assert cred.created == datetime(2020, 1, 1, tzinfo=UTC)
    assert cred.modified == cred.created
    bare = pw.to_credential(
        _login({k: v for k, v in _login_attrs().items() if k not in {"cdat", "mdat"}})
    )
    assert bare is not None
    assert bare.created == datetime(2001, 1, 1, tzinfo=UTC)


def test_a_login_without_a_website_maps_to_none() -> None:
    assert pw.to_credential(_login(_login_attrs(srvr=""))) is None


def test_empty_password_and_username_are_kept() -> None:
    cred = pw.to_credential(_login(_login_attrs(acct="", v_Data=b"")))
    assert cred is not None
    assert (cred.username, cred.password) == ("", "")


def test_missing_password_reads_as_empty() -> None:
    attrs = {k: v for k, v in _login_attrs().items() if k != "v_Data"}
    cred = pw.to_credential(_login(attrs))
    assert cred is not None
    assert cred.password == ""


def test_empty_sidecar_payload_is_empty() -> None:
    assert pw.sidecar_payload(pw.StoredItem("S", _sidecar({}, v_Data=b""))) == {}


@pytest.mark.parametrize("blob", [b"not a plist", plistlib.dumps([1]), "str"])
def test_unreadable_sidecar_payload_raises(blob: object) -> None:
    with pytest.raises(pw.UnreadableLoginError):
        pw.sidecar_payload(pw.StoredItem("S", _sidecar({}, v_Data=blob)))


def test_item_id_and_group_override() -> None:
    cred = pw.to_credential(_login(_login_attrs()), item_id="grp/ID", group="Family")
    assert cred is not None
    assert (cred.id, cred.group) == ("grp/ID", "Family")


# --- writing new logins ----------------------------------------------------------------------


def test_new_login_attributes_match_apple_shape() -> None:
    attrs = pw.new_login(_cred(url="https://example.com:8443/login"), NOW)
    item = attrs.item
    assert item["class"] == "inet"
    assert item["agrp"] == "com.apple.cfnetwork"
    assert (item["srvr"], item["ptcl"], item["port"], item["path"]) == (
        "example.com",
        "htps",
        8443,
        "/login",
    )
    assert item["labl"] == "example.com (alice)"
    assert item["desc"] == "Web form password"
    assert (item["atyp"], item["pdmn"], item["tomb"], item["sdmn"], item["musr"]) == (
        "form",
        "ak",
        0,
        "",
        b"",
    )
    assert item["v_Data"] == b"hunter2"
    assert (item["cdat"], item["mdat"]) == (T0, NOW)
    assert isinstance(item["sha1"], bytes)
    assert len(item["sha1"]) == 20
    assert attrs.sidecar is None
    for never in ("UUID", "sync", "persistref", "accc"):
        assert never not in item


def test_new_login_with_metadata_gets_a_joined_sidecar() -> None:
    cred = _cred(
        title="T",
        notes="N",
        otpauth=f"otpauth://totp/x?secret={SECRET_B32}",
        alt_urls=("b.example",),
    )
    attrs = pw.new_login(cred, NOW)
    assert attrs.sidecar is not None
    side = attrs.sidecar
    assert side["agrp"] == "com.apple.password-manager"
    assert side["labl"] == "Password Manager Metadata: example.com (alice)"
    assert side["type"] == pw.SIDECAR_TYPE
    payload = pw.sidecar_payload(pw.StoredItem("S", side))
    assert payload["title"] == b"T"
    assert payload["notes"] == b"N"
    assert payload["s_as"] == [{"s": "b.example"}]
    [login] = pw.pair_logins([pw.StoredItem("ID-1", attrs.item), pw.StoredItem("S", side)])
    assert pw.to_credential(login) == dataclasses.replace(cred, modified=NOW)


def test_new_login_rejects_non_web_url() -> None:
    with pytest.raises(pw.UnsupportedCredentialError):
        pw.new_login(_cred(url="ssh://host"), NOW)


def test_item_hash_is_stable_and_content_sensitive() -> None:
    a = pw.new_login(_cred(), NOW).item
    b = pw.new_login(_cred(), NOW).item
    c = pw.new_login(_cred(password="other"), NOW).item
    assert a["sha1"] == b["sha1"]
    assert a["sha1"] != c["sha1"]


# --- editing ---------------------------------------------------------------------------------


def test_password_change_rewrites_only_password_and_dates() -> None:
    login = _login(_login_attrs())
    out = pw.updated_login(login, _cred(password="new"), NOW)
    changed = {k for k in out.item if out.item[k] != login.item.attrs.get(k)}
    assert changed == {"v_Data", "mdat", "sha1"}
    assert out.item["vwht"] == "Passwords"
    assert out.sidecar is None


def test_unchanged_credential_rewrites_nothing() -> None:
    payload = {"title": b"T", "ctxt": {"": {"lUsed": 1.0}}}
    login = _login(_login_attrs(), _sidecar(payload))
    current = pw.to_credential(login)
    assert current is not None
    out = pw.updated_login(login, current, NOW)
    assert out.item == login.item.attrs
    assert login.sidecar is not None
    assert out.sidecar == login.sidecar.attrs


def test_username_change_moves_both_records_and_their_labels() -> None:
    login = _login(_login_attrs(), _sidecar({"title": b"T"}))
    out = pw.updated_login(login, _cred(username="bob", title="T"), NOW)
    assert (out.item["acct"], out.item["labl"]) == ("bob", "example.com (bob)")
    assert out.sidecar is not None
    assert (out.sidecar["acct"], out.sidecar["labl"]) == (
        "bob",
        "Password Manager Metadata: example.com (bob)",
    )
    assert out.sidecar["mdat"] == NOW
    [joined] = pw.pair_logins([pw.StoredItem("ID-1", out.item), pw.StoredItem("S", out.sidecar)])
    assert joined.sidecar is not None


def test_site_change_rewrites_server_attributes() -> None:
    login = _login(_login_attrs(port=443))
    out = pw.updated_login(login, _cred(url="http://other.example:8080/in"), NOW)
    assert (out.item["srvr"], out.item["ptcl"], out.item["port"], out.item["path"]) == (
        "other.example",
        "http",
        8080,
        "/in",
    )
    assert out.item["labl"] == "other.example (alice)"


def test_equivalent_url_keeps_original_server_attributes() -> None:
    login = _login(_login_attrs(port=443))  # renders as https://example.com
    out = pw.updated_login(login, _cred(password="new"), NOW)
    assert out.item["port"] == 443


def test_custom_label_survives_a_rename() -> None:
    login = _login(_login_attrs(labl="Work account"))
    out = pw.updated_login(login, _cred(username="bob"), NOW)
    assert out.item["labl"] == "Work account"


def test_metadata_edit_keeps_unknown_sidecar_keys() -> None:
    payload = {
        "title": b"Old",
        "s_hi": [{"p": "older"}],
        "ctxt": {"": {"lUsed": 5.0}},
        "fsm": {"g": 1},
    }
    login = _login(_login_attrs(), _sidecar(payload))
    out = pw.updated_login(login, _cred(title="New", notes="Added"), NOW)
    assert out.sidecar is not None
    new_payload = pw.sidecar_payload(pw.StoredItem("S", out.sidecar))
    assert new_payload["title"] == b"New"
    assert new_payload["notes"] == b"Added"
    for kept in ("s_hi", "ctxt", "fsm"):
        assert new_payload[kept] == payload[kept]
    assert out.item == login.item.attrs  # the login itself did not change


def test_clearing_metadata_empties_but_keeps_the_sidecar() -> None:
    payload = {
        "title": b"T",
        "notes": b"N",
        "totp": {"secret": SECRET},
        "s_as": [{"s": "x"}],
        "ctxt": {},
    }
    login = _login(_login_attrs(), _sidecar(payload))
    out = pw.updated_login(login, _cred(), NOW)
    assert out.sidecar is not None
    assert pw.sidecar_payload(pw.StoredItem("S", out.sidecar)) == {"ctxt": {}}


def test_gaining_metadata_creates_a_sidecar() -> None:
    out = pw.updated_login(_login(_login_attrs()), _cred(notes="hello"), NOW)
    assert out.sidecar is not None
    assert pw.sidecar_payload(pw.StoredItem("S", out.sidecar)) == {"notes": b"hello"}
    assert out.sidecar["cdat"] == NOW


def test_new_sidecar_joins_its_own_login_not_a_same_url_twin() -> None:
    # Ports 443 and 0 render the same URL; a sidecar keyed from the URL would join the twin.
    a = _login(_login_attrs(port=443))
    b = pw.StoredItem("ID-2", _login_attrs(port=0))
    out = pw.updated_login(a, _cred(notes="for A"), NOW)
    assert out.sidecar is not None
    assert pw.primary_key(out.sidecar) == pw.primary_key(a.item.attrs)
    side = pw.StoredItem("SIDE-NEW", out.sidecar)
    joined = {lg.item.record_name: lg.sidecar for lg in pw.pair_logins([b, a.item, side])}
    assert joined == {"ID-2": None, "ID-1": side}


@pytest.mark.parametrize(("over", "joins"), [({"port": 8443}, False), ({"path": "/x"}, True)])
def test_fallback_join_needs_the_same_protocol_and_port(
    over: dict[str, object], joins: bool
) -> None:
    login = pw.StoredItem("ID-1", _login_attrs(port=0))
    side = pw.StoredItem("SIDE-1", _sidecar({"notes": b"n"}, **over))
    [paired] = pw.pair_logins([login, side])
    assert (paired.sidecar is side) is joins


def test_fallback_never_guesses_between_two_candidates() -> None:
    logins = [
        pw.StoredItem("ID-1", _login_attrs(path="/a")),
        pw.StoredItem("ID-2", _login_attrs(path="/b")),
    ]
    sides = [
        pw.StoredItem("S-1", _sidecar({"notes": b"1"}, path="/x")),
        pw.StoredItem("S-2", _sidecar({"notes": b"2"}, path="/y")),
    ]
    assert [lg.sidecar for lg in pw.pair_logins([*logins, *sides])] == [None, None]


def test_renamed_login_keeps_its_fallback_sidecar() -> None:
    item = pw.StoredItem("ID-1", _login_attrs(port=443))
    side = pw.StoredItem("S", _sidecar({"notes": b"n"}, port=443, path="/login"))
    [paired] = pw.pair_logins([item, side])
    assert paired.sidecar is side
    out = pw.updated_login(paired, _cred(username="bob", notes="n"), NOW)
    assert out.sidecar is not None
    [again] = pw.pair_logins([pw.StoredItem("ID-1", out.item), pw.StoredItem("S", out.sidecar)])
    assert again.sidecar is not None


@pytest.mark.parametrize(
    "url", ["https://example.com/#login", "https://alice:secret@example.com/login"]
)
def test_url_parts_the_keychain_cannot_hold_are_refused(url: str) -> None:
    with pytest.raises(pw.UnsupportedCredentialError, match="cannot be stored"):
        pw.new_login(_cred(url=url), NOW)


def test_query_only_url_reads_back_unchanged() -> None:
    out = pw.new_login(_cred(url="https://example.com?tenant=alice"), NOW)
    assert pw.url_of(out.item) == "https://example.com?tenant=alice"


def test_unreadable_sidecar_fails_the_read_and_is_not_overwritten() -> None:
    side = _sidecar({})
    side["v_Data"] = b"not a plist"
    login = _login(_login_attrs(), side)
    with pytest.raises(pw.UnreadableLoginError, match="cannot be read"):
        pw.to_credential(login)
    with pytest.raises(pw.UnreadableLoginError):
        pw.updated_login(login, _cred(title="new title"), NOW)


@pytest.mark.parametrize("password", [b"\xff", 7])
def test_website_login_with_an_unreadable_password_fails_the_read(password: object) -> None:
    with pytest.raises(pw.UnreadableLoginError, match="not text"):
        pw.to_credential(_login(_login_attrs(v_Data=password)))


def test_unchanged_otpauth_keeps_the_original_totp_block() -> None:
    block = {
        "secret": SECRET,
        "issuer": "Bank",
        "_initialDate": T0,
        "originalURL": "otpauth://orig",
    }
    login = _login(_login_attrs(), _sidecar({"totp": block}))
    current = pw.to_credential(login)
    assert current is not None
    out = pw.updated_login(login, dataclasses.replace(current, password="x"), NOW)
    assert out.sidecar is not None
    assert pw.sidecar_payload(pw.StoredItem("S", out.sidecar))["totp"] == block


def test_changed_otpauth_rewrites_the_totp_block() -> None:
    login = _login(_login_attrs(), _sidecar({"totp": {"secret": b"old", "_initialDate": T0}}))
    out = pw.updated_login(login, _cred(otpauth=f"otpauth://totp/x?secret={SECRET_B32}"), NOW)
    assert out.sidecar is not None
    totp = pw.sidecar_payload(pw.StoredItem("S", out.sidecar))["totp"]
    assert isinstance(totp, dict)
    assert totp["secret"] == SECRET
    assert totp["_initialDate"] == T0


def test_reordered_alt_urls_are_rewritten() -> None:
    login = _login(_login_attrs(), _sidecar({"s_as": [{"s": "a"}, {"s": "b"}]}))
    out = pw.updated_login(login, _cred(alt_urls=("b", "a")), NOW)
    assert out.sidecar is not None
    assert pw.sidecar_payload(pw.StoredItem("S", out.sidecar))["s_as"] == [{"s": "b"}, {"s": "a"}]


@pytest.mark.parametrize("value", ["https://example.com", "x"])
def test_is_login_and_is_sidecar(value: str) -> None:
    del value
    assert pw.is_login(_login_attrs())
    assert not pw.is_login(_login_attrs(**{"class": "genp"}))
    assert pw.is_sidecar(_sidecar({}))
    assert not pw.is_sidecar(_login_attrs())


def test_non_ascii_digit_in_otpauth_falls_back_to_the_default() -> None:
    totp = pw.totp_from_otpauth(f"otpauth://totp/alice?secret={SECRET_B32}&digits=%C2%B2")
    assert totp["digits"] == 6


_IDENTITY_URLS = (
    "https://example.com",
    "https://EXAMPLE.com",
    "https://example.com/",
    "https://example.com/login",
    "https://example.com/login?next=1",
    "https://example.com:443",
    "https://example.com:8443",
    "http://example.com",
    "ftp://example.com",
    "https://www.example.com",
    "https://[fe80::1]:444",
)


def test_login_identity_is_the_keychain_duplicate_rule() -> None:
    """`login_identity` (used to restore over a live twin) agrees with what Apple rejects."""
    logins = [
        Credential(f"id{i}-{user}", url, user, "p", T0, T0)
        for i, url in enumerate(_IDENTITY_URLS)
        for user in ("alice", "ALICE", "bob", "")
    ]
    for a in logins:
        key_a = pw.primary_key(pw.new_login(a, NOW).item)
        for b in logins:
            same_in_keychain = key_a == pw.primary_key(pw.new_login(b, NOW).item)
            assert (login_identity(a) == login_identity(b)) == same_in_keychain, (a.url, b.url)

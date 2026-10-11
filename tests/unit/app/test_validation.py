# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Edit-form validation: normalized output on success, one message per bad field otherwise."""

from __future__ import annotations

from urllib.parse import parse_qs, unquote, urlencode, urlsplit

import pytest

from passwords_app.app import i18n
from passwords_app.app.records import Draft
from passwords_app.app.validation import (
    MAX_NOTES,
    MAX_PASSWORD,
    MAX_TITLE,
    MAX_USERNAME,
    Field,
    setup_key_to_otpauth,
    validate,
)
from passwords_app.core.otp import parse_otpauth

PW = "example-pw-1"
KEY_B32 = "JBSWY3DPEHPK3PXP"  # the RFC-style demo key, 10 bytes
SPACES = "   "
ONLY_BASE32 = "A setup key contains only letters A\u2013Z and digits 2\u20137"


@pytest.fixture(autouse=True)
def _english() -> None:
    i18n.setup(["en"])


def _draft(**fields: object) -> Draft:
    values: dict[str, object] = {"url": "example.com", "password": PW}
    values.update(fields)
    return Draft(**values)  # type: ignore[arg-type]


def test_minimal_draft_is_valid_and_normalized() -> None:
    result = validate(_draft())
    assert result.ok
    assert result.errors == {}
    assert result.draft.url == "https://example.com"


# ---------------------------------------------------------------- url


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("example.com", "https://example.com"),
        ("  Example.COM/  ", "https://example.com"),
        ("http://example.com/login?next=1#x", "http://example.com/login?next=1#x"),
        ("https://example.com/#/login", "https://example.com/#/login"),
        ("app.example.com?tenant=acme", "https://app.example.com/?tenant=acme"),
        (
            "example.com/login?next=https://example.org/home",
            "https://example.com/login?next=https://example.org/home",
        ),
        ("example.com/#back=https://example.org", "https://example.com/#back=https://example.org"),
        ("HTTPS://www.example.com:443/", "https://www.example.com"),
        ("example.com:8443/app", "https://example.com:8443/app"),
        ("localhost:3000", "https://localhost:3000"),
        ("пример.рф", "https://xn--e1afmkfd.xn--p1ai"),
    ],
)
def test_url_is_normalized(raw: str, normalized: str) -> None:
    result = validate(_draft(url=raw))
    assert result.ok, result.errors
    assert result.draft.url == normalized


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("", "Enter a website"),
        ("   ", "Enter a website"),
        ("ftp://example.com", "Use a web address such as example.com"),
        ("ssh://host.example", "Use a web address such as example.com"),
        ("chrome://settings", "Use a web address such as example.com"),
        # No "//": only the normalized URL reveals the scheme.
        ("file:\\\\server.example\\share", "Use a web address such as example.com"),
        ("ftp:\\\\files.example\\pub", "Use a web address such as example.com"),
        ("https://", "This is not a valid web address"),
        ("https://exa mple.com", "This is not a valid web address"),
    ],
)
def test_invalid_url(raw: str, message: str) -> None:
    result = validate(_draft(url=raw))
    assert result.errors == {Field.URL: message}
    assert result.draft.url == raw


@pytest.mark.parametrize("raw", ["javascript:alert(1)", "mailto:jane@example.com", "data:,x"])
def test_scheme_without_slashes_is_rejected(raw: str) -> None:
    assert Field.URL in validate(_draft(url=raw)).errors


# ---------------------------------------------------------------- alt urls


def test_alt_urls_normalized_deduplicated_and_main_dropped() -> None:
    result = validate(
        _draft(
            url="example.com",
            alt_urls=(
                "https://example.com/",
                "example.org",
                "",
                "  ",
                "EXAMPLE.org",
                "http://a.example.com",
                "https://a.example.com",
            ),
        )
    )
    assert result.ok
    assert result.draft.alt_urls == (
        "https://example.org",
        "http://a.example.com",
        "https://a.example.com",
    )


def test_bad_alt_url_is_reported_with_its_text() -> None:
    result = validate(_draft(alt_urls=("example.org", "  ftp://files.example  ")))
    assert result.errors == {Field.ALT_URLS: "“ftp://files.example” is not a valid web address"}
    assert result.draft.alt_urls == ("https://example.org",)


# ---------------------------------------------------------------- lengths


def test_password_required() -> None:
    assert validate(_draft(password="")).errors == {Field.PASSWORD: "Enter a password"}


def test_whitespace_password_is_accepted_verbatim() -> None:
    result = validate(_draft(password=SPACES))
    assert result.ok
    assert result.draft.password == SPACES


@pytest.mark.parametrize(
    ("field", "limit", "message"),
    [
        (Field.PASSWORD, MAX_PASSWORD, "Passwords are limited to 4096 characters"),
        (Field.USERNAME, MAX_USERNAME, "User names are limited to 512 characters"),
        (Field.TITLE, MAX_TITLE, "Titles are limited to 256 characters"),
        (Field.NOTES, MAX_NOTES, "Notes are limited to 10000 characters"),
    ],
)
def test_field_limits(field: Field, limit: int, message: str) -> None:
    assert validate(_draft(**{field.value: "x" * limit})).ok
    assert validate(_draft(**{field.value: "x" * (limit + 1)})).errors == {field: message}


def test_title_is_stripped() -> None:
    assert validate(_draft(title="  Example Mail ")).draft.title == "Example Mail"


def test_every_bad_field_is_reported_at_once() -> None:
    result = validate(
        Draft(url="ftp://x", password="", title="t" * (MAX_TITLE + 1), otpauth="otpauth://bad")
    )
    assert set(result.errors) == {Field.URL, Field.PASSWORD, Field.TITLE, Field.OTPAUTH}
    assert not result.ok


# ---------------------------------------------------------------- verification codes


def test_empty_code_stays_empty() -> None:
    assert validate(_draft(otpauth="   ")).draft.otpauth == ""


def test_valid_otpauth_uri_kept_as_is() -> None:
    uri = "otpauth://totp/Example:jane@example.com?" + urlencode({"secret": KEY_B32})
    result = validate(_draft(otpauth=f"  {uri} "))
    assert result.ok
    assert result.draft.otpauth == uri


@pytest.mark.parametrize(
    "uri",
    [
        "otpauth://totp/x",
        "OTPAUTH://totp/x?" + urlencode({"secret": "!!!"}),
        "otpauth://totp/x?" + urlencode({"secret": KEY_B32, "digits": "12"}),
        "otpauth:nothing",
    ],
)
def test_invalid_otpauth_uri(uri: str) -> None:
    result = validate(_draft(otpauth=uri))
    assert result.errors == {Field.OTPAUTH: "This verification code link is not valid"}
    assert result.draft.otpauth == uri


def test_setup_key_becomes_uri_with_issuer_and_account() -> None:
    result = validate(
        _draft(
            url="https://www.example.com",
            username="jane@example.com",
            title="Example Mail",
            otpauth="jbsw y3dp-ehpk 3pxp",
        )
    )
    assert result.ok
    params = parse_otpauth(result.draft.otpauth)
    assert params.period == 30
    parts = urlsplit(result.draft.otpauth)
    assert unquote(parts.path) == "/Example Mail:jane@example.com"
    assert parse_qs(parts.query) == {"secret": [KEY_B32], "issuer": ["Example Mail"]}


def test_setup_key_defaults_issuer_and_account_to_the_site() -> None:
    result = validate(_draft(url="https://www.example.com", otpauth=KEY_B32))
    parts = urlsplit(result.draft.otpauth)
    assert unquote(parts.path) == "/example.com:example.com"
    assert parse_qs(parts.query)["issuer"] == ["example.com"]


@pytest.mark.parametrize(
    ("key", "message"),
    [
        ("JBSW Y3D1 EHPK 3PXP", ONLY_BASE32),
        ("JBSW_Y3DP", ONLY_BASE32),
        ("JBSWY3DPE", "This setup key is incomplete"),
        ("JBSWY3DPEHPK3PXPA", "This setup key is incomplete"),
        ("JBSWY3DPEHPK3PX", "This setup key is too short"),
        ("JBSW", "This setup key is too short"),
    ],
)
def test_bad_setup_key(key: str, message: str) -> None:
    assert validate(_draft(otpauth=key)).errors == {Field.OTPAUTH: message}


def test_setup_key_to_otpauth_without_issuer_has_bare_label() -> None:
    uri = setup_key_to_otpauth(KEY_B32, account="jane@example.com", issuer="")
    assert uri == "otpauth://totp/jane@example.com?" + urlencode({"secret": KEY_B32})


def test_setup_key_to_otpauth_drops_padding_and_escapes_label() -> None:
    uri = setup_key_to_otpauth(f"{KEY_B32}======", account="j d", issuer="A&B")
    parts = urlsplit(uri)
    assert parts.path == "/A%26B:j%20d"
    assert parse_qs(parts.query) == {"secret": [KEY_B32], "issuer": ["A&B"]}
    assert parse_otpauth(uri).secret == b"Hello!\xde\xad\xbe\xef"


@pytest.mark.parametrize("field", ["password", "username", "title", "notes"])
def test_nul_is_rejected_before_dbus_would_cut_the_value(field: str) -> None:
    result = validate(_draft(**{field: "prefix\0suffix"}))
    assert result.errors == {Field(field): "Contains a character that cannot be saved"}


def test_saving_an_unchanged_url_keeps_it() -> None:
    first = validate(_draft(url="https://example.com/sign-in?tenant=acme#sso")).draft
    again = validate(_draft(url=first.url, title="Renamed")).draft
    assert again.url == first.url == "https://example.com/sign-in?tenant=acme#sso"


def test_nul_inside_an_otpauth_uri_is_rejected() -> None:
    # D-Bus would cut at the NUL and drop `period=60`, silently giving 30-second codes.
    uri = f"otpauth://totp/account?secret={KEY_B32}&issuer=A\0&period=60"
    result = validate(_draft(otpauth=uri))
    assert result.errors == {Field.OTPAUTH: "Contains a character that cannot be saved"}

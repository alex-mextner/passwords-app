# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Requests and responses of the native messaging protocol (see `extension/PROTOCOL.md`).

Validation is strict on purpose: the extension is the only legitimate sender, so anything it
would never send (extra fields, odd types, non-web URLs) is more likely a bug or an attack than
something worth guessing the meaning of.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal, override
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

PROTOCOL_VERSION: Final = 1
MAX_REQUEST_ID: Final = 2**53  # exclusive; the largest integer a JS number holds exactly
MAX_REQUEST_ID_CHARS: Final = 64
MAX_URL_CHARS: Final = 4096
MAX_ITEM_ID_CHARS: Final = 256
MAX_USERNAME_CHARS: Final = 1024
MAX_PASSWORD_CHARS: Final = 4096
MAX_TITLE_CHARS: Final = 256
_MAX_NAME_IN_MESSAGE: Final = 64

type RequestId = int | str
type ErrorCode = Literal[
    "malformed",
    "too-large",
    "bad-request",
    "not-allowed",
    "not-found",
    "daemon-unavailable",
    "unavailable",
    "auth-required",
    "locked",
    "invalid",
    "internal",
]
type SaveAction = Literal["create", "update", "none"]


class ProtocolError(Exception):
    """A failure answered with an error response; `message` never carries secrets."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code: ErrorCode = code
        self.message = message


def _bad(message: str) -> ProtocolError:
    return ProtocolError("bad-request", message)


def not_allowed() -> ProtocolError:
    return ProtocolError("not-allowed", "the item is not a candidate for this URL")


# ---------------------------------------------------------------------- requests


@dataclass(frozen=True, slots=True)
class Status:
    pass


@dataclass(frozen=True, slots=True)
class Match:
    url: str


@dataclass(frozen=True, slots=True)
class Fill:
    item_id: str
    url: str


@dataclass(frozen=True, slots=True)
class Code:
    item_id: str
    url: str


@dataclass(frozen=True, slots=True)
class Save:
    url: str
    username: str
    password: str
    title: str | None = None
    item_id: str | None = None
    dry_run: bool = False

    @override
    def __repr__(self) -> str:
        # The dataclass repr would print the password into any traceback or log line.
        return f"Save(url={self.url!r}, item_id={self.item_id!r}, dry_run={self.dry_run!r})"


type Command = Status | Match | Fill | Code | Save


@dataclass(frozen=True, slots=True)
class Request:
    id: RequestId
    command: Command


# (required, optional) fields per command, besides the envelope's `id` and `cmd`.
_FIELDS: Final[Mapping[str, tuple[frozenset[str], frozenset[str]]]] = {
    "status": (frozenset(), frozenset()),
    "match": (frozenset({"url"}), frozenset()),
    "fill": (frozenset({"item_id", "url"}), frozenset()),
    "code": (frozenset({"item_id", "url"}), frozenset()),
    "save": (
        frozenset({"url", "username", "password"}),
        frozenset({"title", "item_id", "dry_run"}),
    ),
}
COMMANDS: Final = frozenset(_FIELDS)


def _name(value: str) -> str:
    """Quote a caller-chosen name, shortened, for an error message."""
    return repr(value[:_MAX_NAME_IN_MESSAGE])


def _valid_text(value: str) -> bool:
    # D-Bus strings must be valid UTF-8 without NUL; lone surrogates fail the encode.
    if "\x00" in value:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def request_id(message: Mapping[str, object]) -> RequestId | None:
    """Return the envelope id to echo, or None when it is missing or not a valid id."""
    value = message.get("id")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value < MAX_REQUEST_ID else None
    if isinstance(value, str) and 1 <= len(value) <= MAX_REQUEST_ID_CHARS and "\x00" not in value:
        return value
    return None


def command_name(message: Mapping[str, object]) -> str | None:
    """Return `cmd` when it is a known command (safe to log), else None."""
    cmd = message.get("cmd")
    return cmd if isinstance(cmd, str) and cmd in COMMANDS else None


def _text(message: Mapping[str, object], key: str, *, min_chars: int, max_chars: int) -> str:
    value = message[key]
    if not isinstance(value, str):
        msg = f"{key} must be a string"
        raise _bad(msg)
    if not min_chars <= len(value) <= max_chars:
        msg = f"{key} must have {min_chars}-{max_chars} characters"
        raise _bad(msg)
    if not _valid_text(value):
        msg = f"{key} contains U+0000 or an unpaired surrogate"
        raise _bad(msg)
    return value


def _url(message: Mapping[str, object]) -> str:
    url = _text(message, "url", min_chars=1, max_chars=MAX_URL_CHARS)
    try:
        parts = urlsplit(url)
        # Reading the port validates it (range, digits); the value itself is not needed.
        _ = parts.port
    except ValueError:
        msg = "url cannot be parsed"
        raise _bad(msg) from None
    if parts.scheme.lower() not in {"http", "https"}:
        msg = "url must be http: or https:"
        raise _bad(msg)
    if not parts.hostname:
        msg = "url must have a host"
        raise _bad(msg)
    return url


def _item_id(message: Mapping[str, object]) -> str:
    return _text(message, "item_id", min_chars=1, max_chars=MAX_ITEM_ID_CHARS)


def _save(message: Mapping[str, object]) -> Save:
    dry_run = message.get("dry_run", False)
    if not isinstance(dry_run, bool):
        msg = "dry_run must be a boolean"
        raise _bad(msg)
    return Save(
        url=_url(message),
        username=_text(message, "username", min_chars=0, max_chars=MAX_USERNAME_CHARS),
        password=_text(message, "password", min_chars=1, max_chars=MAX_PASSWORD_CHARS),
        title=(
            _text(message, "title", min_chars=0, max_chars=MAX_TITLE_CHARS)
            if "title" in message
            else None
        ),
        item_id=_item_id(message) if "item_id" in message else None,
        dry_run=dry_run,
    )


def _command(cmd: str, message: Mapping[str, object]) -> Command:
    match cmd:
        case "status":
            return Status()
        case "match":
            return Match(url=_url(message))
        case "fill":
            return Fill(item_id=_item_id(message), url=_url(message))
        case "code":
            return Code(item_id=_item_id(message), url=_url(message))
        case _:
            return _save(message)


def parse_request(message: Mapping[str, object]) -> Request:
    """Validate a decoded frame; raises `ProtocolError` (`bad-request`)."""
    rid = request_id(message)
    if rid is None:
        msg = "id must be an integer in [0, 2^53) or a string of 1-64 characters"
        raise _bad(msg)
    cmd = message.get("cmd")
    if not isinstance(cmd, str):
        msg = "cmd must be a string"
        raise _bad(msg)
    fields = _FIELDS.get(cmd)
    if fields is None:
        msg = f"unknown command {_name(cmd)}"
        raise _bad(msg)
    required, optional = fields
    present = message.keys() - {"id", "cmd"}
    if unknown := present - required - optional:
        msg = f"unknown field {_name(min(unknown))} for {cmd}"
        raise _bad(msg)
    if missing := required - present:
        msg = f"missing field {min(missing)!r} for {cmd}"
        raise _bad(msg)
    return Request(id=rid, command=_command(cmd, message))


# ---------------------------------------------------------------------- results


@dataclass(frozen=True, slots=True)
class DaemonStatus:
    state: str
    message: str
    item_count: int


@dataclass(frozen=True, slots=True)
class Candidate:
    """A `Match` result as the extension may see it: no password, no otpauth, no notes."""

    id: str
    title: str
    username: str
    url: str
    alt_urls: tuple[str, ...]
    has_code: bool


@dataclass(frozen=True, slots=True)
class Login:
    username: str
    password: str

    @override
    def __repr__(self) -> str:
        return f"Login(username={self.username!r})"


def origin(url: str) -> str:
    """`scheme://host[:port]` of a validated URL: what a newly created item is saved under."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:  # IPv6 literal; urlsplit drops the brackets
        host = f"[{host}]"
    port = parts.port
    return f"{parts.scheme.lower()}://{host}" + (f":{port}" if port is not None else "")


def status_result(status: DaemonStatus) -> dict[str, object]:
    return {
        "state": status.state,
        "message": status.message,
        "item_count": status.item_count,
        "protocol": PROTOCOL_VERSION,
    }


def match_result(candidates: Sequence[Candidate]) -> dict[str, object]:
    return {
        "items": [
            {
                "id": c.id,
                "title": c.title,
                "username": c.username,
                "url": c.url,
                "alt_urls": list(c.alt_urls),
                "has_code": c.has_code,
            }
            for c in candidates
        ]
    }


def fill_result(login: Login) -> dict[str, object]:
    return {"username": login.username, "password": login.password}


def code_result(code: str, seconds_left: int) -> dict[str, object]:
    return {"code": code, "seconds_left": seconds_left}


def save_result(action: SaveAction, item_id: str | None, *, saved: bool) -> dict[str, object]:
    return {"action": action, "id": item_id, "saved": saved}


def ok(rid: RequestId | None, result: Mapping[str, object]) -> dict[str, object]:
    return {"id": rid, "ok": True, "result": dict(result)}


def failure(rid: RequestId | None, code: ErrorCode, message: str) -> dict[str, object]:
    return {"id": rid, "ok": False, "error": {"code": code, "message": message}}

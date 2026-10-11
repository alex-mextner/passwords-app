# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""`Credential` ⇄ Secret Service item (label, attributes, secret), spec §4.

Beyond the spec's attribute table we keep two bookkeeping attributes:

- ``title``: the label alone cannot round-trip a title (``title or host`` loses a title that
  equals the host, and ``""``), and a lossy round trip would make every sync see a change.
  The label stays the user-facing source: when someone renames the item in Seahorse, the
  new label wins and becomes the title.
- ``pa-synced``: when we last wrote the item (unix seconds). gnome-keyring bumps the item's
  ``Modified`` on every write, ours included, so ``Modified`` alone cannot tell a Seahorse
  edit from our own write; a ``Modified`` clearly after ``pa-synced`` can, and then becomes
  the credential's ``modified`` so "newer edit wins" sees the Seahorse edit as new.

Items without ``pa-id`` were not written by us (typically created in Seahorse): they are
*adopted* — given a fresh id, website and username read from our attributes if present,
else from the label — and the caller writes the result back.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from passwords_app.core.model import Credential
from passwords_app.keyring.labels import UnparseableLabelError, parse_label

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

SCHEMA = "io.github.alex_mextner.Passwords"
SCHEMA_ATTRIBUTE = "xdg:schema"
ID_ATTRIBUTE = "pa-id"
LABEL_SEPARATOR = " \u2014 "
# gnome-keyring timestamps have one-second resolution and our write itself takes a moment.
_EDIT_SLACK_SECONDS = 2
_OPTIONAL_TEXT = ("title", "notes", "otpauth", "group")


class ItemRejectedError(ValueError):
    """A keyring item that cannot become a Credential; the reason is shown to the user."""


@dataclass(frozen=True, slots=True)
class StoredItem:
    """An item as read from the collection (``created``/``modified`` are unix seconds).

    ``created`` may be left unread (None) when `needs_created` says the item is untouched
    since our last write: then it is in the attributes. Each property read costs
    gnome-keyring ~0.2 ms per item, which is what keeps a 2 000-item fetch inside its
    budget. The label is always read: a rename within a second or two of our write leaves
    ``Modified`` indistinguishable from the write itself.
    """

    ref: str
    label: str
    attributes: Mapping[str, str]
    secret: bytes
    created: int | None
    modified: int


@dataclass(frozen=True, slots=True)
class ItemContent:
    label: str
    attributes: dict[str, str]
    secret: bytes


@dataclass(frozen=True, slots=True)
class ReadItem:
    credential: Credential
    adopted: bool


def display_host(url: str) -> str:
    """``host[:port]`` of a URL, without user info; the URL itself if it has no host."""
    try:
        netloc = urlsplit(url).netloc
    except ValueError:
        return url
    return netloc.rpartition("@")[2] or url


def make_label(title: str | None, url: str, username: str) -> str:
    name = title or display_host(url)
    return f"{name}{LABEL_SEPARATOR}{username}" if username else name


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _parse_time(name: str, raw: str | None, fallback: int | None) -> datetime:
    if raw is None:
        if fallback is None:
            msg = f"attribute {name!r} is missing"
            raise ItemRejectedError(msg)
        return datetime.fromtimestamp(fallback, UTC)
    try:
        value = datetime.fromisoformat(raw)
    except ValueError as exc:
        msg = f"attribute {name!r} is not a timestamp"
        raise ItemRejectedError(msg) from exc
    if value.tzinfo is None:
        msg = f"attribute {name!r} has no time zone"
        raise ItemRejectedError(msg)
    return value


def item_content(credential: Credential, *, written_at: int) -> ItemContent:
    """Build what to store for a credential; ValueError for anything D-Bus cannot carry."""
    if any(not url or "\n" in url for url in credential.alt_urls):
        msg = "alternative URLs must be non-empty single lines"
        raise ValueError(msg)
    attributes = {
        SCHEMA_ATTRIBUTE: SCHEMA,
        ID_ATTRIBUTE: credential.id,
        "url": credential.url,
        "username": credential.username,
        "created": _format_time(credential.created),
        "modified": _format_time(credential.modified),
        "pa-synced": str(written_at),
    }
    try:
        server = urlsplit(credential.url).hostname
    except ValueError:
        server = None
    if server:
        attributes["server"] = server
    for name in _OPTIONAL_TEXT:
        value: str | None = getattr(credential, name)
        if value is not None:
            attributes[name] = value
    if credential.alt_urls:
        attributes["alt-urls"] = "\n".join(credential.alt_urls)
    label = make_label(credential.title, credential.url, credential.username)
    # Checked before any write: an update stores the secret first, so failing later on an
    # attribute would leave the new password under the old account.
    if not all(map(_dbus_string, (label, *attributes.values()))):
        msg = "text fields must not contain NUL characters or unpaired surrogates"
        raise ValueError(msg)
    return ItemContent(label=label, attributes=attributes, secret=credential.password.encode())


def _dbus_string(value: str) -> bool:
    """Whether D-Bus can carry `value` as a string (valid UTF-8 without NUL)."""
    if "\x00" in value:
        return False
    try:
        value.encode()
    except UnicodeEncodeError:
        return False
    return True


def _title(label: str, attributes: Mapping[str, str], url: str, username: str) -> str | None:
    stored = attributes.get("title")
    if label == make_label(stored, url, username):
        return stored
    # Renamed in Seahorse: the visible label is what the person wants to see everywhere.
    text = label.strip()
    suffix = f"{LABEL_SEPARATOR}{username}"
    if username and text.endswith(suffix):
        text = text[: -len(suffix)].strip()
    if not text or text == display_host(url):
        return None
    return text


def _edited_after_sync(attributes: Mapping[str, str], modified: int) -> bool:
    try:
        synced = int(attributes.get("pa-synced", "0"))
    except ValueError:
        synced = 0
    return modified > synced + _EDIT_SLACK_SECONDS


def needs_created(attributes: Mapping[str, str], modified: int) -> bool:
    """Whether the item's creation time must be read to map it.

    Not needed for an item of ours untouched since we wrote it: its timestamps are in the
    attributes.
    """
    return (
        not attributes.get(ID_ATTRIBUTE)
        or "created" not in attributes
        or "modified" not in attributes
        or _edited_after_sync(attributes, modified)
    )


def _modified(attributes: Mapping[str, str], item: StoredItem) -> datetime:
    modified = _parse_time("modified", attributes.get("modified"), item.modified)
    if _edited_after_sync(attributes, item.modified):
        modified = max(modified, datetime.fromtimestamp(item.modified, UTC))
    return modified


def _password(item: StoredItem) -> str:
    try:
        return item.secret.decode()
    except UnicodeDecodeError as exc:
        msg = "the secret is not text"
        raise ItemRejectedError(msg) from exc


def _read_ours(item: StoredItem, password: str) -> Credential:
    attributes = item.attributes
    url = attributes.get("url", "")
    if not url:
        msg = "attribute 'url' is missing"
        raise ItemRejectedError(msg)
    username = attributes.get("username", "")
    alt_urls = attributes.get("alt-urls", "")
    return Credential(
        id=attributes[ID_ATTRIBUTE],
        url=url,
        username=username,
        password=password,
        created=_parse_time("created", attributes.get("created"), item.created),
        modified=_modified(attributes, item),
        title=_title(item.label, attributes, url, username),
        notes=attributes.get("notes"),
        otpauth=attributes.get("otpauth"),
        alt_urls=tuple(alt_urls.split("\n")) if alt_urls else (),
        group=attributes.get("group"),
    )


def _adopt(item: StoredItem, password: str, new_id: str) -> Credential:
    attributes = item.attributes
    url = attributes.get("url", "") if attributes.get(SCHEMA_ATTRIBUTE) == SCHEMA else ""
    notes = otpauth = group = None
    alt_urls: tuple[str, ...] = ()
    if url:
        # Our schema without a pa-id (e.g. restored from a backup): keep every field we know.
        username = attributes.get("username", "")
        title = _title(item.label, attributes, url, username)
        notes, otpauth, group = (attributes.get(k) for k in ("notes", "otpauth", "group"))
        alt = attributes.get("alt-urls", "")
        alt_urls = tuple(alt.split("\n")) if alt else ()
    else:
        try:
            parsed = parse_label(item.label)
        except UnparseableLabelError as exc:
            raise ItemRejectedError(str(exc)) from exc
        url, username, title = parsed.url, parsed.username, None
    created = item.modified if item.created is None else item.created
    return Credential(
        id=new_id,
        url=url,
        username=username,
        password=password,
        created=datetime.fromtimestamp(created, UTC),
        modified=datetime.fromtimestamp(item.modified, UTC),
        title=title,
        notes=notes,
        otpauth=otpauth,
        alt_urls=alt_urls,
        group=group,
    )


def read_item(item: StoredItem, *, new_id: Callable[[], str]) -> ReadItem:
    """Map an item to a Credential, adopting it if it has no ``pa-id``."""
    password = _password(item)
    if item.attributes.get(ID_ATTRIBUTE):
        return ReadItem(_read_ours(item, password), adopted=False)
    adopted = _adopt(item, password, new_id())
    # Adoption writes the item back; reject here what that write could not represent,
    # so one bad item is reported instead of aborting the whole fetch.
    try:
        item_content(adopted, written_at=item.modified)
    except ValueError as exc:
        raise ItemRejectedError(str(exc)) from exc
    return ReadItem(adopted, adopted=True)

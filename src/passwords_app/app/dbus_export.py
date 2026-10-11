# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""What the app itself exports on its own bus name `io.github.alex_mextner.Passwords.App`.

- `org.freedesktop.Application`, so a second launch hands over to the running instance (the
  GApplication runs NON_UNIQUE because the daemon owns the app id as its bus name).
- `org.gnome.Shell.SearchProvider2`: typing a site name in Activities lists matching logins;
  activating one copies its password.

Only titles, user names and websites are sent to the Shell, never a password.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from gi.repository import Gio, GLib

from passwords_app.app.constants import APP_BUS_NAME, APP_ID, APP_OBJECT_PATH, SEARCH_PROVIDER_PATH
from passwords_app.app.search import Query

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from passwords_app.app.records import Item

MAX_RESULTS = 8

_APPLICATION_XML = """
<node>
  <interface name="org.freedesktop.Application">
    <method name="Activate"><arg type="a{sv}" name="platform_data" direction="in"/></method>
    <method name="Open">
      <arg type="as" name="uris" direction="in"/>
      <arg type="a{sv}" name="platform_data" direction="in"/>
    </method>
    <method name="ActivateAction">
      <arg type="s" name="action_name" direction="in"/>
      <arg type="av" name="parameter" direction="in"/>
      <arg type="a{sv}" name="platform_data" direction="in"/>
    </method>
  </interface>
</node>
"""

_SEARCH_XML = """
<node>
  <interface name="org.gnome.Shell.SearchProvider2">
    <method name="GetInitialResultSet">
      <arg type="as" name="terms" direction="in"/>
      <arg type="as" name="results" direction="out"/>
    </method>
    <method name="GetSubsearchResultSet">
      <arg type="as" name="previous_results" direction="in"/>
      <arg type="as" name="terms" direction="in"/>
      <arg type="as" name="results" direction="out"/>
    </method>
    <method name="GetResultMetas">
      <arg type="as" name="identifiers" direction="in"/>
      <arg type="aa{sv}" name="metas" direction="out"/>
    </method>
    <method name="ActivateResult">
      <arg type="s" name="identifier" direction="in"/>
      <arg type="as" name="terms" direction="in"/>
      <arg type="u" name="timestamp" direction="in"/>
    </method>
    <method name="LaunchSearch">
      <arg type="as" name="terms" direction="in"/>
      <arg type="u" name="timestamp" direction="in"/>
    </method>
  </interface>
</node>
"""

# RequestName replies (D-Bus specification).
_PRIMARY_OWNER = 1
_ALREADY_OWNER = 4
_DO_NOT_QUEUE = 4


def search(items: Sequence[tuple[Item, str]], terms: Sequence[str]) -> list[str]:
    """Ids of items whose haystack contains every term; best (title prefix) first."""
    query = Query.parse(" ".join(terms))
    if query.empty:
        return []
    first = query.tokens[0]
    hits = [(item, hay) for item, hay in items if query.matches(hay)]
    hits.sort(key=lambda pair: (not pair[1].startswith(first), pair[0].display_title.casefold()))
    return [item.id for item, _hay in hits[:MAX_RESULTS]]


def result_meta(item: Item) -> dict[str, GLib.Variant]:
    description = " · ".join(p for p in (item.username, item.host) if p)
    return {
        "id": GLib.Variant("s", item.id),
        "name": GLib.Variant("s", item.display_title),
        "description": GLib.Variant("s", description),
        "gicon": GLib.Variant("s", Gio.ThemedIcon.new(APP_ID).to_string() or APP_ID),
    }


def claim_app_name(connection: Gio.DBusConnection) -> bool:
    """Become the primary instance; False when another instance already runs."""
    reply = connection.call_sync(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "RequestName",
        GLib.Variant("(su)", (APP_BUS_NAME, _DO_NOT_QUEUE)),
        GLib.VariantType.new("(u)"),
        Gio.DBusCallFlags.NONE,
        5000,
        None,
    )
    (code,) = cast("tuple[int]", reply.unpack())
    return code in {_PRIMARY_OWNER, _ALREADY_OWNER}


def release_app_name(connection: Gio.DBusConnection) -> None:
    connection.call_sync(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "ReleaseName",
        GLib.Variant("(s)", (APP_BUS_NAME,)),
        GLib.VariantType.new("(u)"),
        Gio.DBusCallFlags.NONE,
        5000,
        None,
    )


def forward_to_primary(connection: Gio.DBusConnection, action: str | None) -> None:
    """Ask the running instance to show its window (or run `action`, e.g. new-password)."""
    if action:
        method, params = "ActivateAction", GLib.Variant("(sava{sv})", (action, [], {}))
    else:
        method, params = "Activate", GLib.Variant("(a{sv})", ({},))
    connection.call_sync(
        APP_BUS_NAME,
        APP_OBJECT_PATH,
        "org.freedesktop.Application",
        method,
        params,
        None,
        Gio.DBusCallFlags.NONE,
        5000,
        None,
    )


class AppExports:
    """Registers both interfaces on `connection`; callbacks run on the main context."""

    def __init__(  # noqa: PLR0913 - one keyword-only callback per exported method
        self,
        connection: Gio.DBusConnection,
        *,
        items: Callable[[], Sequence[tuple[Item, str]]],
        lookup: Callable[[str], Item | None],
        on_activate: Callable[[], None],
        on_action: Callable[[str], None],
        on_result: Callable[[str], None],
        on_launch_search: Callable[[str], None],
    ) -> None:
        self.connection = connection
        self._items = items
        self._lookup = lookup
        self._on_activate = on_activate
        self._on_action = on_action
        self._on_result = on_result
        self._on_launch_search = on_launch_search
        app_info = Gio.DBusNodeInfo.new_for_xml(_APPLICATION_XML).interfaces[0]
        search_info = Gio.DBusNodeInfo.new_for_xml(_SEARCH_XML).interfaces[0]
        self._ids = [
            connection.register_object_with_closures2(
                APP_OBJECT_PATH, app_info, self._on_app_call, None, None
            ),
            connection.register_object_with_closures2(
                SEARCH_PROVIDER_PATH, search_info, self._on_search_call, None, None
            ),
        ]

    def close(self) -> None:
        for registration in self._ids:
            self.connection.unregister_object(registration)
        self._ids.clear()

    def _on_app_call(
        self,
        _conn: Gio.DBusConnection,
        _sender: str,
        _path: str,
        _iface: str,
        method: str,
        params: GLib.Variant,
        invocation: Gio.DBusMethodInvocation,
    ) -> None:
        if method == "ActivateAction":
            name = cast("tuple[str, list[object], dict[str, object]]", params.unpack())[0]
            self._on_action(name)
        else:
            self._on_activate()
        invocation.return_value(None)

    def _on_search_call(
        self,
        _conn: Gio.DBusConnection,
        _sender: str,
        _path: str,
        _iface: str,
        method: str,
        params: GLib.Variant,
        invocation: Gio.DBusMethodInvocation,
    ) -> None:
        args = cast("tuple[object, ...]", params.unpack())
        if method == "GetInitialResultSet":
            terms = cast("list[str]", args[0])
            invocation.return_value(GLib.Variant("(as)", (search(self._items(), terms),)))
        elif method == "GetSubsearchResultSet":
            previous = set(cast("list[str]", args[0]))
            terms = cast("list[str]", args[1])
            pool = [(i, h) for i, h in self._items() if i.id in previous]
            invocation.return_value(GLib.Variant("(as)", (search(pool, terms),)))
        elif method == "GetResultMetas":
            metas = [
                result_meta(item)
                for item_id in cast("list[str]", args[0])
                if (item := self._lookup(item_id)) is not None
            ]
            invocation.return_value(GLib.Variant("(aa{sv})", (metas,)))
        elif method == "ActivateResult":
            self._on_result(cast("str", args[0]))
            invocation.return_value(None)
        else:  # LaunchSearch
            self._on_launch_search(" ".join(cast("list[str]", args[0])))
            invocation.return_value(None)

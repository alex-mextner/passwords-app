# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Validate the app's installable data files and the identifiers they must agree on.

The real freedesktop/GNOME validators run when installed; cross-file invariants are checked
directly because a mismatch between them (e.g. desktop id vs. search provider DesktopId)
fails silently at runtime instead of at install time.
"""

from __future__ import annotations

import configparser
import re
import shutil
import subprocess
import warnings
import xml.etree.ElementTree as ET
from pathlib import Path

import gi
import pytest

gi.require_version("Gio", "2.0")
gi.require_version("GLib", "2.0")
gi.require_version("GdkPixbuf", "2.0")
# Gtk is deliberately never imported: it would connect to the developer's real display.
with warnings.catch_warnings():
    # PyGObject's own GLib overrides touch a deprecated alias while loading; that is the
    # distro's PyGObject/GLib pairing, not this project, and filterwarnings=error would abort.
    warnings.simplefilter("ignore", DeprecationWarning)
    from gi.repository import GdkPixbuf, Gio, GLib

ROOT = Path(__file__).resolve().parents[3]
DATA = ROOT / "data"
APP_ID = "io.github.alex_mextner.Passwords"
DAEMON_BUS_NAME = "io.github.alex_mextner.Passwords"
APP_BUS_NAME = "io.github.alex_mextner.Passwords.App"

DESKTOP = DATA / "applications" / f"{APP_ID}.desktop"
METAINFO = DATA / "metainfo" / f"{APP_ID}.metainfo.xml"
SCHEMA_DIR = DATA / "glib-2.0" / "schemas"
SCHEMA = SCHEMA_DIR / f"{APP_ID}.gschema.xml"
POLICY = DATA / "polkit" / f"{APP_ID}.policy"
SEARCH_INI = DATA / "search-providers" / f"{APP_ID}.search-provider.ini"
SEARCH_SERVICE = DATA / "search-providers" / f"{APP_ID}.App.service"
ICON = DATA / "icons" / "hicolor" / "scalable" / "apps" / f"{APP_ID}.svg"
SYMBOLIC = DATA / "icons" / "hicolor" / "symbolic" / "apps" / f"{APP_ID}-symbolic.svg"
ACTION_ICON_DIR = ROOT / "src/passwords_app/app/ui/icons/hicolor/scalable/actions"
ACTION_ICONS = tuple(
    ACTION_ICON_DIR / f"pa-{name}-symbolic.svg"
    for name in (
        "codes",
        "synced",
        "syncing",
        "paused",
        "offline",
        "error",
        "external-link",
        "shared-group",
        "key",
        "generate",
    )
)
SYMBOLIC_ICONS = (SYMBOLIC, *ACTION_ICONS)
POLKIT_DTD = Path("/usr/share/polkit-1/policyconfig-1.dtd")
POLKIT_DTD_SYSTEM_ID = "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd"

SVG_NS = "{http://www.w3.org/2000/svg}"
XLINK_HREF = "{http://www.w3.org/1999/xlink}href"
DATA_FILES = (
    DESKTOP,
    METAINFO,
    SCHEMA,
    POLICY,
    SEARCH_INI,
    SEARCH_SERVICE,
    ICON,
    SYMBOLIC,
)


def _tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        pytest.skip(f"{name} is not installed")
    return path


def _run(*argv: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603  (resolved validator binary, repo-owned inputs)
        argv, capture_output=True, text=True, check=False, timeout=60, env=env
    )


def _parse(path: Path) -> ET.Element:
    # Repo-owned files, not untrusted input; the stdlib parser is sufficient.
    return ET.parse(path).getroot()  # noqa: S314


def _keyfile(path: Path) -> GLib.KeyFile:
    keyfile = GLib.KeyFile()
    keyfile.load_from_file(str(path), GLib.KeyFileFlags.KEEP_TRANSLATIONS)
    return keyfile


def _render(path: Path, size: int) -> GdkPixbuf.Pixbuf:
    pixbuf = GdkPixbuf.Pixbuf.new_from_file_at_size(str(path), size, size)
    assert pixbuf is not None
    return pixbuf


def _ini(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    parser.read(path, encoding="utf-8")
    return parser


@pytest.fixture(scope="module")
def schema(tmp_path_factory: pytest.TempPathFactory) -> Gio.SettingsSchema:
    compiler = _tool("glib-compile-schemas")
    target = tmp_path_factory.mktemp("schemas")
    # Summaries and descriptions are read from the XML next to gschemas.compiled.
    shutil.copy(SCHEMA, target)
    result = _run(compiler, "--strict", str(target))
    assert result.returncode == 0, result.stderr
    source = Gio.SettingsSchemaSource.new_from_directory(str(target), None, trusted=True)
    loaded = source.lookup(APP_ID, recursive=False)
    assert loaded is not None
    return loaded


# --- desktop entry -----------------------------------------------------------------------


def test_desktop_file_passes_desktop_file_validate_silently() -> None:
    result = _run(_tool("desktop-file-validate"), str(DESKTOP))
    assert result.returncode == 0
    assert result.stdout + result.stderr == ""


def test_desktop_entry_launches_the_app_binary_with_its_own_icon() -> None:
    entry = _keyfile(DESKTOP)
    assert entry.get_string("Desktop Entry", "Exec") == "passwords-app"
    assert entry.get_string("Desktop Entry", "Icon") == APP_ID
    assert entry.get_boolean("Desktop Entry", "StartupNotify")
    assert entry.get_boolean("Desktop Entry", "X-GNOME-UsesNotifications")


def test_desktop_entry_is_not_dbus_activatable() -> None:
    # The daemon owns the app id's bus name, so D-Bus activation would start the daemon.
    entry = _keyfile(DESKTOP)
    keys, _ = entry.get_keys("Desktop Entry")
    assert "DBusActivatable" not in keys


def test_russian_name_is_distinct_from_seahorse() -> None:
    entry = _keyfile(DESKTOP)
    assert entry.get_locale_string("Desktop Entry", "Name", "ru") == "Пароли"
    assert entry.get_locale_string("Desktop Entry", "Name", "ru") != "Пароли и ключи"
    assert entry.get_string("Desktop Entry", "Name") == "Passwords"


def test_desktop_entry_is_findable_by_keywords_in_both_languages() -> None:
    entry = _keyfile(DESKTOP)
    english = entry.get_string_list("Desktop Entry", "Keywords")
    russian = entry.get_locale_string_list("Desktop Entry", "Keywords", "ru")
    assert {"password", "keychain", "icloud", "totp"} <= set(english)
    assert {"пароль", "icloud"} <= set(russian)


def test_new_password_action_is_declared_and_runnable() -> None:
    entry = _keyfile(DESKTOP)
    assert entry.get_string_list("Desktop Entry", "Actions") == ["new-password"]
    group = "Desktop Action new-password"
    assert entry.get_string(group, "Exec") == "passwords-app --new"
    assert entry.get_locale_string(group, "Name", "ru")


# --- AppStream ---------------------------------------------------------------------------


def test_metainfo_passes_pedantic_appstream_validation() -> None:
    result = _run(_tool("appstreamcli"), "validate", "--no-net", "--pedantic", str(METAINFO))
    assert result.returncode == 0, result.stdout
    issues = [line for line in result.stdout.splitlines() if re.match(r"^[EWI]: ", line)]
    assert issues == []
    # The only pedantic note allowed is about upper case in the fixed, already published
    # reverse-DNS app id ("Passwords"), which cannot change without breaking user installs.
    pedantic = [line for line in result.stdout.splitlines() if line.startswith("P: ")]
    assert all("cid-contains-uppercase-letter" in line for line in pedantic)


def test_metainfo_identifies_the_app_and_its_bus_name() -> None:
    root = _parse(METAINFO)
    assert root.findtext("id") == APP_ID
    assert root.findtext("launchable[@type='desktop-id']") == DESKTOP.name
    assert root.findtext("provides/binary") == "passwords-app"
    assert root.findtext("provides/dbus[@type='user']") == APP_BUS_NAME
    assert root.findtext("translation[@type='gettext']") == "passwords-app"
    assert root.findtext("project_license") == "MIT"
    assert root.findtext("metadata_license") == "CC0-1.0"


def test_metainfo_screenshots_point_at_published_proof_images() -> None:
    root = _parse(METAINFO)
    images = [image.text for image in root.iterfind("screenshots/screenshot/image")]
    prefix = "https://raw.githubusercontent.com/alex-mextner/passwords-app/main/docs/proof/app/"
    assert images == [
        f"{prefix}en-light-all.png",
        f"{prefix}en-dark-detail.png",
        f"{prefix}en-light-security.png",
        f"{prefix}en-light-signin-device.png",
    ]
    assert all(shot.findtext("caption") for shot in root.iterfind("screenshots/screenshot"))


def test_metainfo_has_branding_for_both_color_schemes() -> None:
    root = _parse(METAINFO)
    schemes = {color.get("scheme_preference") for color in root.iterfind("branding/color")}
    assert schemes == {"light", "dark"}


def test_first_release_is_dated() -> None:
    root = _parse(METAINFO)
    release = root.find("releases/release")
    assert release is not None
    assert (release.get("version"), release.get("date")) == ("0.1.0", "2026-10-10")


# --- GNOME Shell search provider ---------------------------------------------------------


def test_search_provider_names_the_app_owned_bus_not_the_daemon() -> None:
    provider = _ini(SEARCH_INI)["Shell Search Provider"]
    assert provider["BusName"] == APP_BUS_NAME
    assert provider["BusName"] != DAEMON_BUS_NAME
    assert provider["ObjectPath"] == "/io/github/alex_mextner/Passwords/SearchProvider"
    assert provider["Version"] == "2"


def test_search_provider_bus_name_is_dbus_activatable_into_the_app() -> None:
    service = _ini(SEARCH_SERVICE)["D-BUS Service"]
    provider = _ini(SEARCH_INI)["Shell Search Provider"]
    assert service["Name"] == provider["BusName"]
    assert service["Exec"] == "@BINDIR@/passwords-app --search-provider"


def test_all_files_agree_on_the_app_id() -> None:
    provider = _ini(SEARCH_INI)["Shell Search Provider"]
    root = _parse(METAINFO)
    ids = {
        DESKTOP.name.removesuffix(".desktop"),
        provider["DesktopId"].removesuffix(".desktop"),
        _keyfile(DESKTOP).get_string("Desktop Entry", "Icon"),
        root.findtext("id"),
        (root.findtext("launchable") or "").removesuffix(".desktop"),
        ICON.stem,
        SYMBOLIC.stem.removesuffix("-symbolic"),
        _parse(POLICY).findtext("icon_name"),
    }
    assert ids == {APP_ID}


# --- GSettings ---------------------------------------------------------------------------


def test_schema_compiles_strictly(schema: Gio.SettingsSchema) -> None:
    assert schema.get_id() == APP_ID
    assert schema.get_path() == "/io/github/alex_mextner/Passwords/"


def test_schema_has_exactly_the_specified_keys(schema: Gio.SettingsSchema) -> None:
    assert set(schema.list_keys()) == {
        "clipboard-clear-seconds",
        "lock-enabled",
        "lock-idle-minutes",
        "hibp-enabled",
        "favicons-enabled",
        "sort-order",
        "window-width",
        "window-height",
        "window-maximized",
        "generator-mode",
        "generator-length",
        "generator-uppercase",
        "generator-digits",
        "generator-symbols",
    }
    for name in schema.list_keys():
        key = schema.get_key(name)
        assert key.get_summary(), name
        assert key.get_description(), name


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("clipboard-clear-seconds", 45),
        ("lock-enabled", False),
        ("lock-idle-minutes", 5),
        ("hibp-enabled", False),
        ("favicons-enabled", False),
        ("sort-order", "title"),
        ("window-width", 1180),
        ("window-height", 760),
        ("window-maximized", False),
        ("generator-mode", "apple"),
        ("generator-length", 20),
        ("generator-uppercase", True),
        ("generator-digits", True),
        ("generator-symbols", True),
    ],
)
def test_schema_defaults(schema: Gio.SettingsSchema, name: str, expected: object) -> None:
    assert schema.get_key(name).get_default_value().unpack() == expected


@pytest.mark.parametrize(
    ("name", "lowest", "highest"),
    [
        ("clipboard-clear-seconds", 0, 600),
        ("lock-idle-minutes", 1, 120),
        ("generator-length", 8, 64),
    ],
)
def test_schema_ranges_accept_bounds_and_reject_outside(
    schema: Gio.SettingsSchema, name: str, lowest: int, highest: int
) -> None:
    key = schema.get_key(name)
    assert key.range_check(GLib.Variant.new_uint32(lowest))
    assert key.range_check(GLib.Variant.new_uint32(highest))
    assert not key.range_check(GLib.Variant.new_uint32(highest + 1))
    if lowest > 0:
        assert not key.range_check(GLib.Variant.new_uint32(lowest - 1))


@pytest.mark.parametrize(
    ("name", "choices"),
    [("sort-order", ["title", "website", "modified"]), ("generator-mode", ["apple", "custom"])],
)
def test_schema_enumerated_choices(
    schema: Gio.SettingsSchema, name: str, choices: list[str]
) -> None:
    kind, allowed = schema.get_key(name).get_range().unpack()
    assert (kind, allowed) == ("enum", choices)
    assert not schema.get_key(name).range_check(GLib.Variant.new_string("random"))


# --- polkit ------------------------------------------------------------------------------


def test_policy_is_valid_against_the_polkit_dtd(tmp_path: Path) -> None:
    xmllint = _tool("xmllint")
    if not POLKIT_DTD.exists():
        pytest.skip(f"{POLKIT_DTD} is not installed")
    # Map the DTD's public URL to the local copy so validation never touches the network.
    catalog = tmp_path / "catalog.xml"
    catalog.write_text(
        '<?xml version="1.0"?>\n'
        '<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">\n'
        f'  <system systemId="{POLKIT_DTD_SYSTEM_ID}" uri="{POLKIT_DTD.as_uri()}"/>\n'
        "</catalog>\n",
        encoding="utf-8",
    )
    env = {"XML_CATALOG_FILES": str(catalog), "PATH": "/usr/bin:/bin"}
    result = _run(xmllint, "--noout", "--nonet", "--valid", str(POLICY), env=env)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""


def test_unlock_action_requires_the_users_own_password_and_is_translated() -> None:
    root = _parse(POLICY)
    actions = root.findall("action")
    assert [action.get("id") for action in actions] == [f"{APP_ID}.unlock"]
    (action,) = actions
    defaults = action.find("defaults")
    assert defaults is not None
    assert {child.tag: child.text for child in defaults} == {
        "allow_any": "auth_self",
        "allow_inactive": "auth_self",
        "allow_active": "auth_self",
    }
    lang = "{http://www.w3.org/XML/1998/namespace}lang"
    for tag in ("description", "message"):
        assert {element.get(lang) for element in action.iterfind(tag)} == {None, "ru"}


# --- icons -------------------------------------------------------------------------------


@pytest.mark.parametrize("path", [ICON, *SYMBOLIC_ICONS], ids=lambda path: path.name)
def test_icons_are_self_contained_plain_svg(path: Path) -> None:
    root = _parse(path)
    assert root.tag == f"{SVG_NS}svg"
    tags = {element.tag for element in root.iter()}
    assert f"{SVG_NS}script" not in tags
    assert f"{SVG_NS}foreignObject" not in tags
    for element in root.iter():
        for attribute in ("href", XLINK_HREF):
            target = element.get(attribute)
            assert target is None or target.startswith("#"), target
    text = path.read_text(encoding="utf-8")
    assert "inkscape" not in text.lower()
    assert "sodipodi" not in text.lower()


def test_app_icon_has_a_128_canvas_and_renders_visibly_at_32px() -> None:
    root = _parse(ICON)
    assert (root.get("width"), root.get("height"), root.get("viewBox")) == (
        "128",
        "128",
        "0 0 128 128",
    )
    pixbuf = _render(ICON, 32)
    assert (pixbuf.get_width(), pixbuf.get_height()) == (32, 32)
    assert pixbuf.get_has_alpha()
    pixels = pixbuf.get_pixels()
    stride, channels = pixbuf.get_rowstride(), pixbuf.get_n_channels()
    alphas = [pixels[y * stride + x * channels + 3] for y in range(32) for x in range(32)]
    opaque = sum(alpha == 255 for alpha in alphas)
    # The tile fills most of the canvas; the corners stay transparent.
    assert opaque > 32 * 32 // 2
    assert alphas[0] == 0


@pytest.mark.parametrize("path", SYMBOLIC_ICONS, ids=lambda path: path.name)
def test_symbolic_icons_are_16px_and_single_colored(path: Path) -> None:
    # GTK recolors symbolic icons by fill; a second color or a stroke would not follow the theme.
    root = _parse(path)
    assert (root.get("width"), root.get("height"), root.get("viewBox")) == (
        "16",
        "16",
        "0 0 16 16",
    )
    shapes = [element for element in root.iter() if element.tag != f"{SVG_NS}svg"]
    assert shapes
    assert {element.get("fill") for element in shapes} == {"#2e3436"}
    assert all(element.get("stroke") in {None, "none"} for element in shapes)
    pixbuf = _render(path, 16)
    assert any(pixbuf.get_pixels()[3 :: pixbuf.get_n_channels()])


# --- wording -----------------------------------------------------------------------------


@pytest.mark.parametrize("path", DATA_FILES + ACTION_ICONS, ids=lambda path: path.name)
def test_no_data_file_mentions_escrow(path: Path) -> None:
    assert "escrow" not in path.read_text(encoding="utf-8").lower()

# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The Russian catalog: complete for the current sources, well-formed, and wired into `i18n`.

The POT is re-extracted from the sources on every run, so adding or changing an English string
without translating it fails here rather than shipping half-English UI.
"""

from __future__ import annotations

import gettext
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from passwords_app.app import formatting, i18n
from passwords_app.app.constants import GETTEXT_DOMAIN

ROOT = Path(__file__).resolve().parents[3]
PO_DIR = ROOT / "po"
RU_PO = PO_DIR / "ru.po"
APP_SRC = ROOT / "src" / "passwords_app" / "app"
XGETTEXT = shutil.which("xgettext") or shutil.which("/home/linuxbrew/.linuxbrew/bin/xgettext")
MSGFMT = shutil.which("msgfmt") or shutil.which("/home/linuxbrew/.linuxbrew/bin/msgfmt")
PLACEHOLDER = re.compile(r"\{([a-z_]*)\}")
FORBIDDEN = re.compile(r"escrow|эскроу|депонир", re.IGNORECASE)


class Entry:
    def __init__(self) -> None:
        self.msgid = ""
        self.msgid_plural: str | None = None
        self.msgctxt: str | None = None
        self.msgstr: dict[int, str] = {}
        self.flags: set[str] = set()
        self.obsolete = False


def _unquote(text: str) -> str:
    return text.strip()[1:-1].encode("raw_unicode_escape").decode("unicode_escape")


def parse_po(path: Path) -> list[Entry]:  # noqa: C901, PLR0912 - one flat dispatch per PO line kind
    """Minimal PO reader: enough for msgid/msgid_plural/msgstr[n] and `#,` flags."""
    entries: list[Entry] = []
    current = Entry()
    field: tuple[str, int] | None = None

    def flush() -> None:
        nonlocal current
        if field is not None or current.flags:
            entries.append(current)
        current = Entry()

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            flush()
            field = None
            continue
        if line.startswith("#~"):
            current.obsolete = True
            continue
        if line.startswith("#,"):
            current.flags |= {f.strip() for f in line[2:].split(",")}
            continue
        if line.startswith("#"):
            continue
        if line.startswith("msgctxt "):
            field = ("msgctxt", 0)
            current.msgctxt = _unquote(line[len("msgctxt ") :])
            continue
        if line.startswith("msgid_plural "):
            field = ("msgid_plural", 0)
            current.msgid_plural = _unquote(line[len("msgid_plural ") :])
        elif line.startswith("msgid "):
            field = ("msgid", 0)
            current.msgid = _unquote(line[len("msgid ") :])
        elif line.startswith("msgstr["):
            index = int(line[7 : line.index("]")])
            field = ("msgstr", index)
            current.msgstr[index] = _unquote(line[line.index("]") + 1 :])
        elif line.startswith("msgstr "):
            field = ("msgstr", 0)
            current.msgstr[0] = _unquote(line[len("msgstr ") :])
        elif line.startswith('"') and field is not None:
            name, index = field
            if name == "msgctxt":
                current.msgctxt = (current.msgctxt or "") + _unquote(line)
            elif name == "msgid":
                current.msgid += _unquote(line)
            elif name == "msgid_plural":
                current.msgid_plural = (current.msgid_plural or "") + _unquote(line)
            else:
                current.msgstr[index] += _unquote(line)
    flush()
    return [e for e in entries if e.msgid and not e.obsolete]


RU_ENTRIES = parse_po(RU_PO)
RU_BY_KEY = {(e.msgctxt, e.msgid): e for e in RU_ENTRIES}
PLURAL_KEYS = [(e.msgctxt, e.msgid) for e in RU_ENTRIES if e.msgid_plural]


def extract_pot(target: Path) -> Path:
    if XGETTEXT is None:
        pytest.skip("xgettext is not installed")
    sources = sorted(str(p.relative_to(ROOT)) for p in APP_SRC.rglob("*.py"))
    pot = target / "fresh.pot"
    subprocess.run(  # noqa: S603 - fixed xgettext path from shutil.which; argv built here
        [
            XGETTEXT,
            "--language=Python",
            "--from-code=UTF-8",
            "--keyword=_",
            "--keyword=ngettext:1,2",
            "--keyword=pgettext:1c,2",
            "--keyword=_n_",
            "--add-comments=Translators",
            "--package-name=passwords-app",
            "-o",
            str(pot),
            *sources,
        ],
        cwd=ROOT,
        check=True,
    )
    return pot


@pytest.fixture(scope="module")
def localedir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if MSGFMT is None:
        pytest.skip("msgfmt is not installed")
    root = tmp_path_factory.mktemp("locale")
    messages = root / "ru" / "LC_MESSAGES"
    messages.mkdir(parents=True)
    # Fixed msgfmt path from shutil.which; argv built here.
    subprocess.run([MSGFMT, "-o", str(messages / f"{GETTEXT_DOMAIN}.mo"), str(RU_PO)], check=True)  # noqa: S603
    return root


@pytest.fixture(scope="module")
def ru(localedir: Path) -> gettext.GNUTranslations:
    with (localedir / "ru" / "LC_MESSAGES" / f"{GETTEXT_DOMAIN}.mo").open("rb") as f:
        return gettext.GNUTranslations(f)


@pytest.fixture
def russian(localedir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(i18n, "_translation", i18n._translation)  # restored after the test
    monkeypatch.setenv(i18n.LOCALEDIR_ENV, str(localedir))
    i18n.setup(["ru"])


def test_fresh_extraction_is_fully_translated(tmp_path: Path) -> None:
    fresh = parse_po(extract_pot(tmp_path))
    assert fresh, "xgettext found no strings"
    missing = []
    for source in fresh:
        entry = RU_BY_KEY.get((source.msgctxt, source.msgid))
        ok = (
            entry is not None
            and "fuzzy" not in entry.flags
            and entry.msgid_plural == source.msgid_plural
            and all(entry.msgstr.get(i) for i in range(3 if source.msgid_plural else 1))
        )
        if not ok:
            missing.append(source.msgid)
    assert missing == []


def test_committed_pot_matches_sources(tmp_path: Path) -> None:
    fresh = {(e.msgctxt, e.msgid, e.msgid_plural) for e in parse_po(extract_pot(tmp_path))}
    committed = {
        (e.msgctxt, e.msgid, e.msgid_plural) for e in parse_po(PO_DIR / "passwords-app.pot")
    }
    assert committed == fresh


def test_no_fuzzy_or_untranslated_entries() -> None:
    assert [e.msgid for e in RU_ENTRIES if "fuzzy" in e.flags] == []
    assert [e.msgid for e in RU_ENTRIES if not all(e.msgstr.values())] == []


def test_header() -> None:
    text = RU_PO.read_text(encoding="utf-8")
    # REUSE-IgnoreStart - asserts the catalog's header; not this file's own license tag
    assert "SPDX-License-Identifier: MIT" in text
    # REUSE-IgnoreEnd
    assert "Language: ru\\n" in text
    assert "charset=UTF-8" in text
    assert "Project-Id-Version: passwords-app 0.1.0" in text
    assert "nplurals=3;" in text


def test_linguas_lists_russian() -> None:
    assert "ru" in (PO_DIR / "LINGUAS").read_text(encoding="utf-8").split()


def test_potfiles_exist() -> None:
    listed = [
        line.strip()
        for line in (PO_DIR / "POTFILES.in").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert listed
    assert all((ROOT / path).is_file() for path in listed)


def test_msgfmt_check_passes() -> None:
    if MSGFMT is None:
        pytest.skip("msgfmt is not installed")
    result = subprocess.run(  # noqa: S603 - fixed msgfmt path from shutil.which; argv built here
        [MSGFMT, "--check", "--check-format", "-o", "/dev/null", str(RU_PO)],
        capture_output=True,
        text=True,
        check=False,  # the return code is asserted below, with stderr as the message
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("entry", RU_ENTRIES, ids=lambda e: e.msgid[:40])
def test_placeholders_preserved(entry: Entry) -> None:
    expected = set(PLACEHOLDER.findall(entry.msgid))
    if entry.msgid_plural is not None:
        expected |= set(PLACEHOLDER.findall(entry.msgid_plural))
    for msgstr in entry.msgstr.values():
        assert set(PLACEHOLDER.findall(msgstr)) == expected


def test_plural_entries_have_three_forms() -> None:
    assert PLURAL_KEYS
    for key in PLURAL_KEYS:
        assert sorted(RU_BY_KEY[key].msgstr) == [0, 1, 2], key


@pytest.mark.parametrize(
    ("context", "expected"),
    [
        ("sidebar section", "Удаленные"),
        ("why an item is in Deleted", "Удалено"),
        ("date an item was deleted", "Удален"),
    ],
)
def test_contexts_translate_separately(
    ru: gettext.GNUTranslations, context: str, expected: str
) -> None:
    assert ru.pgettext(context, "Deleted") == expected


def test_no_forbidden_jargon() -> None:
    assert [m for e in RU_ENTRIES for m in e.msgstr.values() if FORBIDDEN.search(m)] == []


def test_no_english_quotes_or_three_dots() -> None:
    for entry in RU_ENTRIES:
        for msgstr in entry.msgstr.values():
            assert "“" not in msgstr, msgstr
            assert "”" not in msgstr, msgstr
            assert "..." not in msgstr, msgstr


def test_consistent_e_without_yo() -> None:
    assert [m for e in RU_ENTRIES for m in e.msgstr.values() if re.search("[ёЁ]", m)] == []


@pytest.mark.parametrize(
    ("n", "expected"),
    [
        (1, "Остался 1 день"),
        (2, "Осталось 2 дня"),
        (5, "Осталось 5 дней"),
        (11, "Осталось 11 дней"),
        (21, "Остался 21 день"),
        (22, "Осталось 22 дня"),
        (25, "Осталось 25 дней"),
    ],
)
def test_plural_days_left(ru: gettext.GNUTranslations, n: int, expected: str) -> None:
    assert ru.ngettext("{n} day left", "{n} days left", n).format(n=n) == expected


@pytest.mark.parametrize(
    ("n", "expected"),
    [
        (1, "1 пароль"),
        (3, "3 пароля"),
        (12, "12 паролей"),
        (101, "101 пароль"),
        (114, "114 паролей"),
    ],
)
def test_plural_password_count(ru: gettext.GNUTranslations, n: int, expected: str) -> None:
    assert ru.ngettext("{n} password", "{n} passwords", n).format(n=n) == expected


@pytest.mark.parametrize(
    ("n", "expected"),
    [(1, "1 минуту назад"), (4, "4 минуты назад"), (11, "11 минут назад"), (21, "21 минуту назад")],
)
def test_plural_minutes_ago(ru: gettext.GNUTranslations, n: int, expected: str) -> None:
    assert ru.ngettext("{n} minute ago", "{n} minutes ago", n).format(n=n) == expected


def test_setup_russian(russian: None) -> None:
    assert i18n.is_translated()
    assert i18n._("Passwords") == "Пароли"
    assert i18n._("Done") == "Готово"
    assert i18n.ngettext("{n} day", "{n} days", 22).format(n=22) == "22 дня"


def test_setup_english_falls_back(localedir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(i18n, "_translation", i18n._translation)
    monkeypatch.setenv(i18n.LOCALEDIR_ENV, str(localedir))
    i18n.setup(["en"])
    assert not i18n.is_translated()
    assert i18n._("Passwords") == "Passwords"


@pytest.mark.parametrize(
    ("month", "expected"),
    [(1, "3 января 2026 г."), (5, "3 мая 2026 г."), (10, "3 октября 2026 г.")],  # noqa: RUF001 - Russian text
)
def test_calendar_date_in_russian(russian: None, month: int, expected: str) -> None:
    at = datetime(2026, month, 3, 12, 0, tzinfo=UTC)
    assert formatting.calendar_date(at, tz=UTC) == expected


def test_calendar_date_example(russian: None) -> None:
    assert formatting.calendar_date(datetime(2026, 10, 10, 9, tzinfo=UTC), tz=UTC) == (
        "10 октября 2026 г."  # noqa: RUF001 - Russian text
    )


_WRONG = "Неверный код-пароль."
_LEFT = "На этом устройстве"  # noqa: RUF001 - Russian text


@pytest.mark.parametrize(
    ("daemon", "expected"),
    [
        (
            "Wrong passcode. 9 attempts left on this device.",
            f"{_WRONG} {_LEFT} осталось 9 попыток.",
        ),
        (
            "Wrong passcode. 2 attempts left on this device.",
            f"{_WRONG} {_LEFT} осталось 2 попытки.",
        ),
        ("Wrong passcode. 1 attempt left on this device.", f"{_WRONG} {_LEFT} осталась 1 попытка."),
        ("the passcode was not accepted", _WRONG),
    ],
)
def test_wrong_passcode_in_russian(russian: None, daemon: str, expected: str) -> None:
    assert formatting.wrong_passcode_text(daemon) == expected

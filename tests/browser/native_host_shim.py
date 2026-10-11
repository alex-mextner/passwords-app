# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Run the real `passwords-app-native-host`, with a line on stderr for every request.

The host logs only failures, so a test that waited in vain for the dropdown could not tell
whether the extension never asked or asked and got nothing back. Here every request also
leaves its command, outcome, number of candidates and duration, and every line (the host's
own failure lines too) starts with a UTC timestamp, as the daemon's log does (its launcher,
tests/e2e/daemon_shim.py, calls `configure_logging` too). Never a URL, user name or secret.
The wrapper that `install_native_host` writes appends stderr to `<browser home>/native-host.log`.
"""

from __future__ import annotations

import logging
import sys
import time
from typing import TYPE_CHECKING, override

from passwords_app.browser import native_host

if TYPE_CHECKING:
    from collections.abc import Mapping

    from passwords_app.browser.protocol import Command

_trace = logging.getLogger("passwords-app-native-host")


def configure_logging(level: int) -> None:
    """Log to stderr with UTC timestamps, so lines from different processes line up whatever
    each one's TZ (the browsers get TZ=UTC, the daemon the host's)."""
    logging.Formatter.converter = time.gmtime
    logging.basicConfig(
        level=level,
        format="%(asctime)s.%(msecs)03dZ %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )


def _ms(started: float) -> int:
    return round((time.monotonic() - started) * 1000)


class TracingHost(native_host.Host):
    @override
    async def _dispatch(self, command: Command) -> Mapping[str, object]:
        name = type(command).__name__.lower()
        started = time.monotonic()
        try:
            result = await super()._dispatch(command)
        except BaseException as e:
            _trace.info("%s: %s after %d ms", name, type(e).__name__, _ms(started))
            raise
        items = result.get("items")
        found = f", {len(items)} candidate(s)" if isinstance(items, list) else ""
        _trace.info("%s: ok%s in %d ms", name, found, _ms(started))
        return result


def _log(line: str) -> None:
    _trace.info("%s", line)


def main() -> int:
    configure_logging(logging.INFO)
    native_host._log = _log  # the host's own failure lines get the timestamp too
    native_host.Host = TracingHost  # type: ignore[misc]  # serve() builds the host it names
    _trace.info("started")
    status = native_host.main()
    _trace.info("exiting with status %d", status)
    return status


if __name__ == "__main__":
    sys.exit(main())

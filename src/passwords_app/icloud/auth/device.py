# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Persistent local device identity, generated once and reused forever.

A stable X-Mme-Device-Id lets Apple remember the 2FA approval and stop re-prompting. Anisette
supplies the volatile X-Apple-I-MD* machine data and may override these values. The file
format (`device.json`: device_id, serial, local_user_uuid) is shared with earlier versions.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import locale
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from passwords_app.icloud.auth.session import write_private
from passwords_app.icloud.errors import AppleError

if TYPE_CHECKING:
    from pathlib import Path


class DeviceError(AppleError):
    """device.json exists but is unreadable."""


@dataclasses.dataclass(frozen=True, slots=True)
class Device:
    device_id: str
    serial: str
    local_user_uuid: str

    @classmethod
    def generate(cls) -> Device:
        return cls(
            device_id=str(uuid.uuid4()).upper(),
            # Mac-like 12-char serial; replaced by anisette's if it provides one.
            serial="C02" + uuid.uuid4().hex[:9].upper(),
            local_user_uuid=str(uuid.uuid4()).upper(),
        )

    @classmethod
    def load_or_create(cls, path: Path) -> Device:
        if path.exists():
            try:
                data = cast("dict[str, object]", json.loads(path.read_text()))
                fields = (data["device_id"], data["serial"], data["local_user_uuid"])
            except (ValueError, KeyError, TypeError) as e:
                msg = f"{path} is not a device identity"
                raise DeviceError(msg) from e
            if not all(isinstance(f, str) and f for f in fields):
                msg = f"{path} is not a device identity"
                raise DeviceError(msg)
            return cls(*(str(f) for f in fields))
        dev = cls.generate()
        dev.save(path)
        return dev

    def save(self, path: Path) -> None:
        write_private(path, json.dumps(dataclasses.asdict(self), indent=2).encode())

    def meta_headers(self) -> dict[str, str]:
        """Fallback identity headers; anisette values override the X-Apple-I-MD* ones."""
        now = datetime.now(UTC).replace(microsecond=0)
        loc = locale.getlocale()[0] or "en_US"
        return {
            "X-Apple-I-Client-Time": now.isoformat().replace("+00:00", "Z"),
            "X-Apple-I-TimeZone": "UTC",
            "loc": loc,
            "X-Apple-Locale": loc,
            "X-Apple-I-MD-RINFO": "17106176",
            "X-Apple-I-MD-LU": base64.b64encode(self.local_user_uuid.upper().encode()).decode(),
            "X-Mme-Device-Id": self.device_id.upper(),
            "X-Apple-I-SRL-NO": self.serial,
        }

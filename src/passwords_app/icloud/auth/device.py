"""Persistent local device identity - generated once, reused forever, so a stable
X-Mme-Device-Id lets Apple remember the 2FA approval and stop re-prompting. Anisette supplies
the volatile X-Apple-I-MD* machine data and may override these values."""

import base64
import json
import locale
import uuid
from datetime import datetime, timezone

from .. import paths


class Device:
    def __init__(self, device_id: str, serial: str, local_user_uuid: str):
        self.device_id = device_id
        self.serial = serial
        self.local_user_uuid = local_user_uuid

    @classmethod
    def load_or_create(cls) -> "Device":
        f = paths.device_file()
        if f.exists():
            data = json.loads(f.read_text())
            return cls(data["device_id"], data["serial"], data["local_user_uuid"])
        dev = cls(
            device_id=str(uuid.uuid4()).upper(),
            # Mac-like 12-char serial; replaced by anisette's if it provides one.
            serial="C02" + uuid.uuid4().hex[:9].upper(),
            local_user_uuid=str(uuid.uuid4()).upper(),
        )
        dev.save()
        return dev

    def save(self) -> None:
        f = paths.device_file()
        f.write_text(
            json.dumps(
                {
                    "device_id": self.device_id,
                    "serial": self.serial,
                    "local_user_uuid": self.local_user_uuid,
                },
                indent=2,
            )
        )
        f.chmod(0o600)

    def meta_headers(self) -> dict:
        """Fallback identity headers; anisette values override the X-Apple-I-MD* ones."""
        now = datetime.now(timezone.utc).replace(microsecond=0)
        loc = (locale.getdefaultlocale()[0] or "en_US")
        return {
            "X-Apple-I-Client-Time": now.isoformat().replace("+00:00", "Z"),
            "X-Apple-I-TimeZone": "UTC",
            "loc": loc,
            "X-Apple-Locale": loc,
            "X-Apple-I-MD-RINFO": "17106176",
            "X-Apple-I-MD-LU": base64.b64encode(
                self.local_user_uuid.upper().encode()
            ).decode(),
            "X-Mme-Device-Id": self.device_id.upper(),
            "X-Apple-I-SRL-NO": self.serial,
        }

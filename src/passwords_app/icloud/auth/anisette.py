"""Anisette client - fetches the "machine validation data" (X-Apple-I-MD / X-Apple-I-MD-M) that
GrandSlam auth requires from an external anisette server run locally."""

import os

import requests

from ..const import DEFAULT_ANISETTE_URL
from ..errors import AppleError


class AnisetteError(AppleError):
    pass


class Anisette:
    # Header keys an anisette server may return; we forward exactly these.
    _KEYS = (
        "X-Apple-I-MD",
        "X-Apple-I-MD-M",
        "X-Apple-I-MD-RINFO",
        "X-Apple-I-MD-LU",
        "X-Apple-I-SRL-NO",
        "X-Mme-Device-Id",
        "X-Apple-I-Client-Time",
        "X-Apple-I-TimeZone",
        "X-Apple-Locale",
    )

    def __init__(self, url: str | None = None):
        self.url = (url or os.environ.get("PASSWORDS_APP_ANISETTE_URL") or DEFAULT_ANISETTE_URL).rstrip("/")

    def headers(self) -> dict:
        try:
            resp = requests.get(self.url, timeout=5)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            raise AnisetteError(
                f"Could not reach anisette server at {self.url}: {e}\n"
                "Start one, e.g.: docker run -d -p 6969:6969 dadoum/anisette-server:latest\n"
                "or set PASSWORDS_APP_ANISETTE_URL to a running instance."
            ) from e

        out = {k: data[k] for k in self._KEYS if k in data}
        if "X-Apple-I-MD" not in out or "X-Apple-I-MD-M" not in out:
            raise AnisetteError(
                f"Anisette server at {self.url} did not return machine data "
                "(X-Apple-I-MD / X-Apple-I-MD-M). Is it a real anisette server?"
            )
        return out

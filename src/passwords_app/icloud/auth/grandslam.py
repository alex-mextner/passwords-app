# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Apple ID sign-in in steps: SRP, then (when Apple asks) a second factor, then the PET.

Split into `start` and `finish` so a UI can ask for the code between the two calls; the PET
(password-equivalent token) in the final server provisioning data mints the iCloud tokens.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import TYPE_CHECKING, Literal

from passwords_app.icloud.auth.gsa import GSAError
from passwords_app.icloud.values import Record, child, integer, text

if TYPE_CHECKING:
    from passwords_app.icloud.auth.gsa import GSAClient

logger = logging.getLogger(__name__)

FactorKind = Literal["trusted", "sms"]
_TRUSTED = "trustedDeviceSecondaryAuth"
_SECONDARY = "secondaryAuth"


@dataclasses.dataclass(frozen=True, slots=True)
class SecondFactor:
    """A pending second-factor challenge: where the code went and the ids to answer it."""

    kind: FactorKind
    dsid: str
    idms_token: str


@dataclasses.dataclass(frozen=True, slots=True)
class Pet:
    dsid: str
    token: str
    expiry_ms: int | None


def account_id(spd: Record) -> str | None:
    """Return the alternate DSID (a GUID), or the numeric DSID when Apple sends only that."""
    adsid = text(spd, "adsid")
    if adsid:
        return adsid
    numeric = spd.get("DsPrsId")
    return str(numeric) if isinstance(numeric, (str, int)) and numeric else None


def _ids(spd: Record) -> tuple[str, str] | None:
    dsid = account_id(spd)
    idms = text(spd, "GsIdmsToken") or text(spd, "GsIdMS")
    return (dsid, idms) if dsid and idms else None


def _factor(response: Record, spd: Record) -> SecondFactor | None:
    au = text(child(response, "Status"), "au")
    if au not in {_TRUSTED, _SECONDARY}:
        return None
    ids = _ids(spd)
    if ids is None:
        msg = "Apple asked for a second factor without the ids to answer it"
        raise GSAError(msg)
    return SecondFactor("trusted" if au == _TRUSTED else "sms", *ids)


def start(gsa: GSAClient, username: str, password: str) -> tuple[Record, SecondFactor | None]:
    """Run SRP; return the provisioning data and the second factor Apple wants, if any.

    The factor is not triggered here: an unattended refresh must not push a code to the
    user's devices, so only an interactive caller calls `trigger`.
    """
    response, spd = gsa.authenticate(username, password, "sign-in")
    logger.debug("GSA sign-in answered: au=%r", text(child(response, "Status"), "au"))
    return spd, _factor(response, spd)


def implied_factor(spd: Record) -> SecondFactor | None:
    """Return the trusted-device factor Apple pushed on its own although `Status.au` named none.

    Under the Windows client identity GrandSlam can answer SRP without `au` yet still send a code
    to the user's devices and refuse the PET at loginDelegates until that code is entered.
    """
    ids = _ids(spd)
    return SecondFactor("trusted", *ids) if ids else None


def trigger(gsa: GSAClient, factor: SecondFactor) -> None:
    if factor.kind == "trusted":
        gsa.trigger_trusted_factor(factor.dsid, factor.idms_token)
    else:
        gsa.trigger_sms_factor(factor.dsid, factor.idms_token)


def finish(gsa: GSAClient, username: str, password: str, factor: SecondFactor, code: str) -> Record:
    """Submit the code, then authenticate again: the device is trusted now, so no new prompt."""
    if factor.kind == "trusted":
        gsa.submit_trusted_factor(code, factor.dsid, factor.idms_token)
    else:
        gsa.submit_sms_factor(code, factor.dsid, factor.idms_token)
    response, spd = gsa.authenticate(username, password, "re-auth after 2FA")
    if text(child(response, "Status"), "au"):
        msg = "still being asked for 2FA after submitting a code"
        raise GSAError(msg)
    return spd


def extract_pet(spd: Record) -> Pet:
    dsid = account_id(spd)
    entry = child(child(spd, "t"), "com.apple.gs.idms.pet")
    token = text(entry, "token")
    if not dsid or not token:
        msg = "Apple's answer carries no password-equivalent token"
        raise GSAError(msg)
    return Pet(dsid, token, integer(entry, "expiry"))

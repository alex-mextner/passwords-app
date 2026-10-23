# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The iCloud account on this computer: sign in, join the keychain, sign out, open the store.

Sign-in is a short state machine a UI drives one step at a time:

    sign_in(apple_id, password) -> CODE (a second factor was sent) | DEVICE | DONE
    submit_code(code)            -> DEVICE (not yet joined) | DONE
    recovery_devices()           -> the devices whose passcode can admit this computer
    join(device_id, passcode)    -> DONE

Joining spends one of the chosen device's ~10 escrow attempts; passing its passcode to `join`
is the user's consent. The password is kept in the encrypted session so that expired tokens
can be re-minted unattended; if Apple then wants a second factor, sync stops with
`SignInRequired` instead of pushing a code to the user's devices.
"""

from __future__ import annotations

import dataclasses
import enum
import logging
import threading
import time
from http import HTTPStatus
from typing import TYPE_CHECKING

from passwords_app.icloud import const, tls
from passwords_app.icloud.auth import grandslam
from passwords_app.icloud.auth import icloud as icloud_auth
from passwords_app.icloud.auth.anisette import Anisette, AnisetteError
from passwords_app.icloud.auth.device import Device
from passwords_app.icloud.auth.gsa import CodeRejectedError, GSAClient, GSAError
from passwords_app.icloud.auth.session import SessionStore
from passwords_app.icloud.errors import AppleError
from passwords_app.icloud.escrow.srp import EscrowError, WrongEscrowPasscodeError
from passwords_app.icloud.keychain.client import Identity, KeychainClient
from passwords_app.icloud.keychain.zones import ZoneCache
from passwords_app.icloud.octagon import client as octagon
from passwords_app.icloud.paths import ConfigPaths
from passwords_app.icloud.transport.cloudkit import CloudKitError
from passwords_app.icloud.values import Record, child, text

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    import requests

    from passwords_app.icloud.auth.anisette import AnisetteSource
    from passwords_app.sync.remote_icloud import ICloudRemoteStore

logger = logging.getLogger(__name__)


class AccountError(AppleError):
    """A sign-in or join step failed; the message is fit to show the user."""


class WrongCode(AccountError):  # noqa: N818 - public API name fixed by the plan
    """Apple rejected the verification code."""


class WrongPasscode(AccountError):  # noqa: N818 - public API name fixed by the plan
    """The device passcode did not open its escrow record (one attempt is spent)."""


class SignInRequired(AccountError):  # noqa: N818 - public API name fixed by the plan
    """Apple wants an interactive sign-in (password or verification code) before syncing."""


class SignInStep(enum.StrEnum):
    CODE = "code"
    DEVICE = "device"
    DONE = "done"


@dataclasses.dataclass(frozen=True, slots=True)
class AccountStatus:
    apple_id: str | None
    signed_in: bool
    joined: bool


@dataclasses.dataclass(frozen=True, slots=True)
class RecoveryDevice:
    id: str
    name: str
    model: str
    serial: str


@dataclasses.dataclass(frozen=True, slots=True)
class _Pending:
    """A sign-in waiting for its second-factor code."""

    gsa: GSAClient
    apple_id: str
    password: str
    factor: grandslam.SecondFactor


@dataclasses.dataclass(frozen=True, slots=True)
class Endpoints:
    """Apple's sign-in endpoints; tests point them at local servers."""

    gsa: str = const.GSA_BASE_URL
    login_delegates: str = icloud_auth.LOGIN_DELEGATES_URL
    account_settings: str = icloud_auth.ACCOUNT_SETTINGS_URL


class Account:
    """The account whose state lives in `config_dir` (default `~/.config/passwords-app`)."""

    def __init__(
        self,
        config_dir: Path | None = None,
        anisette_url: str | None = None,
        *,
        anisette: AnisetteSource | None = None,
        endpoints: Endpoints | None = None,
        http: requests.Session | None = None,
    ) -> None:
        self.paths = ConfigPaths(config_dir) if config_dir is not None else ConfigPaths.default()
        self._sessions = SessionStore(self.paths)
        self._http = http or tls.new_session()
        self._anisette = anisette or Anisette(anisette_url, http=self._http)
        self._endpoints = endpoints or Endpoints()
        self._lock = threading.RLock()
        self._pending: _Pending | None = None
        self._bottles: dict[str, Record] = {}
        self._device: Device | None = None
        # Bumped whenever the signed-in identity changes, so open stores reconnect.
        self._generation = 0

    # --- state ---------------------------------------------------------------------------------

    def _device_identity(self) -> Device:
        if self._device is None:
            self.paths.ensure()
            self._device = Device.load_or_create(self.paths.device)
        return self._device

    def _record(self) -> Record | None:
        return self._sessions.load()

    def _signed_in_record(self) -> Record:
        record = self._record()
        if record is None or not text(child(record, "mme"), "mmeAuthToken"):
            msg = "not signed in"
            raise SignInRequired(msg)
        return record

    def status(self) -> AccountStatus:
        with self._lock:
            record = self._record() or {}
            return AccountStatus(
                apple_id=text(record, "username"),
                signed_in=bool(text(child(record, "mme"), "mmeAuthToken")),
                joined=octagon.is_joined(record),
            )

    # --- sign-in ---------------------------------------------------------------------------------

    def _gsa(self) -> GSAClient:
        return GSAClient(
            self._device_identity(), self._anisette, http=self._http, base_url=self._endpoints.gsa
        )

    def sign_in(self, apple_id: str, password: str) -> SignInStep:
        with self._lock:
            self._pending = None
            gsa = self._gsa()
            try:
                spd, factor = grandslam.start(gsa, apple_id, password)
                if factor is not None:
                    grandslam.trigger(gsa, factor)
                    self._pending = _Pending(gsa, apple_id, password, factor)
                    return SignInStep.CODE
            except (GSAError, AnisetteError) as e:
                raise AccountError(str(e)) from e
            try:
                return self._complete(spd, apple_id, password)
            except icloud_auth.LoginRejected as e:
                # SRP passed (a wrong password stops at GSA), so "entered incorrectly" here means
                # an untrusted device whose code Apple pushed by itself: ask for that code.
                implied = grandslam.implied_factor(spd)
                if not e.needs_code or implied is None:
                    raise AccountError(str(e)) from e
                logger.info("sign-in: loginDelegates wants the pushed code; asking for it")
                self._pending = _Pending(gsa, apple_id, password, implied)
                return SignInStep.CODE

    def submit_code(self, code: str) -> SignInStep:
        with self._lock:
            pending = self._pending
            if pending is None:
                msg = "no sign-in is waiting for a code"
                raise AccountError(msg)
            try:
                spd = grandslam.finish(
                    pending.gsa, pending.apple_id, pending.password, pending.factor, code.strip()
                )
            except CodeRejectedError as e:
                raise WrongCode(str(e)) from e
            except (GSAError, AnisetteError) as e:
                raise AccountError(str(e)) from e
            self._pending = None
            try:
                return self._complete(spd, pending.apple_id, pending.password)
            except icloud_auth.LoginRejected as e:
                raise AccountError(str(e)) from e

    def request_sms(self) -> SignInStep:
        """Send the verification code by text message instead of to trusted devices."""
        with self._lock:
            pending = self._pending
            if pending is None:
                msg = "no sign-in is waiting for a code"
                raise AccountError(msg)
            factor = dataclasses.replace(pending.factor, kind="sms")
            try:
                grandslam.trigger(pending.gsa, factor)
            except (GSAError, AnisetteError) as e:
                raise AccountError(str(e)) from e
            self._pending = dataclasses.replace(pending, factor=factor)
            return SignInStep.CODE

    def _complete(self, spd: Record, apple_id: str, password: str) -> SignInStep:
        """Mint the iCloud tokens from a fresh PET and save the session."""
        prior = self._record() or {}
        record: Record = {}
        # Trust membership is tied to the peer identity, not to the tokens: keep it.
        if prior.get("octagon") and text(prior, "username") == apple_id:
            record["octagon"] = prior["octagon"]
            user_id = text(child(prior, "mme"), "cloudKitUserId")
            if user_id:
                record["mme"] = {"cloudKitUserId": user_id}
        record["password"] = password
        try:
            self._mint_tokens(record, spd, apple_id)
            self._refresh_webservices(record)
        except icloud_auth.LoginRejected:
            raise
        except (GSAError, AnisetteError, icloud_auth.ICloudError) as e:
            raise AccountError(str(e)) from e
        self._sessions.save(record)
        self._generation += 1
        return SignInStep.DONE if octagon.is_joined(record) else SignInStep.DEVICE

    def _mint_tokens(self, record: Record, spd: Record, apple_id: str) -> None:
        pet = grandslam.extract_pet(spd)
        record.update(
            {
                "username": apple_id,
                "dsid": pet.dsid,
                "dsid_numeric": spd.get("DsPrsId"),
                "logged_in_at": int(time.time()),
            }
        )
        device = self._device_identity()
        mme_dsid, mme_token, service_data, _ = icloud_auth.login_mobileme(
            apple_id,
            pet.token,
            pet.dsid,
            device.local_user_uuid,
            device,
            self._anisette,
            url=self._endpoints.login_delegates,
            http=self._http,
        )
        mme = child(record, "mme")
        mme.update(
            {
                "dsid": mme_dsid,
                "mmeAuthToken": mme_token,
                "tokens": child(service_data, "tokens"),
                "minted_at": int(time.time()),
            }
        )
        record["mme"] = mme

    def _refresh_webservices(self, record: Record) -> None:
        """Fetch the service URLs and a fresh cloudKitToken with the stored mmeAuthToken."""
        status, data = icloud_auth.fetch_account_settings(
            record,
            self._device_identity(),
            self._anisette,
            url=self._endpoints.account_settings,
            http=self._http,
        )
        if status == HTTPStatus.UNAUTHORIZED or data.get("ErrorID") == "UNAUTHORIZED":
            msg = "iCloud credentials expired"
            raise icloud_auth.ICloudAuthError(msg)
        if data.get("status") not in {0, None}:
            msg = f"iCloud rejected the token: {data.get('status-message')}"
            raise icloud_auth.ICloudError(msg)
        services = icloud_auth.extract_webservices(data)
        if not services:
            msg = "iCloud returned no service addresses"
            raise icloud_auth.ICloudError(msg)
        webservices = child(record, "webservices")
        webservices.update({k: v.get("url") for k, v in services.items()})
        record["webservices"] = webservices
        tokens = child(data, "tokens")
        if text(tokens, "cloudKitToken"):
            mme = child(record, "mme")
            mme["tokens"] = {**child(mme, "tokens"), **tokens}
            record["mme"] = mme

    def refresh_tokens(self, record: Record) -> None:
        """Renew the short-lived cloudKitToken unattended; re-mint expired tokens if possible.

        Raises `SignInRequired` when that would need the user (no saved password, or Apple
        asks for a second factor).
        """
        try:
            self._refresh_webservices(record)
        except icloud_auth.ICloudAuthError:
            pass
        else:
            return
        apple_id, password = text(record, "username"), text(record, "password")
        if not apple_id or not password:
            msg = "iCloud sign-in expired; sign in again"
            raise SignInRequired(msg)
        try:
            spd, factor = grandslam.start(self._gsa(), apple_id, password)
            if factor is not None:
                msg = "Apple asks for a verification code; sign in again"
                raise SignInRequired(msg)
            self._mint_tokens(record, spd, apple_id)
            self._refresh_webservices(record)
        except icloud_auth.ICloudAuthError as e:
            raise SignInRequired(str(e)) from e
        except GSAError as e:
            raise SignInRequired(str(e)) from e

    # --- joining the keychain ----------------------------------------------------------------

    def _pet(self, record: Record) -> str:
        """Mint a fresh PET for escrowproxy (it lives minutes, so one per escrow step)."""
        apple_id, password = text(record, "username"), text(record, "password")
        if not apple_id or not password:
            msg = "the password is needed again; sign in again"
            raise SignInRequired(msg)
        try:
            spd, factor = grandslam.start(self._gsa(), apple_id, password)
        except (GSAError, AnisetteError) as e:
            raise AccountError(str(e)) from e
        if factor is not None:
            msg = "Apple asks for a verification code; sign in again"
            raise SignInRequired(msg)
        return grandslam.extract_pet(spd).token

    def _octagon(self, record: Record) -> octagon.OctagonClient:
        device = self._device_identity()
        octagon.ensure_peer_identity(record, device)
        client = octagon.OctagonClient(record, device, self._anisette, http=self._http)
        self._sessions.save(record)  # the peer identity and cloudKitUserId
        return client

    def recovery_devices(self) -> list[RecoveryDevice]:
        """Devices whose passcode can admit this computer (no escrow attempt is spent)."""
        with self._lock:
            record = self._signed_in_record()
            escrow_host = text(child(record, "webservices"), "keychainsync")
            if not escrow_host:
                msg = "iCloud did not provide the keychain recovery service"
                raise AccountError(msg)
            try:
                client = self._octagon(record)
                bottles = client.list_recoverable_bottles(
                    escrow_host, text(record, "username") or "", self._pet(record)
                )
            except (CloudKitError, octagon.OctagonError, EscrowError, AnisetteError) as e:
                raise AccountError(str(e)) from e
            self._bottles = {text(b, "id") or "": b for b in bottles}
            return [_describe(b) for b in bottles]

    def join(self, device_id: str, passcode: str) -> SignInStep:
        """Join the keychain with that device's passcode (IRREVERSIBLE attempt on failure)."""
        with self._lock:
            record = self._signed_in_record()
            chosen = self._bottles.get(device_id)
            if chosen is None:
                msg = "unknown device; list the recovery devices first"
                raise AccountError(msg)
            if not passcode:
                msg = "the passcode is empty"
                raise AccountError(msg)
            escrow_host = text(child(record, "webservices"), "keychainsync") or ""
            try:
                client = self._octagon(record)
                client.join_via_escrow(
                    escrow_host,
                    text(record, "username") or "",
                    self._pet(record),
                    passcode.encode(),
                    chosen,
                    confirm_irreversible=True,
                )
            except WrongEscrowPasscodeError as e:
                raise WrongPasscode(str(e)) from e
            except (CloudKitError, octagon.OctagonError, EscrowError, AnisetteError) as e:
                raise AccountError(str(e)) from e
            self._sessions.save(record)
            self._generation += 1
            self._bottles = {}
            return SignInStep.DONE

    def sign_out(self) -> None:
        with self._lock:
            self._pending = None
            self._bottles = {}
            self._sessions.clear()
            self.paths.zone_cache.unlink(missing_ok=True)
            self._generation += 1

    # --- the password store --------------------------------------------------------------------

    def open_keychain(self) -> KeychainClient:
        """Refresh the tokens and connect to the keychain's Passwords zone (blocking)."""
        with self._lock:
            record = self._signed_in_record()
            if not octagon.is_joined(record):
                msg = "this computer has not joined iCloud Keychain yet"
                raise SignInRequired(msg)
            self.refresh_tokens(record)
            self._sessions.save(record)
            return connect_keychain(
                record,
                self._device_identity(),
                self._anisette,
                ZoneCache(self.paths.zone_cache),
                http=self._http,
                saved=self._sessions.save,
            )

    def remote_store(self) -> ICloudRemoteStore:
        from passwords_app.sync.remote_icloud import ICloudRemoteStore  # noqa: PLC0415 - layering

        return ICloudRemoteStore(self.open_keychain, lambda: self._generation)


def connect_keychain(  # noqa: PLR0913 - the session, its identity and the persistence seams
    record: Record,
    device: Device,
    anisette: AnisetteSource,
    cache: ZoneCache,
    *,
    http: requests.Session | None = None,
    saved: Callable[[Record], None] | None = None,
) -> KeychainClient:
    """Build a keychain client for a joined session (resolving cloudKitUserId once if needed)."""
    transport = octagon.transport_for(record, device, anisette, http=http)
    if saved is not None:
        saved(record)
    client = octagon.OctagonClient(record, device, anisette, transport=transport, http=http)
    oct_state = child(record, "octagon")
    keys = octagon.load_peer_keys(oct_state)
    identity = Identity(text(oct_state, "peer_id") or "", keys.encryption.private_key)
    return KeychainClient(
        transport, transport.user_id, identity, client.fetch_recoverable_tlks, cache
    )


def _describe(bottle: Record) -> RecoveryDevice:
    meta = child(bottle, "meta")
    client_meta = child(meta, "ClientMetadata")

    def first_text(*keys: str) -> str:
        return next((v for k in keys if (v := text(client_meta, k))), "")

    model = first_text("device_model", "model", "ProductType", "device_model_class")
    name = first_text("device_name", "deviceName") or model or "Apple device"
    serial = text(meta, "serial") or text(client_meta, "device_serial") or ""
    return RecoveryDevice(id=text(bottle, "id") or "", name=name, model=model, serial=serial)

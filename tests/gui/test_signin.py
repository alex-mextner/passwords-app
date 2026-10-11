# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Sign-in wizard against the fake daemon: every step, every wrong answer."""

from __future__ import annotations

from typing import Any

import pytest
from tests.fakes.fake_daemon import FakeDaemon
from tests.gui import support

pytestmark = pytest.mark.timeout(120)


@pytest.fixture
def daemon_factory() -> Any:
    return FakeDaemon  # signed out, empty


def _wizard(app: support.AppUnderTest) -> Any:
    support.wait_until(app.window.list_page.signin_banner.get_revealed, what="banner")
    app.window.activate_action("win.sign-in", None)
    return support.wait_until(lambda: app.window.sign_in_dialog, what="wizard")


def _account(dialog: Any, password: str = "correct-horse") -> None:  # noqa: S107 - the fake's fictional password
    dialog.apple_id.set_text("alex.doe@example.com")
    dialog.password.set_text(password)
    dialog.continue_button.emit("clicked")


def _to_code(dialog: Any) -> None:
    _account(dialog)
    support.wait_until(lambda: dialog.page_tag == "code", what="code page")


def _to_devices(dialog: Any) -> None:
    _to_code(dialog)
    dialog.code_boxes.paste_text(0, "123456")
    support.wait_until(lambda: dialog.page_tag == "device", what="device page")


def test_signed_out_app_offers_sign_in(app: support.AppUnderTest) -> None:
    app.wait_loaded()
    support.wait_until(app.window.list_page.signin_banner.get_revealed, what="banner")
    assert app.window.status_button.sign_in_button.get_visible()
    assert app.window.list_page.empty.get_title() == "No Passwords"


def test_wrong_password_stays_on_the_first_page(app: support.AppUnderTest) -> None:
    dialog = _wizard(app)
    _account(dialog, "wrong-horse")
    support.wait_until(dialog.account_error.get_visible, what="error")
    assert dialog.account_error.get_text() == "Apple ID or password is incorrect"
    assert dialog.page_tag == "account"
    assert dialog.password.get_text() == ""  # never kept after an attempt


def test_empty_fields_are_refused_without_calling_apple(app: support.AppUnderTest) -> None:
    dialog = _wizard(app)
    dialog.continue_button.emit("clicked")
    assert dialog.account_error.get_text() == "Enter your Apple Account and password."
    assert "SignInStart" not in app.call(lambda d: d.calls)


def test_code_boxes_accept_a_pasted_sms(app: support.AppUnderTest) -> None:
    dialog = _wizard(app)
    _to_code(dialog)
    dialog.code_boxes.entries[2].set_text("Your Apple Account code is: 123456. Don't share it.")
    assert [e.get_text() for e in dialog.code_boxes.entries] == list("123456")
    support.wait_until(lambda: dialog.page_tag == "device", what="device page")


def test_typing_digits_one_by_one_advances_focus(app: support.AppUnderTest) -> None:
    dialog = _wizard(app)
    _to_code(dialog)
    boxes = dialog.code_boxes
    for index, digit in enumerate("12345"):
        boxes.entries[index].set_text(digit)
    support.pump(0.1)
    assert boxes.code == "12345"
    focus = dialog.get_focus()
    assert focus is not None
    assert focus.is_ancestor(boxes.entries[5]) or focus is boxes.entries[5]
    assert dialog.page_tag == "code"


def test_wrong_code_clears_the_boxes(app: support.AppUnderTest) -> None:
    dialog = _wizard(app)
    _to_code(dialog)
    dialog.code_boxes.entries[0].set_text("654321")
    support.wait_until(dialog.code_error.get_visible, what="error")
    assert dialog.code_error.get_text() == "That code is not correct. Try again."
    assert dialog.code_boxes.code == ""
    assert dialog.page_tag == "code"
    dialog.code_boxes.paste_text(0, "123456")
    support.wait_until(lambda: dialog.page_tag == "device", what="second try works")


def test_text_me_switches_to_sms(app: support.AppUnderTest) -> None:
    dialog = _wizard(app)
    _to_code(dialog)
    dialog.sms_button.emit("clicked")
    support.wait_until(lambda: "SignInRequestSms" in app.call(lambda d: d.calls), what="sms")
    support.pump(0.2)
    assert dialog.page_tag == "code"


def test_device_page_explains_in_plain_words(app: support.AppUnderTest) -> None:
    dialog = _wizard(app)
    _to_devices(dialog)
    texts = " ".join(support.visible_texts(dialog))
    assert "Confirm with a Device Passcode" in texts
    assert "sealed with the screen passcode" in texts
    assert "about 10 wrong attempts per device" in texts
    assert "escrow" not in texts.casefold()
    devices = app.call(lambda d: d.recovery_devices)
    assert [r.get_title() for r in dialog.device_rows] == [dev[1] for dev in devices]
    assert all("Serial" in r.get_subtitle() for r in dialog.device_rows)


def test_wrong_passcode_shows_attempts_left(app: support.AppUnderTest) -> None:
    dialog = _wizard(app)
    _to_devices(dialog)
    find = support.find_button
    find(dialog, "Continue").emit("clicked")
    support.wait_until(lambda: dialog.page_tag == "passcode", what="passcode page")
    dialog.passcode.set_text("111111")
    dialog.join_button.emit("clicked")
    support.wait_until(dialog.passcode_error.get_visible, what="error")
    assert dialog.passcode_error.get_text() == "Wrong passcode. 9 attempts left on this device."
    assert dialog.page_tag == "passcode"
    assert dialog.passcode.get_text() == ""


def test_passcode_is_never_sent_twice_on_its_own(app: support.AppUnderTest) -> None:
    dialog = _wizard(app)
    _to_devices(dialog)
    support.find_button(dialog, "Continue").emit("clicked")
    support.wait_until(lambda: dialog.page_tag == "passcode", what="passcode page")
    dialog.passcode.set_text("111111")
    dialog.join_button.emit("clicked")
    dialog.join_button.emit("clicked")  # double click while the first is in flight
    support.wait_until(dialog.passcode_error.get_visible, what="error")
    assert app.call(lambda d: d.calls.count("JoinKeychain")) == 1


def test_choosing_another_device_joins_with_it(app: support.AppUnderTest) -> None:
    dialog = _wizard(app)
    _to_devices(dialog)
    dialog.select_device(1)
    assert dialog.device == dialog.devices[1]
    support.find_button(dialog, "Continue").emit("clicked")
    support.wait_until(lambda: dialog.page_tag == "passcode", what="passcode page")
    texts = support.visible_texts(dialog)
    assert any(dialog.devices[1].name in t for t in texts)


def test_full_flow_ends_signed_in_and_syncing(app: support.AppUnderTest) -> None:
    dialog = _wizard(app)
    _to_devices(dialog)
    support.find_button(dialog, "Continue").emit("clicked")
    support.wait_until(lambda: dialog.page_tag == "passcode", what="passcode page")
    dialog.passcode.set_text("000000")
    dialog.join_button.emit("clicked")
    support.wait_until(lambda: dialog.page_tag == "progress", what="progress page")
    support.wait_until(lambda: dialog.page_tag == "done", what="done page")
    support.find_button(dialog, "Done").emit("clicked")
    support.wait_until(lambda: app.window.sign_in_dialog is None, what="closed")
    support.wait_until(
        lambda: app.window.status_button.content.get_label() in {"Synced", "Syncing…"},
        what="signed in",
    )
    assert not app.window.list_page.signin_banner.get_revealed()


def test_no_2fa_goes_straight_to_devices(app: support.AppUnderTest) -> None:
    app.call(lambda d: setattr(d, "require_2fa", False))
    dialog = _wizard(app)
    _account(dialog)
    support.wait_until(lambda: dialog.page_tag == "device", what="device page")

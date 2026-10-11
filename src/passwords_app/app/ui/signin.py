# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Sign-in wizard: Apple Account → 2FA code → choose a device → its passcode → done.

Joining with a device passcode is the one irreversible step (Apple destroys a device's
recovery copy after about ten wrong passcodes), so the wizard explains it in plain words,
shows the warning before the passcode field, and never retries on its own.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from gi.repository import Adw, Gdk, Gtk

from passwords_app.app.client import DaemonError, ErrorKind
from passwords_app.app.codes import SIGNIN_CODE_LENGTH, Boxes
from passwords_app.app.formatting import wrong_passcode_text
from passwords_app.app.i18n import _
from passwords_app.app.records import RecoveryDevice, SignInStep, StepKind

if TYPE_CHECKING:
    from collections.abc import Callable

    from passwords_app.app.client import DaemonClient


def _page(
    title: str, tag: str, body: Gtk.Widget, action: Gtk.Button | None = None
) -> Adw.NavigationPage:
    clamp = Adw.Clamp(
        maximum_size=420,
        child=body,
        margin_top=12,
        margin_bottom=24,
        margin_start=18,
        margin_end=18,
    )
    view = Adw.ToolbarView(
        content=Gtk.ScrolledWindow(
            hscrollbar_policy=Gtk.PolicyType.NEVER, child=clamp, propagate_natural_height=True
        )
    )
    view.add_top_bar(Adw.HeaderBar())
    if action is not None:
        # The primary action sits in a bottom bar so it stays visible however short the
        # dialog gets; only the explanation above it scrolls.
        bar = Gtk.Box(halign=Gtk.Align.CENTER, margin_top=12, margin_bottom=18)
        bar.append(action)
        view.add_bottom_bar(bar)
        view.set_bottom_bar_style(Adw.ToolbarStyle.RAISED_BORDER)
    return Adw.NavigationPage(title=title, tag=tag, child=view)


def _intro(icon: str, title: str, text: str) -> Gtk.Box:
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    image = Gtk.Image(
        icon_name=icon, pixel_size=64, accessible_role=Gtk.AccessibleRole.PRESENTATION
    )
    image.add_css_class("dim-label")
    heading = Gtk.Label(label=title, wrap=True, justify=Gtk.Justification.CENTER)
    heading.add_css_class("title-2")
    body = Gtk.Label(label=text, wrap=True, justify=Gtk.Justification.CENTER)
    for child in (image, heading, body):
        box.append(child)
    return box


def _error_label() -> Gtk.Label:
    label = Gtk.Label(wrap=True, visible=False, justify=Gtk.Justification.CENTER)
    label.add_css_class("error")
    return label


def _pill(label: str) -> Gtk.Button:
    button = Gtk.Button(label=label, halign=Gtk.Align.CENTER)
    button.add_css_class("suggested-action")
    button.add_css_class("pill")
    return button


class CodeBoxes(Gtk.Box):
    """Six one-digit entries; typing advances, Backspace goes back, a paste fills all."""

    __gtype_name__ = "PasswordsCodeBoxes"

    def __init__(self, on_complete: Callable[[str], None]) -> None:
        super().__init__(spacing=8, halign=Gtk.Align.CENTER)
        self.state = Boxes()
        self._on_complete = on_complete
        self.entries: list[Gtk.Entry] = []
        self._updating = False
        for index in range(SIGNIN_CODE_LENGTH):
            entry = Gtk.Entry(
                max_width_chars=1,
                width_chars=1,
                xalign=0.5,
                input_purpose=Gtk.InputPurpose.DIGITS,
            )
            entry.add_css_class("code-box")
            name = _("Digit {n} of {total}").format(n=index + 1, total=SIGNIN_CODE_LENGTH)
            # The focusable text inside the entry is what a screen reader lands on.
            parts: list[object] = [entry, entry.get_delegate()]
            for accessible in parts:
                if isinstance(accessible, Gtk.Accessible):
                    accessible.update_property([Gtk.AccessibleProperty.LABEL], [name])
            entry.connect("changed", self._on_changed, index)
            # Capture phase: the boxes, not the text widget, decide what Backspace erases.
            keys = Gtk.EventControllerKey(propagation_phase=Gtk.PropagationPhase.CAPTURE)
            keys.connect("key-pressed", self._on_key, index)
            entry.add_controller(keys)
            self.entries.append(entry)
            self.append(entry)
            if index == SIGNIN_CODE_LENGTH // 2 - 1:
                dash = Gtk.Label(label="–", accessible_role=Gtk.AccessibleRole.PRESENTATION)  # noqa: RUF001 - typographic dash between the code halves
                dash.add_css_class("dim-label")
                self.append(dash)

    def _apply(self, state: Boxes) -> None:
        self.state = state
        self._updating = True
        for entry, digit in zip(self.entries, state.digits, strict=True):
            if entry.get_text() != digit:
                entry.set_text(digit)
        self._updating = False
        target = self.entries[state.focus]
        target.grab_focus()
        target.set_position(-1)
        if state.complete:
            self._on_complete(state.code)

    def paste_text(self, index: int, text: str) -> None:
        self._apply(self.state.typed(index, text))

    def _on_changed(self, entry: Gtk.Entry, index: int) -> None:
        if self._updating:
            return
        text, old = entry.get_text(), self.state.digits[index]
        # Work out what was typed or pasted next to the digit already in the box.
        if old and text.startswith(old):
            inserted = text[len(old) :]
        elif old and text.endswith(old):
            inserted = text[: -len(old)]
        else:
            inserted = text
        if not inserted.strip():
            self._apply_no_submit(self.state.backspace(index) if old else self.state)
            return
        self.paste_text(index, inserted)

    def _on_key(
        self,
        _controller: Gtk.EventControllerKey,
        keyval: int,
        _code: int,
        _state: Gdk.ModifierType,
        index: int,
    ) -> bool:
        if keyval == Gdk.KEY_BackSpace:
            self._apply_no_submit(self.state.backspace(index))
            return True
        if keyval == Gdk.KEY_Left and index > 0:
            self.entries[index - 1].grab_focus()
            return True
        if keyval == Gdk.KEY_Right and index < SIGNIN_CODE_LENGTH - 1:
            self.entries[index + 1].grab_focus()
            return True
        return False

    def _apply_no_submit(self, state: Boxes) -> None:
        self.state = state
        self._updating = True
        for entry, digit in zip(self.entries, state.digits, strict=True):
            entry.set_text(digit)
        self._updating = False
        self.entries[state.focus].grab_focus()

    def clear(self) -> None:
        self._apply_no_submit(Boxes())

    @property
    def code(self) -> str:
        return self.state.code


class SignInDialog(Adw.Dialog):
    __gtype_name__ = "PasswordsSignInDialog"

    def __init__(
        self, client: DaemonClient, *, apple_id: str = "", on_done: Callable[[], None]
    ) -> None:
        super().__init__(title=_("Sign In"), content_width=480, content_height=620)
        self.client = client
        self.on_done = on_done
        self.devices: list[RecoveryDevice] = []
        self.code_text: Gtk.Label | None = None
        self.code_boxes: CodeBoxes | None = None
        self.device: RecoveryDevice | None = None
        self.nav = Adw.NavigationView()
        self.nav.add(self._account_page(apple_id))
        self.set_child(self.nav)
        # Re-authenticating (the usual case) only needs the password.
        self.set_focus(self.password if apple_id else self.apple_id)
        self.busy = False

    # ---------------------------------------------------------------- page 1
    def _account_page(self, apple_id: str) -> Adw.NavigationPage:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.append(
            _intro(
                "avatar-default-symbolic",
                _("Sign in with your Apple Account"),
                _("Your passwords stay end-to-end encrypted. This computer talks only to Apple."),
            )
        )
        group = Adw.PreferencesGroup()
        self.apple_id = Adw.EntryRow(title=_("Email or Phone Number"))
        self.apple_id.update_property([Gtk.AccessibleProperty.LABEL], [_("Apple Account")])
        self.apple_id.set_input_purpose(Gtk.InputPurpose.EMAIL)
        self.apple_id.set_text(apple_id)
        self.password = Adw.PasswordEntryRow(title=_("Password"))
        self.password.update_property([Gtk.AccessibleProperty.LABEL], [_("Password")])
        self.apple_id.connect("entry-activated", lambda *_a: self.password.grab_focus())
        self.password.connect("entry-activated", lambda *_a: self.start())
        group.add(self.apple_id)
        group.add(self.password)
        box.append(group)
        self.account_error = _error_label()
        box.append(self.account_error)
        self.continue_button = _pill(_("Continue"))
        self.continue_button.connect("clicked", lambda *_a: self.start())
        self.account_spinner = Adw.Spinner(visible=False, halign=Gtk.Align.CENTER)
        box.append(self.account_spinner)
        return _page(_("Sign In"), "account", box, self.continue_button)

    def _set_busy(self, busy: bool, button: Gtk.Button, spinner: Adw.Spinner) -> None:  # noqa: FBT001
        self.busy = busy
        button.set_sensitive(not busy)
        spinner.set_visible(busy)

    def start(self) -> None:
        apple_id = self.apple_id.get_text().strip()
        if not apple_id or not self.password.get_text():
            self.account_error.set_text(_("Enter your Apple Account and password."))
            self.account_error.set_visible(True)
            return
        self.account_error.set_visible(False)
        self._set_busy(True, self.continue_button, self.account_spinner)  # noqa: FBT003

        def done(result: SignInStep | DaemonError) -> None:
            self._set_busy(False, self.continue_button, self.account_spinner)  # noqa: FBT003
            self.password.set_text("")
            if isinstance(result, DaemonError):
                self.account_error.set_text(result.message or _("Could not sign in."))
                self.account_error.set_visible(True)
                return
            self._advance(result)

        self.client.sign_in_start(apple_id, self.password.get_text(), done)

    def _advance(self, step: SignInStep) -> None:
        if step.step is StepKind.CODE:
            self._show_code_page(step)
        elif step.step is StepKind.DEVICE:
            self._load_devices()
        else:
            self._show_done()

    # ---------------------------------------------------------------- page 2
    def _show_code_page(self, step: SignInStep) -> None:
        sms = step.destination == "sms"
        text = (
            _("Enter the code sent by text message to your trusted phone number.")
            if sms
            else _("Enter the code shown on one of your Apple devices.")
        )
        if self.code_text is not None and self.code_boxes is not None:
            self.code_text.set_label(text)
            self.code_boxes.clear()
            return
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        # The daemon's own sentence is English-only; the destination alone picks our wording.
        intro = _intro("phone-symbolic", _("Two-Factor Authentication"), text)
        self.code_text = cast("Gtk.Label", intro.get_last_child())
        box.append(intro)
        boxes = self.code_boxes = CodeBoxes(self._submit_code)
        box.append(boxes)
        self.code_error = _error_label()
        box.append(self.code_error)
        self.code_spinner = Adw.Spinner(visible=False, halign=Gtk.Align.CENTER)
        box.append(self.code_spinner)
        self.sms_button = Gtk.Button(label=_("Didn’t get a code? Text me"), halign=Gtk.Align.CENTER)  # noqa: RUF001 - typographic punctuation in UI text
        self.sms_button.add_css_class("flat")
        self.sms_button.connect("clicked", lambda *_a: self.request_sms())
        box.append(self.sms_button)
        self.nav.push(_page(_("Verification Code"), "code", box))
        boxes.entries[0].grab_focus()

    def _submit_code(self, code: str) -> None:
        if self.busy:
            return
        self.code_error.set_visible(False)
        self.busy = True
        self.code_spinner.set_visible(True)

        def done(result: SignInStep | DaemonError) -> None:
            self.busy = False
            self.code_spinner.set_visible(False)
            if isinstance(result, DaemonError):
                message = (
                    _("That code is not correct. Try again.")
                    if result.kind is ErrorKind.WRONG_CODE
                    else result.message
                )
                self.code_error.set_text(message)
                self.code_error.set_visible(True)
                if self.code_boxes is not None:
                    self.code_boxes.clear()
                return
            self._advance(result)

        self.client.sign_in_code(code, done)

    def request_sms(self) -> None:
        def done(result: SignInStep | DaemonError) -> None:
            if isinstance(result, DaemonError):
                self.code_error.set_text(result.message)
                self.code_error.set_visible(True)
                return
            self._show_code_page(result)

        self.client.sign_in_request_sms(done)

    # ---------------------------------------------------------------- page 3
    def _load_devices(self) -> None:
        def done(result: list[RecoveryDevice] | DaemonError) -> None:
            if isinstance(result, DaemonError):
                self._show_failure(result.message)
                return
            self.devices = result
            self._show_device_page()

        self.client.recovery_devices(done)

    def _show_device_page(self) -> None:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.append(
            _intro(
                "pa-key-symbolic",
                _("Confirm with a Device Passcode"),
                _(
                    "Apple keeps your keychain keys sealed with the screen passcode of each of "
                    "your devices. Entering the passcode of one of them lets this computer join "
                    "your iCloud Keychain."
                ),
            )
        )
        group = Adw.PreferencesGroup(title=_("Choose a Device"))
        self.device_rows: list[Adw.ActionRow] = []
        first: Gtk.CheckButton | None = None
        for device in self.devices:
            check = Gtk.CheckButton(valign=Gtk.Align.CENTER)
            if first is None:
                first = check
                check.set_active(True)
                self.device = device
            else:
                check.set_group(first)
            check.connect("toggled", self._on_device_toggled, device)
            row = Adw.ActionRow(
                title=device.name,
                subtitle=_("{model} · Serial {serial}").format(
                    model=device.model, serial=device.serial
                ),
                activatable_widget=check,
            )
            row.add_prefix(check)
            icon = "computer-symbolic" if "mac" in device.model.lower() else "phone-symbolic"
            if "ipad" in device.model.lower():
                icon = "tablet-symbolic"
            row.add_suffix(
                Gtk.Image(icon_name=icon, accessible_role=Gtk.AccessibleRole.PRESENTATION)
            )
            group.add(row)
            self.device_rows.append(row)
        box.append(group)
        warning = Adw.ActionRow(
            title=_("Type carefully"),
            subtitle=_(
                "Apple allows about 10 wrong attempts per device. After that, that device’s "  # noqa: RUF001 - typographic punctuation in UI text
                "copy of your keychain keys is destroyed and it can no longer be used here."
            ),
            subtitle_lines=0,
        )
        warning_icon = Gtk.Image(icon_name="dialog-warning-symbolic")
        warning_icon.add_css_class("warning-icon")
        warning.add_prefix(warning_icon)
        warning.add_css_class("warning-row")
        warning_group = Adw.PreferencesGroup()
        warning_group.add(warning)
        box.append(warning_group)
        next_button = _pill(_("Continue"))
        next_button.set_sensitive(bool(self.devices))
        next_button.connect("clicked", lambda *_a: self._show_passcode_page())
        self.nav.push(_page(_("Device Passcode"), "device", box, next_button))

    def _on_device_toggled(self, check: Gtk.CheckButton, device: RecoveryDevice) -> None:
        if check.get_active():
            self.device = device

    def select_device(self, index: int) -> None:
        check = cast("Gtk.CheckButton", self.device_rows[index].get_activatable_widget())
        check.set_active(True)

    # ---------------------------------------------------------------- page 4
    def _show_passcode_page(self) -> None:
        device = self.device
        if device is None:
            return
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.append(
            _intro(
                "system-lock-screen-symbolic",
                _("Enter the Passcode of “{device}”").format(device=device.name),
                _("This is the passcode you use to unlock that device."),
            )
        )
        group = Adw.PreferencesGroup()
        self.passcode = Adw.PasswordEntryRow(title=_("Device Passcode"))
        self.passcode.update_property([Gtk.AccessibleProperty.LABEL], [_("Device Passcode")])
        self.passcode.connect("entry-activated", lambda *_a: self.join())
        group.add(self.passcode)
        box.append(group)
        self.passcode_error = _error_label()
        box.append(self.passcode_error)
        self.join_button = _pill(_("Join iCloud Keychain"))
        self.join_button.connect("clicked", lambda *_a: self.join())
        self.nav.push(_page(_("Device Passcode"), "passcode", box, self.join_button))
        self.passcode.grab_focus()

    def join(self) -> None:
        device = self.device
        passcode = self.passcode.get_text()
        if device is None or not passcode or self.busy:
            return
        self.busy = True
        self.passcode_error.set_visible(False)
        progress = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=18, valign=Gtk.Align.CENTER
        )
        progress.append(Adw.Spinner(height_request=48, width_request=48))
        label = Gtk.Label(label=_("Joining your iCloud Keychain…"), wrap=True)
        label.add_css_class("title-3")
        progress.append(label)
        hint = Gtk.Label(label=_("This can take a minute."), wrap=True)
        hint.add_css_class("dim-label")
        progress.append(hint)
        page = _page(_("Joining"), "progress", progress)
        page.set_can_pop(False)
        self.nav.push(page)

        def done(result: SignInStep | DaemonError) -> None:
            self.busy = False
            self.passcode.set_text("")
            if isinstance(result, DaemonError):
                self.nav.pop_to_tag("passcode")
                if result.kind is ErrorKind.WRONG_PASSCODE:
                    text = wrong_passcode_text(result.message)
                else:
                    text = result.message or _("Could not join.")
                self.passcode_error.set_text(text)
                self.passcode_error.set_visible(True)
                self.passcode.grab_focus()
                return
            self._show_done()

        self.client.join_keychain(device.id, passcode, done)

    # ---------------------------------------------------------------- end
    def _show_done(self) -> None:
        status = Adw.StatusPage(
            icon_name="pa-synced-symbolic",
            title=_("This Computer Is Ready"),
            description=_("Your passwords now sync between this computer and your Apple devices."),
        )
        button = _pill(_("Done"))
        button.connect("clicked", lambda *_a: self._finish())
        status.set_child(button)
        view = Adw.ToolbarView(content=status)
        view.add_top_bar(Adw.HeaderBar())
        page = Adw.NavigationPage(title=_("Done"), tag="done", child=view, can_pop=False)
        self.nav.push(page)
        button.grab_focus()

    def _show_failure(self, message: str) -> None:
        status = Adw.StatusPage(
            icon_name="dialog-warning-symbolic", title=_("Could Not Continue"), description=message
        )
        view = Adw.ToolbarView(content=status)
        view.add_top_bar(Adw.HeaderBar())
        self.nav.push(Adw.NavigationPage(title=_("Error"), tag="failure", child=view))

    def _finish(self) -> None:
        self.close()
        self.on_done()

    @property
    def page_tag(self) -> str:
        page = self.nav.get_visible_page()
        return page.get_tag() or "" if page is not None else ""

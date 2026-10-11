# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Small reusable widgets: monogram tile, countdown ring, strength meter, copy button."""

from __future__ import annotations

import math
import time
from typing import TYPE_CHECKING, Protocol

from gi.repository import Gdk, Gio, GLib, Gtk

from passwords_app.app import codes, monogram
from passwords_app.app.i18n import _
from passwords_app.app.security import Level, level_fraction, level_text

if TYPE_CHECKING:
    from collections.abc import Callable

    from passwords_app.app.records import Item


class Pen(Protocol):
    """The part of cairo.Context the ring draws with.

    pycairo ships with python3-gi-cairo, which only the GUI runtime installs; typing against
    this protocol keeps the module checkable without it, and cairo.Context satisfies it.
    """

    def set_line_width(self, width: float) -> None: ...
    def set_source_rgb(self, red: float, green: float, blue: float) -> None: ...
    def set_source_rgba(self, red: float, green: float, blue: float, alpha: float) -> None: ...
    def arc(self, xc: float, yc: float, radius: float, angle1: float, angle2: float) -> None: ...
    def stroke(self) -> None: ...


class MonogramTile(Gtk.Stack):
    """Rounded square with the site's letter (stable color per site) or its website icon."""

    def __init__(self, size: int = 32) -> None:
        # Decorative: the row next to it already names the site for screen readers.
        super().__init__(
            valign=Gtk.Align.CENTER,
            halign=Gtk.Align.CENTER,
            accessible_role=Gtk.AccessibleRole.PRESENTATION,
        )
        self.set_size_request(size, size)
        self.label = Gtk.Label(xalign=0.5, yalign=0.5)
        self.label.add_css_class("monogram")
        self.label.add_css_class(f"monogram-{size}")
        self.add_named(self.label, "letter")
        self._size = size
        self.picture: Gtk.Picture | None = None  # created when an icon first arrives
        self._tint = ""

    def show_item(self, item: Item, letter: str | None = None, tint: str | None = None) -> None:
        """Show `item`'s letter; callers with cached `letter`/`tint` skip URL parsing."""
        self.label.set_text(letter or monogram.letter(item))
        tint = tint or f"tint-{monogram.color_index(monogram.site_key(item))}"
        if tint != self._tint:
            if self._tint:
                self.label.remove_css_class(self._tint)
            self.label.add_css_class(tint)
            self._tint = tint
        if self.picture is not None:
            self.set_icon(None)

    def set_icon(self, texture: Gdk.Texture | None) -> None:
        if texture is not None and self.picture is None:
            self.picture = Gtk.Picture(content_fit=Gtk.ContentFit.CONTAIN, can_shrink=True)
            self.picture.add_css_class("favicon")
            self.picture.add_css_class(f"favicon-{self._size}")
            self.add_named(self.picture, "icon")
        if self.picture is not None:
            self.picture.set_paintable(texture)
        self.set_visible_child_name("icon" if texture is not None else "letter")

    @property
    def showing_icon(self) -> bool:
        return self.get_visible_child_name() == "icon"

    @property
    def tint(self) -> str:
        return self._tint

    def get_text(self) -> str:
        return self.label.get_text()


class CountdownRing(Gtk.DrawingArea):
    """Circular timer for a verification code; drains clockwise and turns red near zero.

    It animates from the frame clock between the once-a-second refreshes from the daemon so
    the arc moves smoothly instead of ticking.
    """

    def __init__(self, size: int = 22) -> None:
        super().__init__(content_width=size, content_height=size, valign=Gtk.Align.CENTER)
        self.add_css_class("countdown-ring")
        self.set_draw_func(self._draw)
        self._period = codes.DEFAULT_PERIOD
        self._deadline = 0.0  # monotonic time at which the current code expires
        self._tick = 0
        self.update_property([Gtk.AccessibleProperty.LABEL], [_("Time left for this code")])

    def start(self, seconds_left: int, period: int) -> None:
        self._period = max(1, period)
        self._deadline = time.monotonic() + seconds_left
        if not self._tick:
            self._tick = self.add_tick_callback(self._on_tick)
        self.queue_draw()

    def stop(self) -> None:
        if self._tick:
            self.remove_tick_callback(self._tick)
            self._tick = 0
        self._deadline = 0.0
        self.queue_draw()

    @property
    def seconds_left(self) -> float:
        return max(0.0, self._deadline - time.monotonic())

    @property
    def urgent(self) -> bool:
        return codes.urgent(self.seconds_left)

    def _on_tick(self, _widget: Gtk.Widget, _clock: Gdk.FrameClock) -> bool:
        self.queue_draw()
        return True

    def _draw(self, _area: Gtk.DrawingArea, cr: Pen, w: int, h: int) -> None:
        fraction = codes.ring_fraction(self.seconds_left, self._period)
        radius = min(w, h) / 2 - 2
        cx, cy = w / 2, h / 2
        color = self.get_color()
        cr.set_line_width(2.5)
        cr.set_source_rgba(color.red, color.green, color.blue, 0.15)
        cr.arc(cx, cy, radius, 0, 2 * math.pi)
        cr.stroke()
        if fraction <= 0:
            return
        if codes.urgent(self.seconds_left):
            cr.set_source_rgb(0.88, 0.11, 0.14)  # Adwaita red 3
        else:
            cr.set_source_rgba(color.red, color.green, color.blue, 0.85)
        start = -math.pi / 2
        cr.arc(cx, cy, radius, start, start + 2 * math.pi * fraction)
        cr.stroke()


class StrengthMeter(Gtk.Box):
    """Bar plus label (`Strong`, `Weak`, ...) under the password row."""

    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.add_css_class("strength-meter")
        self.bar = Gtk.LevelBar(min_value=0, max_value=1, hexpand=True)
        self.bar.remove_offset_value(Gtk.LEVEL_BAR_OFFSET_LOW)
        self.bar.remove_offset_value(Gtk.LEVEL_BAR_OFFSET_HIGH)
        self.bar.remove_offset_value(Gtk.LEVEL_BAR_OFFSET_FULL)
        for name, value in (("very-weak", 0.15), ("weak", 0.4), ("good", 0.7), ("strong", 1.0)):
            self.bar.add_offset_value(name, value)
        self.label = Gtk.Label(xalign=0)
        self.label.add_css_class("caption")
        self.append(self.bar)
        self.append(self.label)
        self.level: Level | None = None

    def show_level(self, level: Level) -> None:
        self.level = level
        self.bar.set_value(level_fraction(level))
        self.label.set_text(_("Password strength: {level}").format(level=level_text(level)))
        self.bar.update_property(
            [Gtk.AccessibleProperty.LABEL],
            [_("Password strength: {level}").format(level=level_text(level))],
        )


def copy_button(tooltip: str, on_click: Callable[[], None]) -> Gtk.Button:
    button = Gtk.Button(
        icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER, tooltip_text=tooltip
    )
    button.add_css_class("flat")
    button.update_property([Gtk.AccessibleProperty.LABEL], [tooltip])
    button.connect("clicked", lambda *_a: on_click())
    return button


def icon_button(icon: str, tooltip: str, on_click: Callable[[], None]) -> Gtk.Button:
    button = Gtk.Button(icon_name=icon, valign=Gtk.Align.CENTER, tooltip_text=tooltip)
    button.add_css_class("flat")
    button.update_property([Gtk.AccessibleProperty.LABEL], [tooltip])
    button.connect("clicked", lambda *_a: on_click())
    return button


def on_activate(action: Gio.SimpleAction, callback: Callable[[], None]) -> None:
    """Run `callback` whenever `action` is activated; its parameter is ignored."""

    def activated(_action: Gio.SimpleAction, _param: GLib.Variant | None) -> None:
        callback()

    action.connect("activate", activated)

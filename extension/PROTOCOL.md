<!--
SPDX-FileCopyrightText: 2026 Alex Mextner
SPDX-License-Identifier: MIT
-->

# Native messaging protocol

The extension talks to `passwords-app-native-host` (native messaging host
`io.github.alex_mextner.passwords`); the host talks to `passwords-appd` over the D-Bus session
bus (`io.github.alex_mextner.Passwords1`, see `data/dbus/io.github.alex_mextner.Passwords1.xml`).
The host holds no state and no secrets between requests: every answer comes from the daemon.

## Framing

Each message, in both directions, is a 32-bit unsigned length in native byte order (little
endian on every platform this project supports) followed by that many bytes of UTF-8 JSON.

- The cap is **1 MiB (1 048 576 bytes) of payload** in both directions. Larger incoming
  frames are read and discarded in bounded chunks, then answered with `too-large`; the host
  never buffers more than the cap.
- A zero-length frame, invalid UTF-8, invalid JSON, or a JSON value that is not an object is
  answered with `malformed`. A request whose `id` cannot be read is answered with `"id": null`.
- End of input (the browser closed the port) ends the host with exit status 0. A stream that
  ends in the middle of a length prefix or payload also ends the host quietly: nobody is left
  to read an answer.
- Requests are processed one at a time, in order; every request gets exactly one response.
- Deadlines: the host answers every request within 12 s (`daemon-unavailable` when the
  daemon is slower). The extension gives each request 15 s counted from when the host
  reaches it, i.e. from the answer to the request before it, so time spent waiting in line
  behind a slow request is not held against the next one.

## Requests

```json
{ "id": 7, "cmd": "match", "url": "https://accounts.example.com/login" }
```

| field | type                                            | rule                      |
| ----- | ----------------------------------------------- | ------------------------- |
| `id`  | integer `0 ≤ id < 2^53` or string of 1–64 chars | echoed back verbatim      |
| `cmd` | string                                          | one of the commands below |

Unknown fields are rejected (`bad-request`) so that typos do not silently change meaning.
Every `url` is the URL of the **frame the request is about, as reported by the browser**
(`runtime.MessageSender.url`), never a URL a page supplied. It must be `http:` or `https:`
with a host and at most 4096 characters.

### `status`

No fields. Result:

```json
{ "state": "idle", "message": "", "item_count": 42, "protocol": 1 }
```

`state` is the daemon state (`signed-out | syncing | idle | paused | offline |
signin-required | error`).

### `match`

Fields: `url`. Result: candidates the daemon's `Match(url)` returned, best first. **Never
contains a password, an `otpauth` URI, or notes.** `alt_urls` is passed through so the
extension can re-check, independently of the daemon, that the page belongs to the same site
as one of the item's websites before it fills anything.

```json
{
  "items": [
    {
      "id": "…",
      "title": "Northwind",
      "username": "alex@example.com",
      "url": "https://northwind.example",
      "alt_urls": [],
      "has_code": true
    }
  ]
}
```

### `fill`

Fields: `item_id` (string, 1–256 chars), `url`. Sent only after an explicit user pick (a
trusted click or key press in the extension's own dropdown or popup). The host re-runs
`Match(url)` and answers `not-allowed` unless `item_id` is among the candidates, so a
password is only ever released for
a page the daemon considers the same site (same registrable domain, no https→http
downgrade, same explicit port). Result:

```json
{ "username": "alex@example.com", "password": "…" }
```

### `code`

Fields: `item_id`, `url`; the same `Match(url)` check as `fill`. Result: the current one-time
code and how long it stays valid. The TOTP seed never leaves the daemon.

```json
{ "code": "492039", "seconds_left": 17 }
```

### `save`

Fields: `url`, `username` (≤ 1024 chars, may be empty), `password` (1–4096 chars), optional
`title` (≤ 256 chars; used only when a new item is created — an update never renames the
user's item), optional `item_id` (update that item; it must be among `Match(url)`),
optional `dry_run` (boolean, default `false`). The request `id` is only the envelope id; the
item is always named by `item_id`.

Without `item_id`, the host looks for a candidate of `Match(url)` with exactly the same username:
one → that item is the update target; none → a new item is created with `url` reduced to
its origin (`scheme://host[:port]`, no path or query). If the target already holds the same
username and password, nothing is written.

```json
{ "action": "update", "id": "…", "saved": true }
```

`action` is `create`, `update` or `none`; `saved` is `true` only when the daemon's `Save`
ran (never with `dry_run`); `id` is `null` for a dry-run `create`. The extension uses
`dry_run` to decide whether to offer _Save password_, _Update password_, or nothing.

No string field may contain U+0000.

## Responses

```json
{"id": 7, "ok": true, "result": {…}}
{"id": 7, "ok": false, "error": {"code": "not-allowed", "message": "…"}}
```

Error messages are for logs and never contain secrets.

| code                 | meaning                                                           |
| -------------------- | ----------------------------------------------------------------- |
| `malformed`          | frame or JSON could not be read                                   |
| `too-large`          | frame over 1 MiB                                                  |
| `bad-request`        | unknown command, missing/extra/ill-typed field, bad URL           |
| `not-allowed`        | item is not a candidate for this URL                              |
| `not-found`          | no such item, or it has no verification code                      |
| `daemon-unavailable` | no daemon on the session bus, bus unreachable, or call timed out  |
| `unavailable`        | the daemon cannot serve right now (offline, keyring unreachable)  |
| `auth-required`      | the daemon needs the user to sign in                              |
| `locked`             | the keyring collection is locked                                  |
| `invalid`            | the daemon rejected the item                                      |
| `internal`           | unexpected failure in the host (details on stderr, never secrets) |

D-Bus errors map one-to-one: `…Error.NotFound` → `not-found`, `…Error.Invalid` →
`invalid`, `…Error.Unavailable` → `unavailable`, `…Error.AuthRequired` → `auth-required`,
`…Error.Locked` → `locked`; `org.freedesktop.DBus.Error.ServiceUnknown`, `NameHasNoOwner`,
`NoReply`, `Disconnected`, timeouts and connection failures → `daemon-unavailable`.

## Manifests

Host name `io.github.alex_mextner.passwords`. Templates: `data/native-messaging/firefox.json.in`
(`allowed_extensions: ["passwords-app@alex-mextner.github.io"]`) and
`data/native-messaging/chrome.json.in` (`allowed_origins:
["chrome-extension://djaiceficanbdafmmlcmgbfjefiapjaf/"]`, the id derived from the pinned
`key` in the Chrome manifest). `@HOST_PATH@` is replaced with the absolute path of
`passwords-app-native-host`; `passwords_app.browser.manifests` renders and installs them.

| browser                | user manifest directory                                                                                                                  |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Firefox (deb/tarball)  | `~/.mozilla/native-messaging-hosts/`                                                                                                     |
| Firefox (snap, Ubuntu) | the same `~/.mozilla/native-messaging-hosts/`, read by the WebExtensions portal / native messaging proxy outside the sandbox (see below) |
| Google Chrome          | `~/.config/google-chrome/NativeMessagingHosts/`                                                                                          |
| Chromium               | `~/.config/chromium/NativeMessagingHosts/`                                                                                               |

### Snap Firefox

Snap Firefox cannot read `~/.mozilla` on the host or start host programs itself. With
`widget.use-xdg-desktop-portal.native-messaging` (default on in the Ubuntu snap) it asks
`xdg-desktop-portal`'s `org.freedesktop.portal.WebExtensions` interface (Ubuntu patch; the
`xdg-native-messaging-proxy` service on releases that ship it) for the manifest. The portal
searches `~/.mozilla/native-messaging-hosts/`, then `/usr/lib/mozilla/native-messaging-hosts/`,
`/usr/lib64/mozilla/native-messaging-hosts/` and
`/usr/lib/x86_64-linux-gnu/mozilla/native-messaging-hosts/`, and starts the host **outside**
the sandbox, in the user session, so the host reaches the daemon on the normal session bus.
The first start shows a one-time _"Allow Firefox to start WebExtension backend?"_ prompt;
the answer is kept in the permission store (`flatpak permissions webextensions` lists it,
`flatpak permission-remove webextensions io.github.alex_mextner.passwords` resets it).

The host binary and the manifest must not be writable by the sandboxed browser: both live
under hidden directories (`~/.local/…`, `~/.mozilla/…`), which the snap `home` interface
does not grant.

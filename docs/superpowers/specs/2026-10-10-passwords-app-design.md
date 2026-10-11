# Passwords app — design spec

Date: 2026-10-10 · Status: approved by owner (autonomous build) · Repo: `alex-mextner/passwords-app` (MIT)

## 1. Purpose

Linux has no iCloud Keychain client. This project makes an Ubuntu desktop a full peer of the
user's Apple devices for **website passwords**:

- **Two-way, continuous sync** between iCloud Keychain (the Passwords app data) and
  GNOME Keyring (Secret Service), so Seahorse ("Пароли и ключи") and every libsecret app see
  the same passwords.
- A **native Passwords app** (GTK4 + libadwaita) at or above the UX of Apple's Passwords app.
- **Browser autofill and save** in Firefox (snap) and Google Chrome.
- **Deleted items are kept for 90 days** (restorable), whichever side deleted them.

Success = a password created, edited, or deleted on an iPhone shows up the same way on Linux
(keyring, app, browsers), and vice versa, without user action; every scenario in §11 has a
passing automated test; screenshots and a video show both directions.

## 2. Scope

In: personal Passwords-app logins (website, username, password, title, notes, verification
codes, additional websites); shared password groups the account belongs to; GNOME Keyring
mirror; GTK app; CLI; Firefox + Chrome extension; systemd user services; installer.

Out (explicit): passkeys (no Linux WebAuthn platform authenticator), Wi‑Fi passwords
(NetworkManager owns them), credit cards, Hide My Email, macOS/Windows builds, any cloud
hosting. **No server of ours ever sees a password**: all components run on the user's
machine and talk only to Apple. (Vercel/Neon were offered; rejected — a hosted copy of a
decrypted keychain is pure risk and nothing here needs a server.)

## 3. Architecture

```
iPhone/Mac ─┐
            ├─ iCloud (CloudKit: Octagon trust, CKKS "Passwords" zone, shared groups)
Linux:      │      ▲  HTTPS (GSA/anisette auth)          anisette-v3-server (docker, 127.0.0.1:6969)
            │      │
   passwords-appd (systemd --user, D-Bus io.github.alex_mextner.Passwords)
     ├─ icloud/        protocol client: auth, Octagon join, CKKS decrypt + encrypt, save/delete
     ├─ sync/          3-way planner + executor, guards, trash, scheduler
     ├─ store/         state.db (SQLite; secret columns AES-256-GCM, key in Secret Service)
     └─ keyring/       Secret Service adapter → collection "iCloud Passwords"
            ▲ D-Bus                     ▲ D-Bus                    ▲ Secret Service
   GTK app (passwords-app)    native host (browser)          Seahorse / libsecret apps
                                   ▲ native messaging (portal for snap Firefox)
                              WebExtension (Firefox + Chrome)
```

Language: Python ≥ 3.13 on the system interpreter (PyGObject/GTK need it); venv with
`--system-site-packages`. Extension: TypeScript, bundled with bun.

The protocol core is vendored from Sank6/iCloud-Keychain-for-Linux (MIT, read-only) and
extended with a write path written for this project. OpenBubbles/rustpush (SSPL) is used only
as protocol documentation; no code is copied from it.

## 4. Data model

`Credential` (immutable dataclass, `core/model.py`) is the only shape that crosses layers:

| field | type | iCloud source | Secret Service |
|---|---|---|---|
| `id` | `str` (uppercase UUID) | inet record UUID | attr `pa-id` |
| `url` | `str` | `ptcl`+`srvr`+`port`+`path` | attr `url`, also `server` |
| `username` | `str` | `acct` | attr `username` |
| `password` | `str` | `v_Data` | secret |
| `title` | `str \| None` | sidecar `title` | label (see below) |
| `notes` | `str \| None` | sidecar `notes` | attr `notes` |
| `otpauth` | `str \| None` | sidecar `totp` → `otpauth://` URI | attr `otpauth` |
| `alt_urls` | `tuple[str, ...]` | sidecar `s_as` | attr `alt-urls` (newline-joined) |
| `group` | `str \| None` | shared group zone id | attr `group` |
| `created`, `modified` | aware UTC `datetime` | `cdat`, `mdat` | attrs |

Keyring item: collection **"iCloud Passwords"**, schema `io.github.alex_mextner.Passwords`,
label `"{title or host} — {username}"`. Users can create items in that collection from
Seahorse: label convention `username @ example.com` (also `example.com username`, or a bare
URL); unparseable labels produce a desktop notification and are left alone.

`content_hash` = SHA-256 over the canonical JSON of all fields except timestamps; it is what
"changed" means everywhere.

## 5. Sync semantics

Per item id, compare **base** (last synced, in state.db) with **remote** and **local**:

| base | remote | local | action |
|---|---|---|---|
| — | new | — | create local |
| — | — | new | create remote (local item gets an id) |
| — | new | new | equal content → link; else both kept (distinct ids) |
| ✓ | = | = | nothing |
| ✓ | changed | = | update local |
| ✓ | = | changed | update remote |
| ✓ | changed | changed | equal → refresh base; else newer `modified` wins, loser → trash (`conflict`) |
| ✓ | deleted | = | delete local, base → trash (`deleted-in-icloud`) |
| ✓ | = | deleted | delete remote, base → trash (`deleted-on-linux`) |
| ✓ | deleted | deleted | base → trash, drop base |
| ✓ | deleted | changed | recreate remote from local (edit beats delete) |
| ✓ | changed | deleted | recreate local from remote |

First sync of a non-empty collection: local items without base that match a remote item on
(normalized host, username, password) are **linked**, not duplicated.

Guards (never bypassed silently):
- Local side unreadable (collection locked/missing, D-Bus error) → cycle skipped; never read as "empty".
- Remote fetch incomplete → cycle skipped.
- A cycle that would delete more than `max(5, 10% of items)` on either side **pauses**: nothing
  is deleted, status = `paused`, banner in the app, notification; user chooses
  *Apply deletions* or *Restore them*.
- Writes to iCloud are **conditional on the record etag** captured at fetch time, and writes
  to the keyring on the item's content as read at fetch time (re-read just before writing);
  a conflict error aborts that action and the next cycle re-plans with fresh data.
- A login iCloud refuses to store (another login has its site and username, or the address
  is not a website) only sets **that item** aside: the rest of the cycle continues, status is
  `idle` (not `offline`) and the status message names the login, a notification fires once per
  refused version saying the password stays on this computer only, and it is withdrawn once a
  complete cycle no longer finds the login refused (accepted after an edit, or deleted). The
  item is retried with its own backoff (2 min doubling to 6 h; at once after an edit). Its
  item dict's read-only `sync_problem` carries the plain-language reason until iCloud stores
  it or it is deleted (§7), so the app can mark it "On this computer only".

Trash: every item removed from either side, and every conflict loser, is stored encrypted in
state.db with `deleted_at`, `reason`, and origin for **90 days** (setting, default 90), then
purged. *Restore* re-inserts it locally; the next cycle pushes it to iCloud. iCloud keeps one
login per site and username, so when a live keyring login has the restored version's site and
username (e.g. restoring a conflict loser), the restored version **replaces** that login in
place and the displaced version goes to trash (reason `conflict`); Restore returns the live
login's id. Restoring is the user's explicit choice: the restored login wins over an iCloud
edit of it not synced yet (even when it equals the version both sides last agreed on), and
that edit goes to trash. Otherwise a deleted item comes back under its own id while that id
is free, so iCloud moves its record out of Recently Deleted instead of duplicating it; a
conflict loser gets a fresh id. Restores and sync cycles run one at a time. A trash entry
added again (the same version lost again) keeps its latest `deleted_at`.

Scheduling: a cycle runs at start, every 60 s while the app or a browser is active and every
5 min otherwise, 2 s after any local change (Secret Service `ItemCreated/Changed/Deleted`
signals, debounced), on network-up, and on demand. Failures back off exponentially (max 30
min) and surface in status.

## 6. iCloud client

Kept from Sank6: GSA SRP login with anisette, 2FA (trusted device + SMS), MobileMe/CloudKit
tokens, listing recovery devices and joining the keychain trust circle (Octagon) with one
device's passcode, TLK share recovery, CKKS decrypt, sidecar
parsing. Changes:

- State moves to `~/.config/passwords-app/` (0700); session master key in Secret Service.
- Persisted per-zone sync tokens; incremental fetch; record etags kept per item.
- **Write path** (new): item encryption (inverse of decrypt: random item key wrapped by the
  zone class key, AES-SIV, AAD v2), CloudKit record encoder and `record/save`, for the inet
  record and its Passwords sidecar. Each update is conditional on the tag read at fetch time,
  sent as RecordSaveRequest field 4 (Apple ignores the tag inside the record; a stale tag
  fails with client error 15 and the rest of the batch with 16); `record/delete` takes its
  tag in RecordDeleteRequest field 2.
- Deleting works like Apple's Passwords app: the login moves to access group
  `com.apple.cfnetwork-recently-deleted` and its sidecar to
  `com.apple.password-manager-recently-deleted` (one conditional save batch), so every Apple
  device can still recover it; nothing is hard-deleted. Creating a login whose record sits
  there moves it back.
- Silent token refresh with the saved Apple ID password; when Apple demands 2FA the daemon
  status becomes `signin-required` and the app shows a re-auth dialog.
- Apple's own *Recently Deleted* groups are read apart from live logins, so a login deleted
  on the iPhone reaches the sync engine as a delete.

Exposed to the sync layer only as `RemoteStore` (§10).

## 7. Daemon (`passwords-appd`)

systemd user service + D-Bus activation. Bus name `io.github.alex_mextner.Passwords`,
object `/io/github/alex_mextner/Passwords`, interface `io.github.alex_mextner.Passwords1`.

Methods: `GetStatus() → a{sv}`, `List() → aa{sv}` (no secrets), `Get(s id) → a{sv}`,
`Save(a{sv}) → s id`, `Delete(s id)`, `ListTrash() → aa{sv}`, `Restore(s trash_id) → s id`,
`Purge(s trash_id)`, `SyncNow()`, `ResolvePause(b apply)`, `Match(s url) → aa{sv}`,
`GetCode(s id) → (s code, u seconds_left)`, sign-in: `SignInStart(s apple_id, s password) →
a{sv}`, `SignInCode(s code) → a{sv}`, `ListRecoveryDevices() → aa{sv}`,
`JoinKeychain(s device_id, s passcode) → a{sv}`, `SignOut()`.
Signals: `StatusChanged(a{sv})`, `ItemsChanged(as ids)`.

Item dicts carry `sync_problem s`: "" while the item syncs, otherwise the plain-language reason
iCloud refuses to store it (e.g. "another password for this website and username already
exists"). It is read-only (Save accepts and ignores it), set from the last complete cycle (an
interrupted one only adds refusals), cleared on sign-out, and `ItemsChanged` names an item
whenever it changes.

Status `state` ∈ `signed-out | syncing | idle | paused | offline | signin-required | error`.

## 8. App UX (GTK4 + libadwaita ≥ 1.8)

Bar: Apple Passwords (macOS 26). Above it where marked ★.

- Three-pane adaptive layout (`Adw.NavigationSplitView` ×2): sidebar → list → detail;
  collapses to one pane on narrow windows.
- Sidebar: All, Codes, Security (badge), Deleted (count, "N days left" per item), shared groups.
- List: instant search (type anywhere), sort by title/website/modified, monogram avatars with
  stable colors (★ no network; optional favicons, off by default).
- Detail: title, website(s), username, password (masked, reveal, copy), verification code
  with live countdown ring, notes, created/modified, strength meter, reuse warning.
  Edit in place; Save/Cancel; validation.
- Copy anything with one click; ★ clipboard auto-cleared after 45 s (setting).
- New password dialog with ★ Apple-style generator (`xxxxxx-xxxxxx-xxxxxx`) and options.
- Delete → toast with Undo; Deleted view with Restore / Delete now.
- Security: weak, reused, ★ compromised (opt-in HIBP k-anonymity: only 5 hex chars of SHA-1 leave the machine).
- Sync status in header (synced / syncing / paused / offline / sign-in required) with details
  popover and *Sync now*; `Adw.Banner` for pause and sign-in. While iCloud refuses any
  password (its `sync_problem`, §7), "Synced" becomes a warning ("Not All Synced") and the
  popover counts them; such a password's row carries an "On this computer only" badge and its
  detail a banner with the reason.
- Sign-in wizard: Apple ID → 2FA code (6 boxes, paste-aware) → "Confirm with a device
  passcode": plain-language explanation (Apple keeps your keychain keys sealed with the screen
  passcode of each of your devices; entering one device's passcode lets this computer join),
  device list with model/serial, attempts warning (~10 wrong tries destroy that device's
  copy) → passcode → progress → done. The word "escrow" never appears in UI or CLI text.
- ★ GNOME Shell search provider: type a site name in Activities, Enter copies the password.
- ★ Optional app lock after idle (polkit `auth_self`, fingerprint where configured).
- Shortcuts: Ctrl+N, Ctrl+F, Ctrl+C (password), Ctrl+Shift+C (username), Ctrl+Alt+C (code),
  Ctrl+E, Delete, Ctrl+Z (undo delete), Ctrl+, , Ctrl+?. Russian and English UI (gettext).
- Accessibility: every control has an accessible name; keyboard-only operation works.

## 9. Browser integration

One MV3 extension for Firefox and Chrome. In-page dropdown under username/password and
one-time-code fields, matching by registrable domain (public suffix list, ports, IP literals,
`alt_urls`), fills username + password, fills codes (split inputs), offers to **save** a new
or changed login after submit (→ `Save` → iCloud), password generator in new-password fields,
toolbar popup with search.

Native messaging host `io.github.alex_mextner.passwords` (stdio ↔ daemon D-Bus). The
extension never receives TOTP seeds or a password until the user picks an entry. Manifests:
`~/.mozilla/native-messaging-hosts/` (snap Firefox reaches it via the WebExtensions portal) and
`~/.config/google-chrome/NativeMessagingHosts/`. Firefox build is signed as an unlisted AMO
add-on (owner's AMO API key); Chrome loads the unpacked build with a pinned `key` (stable ID).

## 10. Internal contracts

```python
class RemoteStore(Protocol):  # sync/ports.py
    async def fetch(self) -> RemoteSnapshot: ...  # full current view (incremental inside)
    async def upsert(self, c: Credential, etag: str | None) -> str: ...  # → new etag; ConflictError
    async def delete(self, item_id: str, etag: str | None) -> None: ...  # ConflictError


class LocalStore(Protocol):  # sync/ports.py
    async def fetch(self) -> LocalSnapshot: ...  # LocalUnavailable if locked/missing
    # `expected`: the content_hash() read at fetch time (ConflictError if it changed since);
    # None writes unconditionally.
    async def upsert(self, c: Credential, *, expected: str | None = None) -> None: ...
    async def delete(self, item_id: str, *, expected: str | None = None) -> None: ...


def plan(
    base: Mapping[str, BaseEntry], remote: RemoteSnapshot, local: LocalSnapshot, policy: SyncPolicy
) -> SyncPlan: ...  # pure; sync/plan.py
```

## 11. Scenario catalog (each has an e2e test)

S1 new on Apple → Linux keyring, app, both browsers · S2 edit on Apple → Linux · S3 delete on
Apple → removed + trash · S4 new in app → iCloud · S5 edit in app · S6 delete in app → iCloud +
trash · S7–S9 create/edit/delete in Seahorse → iCloud · S10 save from Firefox → iCloud · S11
save from Chrome · S12 edit/edit conflict · S13 edit/delete conflict · S14 restore from trash →
both sides · S15 purge after 90 days · S16 mass-delete pause → apply / restore · S17 keyring
locked → no deletions · S18 offline → retry, no loss · S19 token expiry → silent refresh; 2FA →
sign-in-required · S20 daemon restart/reboot → no duplicates · S21 TOTP shown + filled · S22
notes/title/alt-urls round-trip · S23 Unicode, long, empty-username, IP/port URLs · S24 first
sync links existing Seahorse items · S25 shared-group item read + edit.

## 12. Quality gates

- Lint/format: ruff (ALL, documented ignores), ruff format, mypy --strict, pyright,
  codespell, vulture, deptry, xenon (complexity), shellcheck, shfmt, yamllint, actionlint,
  zizmor, eslint (typescript-eslint strict, security, no-unsanitized), tsc --strict, prettier,
  web-ext lint, desktop-file-validate, appstreamcli validate, REUSE/SPDX.
- Security: bandit, semgrep (python, security-audit, secrets, typescript), pip-audit,
  `bun audit`, gitleaks (hook + CI), CodeQL, dependency-review, OpenSSF Scorecard, Dependabot.
  Logs are redacted (no secrets, tokens, or passwords — enforced by a test).
- Performance budgets (pytest-benchmark, CI-enforced): `plan()` 10k items < 100 ms;
  keyring fetch 2k items < 2 s, including the first fetch after a daemon restart (it starts
  from the item properties state.db keeps), except the one-off first fetch of a collection no
  store has read yet, < 4 s (gnome-keyring scans every item per property read); app cold
  start to first frame < 800 ms; search keystroke on 5k items < 16 ms; native host `Match`
  p95 < 50 ms; daemon idle RSS < 120 MB.
- Tests ≥ 2000, all meaningful: unit (planner matrix, crypto vectors and round-trips, codec,
  URL matching, mapping, generator, strength, TOTP), integration (real gnome-keyring on a
  private D-Bus, SQLite, daemon D-Bus API, native host), e2e (fake CloudKit server + real
  keyring + daemon + GTK app in headless gnome-shell + real Firefox and Chrome), live (opt-in,
  real iCloud account, `e2e-passwords-app-*.invalid` items, cleaned up). Coverage ≥ 90% for
  `core`, `sync`, `store`, `keyring`, `icloud` write path.

## 13. Proof

Headless gnome-shell (`--headless --virtual-monitor`, private session, unsafe mode for its
Screenshot/Screencast D-Bus) drives the real app and browsers; e2e runs save PNGs and WebM
recordings under `docs/proof/`. Live proof on the owner's desktop: app, Seahorse, Firefox,
Chrome, and the owner's iPhone screenshot for the Apple side.

## 14. Risks

| risk | mitigation |
|---|---|
| Malformed write propagates to all Apple devices | write path tested against decrypt of real records; first live writes on a disposable item; etag-conditional saves; trash keeps every overwritten/deleted version |
| Passcode join is irreversible (~10 wrong passcodes destroy that device's recovery copy) | join only once, through a gated confirm + typed passcode; never automated |
| Apple changes protocol / rejects spoofed Mac | status `error` with clear message; no local deletes on failure |
| Unattended 2FA on refresh | `signin-required` state + app dialog |
| Mass deletion from a bug | pause guard + trash + locked/empty-read guard |
| Same-user malware reads secrets | same model as GNOME Keyring itself; documented |

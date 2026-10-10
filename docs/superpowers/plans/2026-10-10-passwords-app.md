# Passwords app Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship two-way iCloud Keychain ⇄ GNOME Keyring sync with a native GTK app and Firefox/Chrome autofill, proven by ≥ 2000 tests, every lint/security/perf gate, screenshots and video.

**Architecture:** One Python package (`passwords_app`) on the system interpreter: vendored+extended iCloud client, pure 3-way planner, SQLite state, Secret Service adapter, a D-Bus daemon that is the only writer, and three D-Bus clients (GTK app, native messaging host, CLI). A TypeScript MV3 extension talks to the native host.

**Tech Stack:** Python 3.14, PyGObject (GTK 4.22, libadwaita 1.9), dbus-fast, cryptography, requests, SQLite; TypeScript + bun; pytest/hypothesis/pytest-benchmark; Selenium (Firefox), Playwright (Chromium); headless gnome-shell 50.

**Spec:** `docs/superpowers/specs/2026-10-10-passwords-app-design.md`

## Global Constraints

- Python ≥ 3.13, run on `/usr/bin/python3`; venv via `uv venv --python /usr/bin/python3 --system-site-packages .venv`, deps `uv pip install -e . --group dev` + `uv pip install --no-deps pygobject-stubs`.
- Every file passes `ruff check`, `ruff format --check`, `mypy --strict`, `pyright` (strict, `src/`), `bandit`; new files carry `# SPDX-FileCopyrightText: 2026 Alex Mextner` / `# SPDX-License-Identifier: MIT`.
- Contracts are fixed: `src/passwords_app/core/model.py`, `src/passwords_app/sync/ports.py`, `data/dbus/io.github.alex_mextner.Passwords1.xml`. Changing one requires a note to the orchestrator and every consumer.
- App id / bus name `io.github.alex_mextner.Passwords`; object `/io/github/alex_mextner/Passwords`; gettext domain `passwords-app`; state `~/.config/passwords-app/` (0700) and `~/.local/share/passwords-app/state.db`.
- Never log secrets, tokens, passwords, passcodes, 2FA codes, otpauth seeds. User-facing text never says "escrow".
- TLS verification is never disabled; `gsa.apple.com` verifies against `icloud/certs/apple-roots.pem`.
- No test or agent touches the owner's real iCloud account or real login keyring; live tests are opt-in (`PASSWORDS_APP_LIVE=1`) and run only by the orchestrator.
- On-disk formats of `~/.config/passwords-app/{device.json,session.enc,vault.enc}` stay readable (the owner's live session was created by the vendored code).
- Trash retention default 90 days; mass-delete guard `max(5, 10%)`.

## Review Focus

1. Keyring locked/unreachable or iCloud partial fetch must never translate into deletions — tests in Task B (planner + engine) and Task C (locked collection → `LocalUnavailable`).
2. A record written by our encoder must decrypt with the existing decrypt pipeline byte-for-byte (round-trip + fixtures from real responses) — Task A.
3. Seahorse-created items with odd labels (no username, IDN, IP:port, emoji) must neither crash sync nor be silently dropped — Task C label parser table tests + `rejected` reporting.
4. Two quick consecutive edits (app then iPhone) must not lose either version — Task B conflict tests (loser lands in trash) + Task A etag-conditional save.
5. Browser fill must never leak a password to a page on a different registrable domain (lookalikes, subdomain of public suffix, `http` downgrade) — Task B `core/urls.py` table + Task F e2e.

---

### Task A: iCloud client — TLS fix, write path, account API, remote store, fake CloudKit

**Files:** own `src/passwords_app/icloud/**`, `src/passwords_app/sync/remote_icloud.py`, `tests/unit/icloud/**`, `tests/fakes/cloudkit_server.py`, `tests/fakes/icloud_session.py`.

**Interfaces:**
- Consumes: `Credential`, `RemoteStore`, `RemoteSnapshot`, `RemoteItem`, errors from `sync/ports.py`.
- Produces:
  - `icloud/account.py`: `class Account(config_dir: Path | None = None, anisette_url: str | None = None)` with `status() -> AccountStatus(apple_id: str | None, signed_in: bool, joined: bool)`, `sign_in(apple_id, password) -> SignInStep`, `submit_code(code) -> SignInStep` (raises `WrongCode`), `request_sms() -> SignInStep`, `recovery_devices() -> list[RecoveryDevice(id, name, model, serial)]`, `join(device_id, passcode) -> SignInStep` (raises `WrongPasscode`), `sign_out() -> None`, `remote_store() -> ICloudRemoteStore`. `SignInStep` is a `StrEnum` `code|device|done`. All blocking.
  - `sync/remote_icloud.py`: `class ICloudRemoteStore` implementing `RemoteStore` (async via `asyncio.to_thread`), errors mapped to `RemoteUnavailable` / `AuthRequired` / `ConflictError`.
  - `tests/fakes/cloudkit_server.py`: `FakeCloudKit` HTTP server (ckAppInit, record/sync, record/save with etag check, record/delete) holding real encrypted Passwords-zone records; `make_session(fake) -> dict` builds a session whose webservices point at it.

- [ ] A0 TLS: test `tests/unit/icloud/test_tls_verification.py` — local HTTPS server with an unknown-issuer cert; GSA `_request`, every 2FA call, `login_mobileme`, `fetch_account_settings` raise their module error; positive control: same server trusted via the CA bundle succeeds. Then implement `icloud/tls.py:apple_ca_bundle() -> str`, use it for every `gsa.apple.com` call, default verification elsewhere, remove `urllib3.disable_warnings`, wrap transport/parse errors (`GSAError`, `ICloudError`) so the 5 vendored `test_gsa.py` failures pass. Delete dead HME code (`auth/webauth.py`, its tests, `cli/app.py:_ensure_web_session`).
- [ ] A1 Mapping `icloud/passwords.py`: inet record + sidecar ⇄ `Credential` (url from ptcl/srvr/port/path, totp dict ⇄ `otpauth://` URI, `s_as` ⇄ alt_urls, title/notes); table tests over real-shaped fixtures; unknown attributes preserved on rewrite.
- [ ] A2 Write path: item encryption (inverse of `keychain/pipeline.py` decrypt), CloudKit record encoder, `record/save` (etag-conditional) and `record/delete`; property test: encrypt→decrypt identity for arbitrary plists; encoder→parser identity.
- [ ] A3 Persistence: per-zone sync token + per-record etag persisted; incremental fetch; Apple "Recently Deleted" marker → treated as deletion.
- [ ] A4 `Account` API extracted from `cli/app.py`; non-interactive 2FA → `AuthRequired`; then delete `icloud/cli/` and `vault/` code paths that the new layers replace (keep on-disk compat).
- [ ] A5 `ICloudRemoteStore` + `FakeCloudKit`; tests: fetch/upsert/delete/conflict/partial-failure against the fake.
- [ ] A6 Shared password groups (container `com.apple.security.shared.keychain`): read + write items in groups the account belongs to.
- [ ] A7 Whole `icloud/` package strict-clean (ruff ALL, mypy --strict, pyright strict).
- Verify: `.venv/bin/python -m pytest tests/unit/icloud -q` all pass; linters clean on owned paths.

### Task B: Core + sync planner/engine + state store

**Files:** own `src/passwords_app/core/{urls,otp,generator,strength}.py`, `src/passwords_app/sync/{plan,engine}.py`, `src/passwords_app/store/**`, `tests/unit/{core,sync,store}/**`, `tests/fakes/memory_stores.py`, `tests/bench/test_bench_sync.py`.

**Interfaces:**
- Produces:
  - `core/urls.py`: `normalize_url(raw: str) -> str`, `registrable_domain(host: str) -> str`, `match(page_url: str, c: Credential) -> MatchKind` (`EXACT_HOST | SAME_SITE | NONE`; scheme downgrade https→http and differing explicit ports are `NONE`).
  - `core/otp.py`: `parse_otpauth(uri) -> OtpParams`, `code_at(p: OtpParams, at: datetime) -> tuple[str, int]` (RFC 6238 vectors).
  - `core/generator.py`: `apple_style() -> str` (`xxxxxx-xxxxxx-xxxxxx`, ≥1 upper, ≥1 digit, from `secrets`), `generate(length, *, upper, lower, digits, symbols) -> str`.
  - `core/strength.py`: `assess(password: str, *, user_inputs=()) -> Strength(score: int, weak: bool)`, `reused(creds) -> dict[str, list[str]]`.
  - `sync/plan.py`: `BaseEntry(credential: Credential, etag: str | None)`, action dataclasses `CreateLocal, UpdateLocal, DeleteLocal, CreateRemote, UpdateRemote, DeleteRemote, Link, Trash, SetBase, DropBase`, `SyncPlan(actions, pending: PendingDeletions | None)`, pure `plan(base, remote, local, policy) -> SyncPlan` implementing spec §5 exactly.
  - `store/state.py`: `StateStore(path: Path, key: bytes)` — bases, trash (encrypted, `purge_older_than(cutoff) -> int`), pending deletions, key-value; AES-256-GCM per row, WAL, schema version.
  - `sync/engine.py`: `SyncEngine(remote, local, state, *, policy=SyncPolicy(), clock=utcnow)` with `run_once() -> SyncReport`, `resolve_pause(apply: bool) -> SyncReport`, `trash() -> list[TrashEntry]`, `restore(trash_id) -> str`, `purge(trash_id) -> None`.
  - `tests/fakes/memory_stores.py`: `MemoryRemote` (etags, conflict + outage injection), `MemoryLocal` (lock/unlock, change notifications, rejected items).
- [ ] Exhaustive planner matrix (every base×remote×local state, every field-level change, guards, first-sync linking) as parametrized tests; hypothesis model test: random interleavings of edits on both sides converge, nothing lost (every removed/overwritten version is in trash).
- [ ] Engine tests with fakes: S12–S18, S20, S24 semantics; restore; purge at 90 days; pause/apply/restore.
- [ ] Benchmark: `plan()` on 10 000 items < 100 ms.

### Task C: GNOME Keyring adapter

**Files:** own `src/passwords_app/keyring/**`, `tests/integration/keyring/**`, `tests/harness/dbus_session.py`.

**Interfaces:**
- Produces: `SecretServiceStore` implementing `LocalStore` — `await SecretServiceStore.open(bus: MessageBus, *, label: str = "iCloud Passwords") -> SecretServiceStore`; DH-encrypted Secret Service session (never `plain`); items carry schema `io.github.alex_mextner.Passwords` and attributes per spec §4; items without `pa-id` get one assigned and written back; unparseable labels → `rejected`. `keyring/app_key.py`: `async def app_secret(bus, name: str, size: int = 32) -> bytes` (stored in the default collection, attributes `application=passwords-app`, `type=<name>`). `tests/harness/dbus_session.py`: fixture `private_bus` → address of a fresh session bus with an unlocked `gnome-keyring-daemon` (known password), plus helpers `lock_collection()`.
- [ ] Label parser table (≥ 150 cases); integration: CRUD round-trip, attribute fidelity, Unicode, 2 000-item fetch < 2 s, locked → `LocalUnavailable`, change signals → `changes()`, Seahorse-style item adoption.

### Task D: Daemon, CLI, install

**Files:** own `src/passwords_app/{daemon,cli}/**`, `data/systemd/**`, `data/dbus/io.github.alex_mextner.Passwords.service`, `scripts/install.sh`, `scripts/uninstall.sh`, `tests/integration/daemon/**`; owns `[project.scripts]` in `pyproject.toml`.

**Interfaces:**
- Consumes: Task A `Account`, `ICloudRemoteStore`; Task B `SyncEngine`, `StateStore`, `core.*`; Task C `SecretServiceStore`, `app_secret`; D-Bus XML.
- Produces: `passwords-appd` (`passwords_app.daemon.main:main`) implementing the XML exactly; `passwords-app` (`passwords_app.cli.main:main`: no args → `passwords_app.app.main:main` lazily; subcommands `status sync list show trash resolve signin signout doctor install uninstall`); `passwords-app-native-host` entry → `passwords_app.browser.native_host:main` (Task F).
- [ ] D-Bus contract tests against the daemon wired to `MemoryRemote`/`MemoryLocal` on `private_bus`; scheduler timing (fake clock); notifications; idempotent install/uninstall into a temp `$HOME`.

### Task E: GTK app

**Files:** own `src/passwords_app/app/**`, `data/{applications,metainfo,icons,search-providers,glib-2.0}/**`, `po/**`, `tests/gui/**`, `tests/fakes/fake_daemon.py`.

**Interfaces:**
- Consumes: D-Bus XML only (via Gio). `tests/harness/gnome_shell.py` from Task G.
- Produces: `passwords_app.app.main:main(argv) -> int`; `FakeDaemon` (in-memory implementation of the XML for GUI tests and screenshots).
- [ ] Spec §8 complete, Russian + English; GUI tests drive real widgets (search, edit/save, delete+undo, restore, OTP countdown, copy+auto-clear, sign-in wizard flow, pause banner) against `FakeDaemon`; screenshots per view in light/dark under `docs/proof/`.

### Task F: Browser extension + native host

**Files:** own `extension/**`, `src/passwords_app/browser/**`, `data/native-messaging/**`, `tests/browser/**`, `tests/unit/browser/**`.

**Interfaces:**
- Consumes: D-Bus `Match`, `Get`, `GetCode`, `Save`.
- Produces: native host `io.github.alex_mextner.passwords` (stdio, 4-byte LE length + JSON, 1 MiB cap), protocol doc `extension/PROTOCOL.md`; Firefox id `passwords-app@alex-mextner.github.io`; Chrome pinned `key`; builds `extension/dist/{firefox,chrome}`.
- [ ] Spec §9 complete; unit tests (field detection on fixture pages, split OTP inputs, save-prompt heuristics); e2e with real Firefox (Selenium, temporary add-on) and Chromium (Playwright) against `FakeDaemon` + real native host: fill, OTP fill, save new login, no fill on lookalike domains.

### Task G: Tooling, CI, headless GNOME harness

**Files:** own `scripts/check.sh`, `.pre-commit-config.yaml`, `.github/**`, `REUSE.toml`, `LICENSES/**`, `rig.yaml`, `tests/harness/gnome_shell.py`, `tests/harness/test_gnome_shell.py`.

**Interfaces:**
- Produces: `GnomeShellSession` context manager (private bus + headless `gnome-shell --virtual-monitor`), `screenshot(path)`, `start_recording(path)`, `stop_recording()`, `env()` for launching apps inside it; `scripts/check.sh [lint|security|types|test|bench|all]`.
- [ ] Every gate in spec §12 wired into `check.sh`, pre-commit, and CI (container `ubuntu:26.04`); rig applied (`stack: backend/python`).

### Wave 2 (after A–G merge)

- [ ] E2E scenario suite `tests/e2e/` S1–S25 on FakeCloudKit + private keyring + real daemon + GUI + browsers, with screenshots/video into `docs/proof/`.
- [ ] Live verification on the owner's account (orchestrator only): disposable item create/edit/delete both ways, iPhone screenshot from owner.
- [ ] Install on the owner's desktop; AMO-signed Firefox build (owner's AMO key); README with screenshots; final audit.

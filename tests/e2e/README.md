# End-to-end scenarios (spec §11)

One test file per scenario `test_sNN_*.py`. Each test gets a `stack` (see `stack.py`): a
private D-Bus session with a throwaway gnome-keyring, `FakeCloudKit` + `AppleServices` (the
Apple side, seeded through the real record encoder), a signed-in session, and the real
`passwords-appd` started through `daemon_shim.py` (Apple endpoints, a ~1 s schedule and a
shiftable wall clock; everything else is production code). `stack.app` (GTK app in a headless
gnome-shell), `stack.firefox` and `stack.chromium` (real browsers with the extension and the
native host) start on first use.

Helpers: `stack.apple` (the iPhone), `stack.keyring` (Seahorse), `stack.daemon` (D-Bus),
`wait_until` / `stays` (poll with a deadline).

Run one file locally: `.venv/bin/python -m pytest tests/e2e/test_s01_new_on_apple.py`.
Needs gnome-shell, gnome-keyring, dbus-daemon, ffmpeg, a non-snap Firefox + geckodriver
(Selenium cache or `PA_FIREFOX`/`PA_GECKODRIVER`), Playwright's Chromium, and the extension
built (`cd extension && bun install && bun scripts/build.ts`).

Proof: captures go to `docs/proof/raw/e2e/` (ignored); set
`PASSWORDS_APP_E2E_PROOF_DIR=docs/proof/e2e` to refresh the committed proof.

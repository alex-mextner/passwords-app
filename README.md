# Passwords app

Two-way iCloud Keychain sync for Linux. Your Apple Passwords show up in GNOME Keyring
("Passwords and Keys"), in a native GTK Passwords app, and in Firefox and Chrome autofill, and
changes made on Linux flow back to your iPhone, iPad, and Mac.

Status: under active development. Design: [`docs/superpowers/specs/2026-10-10-passwords-app-design.md`](docs/superpowers/specs/2026-10-10-passwords-app-design.md).

Unofficial, reverse-engineered for interoperability, not affiliated with Apple. Everything runs
on your machine and talks only to Apple: no third-party server ever sees your passwords.

## Apple sign-in needs a local anisette server

Apple's sign-in service wants a machine-validation blob ("anisette data") with every request.
`scripts/install.sh` (or `passwords-app install`) builds and starts a local anisette server in
Docker on `127.0.0.1:6970`. It runs Apple's own Windows iCloud library under Wine: the build
downloads Apple's iCloud for Windows installers from Apple's servers, checks them against pinned
SHA-256 sums, and keeps them only in the image on your machine (see [`docker/anisette`](docker/anisette);
never push that image anywhere). The first start provisions the server once with Apple; the
Docker volume `passwords-app-anisette-windows` keeps that identity.

The Android-based `dadoum/anisette-v3-server` used earlier no longer works: since 2026-10-12
Apple refuses its data with error `-80045`
([Dadoum/anisette-v3-server#61](https://github.com/Dadoum/anisette-v3-server/issues/61),
[#144](https://github.com/alex-mextner/passwords-app/issues/144)). Any anisette server that
serves Windows or macOS data is accepted; point `PASSWORDS_APP_ANISETTE_URL` at it (for the
sync service: a `systemctl --user edit passwords-appd` drop-in with
`Environment=PASSWORDS_APP_ANISETTE_URL=...`). `passwords-app doctor` asks Apple with an
account-less probe and says when the configured server's data is refused.

License: MIT, except `docker/anisette` (AGPL-3.0-only). See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

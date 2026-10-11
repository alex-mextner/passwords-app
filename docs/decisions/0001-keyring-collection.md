<!--
SPDX-FileCopyrightText: 2026 Alex Mextner
SPDX-License-Identifier: MIT
-->

# ADR 0001: Synced passwords live in a dedicated, password-protected "iCloud Passwords" collection

Date: 2026-10-10 · Status: accepted · Scope: `src/passwords_app/keyring/`

## Context

The iCloud passwords must be mirrored into GNOME Keyring (Secret Service) so Seahorse
("Passwords and Keys") and libsecret apps see them. Two layouts were possible:

- **(a)** a dedicated collection "iCloud Passwords";
- **(b)** the default (login) collection, our items told apart by schema
  `io.github.alex_mextner.Passwords` and a label/attribute marker.

Hard constraints:

1. never create an unencrypted keyring;
2. never prompt from the background service;
3. items visible and editable in Seahorse;
4. items created in Seahorse must be recognizable as meant for sync;
5. unrelated secrets (Chrome Safe Storage, GOA tokens, Wi-Fi) are never read as credentials.

## Evidence

All observations were made against gnome-keyring 50.0 (Ubuntu 26.04) on a private session
bus, and most are now integration tests in `tests/integration/keyring/test_collection.py`.

| Question | Finding |
|---|---|
| Standard `Service.CreateCollection` | Always returns a prompt object; the user must type a new keyring password in a dialog (`test_standard_create_collection_would_prompt`). Unusable from a background service. |
| `org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface.CreateWithMasterPassword` | Present in 50.0. Creates the collection with a password we pass in (DH-encrypted on the bus), no prompt. The `.keyring` file is the encrypted binary format (`GnomeKeyring\n\r\0\n` header); no password, username, note, or TOTP seed appears in it (`test_keyring_file_is_encrypted`). An empty password would create a plaintext keyring — we never pass one. |
| `UnlockWithMasterPassword` | Unlocks without a prompt given the right password; a wrong one fails with `org.gnome.keyring.Error.Denied` and the collection stays locked. |
| Auto-unlock at login | gnome-keyring unlocks only the login keyring at login (PAM). For any other keyring, its PKCS#11 wrap layer (`pkcs11/wrap-layer/gkm-wrap-prompt.c`, `auto_unlock_lookup_keyring`) first looks in the login keyring for an item with attribute `keyring=LOCAL:/keyrings/<id>.keyring` and, if found, unlocks with that password **without showing a dialog** — the same item Seahorse writes when you tick "Automatically unlock this keyring whenever I'm logged in". Storing our random password there makes a Seahorse/libsecret `Unlock` + `Prompt` complete with `dismissed=false` on a bus that has no prompter at all (`test_other_apps_unlock_it_without_a_password_dialog`); without that item the same call is dismissed (`test_without_the_stored_password_other_apps_would_need_a_dialog`). The `<id>` is the collection's object-path id with gnome-keyring's `_XX` escaping undone (`iCloud_5fPasswords` → `iCloud_Passwords`). |
| Restart / reboot | After a daemon restart the collection comes back locked with only hashed attributes visible; our store unlocks it silently from the login keyring and every item is intact (`test_items_survive_a_restart_and_unlock_silently`). |
| Seahorse editing | Items in any unlocked collection are listed and editable in Seahorse; Seahorse's "New password" creates an `org.gnome.keyring.Note` item with just a label and secret in the collection the user selects. |
| Default-collection option (b) | A Seahorse-created note in the login keyring is indistinguishable from any other note (no schema of ours, arbitrary label), so constraint 4 would need users to type a magic marker into labels; and every fetch would have to enumerate the whole login keyring (browser keys, GOA tokens, Wi-Fi PSKs), relying on filters to satisfy constraint 5. |

## Decision

Use **(a)**: a dedicated collection, labelled "iCloud Passwords", created through
`CreateWithMasterPassword` with a random 32-byte (URL-safe base64) password.

- The password is stored in the **login** keyring as gnome-keyring's own auto-unlock item
  (label `Unlock password for: iCloud Passwords`, attributes `keyring=LOCAL:/keyrings/<id>.keyring`,
  `application=passwords-app`, `type=keyring-password`, `pa-keyring=<label>`).
- The daemon unlocks the collection only with `UnlockWithMasterPassword` using that stored
  password. It never calls `Prompt`. If the login keyring is locked, or the password is
  missing or wrong, the store raises `LocalUnavailable` and the sync cycle is skipped
  (spec §5 guard). It never deletes anything because of it.
- Every item in the collection is meant for sync, which covers constraint 4. Items without a
  `pa-id` (typically created in Seahorse) are *adopted*: their label is parsed (`keyring/labels.py`),
  then an id and our attributes are written back. Labels it cannot parse are reported as
  `rejected`, and the item is left as it is.
- Other collections are never enumerated, which covers constraint 5. The app's own keys (the
  `app_secret` state.db key) stay in the default collection under
  `application=passwords-app`, `type=<name>`, schema `io.github.alex_mextner.Passwords.AppKey`.

### Crash safety of creation

1. Delete leftover password items for this label whose collection no longer exists. Items
   for a collection the user renamed are kept, because they are still its only password.
2. Create the password item without a location. It is created with `replace=false`
   because gnome-keyring's `replace` also overwrites items whose attributes are a
   *superset* of the new item's.
3. Create the collection.
4. Point the item at the new location.

A crash between steps leaves an orphan password item, never a collection with a lost
password. A later unlock also tries items that have no location yet and repairs the
attribute (`test_interrupted_creation_is_repaired_on_next_unlock`).

## Consequences

- We rely on an interface gnome-keyring calls "internal, unsupported". It has been stable
  since 2011 and its own test suite uses it. If it disappears (or the Secret Service is
  provided by a different daemon, e.g. oo7 or KeePassXC), `open()` fails with
  `LocalUnavailable` naming the failed call, and sync pauses with nothing deleted. Moving
  to such a daemon needs a new ADR.
- The collection is located by label. If the user renames it in Seahorse, the next
  `open()` creates a new empty "iCloud Passwords". The engine then sees every item as
  deleted locally. The spec §5 mass-delete guard pauses only above `max(5, 10%)`
  deletions, so with 1–5 synced items those deletions would reach iCloud unpaused. This
  is a known limitation; closing it needs an engine-side guard for a replaced collection
  (out of scope for this adapter). The renamed collection keeps its working unlock
  password (`test_renamed_collection_keeps_its_password`).
- If the user deletes the whole collection while the daemon runs, `fetch()` raises
  `LocalUnavailable` and the collection is not recreated mid-run. Only the next `open()`
  creates it again, empty, and the same mass-delete guard (and the same 1–5-item
  limitation) applies.
- gnome-keyring keeps attribute values in the clear in memory while a collection is
  unlocked, and only hashes them on disk and while locked. The spec puts `notes` and
  `otpauth` in attributes, so any same-user process on the session bus can read them while
  the collection is unlocked. That is no weaker than the secrets themselves: gnome-keyring
  has no per-app access control, and any same-user process can call `GetSecrets` too.
- `SetSecret` (how Seahorse saves an edited password) emits no `ItemChanged` signal in
  gnome-keyring 50 (`daemon/dbus/gkd-secret-objects.c`, `item_method_set_secret`). So
  `changes()` also polls the collection's keyring file every 2 s, which matches the spec's
  "2 s after any local change".

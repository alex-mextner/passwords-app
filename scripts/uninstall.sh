#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
#
# Remove what install.sh installed. Your data stays unless --purge is given: state.db (the
# sync state and Recently Deleted) in $XDG_DATA_HOME/passwords-app, the iCloud session in
# $XDG_CONFIG_HOME/passwords-app, and the anisette volume. The passwords themselves live in
# the "iCloud Passwords" keyring collection and are never touched by this script.
#
# Overridable: SYSTEMCTL, DOCKER, GLIB_COMPILE_SCHEMAS, UPDATE_DESKTOP_DATABASE,
# GTK_UPDATE_ICON_CACHE (see install.sh). The polkit action, if the user installed it as
# root, is not removed here: the command to do it is printed.
set -euo pipefail

data_home=${XDG_DATA_HOME:-$HOME/.local/share}
config_home=${XDG_CONFIG_HOME:-$HOME/.config}
app_data=$data_home/passwords-app
app_config=$config_home/passwords-app
manifest=$app_data/installed-files

SYSTEMCTL=${SYSTEMCTL:-systemctl}
DOCKER=${DOCKER:-docker}
GLIB_COMPILE_SCHEMAS=${GLIB_COMPILE_SCHEMAS:-glib-compile-schemas}
UPDATE_DESKTOP_DATABASE=${UPDATE_DESKTOP_DATABASE:-update-desktop-database}
GTK_UPDATE_ICON_CACHE=${GTK_UPDATE_ICON_CACHE:-gtk-update-icon-cache}
ANISETTE_VOLUME=passwords-app-anisette
UNIT=passwords-appd.service

say() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  say "usage: uninstall.sh [--purge]"
  say "  --purge  also delete local data: sync state, Recently Deleted, the iCloud session"
}

purge=0
for arg in "$@"; do
  case $arg in
    --purge) purge=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n ${HOME:-} ]] || {
  warn "HOME is not set"
  exit 1
}

if have "$SYSTEMCTL"; then
  "$SYSTEMCTL" --user disable --now "$UNIT" >/dev/null 2>&1 || true
fi

if [[ -f $manifest ]]; then
  while IFS= read -r line; do
    case $line in
      "") ;;
      docker-container:*)
        if have "$DOCKER"; then
          "$DOCKER" rm -f "${line#docker-container:}" >/dev/null 2>&1 || true
          if ((purge)); then
            "$DOCKER" volume rm "$ANISETTE_VOLUME" >/dev/null 2>&1 || true
          fi
        fi
        ;;
      polkit-action:*)
        action=${line#polkit-action:}
        if [[ -e $action ]]; then
          say "To remove the app's polkit action too, run: pkexec rm -f $(printf '%q' "$action")"
        fi
        ;;
      *) rm -f -- "$line" ;;
    esac
  done <"$manifest"
fi

rm -rf -- "$app_data/venv"
rm -f -- "$manifest" "$app_data/source-dir" "$app_data/uninstall.sh"

if [[ -d $data_home/glib-2.0/schemas ]] && have "$GLIB_COMPILE_SCHEMAS"; then
  "$GLIB_COMPILE_SCHEMAS" "$data_home/glib-2.0/schemas" >/dev/null 2>&1 || true
fi
if [[ -d $data_home/applications ]] && have "$UPDATE_DESKTOP_DATABASE"; then
  "$UPDATE_DESKTOP_DATABASE" -q "$data_home/applications" >/dev/null 2>&1 || true
fi
if [[ -d $data_home/icons/hicolor ]] && have "$GTK_UPDATE_ICON_CACHE"; then
  "$GTK_UPDATE_ICON_CACHE" -q -t -f "$data_home/icons/hicolor" >/dev/null 2>&1 || true
fi
if have "$SYSTEMCTL"; then
  "$SYSTEMCTL" --user daemon-reload >/dev/null 2>&1 || true
fi

if ((purge)); then
  rm -rf -- "$app_data" "$app_config"
  say "Removed passwords-app and its local data."
  say "Your passwords are still in the \"iCloud Passwords\" keyring collection (and in iCloud)."
else
  rmdir -- "$app_data" 2>/dev/null || true
  say "Removed passwords-app. Kept your data:"
  [[ -d $app_data ]] && say "  $app_data (sync state, Recently Deleted)"
  [[ -d $app_config ]] && say "  $app_config (iCloud session)"
  say "Run with --purge to delete it too."
fi

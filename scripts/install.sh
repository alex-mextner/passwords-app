#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
#
# Install or update passwords-app for the current user (no root needed). Idempotent: every
# run converges on the same layout, and files a previous version installed but this one no
# longer ships are removed. Everything goes under $HOME / the XDG directories; the list of
# installed paths is kept in $XDG_DATA_HOME/passwords-app/installed-files for uninstall.sh.
#
# External commands can be overridden (tests, unusual systems): PYTHON, UV, SYSTEMCTL,
# DOCKER, GLIB_COMPILE_SCHEMAS, MSGFMT, UPDATE_DESKTOP_DATABASE, GTK_UPDATE_ICON_CACHE;
# ANISETTE_PORT; POLKIT_ACTIONS_DIR; PASSWORDS_APP_SKIP_ANISETTE=1 skips the anisette
# container. Nothing here runs as root: what needs root is printed for the user to run.
set -euo pipefail

src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
data_home=${XDG_DATA_HOME:-$HOME/.local/share}
config_home=${XDG_CONFIG_HOME:-$HOME/.config}
app_data=$data_home/passwords-app
app_config=$config_home/passwords-app
venv=$app_data/venv
bindir=$venv/bin
manifest=$app_data/installed-files
new_manifest=$manifest.new

PYTHON=${PYTHON:-/usr/bin/python3}
UV=${UV:-uv}
SYSTEMCTL=${SYSTEMCTL:-systemctl}
DOCKER=${DOCKER:-docker}
GLIB_COMPILE_SCHEMAS=${GLIB_COMPILE_SCHEMAS:-glib-compile-schemas}
MSGFMT=${MSGFMT:-msgfmt}
UPDATE_DESKTOP_DATABASE=${UPDATE_DESKTOP_DATABASE:-update-desktop-database}
GTK_UPDATE_ICON_CACHE=${GTK_UPDATE_ICON_CACHE:-gtk-update-icon-cache}
POLKIT_ACTIONS_DIR=${POLKIT_ACTIONS_DIR:-/usr/share/polkit-1/actions}
# Apple refuses the anisette data of the Android-based dadoum/anisette-v3-server since 2026-10-12
# (ec=-80045, passwords-app#144), so the container runs Apple's Windows ADI library under Wine, built
# from docker/anisette. It has its own name, volume and port (6970): a leftover Android container on
# 6969 is never reused and stays untouched.
ANISETTE_PORT=${ANISETTE_PORT:-6970}
ANISETTE_IMAGE=passwords-app-anisette-windows:local
ANISETTE_CONTAINER=passwords-app-anisette-windows
ANISETTE_VOLUME=passwords-app-anisette-windows
ANISETTE_LABEL=io.github.alex_mextner.passwords.anisette-source
UNIT=passwords-appd.service

say() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

have() { command -v "$1" >/dev/null 2>&1; }

record() {
  grep -qxF -- "$1" "$new_manifest" 2>/dev/null || printf '%s\n' "$1" >>"$new_manifest"
}

# Text files get the install paths substituted; written atomically so a running daemon or
# D-Bus never reads a half-written file.
place_text() {
  local from=$1 to=$2 mode=${3:-0644} tmp
  mkdir -p -- "$(dirname -- "$to")"
  tmp=$(mktemp "$to.XXXXXX")
  sed -e "s|@BINDIR@|$bindir|g" -e "s|@DATADIR@|$app_data|g" -e "s|@CONFIGDIR@|$app_config|g" \
    -e "s|@HOST_PATH@|$bindir/passwords-app-native-host|g" -- "$from" >"$tmp"
  chmod "$mode" -- "$tmp"
  mv -f -- "$tmp" "$to"
  record "$to"
}

place_copy() {
  local from=$1 to=$2
  mkdir -p -- "$(dirname -- "$to")"
  install -m 0644 -- "$from" "$to"
  record "$to"
}

# place_tree SRC_DIR DEST_DIR GLOB: install matching files below SRC_DIR, keeping subpaths.
place_tree() {
  local from=$1 to=$2 pattern=$3 file rel
  [[ -d $from ]] || return 0
  while IFS= read -r -d '' file; do
    rel=${file#"$from"/}
    case $file in
      *.desktop | *.ini | *.xml | *.json | *.service) place_text "$file" "$to/$rel" ;;
      *) place_copy "$file" "$to/$rel" ;;
    esac
  done < <(find "$from" -type f -name "$pattern" -print0 | sort -z)
}

anisette_answers() {
  (exec 3<>"/dev/tcp/127.0.0.1/$ANISETTE_PORT") 2>/dev/null
}

# A fingerprint of everything the image is built from: a changed helper or Dockerfile in the
# checkout rebuilds the image and recreates the container (the volume with the identity stays).
anisette_source_hash() {
  (cd -- "$src/docker/anisette" 2>/dev/null &&
    find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)
}

docker_label() {
  "$DOCKER" "$1" inspect --format "{{ index .Config.Labels \"$ANISETTE_LABEL\" }}" "$2" 2>/dev/null || true
}

create_anisette_container() {
  # Published on loopback only: the helper must never be reachable from the network. The named
  # volume holds the Wine prefix, i.e. the device identity Apple trusts: keep it across container
  # upgrades.
  "$DOCKER" run -d --name "$ANISETTE_CONTAINER" --restart unless-stopped --init \
    --label "$ANISETTE_LABEL=$1" \
    --memory 512m --memory-swap 768m --cap-drop ALL --security-opt no-new-privileges \
    -p "127.0.0.1:$ANISETTE_PORT:6969" \
    -v "$ANISETTE_VOLUME:/state" \
    "$ANISETTE_IMAGE" >/dev/null || warn "could not create the $ANISETTE_CONTAINER container"
}

build_anisette_image() {
  say "Building the anisette image: it downloads Apple's iCloud for Windows installers (about 320 MB) and stays on this machine."
  "$DOCKER" build --label "$ANISETTE_LABEL=$1" -t "$ANISETTE_IMAGE" "$src/docker/anisette" >/dev/null
}

setup_anisette() {
  local want exists=0
  if [[ ${PASSWORDS_APP_SKIP_ANISETTE:-0} == 1 ]]; then
    return 0
  fi
  if ! have "$DOCKER"; then
    if anisette_answers; then
      say "Apple sign-in helper (anisette) already answers on 127.0.0.1:$ANISETTE_PORT."
      return 0
    fi
    warn "docker is not installed; Apple sign-in needs an anisette server on 127.0.0.1:$ANISETTE_PORT."
    warn "Install docker and re-run this script, or run one that serves Windows or macOS ADI data yourself"
    warn "and point PASSWORDS_APP_ANISETTE_URL at it (the Android-based dadoum/anisette-v3-server is refused by Apple)."
    return 0
  fi
  if "$DOCKER" container inspect "$ANISETTE_CONTAINER" >/dev/null 2>&1; then
    exists=1
  elif anisette_answers; then
    say "Apple sign-in helper (anisette) already answers on 127.0.0.1:$ANISETTE_PORT."
    return 0
  fi
  want=$(anisette_source_hash) || want=
  if [[ -z $want ]]; then
    warn "$src/docker/anisette is missing; cannot build the anisette image."
    return 0
  fi
  if [[ $(docker_label image "$ANISETTE_IMAGE") != "$want" ]]; then
    build_anisette_image "$want" || warn "could not build $ANISETTE_IMAGE from $src/docker/anisette"
  fi
  if ((exists)); then
    if [[ $(docker_label container "$ANISETTE_CONTAINER") != "$want" ]] &&
      [[ $(docker_label image "$ANISETTE_IMAGE") == "$want" ]]; then
      say "Replacing $ANISETTE_CONTAINER with one from the updated image (its volume is kept)."
      "$DOCKER" rm -f "$ANISETTE_CONTAINER" >/dev/null
      create_anisette_container "$want"
    else
      "$DOCKER" start "$ANISETTE_CONTAINER" >/dev/null || warn "could not start $ANISETTE_CONTAINER"
    fi
  elif [[ $(docker_label image "$ANISETTE_IMAGE") == "$want" ]]; then
    create_anisette_container "$want"
  else
    return 0
  fi
  record "docker-container:$ANISETTE_CONTAINER"
}

# Compiled catalogs go where the app looks first: share/locale under its own prefix (the
# venv). A catalog that does not compile is left out; the app then shows English.
install_translations() {
  local po lang to tmp
  compgen -G "$src/po/*.po" >/dev/null || return 0
  if ! have "$MSGFMT"; then
    warn "msgfmt not found (package gettext); the app stays in English until you install it and re-run."
    return 0
  fi
  for po in "$src"/po/*.po; do
    lang=$(basename -- "$po" .po)
    to=$venv/share/locale/$lang/LC_MESSAGES/passwords-app.mo
    mkdir -p -- "$(dirname -- "$to")"
    tmp=$(mktemp "$to.XXXXXX")
    if "$MSGFMT" --check -o "$tmp" -- "$po"; then
      chmod 0644 -- "$tmp"
      mv -f -- "$tmp" "$to"
      record "$to"
    else
      rm -f -- "$tmp"
      warn "the $lang translation does not compile ($po); left out"
    fi
  done
}

# Polkit reads actions only from a root-owned directory, so the command is printed for the
# user instead of escalating here.
polkit_commands=()
setup_polkit() {
  local policy to
  for policy in "$src"/data/polkit/*.policy; do
    [[ -f $policy ]] || continue
    to=$POLKIT_ACTIONS_DIR/${policy##*/}
    record "polkit-action:$to"
    if ! cmp -s -- "$policy" "$to"; then
      polkit_commands+=("pkexec install -m 0644 $(printf '%q' "$policy") $(printf '%q' "$to")")
    fi
  done
}

remove_stale() {
  local line action
  [[ -f $manifest ]] || return 0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    grep -qxF -- "$line" "$new_manifest" && continue
    case $line in
      docker-container:*) ;;
      polkit-action:*)
        action=${line#polkit-action:}
        if [[ -e $action ]]; then
          say "This version no longer uses $action; remove it with: pkexec rm -f $(printf '%q' "$action")"
        fi
        ;;
      *) rm -f -- "$line" ;;
    esac
  done <"$manifest"
}

main() {
  [[ -n ${HOME:-} ]] || die "HOME is not set"
  have "$PYTHON" || die "$PYTHON not found; install python3 (>= 3.13)"
  have "$UV" || die "uv not found; install it: https://docs.astral.sh/uv/getting-started/installation/"
  [[ -f $src/pyproject.toml ]] || die "$src is not a passwords-app checkout"

  # Only the app's own directories are private; their parents are ordinary XDG dirs.
  mkdir -p -- "$data_home" "$config_home"
  mkdir -p -- "$app_data" "$app_config"
  chmod 0700 -- "$app_data" "$app_config"
  : >"$new_manifest"

  if [[ ! -x $venv/bin/python ]]; then
    say "Creating $venv"
    "$UV" venv -q --python "$PYTHON" --system-site-packages "$venv"
  fi
  say "Installing passwords-app into $venv"
  "$UV" pip install -q --python "$venv/bin/python" --reinstall-package passwords-app "$src"

  install -m 0755 -- "$src/scripts/uninstall.sh" "$app_data/uninstall.sh"
  printf '%s\n' "$src" >"$app_data/source-dir"

  mkdir -p -- "$HOME/.local/bin"
  ln -sfn -- "$bindir/passwords-app" "$HOME/.local/bin/passwords-app"
  record "$HOME/.local/bin/passwords-app"

  place_text "$src/data/systemd/$UNIT" "$config_home/systemd/user/$UNIT"
  place_text "$src/data/dbus/io.github.alex_mextner.Passwords.service" \
    "$data_home/dbus-1/services/io.github.alex_mextner.Passwords.service"
  place_copy "$src/data/dbus/io.github.alex_mextner.Passwords1.xml" \
    "$data_home/dbus-1/interfaces/io.github.alex_mextner.Passwords1.xml"

  # The GTK app's files, when this checkout has them.
  place_tree "$src/data/applications" "$data_home/applications" '*.desktop'
  place_tree "$src/data/metainfo" "$data_home/metainfo" '*.xml'
  place_tree "$src/data/icons" "$data_home/icons" '*'
  place_tree "$src/data/search-providers" "$data_home/gnome-shell/search-providers" '*.ini'
  # GNOME Shell starts the search provider through D-Bus activation.
  place_tree "$src/data/search-providers" "$data_home/dbus-1/services" '*.service'
  place_tree "$src/data/glib-2.0/schemas" "$data_home/glib-2.0/schemas" '*.gschema.xml'
  install_translations
  setup_polkit

  # Browser native-messaging manifests (templates from extension/PROTOCOL.md), when this
  # checkout has them. Snap Firefox reads ~/.mozilla through the WebExtensions portal;
  # chrome.json.in serves Chromium too.
  local templates=$src/data/native-messaging host=io.github.alex_mextner.passwords.json browser
  if [[ -f $templates/firefox.json.in ]]; then
    place_text "$templates/firefox.json.in" "$HOME/.mozilla/native-messaging-hosts/$host"
  fi
  for browser in google-chrome chromium; do
    if [[ -f $templates/chrome.json.in && -d $config_home/$browser ]]; then
      place_text "$templates/chrome.json.in" "$config_home/$browser/NativeMessagingHosts/$host"
    fi
  done

  setup_anisette
  remove_stale
  mv -f -- "$new_manifest" "$manifest"

  if [[ -d $data_home/glib-2.0/schemas ]] && have "$GLIB_COMPILE_SCHEMAS"; then
    "$GLIB_COMPILE_SCHEMAS" "$data_home/glib-2.0/schemas" || warn "glib-compile-schemas failed"
  fi
  if [[ -d $data_home/applications ]] && have "$UPDATE_DESKTOP_DATABASE"; then
    "$UPDATE_DESKTOP_DATABASE" -q "$data_home/applications" || warn "update-desktop-database failed"
  fi
  if [[ -d $data_home/icons/hicolor ]] && have "$GTK_UPDATE_ICON_CACHE"; then
    "$GTK_UPDATE_ICON_CACHE" -q -t -f "$data_home/icons/hicolor" || warn "gtk-update-icon-cache failed"
  fi

  if "$SYSTEMCTL" --user daemon-reload; then
    "$SYSTEMCTL" --user enable "$UNIT" >/dev/null
    "$SYSTEMCTL" --user restart "$UNIT" || warn "$UNIT did not start; see: journalctl --user -u $UNIT"
  else
    warn "no systemd user manager; the service starts on first use through D-Bus activation"
  fi

  say "Done. Run \`passwords-app signin\` to connect your iCloud Keychain."
  if ((${#polkit_commands[@]})); then
    say "To unlock the app with your login password, install its polkit action once (needs root):"
    printf '  %s\n' "${polkit_commands[@]}"
  fi
  case :$PATH: in
    *:"$HOME/.local/bin":*) ;;
    *) say "Note: add $HOME/.local/bin to PATH to run passwords-app from a terminal." ;;
  esac
}

main "$@"

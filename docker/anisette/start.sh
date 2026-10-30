#!/bin/sh
# Modified by Alex Mextner on 2026-10-30: added a shellcheck directive before the registry call.
# Based on hinatamaxxx/AltServer-Linux anisette/icloud-wine (AGPL-3.0, commit 6272cce175413ee64d0baead62683b2b9ba0f83c).
set -eu
umask 077
mkdir -p /state/prefix
Xvfb :99 -screen 0 800x600x16 -nolisten tcp >/dev/null 2>&1 &
wineboot --init >/tmp/wineboot.log 2>&1
mkdir -p '/state/prefix/drive_c/ProgramData/Apple Computer/iTunes/adi'
# shellcheck disable=SC1003 # a Windows path ending in a backslash, not an escaped quote
# The Apple runtime locates CoreADI through this registry value; DLL placement alone is insufficient.
wine reg add 'HKLM\Software\Apple Inc.\Apple Application Support' /v InstallDir /t REG_SZ /d 'Z:\apple\Apple Application Support\' /f >/tmp/apple-support-register.log 2>&1
wine reg add 'HKLM\Software\Apple Inc.\Apple Application Support' /v Version /t REG_SZ /d '8.7' /f >>/tmp/apple-support-register.log 2>&1
exec python3 /app/server.py

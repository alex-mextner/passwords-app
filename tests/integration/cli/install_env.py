# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""A throwaway HOME, a copy of the checkout, and logging stand-ins for uv/systemctl/docker.

The installer scripts run for real (bash, sed, install, ln) against the temp HOME; only the
commands that would reach outside it are replaced. Each stand-in appends its argv to
`calls.log` as one tab-separated line, so tests assert what would have been executed.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]

_FAKE = {
    "uv": r"""#!/bin/bash
printf 'uv\t%s\n' "$*" >>"$CALLS"
if [[ $1 == venv ]]; then
  dir=${@: -1}
  mkdir -p "$dir/bin"
  ln -sf /usr/bin/python3 "$dir/bin/python"
elif [[ $1 == pip ]]; then
  py=""
  while (($#)); do [[ $1 == --python ]] && py=$2; shift; done
  bin=$(dirname "$py")
  for exe in passwords-app passwords-appd passwords-app-native-host; do
    printf '#!/bin/sh\necho %s "$@"\n' "$exe" >"$bin/$exe"
    chmod +x "$bin/$exe"
  done
fi
""",
    "systemctl": r"""#!/bin/bash
printf 'systemctl\t%s\n' "$*" >>"$CALLS"
exit "${FAKE_SYSTEMCTL_RC:-0}"
""",
    "docker": r"""#!/bin/bash
printf 'docker\t%s\n' "$*" >>"$CALLS"
state=$FAKE_DOCKER_STATE
case "$1 $2" in
  "container inspect") [[ -f $state/$3 ]] ;;
  "run -d")
    name=""
    while (($#)); do [[ $1 == --name ]] && name=$2; shift; done
    touch "$state/$name" ;;
  "rm -f") rm -f "$state/$3" ;;
  *) exit 0 ;;
esac
""",
    "glib-compile-schemas": r"""#!/bin/bash
printf 'glib-compile-schemas\t%s\n' "$*" >>"$CALLS"
""",
    # Writes a stand-in catalog naming its source; a .po containing BROKEN fails to compile.
    "msgfmt": r"""#!/bin/bash
printf 'msgfmt\t%s\n' "$*" >>"$CALLS"
out="" src=""
while (($#)); do
  case $1 in
    -o) out=$2; shift ;;
    -*) ;;
    *) src=$1 ;;
  esac
  shift
done
! grep -q BROKEN "$src" || exit 1
printf 'catalog from %s\n' "${src##*/}" >"$out"
""",
    "update-desktop-database": r"""#!/bin/bash
printf 'update-desktop-database\t%s\n' "$*" >>"$CALLS"
""",
    "gtk-update-icon-cache": r"""#!/bin/bash
printf 'gtk-update-icon-cache\t%s\n' "$*" >>"$CALLS"
""",
    "pkexec": r"""#!/bin/bash
printf 'pkexec\t%s\n' "$*" >>"$CALLS"
exit 1
""",
}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@dataclass
class InstallEnv:
    root: Path
    home: Path
    checkout: Path
    fakebin: Path
    calls_log: Path
    docker_state: Path
    anisette_port: int
    overrides: dict[str, str]

    @property
    def data(self) -> Path:
        return self.home / ".local" / "share"

    @property
    def config(self) -> Path:
        return self.home / ".config"

    @property
    def app_data(self) -> Path:
        return self.data / "passwords-app"

    @property
    def app_config(self) -> Path:
        return self.config / "passwords-app"

    @property
    def venv_bin(self) -> Path:
        return self.app_data / "venv" / "bin"

    @property
    def polkit_actions(self) -> Path:
        """Stands in for /usr/share/polkit-1/actions."""
        return self.root / "polkit-actions"

    def env(self) -> dict[str, str]:
        env = {
            "HOME": str(self.home),
            "PATH": f"{self.fakebin}:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "CALLS": str(self.calls_log),
            "FAKE_DOCKER_STATE": str(self.docker_state),
            "ANISETTE_PORT": str(self.anisette_port),
        }
        env.update(self.overrides)
        return env

    def run(
        self, script: str, *args: str, script_path: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        path = script_path or self.checkout / "scripts" / script
        return subprocess.run(  # noqa: S603 - our own script, temp HOME
            ["/bin/bash", str(path), *args],
            env=self.env(),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def calls(self, tool: str | None = None) -> list[str]:
        if not self.calls_log.exists():
            return []
        lines = self.calls_log.read_text().splitlines()
        return [
            line.split("\t", 1)[1] for line in lines if tool is None or line.startswith(f"{tool}\t")
        ]

    def clear_calls(self) -> None:
        self.calls_log.unlink(missing_ok=True)

    def tree(self) -> dict[str, str]:
        """Every file/link under HOME -> its content (or link target)."""
        result: dict[str, str] = {}
        for path in sorted(self.home.rglob("*")):
            rel = str(path.relative_to(self.home))
            if path.is_symlink():
                result[rel] = f"-> {path.readlink()}"
            elif path.is_file():
                result[rel] = path.read_bytes().hex()
        return result


def make_env(root: Path) -> InstallEnv:
    home = root / "home"
    home.mkdir()
    checkout = root / "checkout"
    checkout.mkdir()
    for name in ("scripts", "data"):
        shutil.copytree(REPO / name, checkout / name)
    shutil.copy(REPO / "pyproject.toml", checkout / "pyproject.toml")
    fakebin = root / "fakebin"
    fakebin.mkdir()
    for name, body in _FAKE.items():
        exe = fakebin / name
        exe.write_text(body)
        exe.chmod(0o755)
    state = root / "docker-state"
    state.mkdir()
    # Never the real /usr/share/polkit-1/actions: what is installed there must not matter.
    polkit = root / "polkit-actions"
    polkit.mkdir()
    return InstallEnv(
        root=root,
        home=home,
        checkout=checkout,
        fakebin=fakebin,
        calls_log=root / "calls.log",
        docker_state=state,
        anisette_port=free_port(),
        overrides={"POLKIT_ACTIONS_DIR": str(polkit)},
    )

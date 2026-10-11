# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""The daemon's code runs under the unit's MemoryDenyWriteExecute=yes.

systemd implements MemoryDenyWriteExecute with a seccomp filter; Linux >= 6.3 offers the
same rule as prctl(PR_SET_MDWE). A child process turns it on, proves it is active (a
writable+executable mapping is refused), then imports every daemon module and exercises the
native code it relies on (AES-GCM, X25519/NaCl boxes, SQLite, TLS context). If any of those
needed W+X memory, the unit would crash at startup on the user's machine.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.timeout(60)]

PROBE = textwrap.dedent(
    """
    import ctypes, mmap, sys
    libc = ctypes.CDLL(None, use_errno=True)
    PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN = 65, 1
    if libc.prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0) != 0:
        print("MDWE unsupported", ctypes.get_errno())
        sys.exit(3)
    try:
        mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    except PermissionError:
        pass
    else:
        sys.exit("MDWE is not in effect")

    import sqlite3, ssl, tempfile, pathlib
    import nacl.public
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from passwords_app.daemon import controller, main, network, notify, scheduler, service
    from passwords_app.cli import main as cli_main, doctor
    from passwords_app.keyring import dh, secret_service
    from passwords_app.store.state import StateStore

    key = AESGCM.generate_key(bit_length=256)
    with tempfile.TemporaryDirectory() as tmp:
        store = StateStore(pathlib.Path(tmp) / "state.db", key)
        store.set("k", "v")
        assert store.get("k") == "v"
        store.close()
    a, b = nacl.public.PrivateKey.generate(), nacl.public.PrivateKey.generate()
    box = nacl.public.Box(a, b.public_key)
    assert nacl.public.Box(b, a.public_key).decrypt(box.encrypt(b"x")) == b"x"
    ssl.create_default_context()
    print("OK")
    """
)


def test_daemon_code_runs_with_write_xor_execute_enforced() -> None:
    result = subprocess.run(  # noqa: S603 - fixed interpreter and script
        [sys.executable, "-c", PROBE], capture_output=True, text=True, timeout=60, check=False
    )
    if result.returncode == 3:
        pytest.skip(f"kernel lacks PR_SET_MDWE: {result.stdout}")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("OK")

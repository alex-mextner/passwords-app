# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Static identity strings used to impersonate a Mac to Apple's GrandSlam service.

These mirror what AltServer / pypush send. Apple tracks some of these, so they are
kept stable and Mac-like. The volatile per-request machine data (X-Apple-I-MD*) comes
from the anisette server, not from here.
"""

# Sent as the GsService2 User-Agent.
GSA_USER_AGENT = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"

# The platform every client-info string claims. Since 2026-10-12 Apple answers GsService2 `init`
# with ec=-80045 unless the claimed client matches the platform that generated the anisette data
# (third-party anisette servers use Windows ADI): see Dadoum/anisette-v3-server#61. One constant,
# so the GSA, loginDelegates and escrow identities cannot drift apart.
WINDOWS_PLATFORM = "<PC> <Windows;6.2(0,0);9200>"

# AuthKit device description used by GrandSlam and its 2FA endpoints.
GSA_CLIENT_INFO = f"{WINDOWS_PLATFORM} <com.apple.AuthKit/1 (com.apple.akd/1.0)>"

# Default anisette server (SideStore ecosystem). Override with PASSWORDS_APP_ANISETTE_URL.
DEFAULT_ANISETTE_URL = "http://localhost:6969"

GSA_BASE_URL = "https://gsa.apple.com"
GSA_SERVICE_PATH = "/grandslam/GsService2"
GSA_ENDPOINT = GSA_BASE_URL + GSA_SERVICE_PATH

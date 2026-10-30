# Third-party notices

## iCloud-Keychain-for-Linux (MIT)

`src/passwords_app/icloud/` started as a vendored copy of
<https://github.com/Sank6/iCloud-Keychain-for-Linux> at commit
`d098a7af024345f59ede47f2298e3113fd2b821b` and has since been modified (write path, TLS
verification, persistence, packaging). The original notice:

```
MIT License

Copyright (c) 2026 Sankarsh Makam

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Windows-ADI anisette helper (AGPL-3.0-only)

Everything in `docker/anisette/` (`Dockerfile`, `native-wine-anisette.cpp`, `server.py`, `start.sh`) is
derived from <https://github.com/hinatamaxxx/AltServer-Linux> (`anisette/icloud-wine`, commit
`6272cce175413ee64d0baead62683b2b9ba0f83c`, AGPL-3.0, itself built on AltServer for Windows by
Riley Testut) and is licensed AGPL-3.0-only (`LICENSES/AGPL-3.0-only.txt`). It runs as a separate program
inside a Docker image and is never linked into the app. Apple's iCloud for Windows libraries are downloaded
from Apple's servers when the image is built on your machine and are not part of this repository.

Modified by Alex Mextner on 2026-10-30 (each file says so in its header):

- `Dockerfile`: added the `apple` stage that downloads Apple's installers and checks them against pinned
  SHA-256 sums, instead of mounting an exported runtime.
- `native-wine-anisette.cpp`: `main` split into `loadRuntime`, `ensureProvisioned` and `anisetteJson`.
- `server.py`: a five-second answer cache, so one Wine run serves a burst of callers.
- `start.sh`: a shellcheck directive.

## Apple root certificates

`src/passwords_app/icloud/certs/apple-roots.pem` contains Apple's public root CA
certificates as published at <https://www.apple.com/certificateauthority/>. They are used only
to verify TLS connections to Apple's servers.

## Protocol references (no code copied)

- OpenBubbles/rustpush (SSPL-1.0) and Apple's open-source Security framework (APSL-2.0) were
  read as protocol documentation. No source code from either is included in this project.

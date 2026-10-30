# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
#
# Local anisette server for Apple sign-in: Apple's own Windows iCloud ADI library run under Wine.
#
# Why: since 2026-10-12 Apple's GrandSlam refuses the anisette data of the Android-ADI based
# dadoum/anisette-v3-server with ec=-80045 (Dadoum/anisette-v3-server#61) but accepts data made by
# Windows or macOS ADI (passwords-app#144). The Windows library cannot be redistributed, so this
# build downloads Apple's iCloud for Windows installers from Apple's CDN itself, checks them against
# the SHA-256 sums below and keeps the result only in the image on this machine. Never push the image.
#
#   docker build -t passwords-app-anisette-windows:local docker/anisette
#
# iCloud_main.dll must be 261.7.0.49 and CoreADI.dll 4.17.0: native-wine-anisette.cpp calls into the
# first by fixed offsets and refuses any other version. iCloud_main.dll comes from the March 2020
# installer (the one AltServer for Windows downloads), CoreADI.dll from the September 2020 one.

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS helper
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends g++-mingw-w64-i686-win32 \
    && rm -rf /var/lib/apt/lists/*
COPY native-wine-anisette.cpp /src/
RUN i686-w64-mingw32-g++-win32 -std=c++17 -O2 -Wall -Wextra -static -static-libgcc -static-libstdc++ \
    -o /src/native-wine-anisette.exe /src/native-wine-anisette.cpp -lversion -lcrypt32

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS apple
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl 7zip msitools \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
# The installers are one big CAB resource; 7z pulls the MSI packages out, msiextract unpacks them
# with Windows' own directory layout.
RUN set -eu; \
    mkdir -p /apple; \
    fetch() { curl -fsSL --retry 3 -o "$1" "$2"; echo "$3  $1" | sha256sum -c -; }; \
    fetch march.exe https://secure-appldnld.apple.com/windows/061-91601-20200323-974a39d0-41fc-4761-b571-318b7d9205ed/iCloudSetup.exe \
        1100052f27c8ebf6eea57b05682eb4a5a75efd50d7ed1c943bd0108acdc5e692; \
    fetch sept.exe http://updates-http.cdn-apple.com/2020/windows/001-39935-20200911-1A70AA56-F448-11EA-8CC0-99D41950005E/iCloudSetup.exe \
        4cfd20d13cdce2b5c435f2ddaf4ee4c81d976461846bf3b954e8af6cbcdeb9f7; \
    fetch /apple/AppleIncRootCertificate.cer https://www.apple.com/appleca/AppleIncRootCertificate.cer \
        b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024; \
    7z x -y -omarch march.exe iCloud.msi AppleApplicationSupport.msi >/dev/null; \
    7z x -y -osept sept.exe AppleApplicationSupport.msi >/dev/null; \
    msiextract -C march/support march/AppleApplicationSupport.msi >/dev/null; \
    msiextract -C march/internet march/iCloud.msi >/dev/null; \
    msiextract -C sept/support sept/AppleApplicationSupport.msi >/dev/null; \
    cp -r "march/support/Common Files/Apple/Apple Application Support" /apple/; \
    cp -r "march/internet/Common Files/Apple/Internet Services" /apple/; \
    cp "sept/support/Common Files/Apple/Apple Application Support/CoreADI.dll" "/apple/Apple Application Support/CoreADI.dll"; \
    echo "9e3af0c4cf50cc65554a9478aa7b381ff351373bdf034413a877f52912ff5010  /apple/Internet Services/iCloud_main.dll" | sha256sum -c -; \
    echo "961539f222aa018ef5b32fc0c82fca6d3e2a70100c0037741530ee5324447f9b  /apple/Apple Application Support/CoreADI.dll" | sha256sum -c -

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN dpkg --add-architecture i386 \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       wine wine32:i386 xvfb xauth python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ENV WINEARCH=win32 WINEPREFIX=/state/prefix WINEDEBUG=-all DISPLAY=:99 \
    WINEDLLOVERRIDES=mscoree,mshtml= TZ=UTC
COPY --from=helper /src/native-wine-anisette.exe /app/
COPY --from=apple /apple /apple
COPY server.py start.sh /app/
RUN chmod 755 /app/start.sh && mkdir /state
EXPOSE 6969
CMD ["/app/start.sh"]

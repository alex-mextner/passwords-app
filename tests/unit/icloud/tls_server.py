# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""A throwaway PKI and a local HTTPS server for the iCloud client's TLS tests.

The server lets TLS tests exercise the real `requests`/`ssl` verification path end to end
without contacting Apple: a client must reject it while its CA is unknown and accept it once
that CA is the trusted bundle.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import ssl
import threading
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, ClassVar, override

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True, slots=True)
class Pki:
    ca_pem: Path
    cert_pem: Path
    key_pem: Path


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def build_pki(directory: Path) -> Pki:
    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("passwords-app test CA"))
        .issuer_name(_name("passwords-app test CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("localhost"))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    pki = Pki(directory / "ca.pem", directory / "leaf.pem", directory / "leaf.key")
    pki.ca_pem.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    pki.cert_pem.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    pki.key_pem.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return pki


@dataclass(frozen=True, slots=True)
class Reply:
    status: int
    body: bytes
    content_type: str = "application/octet-stream"


Route = Callable[[str, str, bytes], Reply]


class _Handler(BaseHTTPRequestHandler):
    route: ClassVar[Route]

    def _serve(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        reply = type(self).route(self.command, self.path, body)
        self.send_response(reply.status)
        self.send_header("Content-Type", reply.content_type)
        self.send_header("Content-Length", str(len(reply.body)))
        self.end_headers()
        self.wfile.write(reply.body)

    do_GET = do_POST = do_PUT = _serve  # noqa: N815 - BaseHTTPRequestHandler dispatch names

    @override
    def log_message(self, format: str, *args: object) -> None:
        """Silence the per-request stderr line; pytest output stays readable."""


@dataclass(frozen=True, slots=True)
class HttpsServer:
    base_url: str
    ca_pem: str


def serve(pki: Pki, route: Route) -> tuple[ThreadingHTTPServer, HttpsServer]:
    """Start a TLS server on 127.0.0.1 in a daemon thread; the caller shuts it down."""
    handler = type("Handler", (_Handler,), {"route": staticmethod(route)})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(pki.cert_pem, pki.key_pem)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, HttpsServer(f"https://127.0.0.1:{server.server_address[1]}", str(pki.ca_pem))

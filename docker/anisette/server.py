"""Local Wine/iCloud anisette provider. No Apple account credentials, no remote calls."""
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import subprocess
import threading
import time

lock = threading.Lock()
# Requests wait on one Wine run at a time. Answering from the last run for a few seconds (the client
# itself reuses an answer for 10) keeps a burst of callers, abandoned ones included, to one run.
CACHE_SECONDS = 5
cache_lock = threading.Lock()
cache = (0.0, None)
required = ("X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-LU", "X-Apple-I-MD-RINFO",
            "X-Mme-Device-Id", "X-Apple-I-SRL-NO", "X-MMe-Client-Info", "X-Apple-I-Client-Time",
            "X-Apple-Locale", "X-Apple-I-TimeZone")
COMMAND = ["wine", "/app/native-wine-anisette.exe", "Z:\\apple", "Z:\\apple\\AppleIncRootCertificate.cer"]


def run_helper():
    with lock:
        # Wine background services can inherit stdio. Anonymous RAM files let
        # the helper exit without waiting for those services to close a pipe.
        with os.fdopen(os.memfd_create("anisette-output", os.MFD_CLOEXEC), "w+b") as output, \
             os.fdopen(os.memfd_create("anisette-errors", os.MFD_CLOEXEC), "w+b") as errors:
            result = subprocess.run(COMMAND, stdout=output, stderr=errors, timeout=30)
            output.seek(0)
            stdout = output.read(65537)
            errors.seek(0)
            stderr = errors.read(2 * 1024 * 1024)
    if result.returncode:
        loader = re.findall(rb"Native loader error: code=([0-9]{1,12})", stderr)
        if loader:
            print("Native loader error code=" + loader[-1].decode("ascii"), flush=True)
        # Domain/code are diagnostic identifiers; arbitrary library output stays hidden.
        details = re.findall(rb"Native provisioning error: domain=([A-Za-z0-9_.-]{1,128}) code=(-?[0-9]{1,12})", stderr)
        for domain, number in details:
            print("Provisioning error domain=" + domain.decode("ascii") + " code=" + number.decode("ascii"), flush=True)
        matches = re.findall(rb"Native anisette failure: ([a-z_]+)", stderr)
        raise RuntimeError(matches[-1].decode("ascii") if matches else "helper_failed")
    if len(stdout) > 65536:
        raise RuntimeError("oversized_helper_response")
    data = json.loads(stdout)
    if not isinstance(data, dict) or not all(isinstance(data.get(key), str) and data[key] for key in required):
        raise RuntimeError("incomplete_helper_response")
    date = datetime.fromisoformat(data["X-Apple-I-Client-Time"].replace("Z", "+00:00"))
    if date.tzinfo is None or abs((datetime.now(timezone.utc) - date).total_seconds()) > 120:
        raise RuntimeError("stale_helper_date")
    int(data["X-Apple-I-MD-RINFO"])
    return data


def fetch():
    global cache
    with cache_lock:
        stamp, data = cache
        if data is None or time.monotonic() - stamp >= CACHE_SECONDS:
            data = run_helper()
            cache = (time.monotonic(), data)
        return data


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *unused):
        pass

    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        try:
            data, status = fetch(), 200
        except RuntimeError as error:
            print("Native provider failure: " + str(error), flush=True)
            data, status = {"error": str(error)}, 503
        except Exception as error:
            print("Native provider failure: " + type(error).__name__, flush=True)
            data, status = {"error": type(error).__name__}, 503
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


if __name__ == "__main__":
    try:
        fetch()  # Provision (first start) and verify before accepting requests.
    except RuntimeError as error:
        print("Native provider startup failed: " + str(error), flush=True)
        raise SystemExit(1)
    except Exception as error:
        print("Native provider startup failed: " + type(error).__name__, flush=True)
        raise SystemExit(1)
    server = ThreadingHTTPServer(("0.0.0.0", 6969), Handler)
    print("Native iCloud provider ready", flush=True)
    server.serve_forever()

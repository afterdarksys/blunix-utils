"""LAN HTTP server for installs: build relay, iPXE script, netconfig, media.

Threats: becoming an open proxy, serving a file outside the media directory,
relaying a swapped or oversized body, falling back to cleartext when TLS
fails, and slow or huge requests. Only GET and HEAD are served. The relay
accepts only {label}.blnx.io and v{n}.{label}.blnx.io (lowercase, no port,
no userinfo, no IP literal), fetches https://{host}/ with full verification,
follows no redirect, caps the body at 256 KiB and the whole fetch at 20 s,
and relays only an age body. A TLS failure is a 502; there is no retry over
http. Media is an allowlist of three names inside --media, each checked
against SHA256SUMS at startup and opened without following symlinks; a file
that changes after that is not served. boot.ipxe names only an address the
operator gave (--advertise, or a specific --listen), never the Host header.
Request lines are capped at 4 KiB, headers at 8 KiB, and the whole request
at a deadline. At most 64 connections are served at once; more are closed.
Each IP gets a token bucket, and the oldest bucket is evicted when the table
is full. The access log records the client, method, path without query, and
status. No body, header, or key is logged. Keys never reach this process.

What it does not stop: a LAN client reading a public ciphertext or another
machine's install address. Both are public by design; age protects the body.
Netboot media is plain http and unsigned: SHA256SUMS proves only that the
files match the sums file the operator trusted. Netboot is for trusted LANs
until images are signed.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import re
import socket
import stat
import sys
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from blunix.errors import BlunixError
from blunix.proxy_boot import MEDIA_FILES, render_ipxe
from blunix.proxy_config import parse_hostport, tls_context
from blunix.proxy_site import build_host_kind, normalize_mac

MAX_BUILD = 256 * 1024
FETCH_TIMEOUT = 20
LATEST_TTL = 60
PINNED_TTL = 3600
MAX_CACHE = 128
MAX_BUCKETS = 4096
MAX_CONNECTIONS = 64
REQUEST_DEADLINE = 30
MEDIA_DEADLINE = 900
MAX_SUMS = 64 * 1024
MAX_LINE = 4096
MAX_HEADERS = 8192
_AGE_BINARY = b"age-encryption.org/v1\n"
_AGE_ARMOR = b"-----BEGIN AGE ENCRYPTED FILE-----"
_SEGMENT = re.compile(r"[A-Za-z0-9._:-]{1,253}")
_SUM_LINE = re.compile(r"([0-9a-f]{64}) [ *](\S{1,255})")


class _Conn(http.client.HTTPSConnection):
    def __init__(self, host, context, timeout, connect_to=None):
        super().__init__(host, 443, timeout=timeout, context=context)
        self._connect_to = connect_to

    def connect(self):
        address = self._connect_to or (self.host, self.port)
        sock = socket.create_connection(address, self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def _open_https(host, context, timeout, connect_to=None):
    conn = _Conn(host, context, timeout, connect_to)
    try:
        conn.request(
            "GET",
            "/",
            headers={"User-Agent": "blunix-proxy", "Accept": "application/octet-stream"},
        )
        return conn.getresponse()
    except BaseException:
        conn.close()
        raise


class BuildFetcher:
    """Fetch https://{host}/ for a contract build host, with a small cache."""

    def __init__(self, context_factory=None, opener=None, connect_to=None,
                 timeout=FETCH_TIMEOUT, clock=time.monotonic):
        self._context_factory = context_factory
        self._opener = opener or _open_https
        self._connect_to = connect_to
        self._timeout = timeout
        self._clock = clock
        self._lock = threading.Lock()
        self._cache = {}

    def get(self, host):
        kind = build_host_kind(host)
        now = self._clock()
        with self._lock:
            hit = self._cache.get(host)
            if hit is not None and hit[1] > now:
                return 200, hit[0], hit[2]
        status, body = self._fetch(host)
        if status != 200:
            return status, None, None
        digest = hashlib.sha256(body).hexdigest()
        expires = now + (PINNED_TTL if kind == "pinned" else LATEST_TTL)
        with self._lock:
            self._cache.pop(host, None)
            while len(self._cache) >= MAX_CACHE:
                self._cache.pop(next(iter(self._cache)))
            self._cache[host] = (body, expires, digest)
        return 200, body, digest

    def _fetch(self, host):
        try:
            context = tls_context(self._context_factory)
        except BlunixError:
            return 502, None
        deadline = self._clock() + self._timeout
        resp = None
        try:
            resp = self._opener(host, context, self._timeout, self._connect_to)
            if resp.status == 404:
                return 404, None
            if resp.status != 200:
                return 502, None
            length = resp.getheader("Content-Length")
            if length is not None and (not length.isdigit() or int(length) > MAX_BUILD):
                return 502, None
            chunks = []
            total = 0
            while True:
                if self._clock() > deadline:
                    return 502, None
                block = resp.read(16384)
                if not block:
                    break
                total += len(block)
                if total > MAX_BUILD:
                    return 502, None
                chunks.append(block)
        except (OSError, http.client.HTTPException, ValueError):
            return 502, None
        finally:
            if resp is not None:
                resp.close()
        body = b"".join(chunks)
        if not (body.startswith(_AGE_BINARY) or body.startswith(_AGE_ARMOR)):
            return 502, None
        return 200, body


class RateLimiter:
    """Token bucket per IP. A full table evicts the least recently seen IP, not all."""

    def __init__(self, capacity=60, refill=1.0, clock=time.monotonic, max_buckets=MAX_BUCKETS):
        self._capacity = float(capacity)
        self._refill = float(refill)
        self._clock = clock
        self._max = max_buckets
        self._lock = threading.Lock()
        self._buckets = OrderedDict()

    def allow(self, ip):
        now = self._clock()
        with self._lock:
            if ip in self._buckets:
                self._buckets.move_to_end(ip)
            else:
                while len(self._buckets) >= self._max:
                    self._buckets.popitem(last=False)
            tokens, last = self._buckets.get(ip, (self._capacity, now))
            tokens = min(self._capacity, tokens + (now - last) * self._refill)
            if tokens < 1.0:
                self._buckets[ip] = (tokens, now)
                return False
            self._buckets[ip] = (tokens - 1.0, now)
            return True


def _printable(text):
    return "".join(ch if 32 < ord(ch) < 127 else "?" for ch in text[:256])


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _read_sums(path):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise BlunixError(
            "media: no SHA256SUMS at " + path + "; give --sums PATH from the release"
        ) from None
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise BlunixError("media: " + path + " is not a regular file")
        raw = handle.read(MAX_SUMS + 1)
    if len(raw) > MAX_SUMS:
        raise BlunixError("media: " + path + " is larger than 64 KiB")
    sums = {}
    for line in raw.decode("ascii", "replace").splitlines():
        if not line.strip():
            continue
        match = _SUM_LINE.fullmatch(line)
        if not match or match.group(2) in sums:
            raise BlunixError("media: " + path + " has a line that is not a single sha256 entry")
        sums[match.group(2)] = match.group(1)
    return sums


def verify_media(root, sums_path=None):
    """Check each media file against SHA256SUMS. Returns {name: file identity}."""
    sums = _read_sums(sums_path or os.path.join(root, "SHA256SUMS"))
    verified = {}
    for name in MEDIA_FILES:
        want = sums.get(name)
        if want is None:
            raise BlunixError("media: SHA256SUMS has no entry for " + name + "; refusing to start")
        try:
            fd = os.open(os.path.join(root, name), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            raise BlunixError("media: " + name + " is missing or a symlink; refusing to start") from None
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise BlunixError("media: " + name + " is not a regular file; refusing to start")
            digest = hashlib.sha256()
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
            if not hmac.compare_digest(digest.hexdigest(), want):
                raise BlunixError("media: " + name + " does not match SHA256SUMS; refusing to start")
            if _identity(os.fstat(handle.fileno())) != _identity(info):
                raise BlunixError("media: " + name + " changed while it was checked; refusing to start")
        verified[name] = _identity(info)
    return verified


class _Handler(BaseHTTPRequestHandler):
    server_version = "blunix-proxy"
    sys_version = ""
    protocol_version = "HTTP/1.0"
    timeout = 15

    def setup(self):
        super().setup()
        self._timer = None
        self._arm(self.server.request_deadline)

    def finish(self):
        self._timer.cancel()
        super().finish()

    def _arm(self, seconds):
        # The whole request, not each read, has a deadline: a slow trickle is cut off.
        if self._timer is not None:
            self._timer.cancel()
        self._timer = threading.Timer(seconds, self._expire)
        self._timer.daemon = True
        self._timer.start()

    def _expire(self):
        self.server.log("blunix proxy: " + self.client_address[0] + " passed the request deadline; closed.")
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def handle_one_request(self):
        try:
            self.raw_requestline = self.rfile.readline(MAX_LINE + 1)
            if len(self.raw_requestline) > MAX_LINE:
                self.requestline = ""
                self.request_version = ""
                self.command = ""
                self.send_error(414)
                return
            if not self.raw_requestline:
                self.close_connection = True
                return
            if not self.parse_request():
                return
            size = sum(len(k) + len(v) + 4 for k, v in self.headers.items())
            if size > MAX_HEADERS:
                self.send_error(431)
                return
            self._dispatch()
            self.wfile.flush()
        except OSError:
            self.close_connection = True

    def log_message(self, format, *args):
        return

    def log_request(self, code="-", size="-"):
        path = (getattr(self, "path", "") or "").split("?", 1)[0]
        self.server.log(
            "blunix proxy: " + self.client_address[0] + " " + _printable(self.command or "-")
            + " " + _printable(path or "-") + " " + str(int(code) if str(code).isdigit() else code)
        )

    def _send(self, status, body=b"", ctype="text/plain; charset=utf-8", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def _dispatch(self):
        if self.command not in ("GET", "HEAD"):
            self._send(405, b"", extra={"Allow": "GET, HEAD"})
            return
        if not self.server.limiter.allow(self.client_address[0]):
            self._send(429, b"slow down\n")
            return
        path = self.path
        if not path.startswith("/") or "?" in path or "#" in path or "%" in path:
            self._send(404)
            return
        if path == "/healthz":
            self._send(200, b"ok\n")
        elif path == "/v1/boot.ipxe":
            self._boot()
        elif path.startswith("/v1/build/"):
            self._build(path[len("/v1/build/"):])
        elif path.startswith("/v1/netconfig/"):
            self._netconfig(path[len("/v1/netconfig/"):])
        elif path.startswith("/media/"):
            self._media(path[len("/media/"):])
        else:
            self._send(404)

    def _build(self, host):
        if not _SEGMENT.fullmatch(host):
            self._send(404)
            return
        try:
            status, body, digest = self.server.fetcher.get(host)
        except BlunixError:
            self._send(404)
            return
        if status != 200:
            self._send(status)
            return
        self._send(200, body, "application/octet-stream", {"X-Blunix-Sha256": digest})

    def _netconfig(self, mac):
        try:
            machine = self.server.machines.get(normalize_mac(mac))
        except BlunixError:
            machine = None
        if machine is None or machine["dhcp"]:
            self._send(404)
            return
        body = json.dumps(
            {"address": machine["address"], "gateway": machine["gateway"], "dns": machine["dns"]}
        ).encode("utf-8")
        self._send(200, body, "application/json")

    def _boot(self):
        advertise = self.server.advertise
        if advertise is None:
            self.server.log(
                "blunix proxy: boot.ipxe needs --advertise HOST:PORT or a specific --listen address; answered 404."
            )
            self._send(404)
            return
        self._send(200, render_ipxe(advertise).encode("ascii"))

    def _media(self, name):
        root = self.server.media
        if root is None or name not in MEDIA_FILES:
            self._send(404)
            return
        path = os.path.join(root, name)
        if os.path.dirname(os.path.realpath(path)) != root:
            self._send(404)
            return
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            self._send(404)
            return
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                self._send(404)
                return
            if _identity(info) != self.server.media_ids.get(name):
                self.server.log(
                    "blunix proxy: media " + name + " changed since startup; restart the proxy to check it again."
                )
                self._send(404)
                return
            self._arm(self.server.media_deadline)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(info.st_size))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if self.command == "HEAD":
                return
            while True:
                block = handle.read(65536)
                if not block:
                    break
                self.wfile.write(block)


def _stderr(line):
    print(line, file=sys.stderr, flush=True)


class ProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, site=None, media=None, advertise=None,
                 fetcher=None, limiter=None, log=None, sums=None,
                 max_connections=MAX_CONNECTIONS):
        self.machines = {m["mac"]: m for m in site["machines"]} if site else {}
        self.media_ids = {}
        if media is not None:
            media = os.path.realpath(media)
            if not os.path.isdir(media):
                raise BlunixError("media directory not found")
            self.media_ids = verify_media(media, sums)
        self.media = media
        if advertise is not None:
            name, port = parse_hostport(advertise, "advertise address")
            advertise = name + ":" + str(port)
        self.fetcher = fetcher or BuildFetcher()
        self.limiter = limiter or RateLimiter()
        self.log = log or _stderr
        self.request_deadline = REQUEST_DEADLINE
        self.media_deadline = MEDIA_DEADLINE
        self._slots = threading.BoundedSemaphore(max_connections)
        super().__init__(address, _Handler)
        if advertise is None and address[0] not in ("", "0.0.0.0", "::"):
            # A specific listen address is one the operator chose, so it can be named.
            try:
                name, port = parse_hostport(address[0] + ":" + str(self.server_address[1]))
                advertise = name + ":" + str(port)
            except BlunixError:
                advertise = None
        self.advertise = advertise

    def process_request(self, request, client_address):
        # Over the cap, close at once: no thread, no read, no answer.
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

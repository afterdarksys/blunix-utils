"""Build-proxy config, account key file, and the API client.

Threats: an account key that leaks through argv, logs, a readable file, a
redirect, an environment proxy, or cleartext HTTP. The key is read only from
its own file, which must be a regular file owned by the caller with no group
or other bits. A `blx_join_` token is refused. The client verifies TLS
(default CA store, hostname check, TLS 1.2 or higher), follows no redirects,
ignores *_PROXY variables, caps every response at 1 MiB, times out at 20 s,
and reports fixed sentences. Plain http is accepted only for localhost
(wrangler dev). A key is only ever named by a sha256 fingerprint prefix.

What it does not stop: a local root user, or malware running as the operator,
reading the key file.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import ssl
import stat
import urllib.error
import urllib.parse
import urllib.request

import yaml

from blunix.errors import BlunixError
from blunix.proxy_site import check_label
from blunix.schema import UniqueKeyLoader

DEFAULT_API = "https://api.blunix.io"
DEFAULT_LISTEN = "0.0.0.0:8750"
TIMEOUT = 20
MAX_RESPONSE = 1024 * 1024
MAX_CONFIG = 16 * 1024
_LOCAL = ("localhost", "127.0.0.1", "::1")
_KEY = re.compile(r"blx_[A-Za-z0-9_-]{43}")
_SHA = re.compile(r"[0-9a-f]{64}")
_DNS_NAME = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*")
_CONFIG_KEYS = {"api", "key_file", "listen"}


def config_dir():
    return os.path.join(os.path.expanduser("~"), ".config", "blunix")


def default_config_path():
    return os.path.join(config_dir(), "proxy.yaml")


def default_key_path():
    return os.path.join(config_dir(), "proxy.key")


def fingerprint(key):
    return hashlib.sha256(key.encode("ascii")).hexdigest()[:12]


def check_key(value):
    if not isinstance(value, str):
        raise BlunixError("refused key")
    if value.startswith("blx_join_"):
        raise BlunixError("a blx_join_ token is not an account key")
    if not _KEY.fullmatch(value):
        raise BlunixError("not a blx_ account key")
    return value


def check_api_url(value):
    if not isinstance(value, str) or len(value) > 256:
        raise BlunixError("refused api url")
    parts = urllib.parse.urlsplit(value)
    try:
        port = parts.port
    except ValueError:
        raise BlunixError("refused api url") from None
    host = parts.hostname or ""
    if (
        parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or parts.path not in ("", "/")
        or not host
        or any(ord(ch) < 33 or ord(ch) > 126 for ch in value)
    ):
        raise BlunixError("refused api url")
    if parts.scheme == "http":
        if host not in _LOCAL:
            raise BlunixError("plain http is allowed only for localhost")
    elif parts.scheme != "https":
        raise BlunixError("refused api url")
    netloc = ("[" + host + "]" if ":" in host else host) + (":" + str(port) if port else "")
    return parts.scheme + "://" + netloc


def parse_hostport(value, what="address"):
    """HOST:PORT with an IPv4 address or a DNS name. Returns (host, port)."""
    if not isinstance(value, str) or len(value) > 260 or value.count(":") != 1:
        raise BlunixError("refused " + what)
    host, _, port_text = value.partition(":")
    if not port_text.isdigit() or len(port_text) > 5 or not 1 <= int(port_text) <= 65535:
        raise BlunixError("refused " + what)
    host = host.lower()
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        if not _DNS_NAME.fullmatch(host) or len(host) > 253 or host.replace(".", "").isdigit():
            raise BlunixError("refused " + what) from None
    return host, int(port_text)


def _secure_open(path, what):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise BlunixError(what + " unreadable") from None
    try:
        info = os.fstat(fd)
    except OSError:
        os.close(fd)
        raise BlunixError(what + " unreadable") from None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        os.close(fd)
        raise BlunixError(what + " must be a regular file you own")
    return fd, info


def read_key_file(path):
    fd, info = _secure_open(path, "key file")
    try:
        if info.st_mode & 0o077:
            raise BlunixError("key file is readable by group or others; chmod 600 it")
        data = os.read(fd, 257)
    finally:
        os.close(fd)
    if len(data) > 256:
        raise BlunixError("not a blx_ account key")
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError:
        raise BlunixError("not a blx_ account key") from None
    return check_key(text)


def write_private(path, data, exclusive=True):
    """Create a 0600 file. With exclusive, an existing file is refused."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    target = path if exclusive else path + ".tmp"
    if not exclusive and os.path.lexists(target):
        os.unlink(target)
    try:
        fd = os.open(target, flags, 0o600)
    except FileExistsError:
        raise BlunixError(os.path.basename(path) + " already exists") from None
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    if not exclusive:
        os.replace(target, path)


def save_config(path, api, key_file, listen):
    body = yaml.safe_dump(
        {"api": check_api_url(api), "key_file": key_file, "listen": listen},
        sort_keys=False,
    )
    write_private(path, body.encode("utf-8"), exclusive=False)


def load_config(path=None):
    path = path or default_config_path()
    if not os.path.lexists(path):
        raise BlunixError("no proxy config; run blunix proxy init")
    fd, info = _secure_open(path, "proxy config")
    try:
        if info.st_mode & 0o022:
            raise BlunixError("proxy config is writable by group or others")
        data = os.read(fd, MAX_CONFIG + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_CONFIG:
        raise BlunixError("proxy config too large")
    try:
        doc = yaml.load(data.decode("utf-8"), Loader=UniqueKeyLoader)
    except Exception:
        raise BlunixError("proxy config is not valid yaml") from None
    if not isinstance(doc, dict) or set(doc) != _CONFIG_KEYS:
        raise BlunixError("proxy config needs exactly api, key_file and listen")
    key_file = doc["key_file"]
    if not isinstance(key_file, str) or not os.path.isabs(key_file):
        raise BlunixError("proxy config key_file must be an absolute path")
    parse_hostport(doc["listen"], "listen address")
    return {"api": check_api_url(doc["api"]), "key_file": key_file, "listen": doc["listen"]}


def tls_context(factory=None):
    context = ssl.create_default_context() if factory is None else factory()
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise BlunixError("tls verify disabled")
    if factory is None:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_STATUS = {
    400: "api refused the request",
    401: "api refused the account key",
    403: "the account key lacks the hosts:write scope",
    404: "api route not found",
    413: "api refused the build size",
    429: "api rate limit reached; try again later",
}


def _status_error(status):
    if 300 <= status < 400:
        return BlunixError("api redirected; refused")
    if status >= 500:
        return BlunixError("api failed; try again later")
    return BlunixError(_STATUS.get(status, "api refused the request"))


def _labels(doc):
    items = doc
    if isinstance(doc, dict):
        items = None
        for key in ("hosts", "labels"):
            if isinstance(doc.get(key), list):
                items = doc[key]
                break
    if not isinstance(items, list):
        raise BlunixError("api sent an unexpected host list")
    out = set()
    for item in items:
        if isinstance(item, dict):
            item = item.get("label")
        if isinstance(item, str):
            out.add(item)
    return out


class Api:
    """Bearer-key client for https://api.blunix.io/v1."""

    def __init__(self, base, key, context_factory=None, timeout=TIMEOUT):
        self.base = check_api_url(base)
        self._key = check_key(key)
        self._timeout = timeout
        handlers = [urllib.request.ProxyHandler({}), _NoRedirect()]
        if self.base.startswith("https://"):
            handlers.append(urllib.request.HTTPSHandler(context=tls_context(context_factory)))
        self._opener = urllib.request.build_opener(*handlers)

    def __repr__(self):
        return "Api(" + self.base + ")"

    def _call(self, method, path, body=None, content_type=None):
        headers = {
            "Authorization": "Bearer " + self._key,
            "Accept": "application/json",
            "User-Agent": "blunix-proxy",
        }
        if content_type:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(self.base + path, data=body, method=method, headers=headers)
        resp = None
        try:
            try:
                resp = self._opener.open(req, timeout=self._timeout)
            except urllib.error.HTTPError as exc:
                resp = exc
            except urllib.error.URLError as exc:
                if isinstance(exc.reason, ssl.SSLError):
                    raise BlunixError("api tls verification failed") from None
                raise BlunixError("api unreachable") from None
            except ssl.SSLError:
                raise BlunixError("api tls verification failed") from None
            except (OSError, ValueError):
                raise BlunixError("api unreachable") from None
            status = resp.getcode()
            try:
                raw = resp.read(MAX_RESPONSE + 1)
            except (OSError, ValueError):
                raise BlunixError("api unreachable") from None
        finally:
            if resp is not None:
                resp.close()
        if len(raw) > MAX_RESPONSE:
            raise BlunixError("api response too large")
        doc = None
        if raw:
            try:
                doc = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                doc = None
        return status, doc

    def list_labels(self):
        status, doc = self._call("GET", "/v1/hosts")
        if status != 200:
            raise _status_error(status)
        return _labels(doc)

    def reserve(self, label):
        """Return "reserved" or "taken". 409 means the label exists somewhere."""
        body = json.dumps({"label": check_label(label)}).encode("utf-8")
        status, _ = self._call("POST", "/v1/hosts", body, "application/json")
        if status in (200, 201):
            return "reserved"
        if status == 409:
            return "taken"
        if status == 400:
            raise BlunixError("api refused label " + label)
        raise _status_error(status)

    def upload(self, label, ciphertext):
        path = "/v1/hosts/" + check_label(label) + "/builds"
        status, doc = self._call("POST", path, bytes(ciphertext), "application/octet-stream")
        if status != 201:
            raise _status_error(status)
        if not isinstance(doc, dict):
            raise BlunixError("api sent an unexpected build result")
        version = doc.get("version")
        sha = doc.get("sha256")
        size = doc.get("size")
        local = hashlib.sha256(ciphertext).hexdigest()
        if (
            isinstance(version, bool)
            or not isinstance(version, int)
            or not 1 <= version <= 999999
            or not isinstance(sha, str)
            or not _SHA.fullmatch(sha)
            or not hmac.compare_digest(sha, local)
            or size != len(ciphertext)
        ):
            raise BlunixError("api build result does not match the upload")
        return {"version": version, "sha256": local, "size": len(ciphertext)}

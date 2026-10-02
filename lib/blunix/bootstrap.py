"""Threats: the build passphrase stays on the machine. Fetch uses the default
TLS verifier, TLS 1.2 or higher, a 256 KiB cap, and refuses any URL that is
not https://{assigned-host}/, including on a redirect. A wrong passphrase, a
shell script, or missing test guestinfo fails closed and does not apply. The
typed key is canonicalized (keyfmt) and never logged.

What it does not stop: the test image reads VMware guestinfo, which root in
the guest can see. That path exists only for the fixture marker. Production
prompts on the console. The node document is still unsigned in this spike.
"""

from __future__ import annotations

import os
import re
import secrets
import ssl
import subprocess
import time
import urllib.parse
import urllib.request

from blunix.access import profile_from_cmdline
from blunix.age import decrypt_bytes, encrypt_bytes
from blunix.cmd import run_cmd
from blunix.console import console_line
from blunix.errors import BlunixError, DecryptError
from blunix.keyfmt import passphrase_candidates
from blunix.node import apply_node
from blunix.schema import (
    MAX_DOCUMENT,
    expand_build_host,
    load_bytes,
    require_build_host,
)

FIXTURE_PATH = "/usr/share/blunix/bootstrap-fixture.age"
MARKER_NAME = "test-image"
_MARKER_KEYS = ("mode", "host", "fixture")
_GUESTINFO = re.compile(r"guestinfo\.blunix\.[a-z.]+")
_INET = re.compile(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+/\d+)\b")
_SPEECH = ("full-speech", "console-speech")
_WRONG = "blunix-self-test-wrong"
# Ciphertext cap on the wire. The plaintext cap is still MAX_DOCUMENT.
MAX_CIPHER = 256 * 1024


def _root_path(root, path):
    if os.path.abspath(root) == "/":
        return path
    return os.path.join(root, path.lstrip("/"))


def read_marker(root="/"):
    path = os.path.join(root, "etc", "blunix", MARKER_NAME)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "rb") as handle:
            data = handle.read(2048)
    except OSError:
        raise BlunixError("refused marker")
    if len(data) > 1024 or b"\x00" in data:
        raise BlunixError("refused marker")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise BlunixError("refused marker")
    fields = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise BlunixError("refused marker")
        key, value = line.split("=", 1)
        if key in fields or key not in _MARKER_KEYS:
            raise BlunixError("refused marker")
        fields[key] = value
    if tuple(sorted(fields)) != tuple(sorted(_MARKER_KEYS)):
        raise BlunixError("refused marker")
    if fields["mode"] != "fixture" or fields["fixture"] != FIXTURE_PATH:
        raise BlunixError("refused marker")
    return {
        "mode": "fixture",
        "host": require_build_host(fields["host"]),
        "fixture": FIXTURE_PATH,
    }


def document_url(host):
    host = require_build_host(host)
    return "https://" + host + "/"


def check_fetch_url(url, host):
    host = require_build_host(host)
    parts = urllib.parse.urlsplit(url)
    name = (parts.hostname or "").lower()
    if parts.scheme != "https" or name != host.lower():
        raise BlunixError("refused url")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise BlunixError("refused url")
    if parts.path not in ("", "/"):
        raise BlunixError("refused url")
    return url


class _Redirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, host):
        super().__init__()
        self.host = host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_fetch_url(newurl, self.host)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def read_cap(resp, cap=MAX_CIPHER):
    data = resp.read(cap + 1)
    if not isinstance(data, (bytes, bytearray)):
        raise BlunixError("document fetch failed")
    if len(data) > cap:
        raise BlunixError("document too large")
    return bytes(data)


def tls_context(context_factory=None):
    if context_factory is None:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        context = context_factory()
    verify = getattr(context, "verify_mode", None)
    if verify != ssl.CERT_REQUIRED or not getattr(context, "check_hostname", False):
        raise BlunixError("tls verify disabled")
    minimum = getattr(context, "minimum_version", ssl.TLSVersion.TLSv1_2)
    if minimum not in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        raise BlunixError("tls verify disabled")
    return context


def fetch_https(host, urlopen=None, context_factory=None, timeout=30):
    url = document_url(host)
    check_fetch_url(url, host)
    context = tls_context(context_factory)
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "blunix-bootstrap"},
    )
    opener = None
    if urlopen is None:
        # No environment proxy: the only proxy is one the operator names.
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _Redirect(host),
            urllib.request.HTTPSHandler(context=context),
        )

        def urlopen(request, timeout=timeout, context=context):
            return opener.open(request, timeout=timeout)

    resp = None
    try:
        try:
            resp = urlopen(req, timeout=timeout, context=context)
        except BlunixError:
            raise
        except Exception:
            raise BlunixError("document fetch failed")
        return read_cap(resp)
    finally:
        close = getattr(resp, "close", None)
        if close is not None:
            close()


def _clean_guestinfo(raw):
    if isinstance(raw, bytes):
        if len(raw) > 257:
            return None
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            return None
    elif isinstance(raw, str):
        text = raw
    else:
        return None
    if text.endswith("\n"):
        text = text[:-1]
    if text.endswith("\r"):
        text = text[:-1]
    if not text or not text.strip() or len(text) > 256:
        return None
    if any(ch in text for ch in ("\n", "\r", "\x00")):
        return None
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in text):
        return None
    return text


def _guestinfo_from_tools(key):
    commands = (
        ["vmtoolsd", "--cmd", "info-get " + key],
        ["vmware-rpctool", "info-get " + key],
    )
    for argv in commands:
        try:
            proc = run_cmd(
                argv,
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            continue
        if proc.returncode != 0 or not proc.stdout:
            continue
        cleaned = _clean_guestinfo(proc.stdout)
        if cleaned:
            return cleaned
    return None


def guestinfo_value(key, getter=None, sleeper=None, attempts=30):
    if not isinstance(key, str) or not _GUESTINFO.fullmatch(key):
        raise BlunixError("refused guestinfo")
    if getter is None:
        getter = _guestinfo_from_tools
    pause = sleeper if sleeper is not None else time.sleep
    for attempt in range(attempts):
        try:
            raw = getter(key)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            raw = None
        cleaned = _clean_guestinfo(raw) if raw is not None else None
        if cleaned:
            return cleaned
        if attempt + 1 < attempts:
            pause(1)
    return None


def parse_global(text):
    if isinstance(text, bytes):
        text = text.decode("ascii", "replace")
    if not isinstance(text, str):
        return []
    found = []
    for line in text.splitlines():
        match = _INET.match(line.strip())
        if not match:
            continue
        addr = match.group(2)
        if addr.startswith("127."):
            continue
        found.append((addr, match.group(1)))
    return found


def default_ip_show():
    try:
        proc = run_cmd(
            ["ip", "-4", "-o", "addr", "show", "scope", "global"],
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""
    if proc.returncode != 0 or not proc.stdout:
        return ""
    return proc.stdout.decode("ascii", "replace")


def wait_global(ip_show, sleeper=None, attempts=18, delay=5):
    pause = sleeper if sleeper is not None else time.sleep
    for attempt in range(attempts):
        found = parse_global(ip_show())
        if found:
            return found[0]
        if attempt + 1 < attempts:
            pause(delay)
    return None


def _say(log, message):
    if log is not None:
        log(message)


def ask_hostname(reader, log, speech, tries=3):
    for _ in range(tries):
        _say(log, "blunix: build hostname.")
        try:
            typed = reader()
        except (EOFError, OSError, BlunixError):
            _say(log, "blunix: refused hostname")
            continue
        if not isinstance(typed, str):
            _say(log, "blunix: refused hostname")
            continue
        try:
            host = expand_build_host(typed.strip().lower())
        except BlunixError:
            _say(log, "blunix: refused hostname")
            continue
        if speech:
            _say(log, "blunix: hostname " + host + ". Say yes to keep it.")
            try:
                answer = reader()
            except (EOFError, OSError, BlunixError):
                _say(log, "blunix: refused hostname")
                continue
            if not isinstance(answer, str) or answer.strip() != "yes":
                _say(log, "blunix: refused hostname")
                continue
        return host
    return None


def read_passphrase(reader, log):
    _say(log, "blunix: key. Type it. It will not be spoken.")
    try:
        if reader is None:
            import getpass

            value = getpass.getpass("")
        else:
            value = reader()
    except (EOFError, OSError):
        return ""
    if not isinstance(value, str):
        return ""
    return value


def decrypt_candidates(ciphertext, typed, decrypt=None):
    """Try the canonical key, then the raw input. None if neither decrypts."""
    if decrypt is None:
        decrypt = decrypt_bytes
    for candidate in passphrase_candidates(typed):
        try:
            return decrypt(ciphertext, candidate)
        except DecryptError:
            continue
    return None


def _read_cmdline(cmdline):
    if cmdline is not None:
        return cmdline
    try:
        with open("/proc/cmdline", "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return ""


def _speech(cmdline):
    return profile_from_cmdline(cmdline) in _SPEECH


def _self_test(ciphertext, log):
    try:
        decrypt_bytes(ciphertext, _WRONG)
    except DecryptError:
        _say(log, "blunix self-test: wrong passphrase: could not decrypt")
    else:
        _say(log, "blunix: bootstrap failed closed")
        return False
    token = secrets.token_urlsafe(18)
    try:
        blob = encrypt_bytes(b"#!/bin/sh\n", token)
        plain = decrypt_bytes(blob, token)
    except (DecryptError, BlunixError):
        _say(log, "blunix: bootstrap failed closed")
        return False
    try:
        load_bytes(plain)
    except BlunixError:
        _say(log, "blunix self-test: shell script: rejected")
        return True
    _say(log, "blunix: bootstrap failed closed")
    return False


def _load_fixture(root, marker):
    path = _root_path(root, marker["fixture"])
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_DOCUMENT + 1)
    except OSError:
        raise BlunixError("document unreadable")
    if len(data) > MAX_DOCUMENT:
        raise BlunixError("document too large")
    return data


def _boot_fixture(root, marker, models, log, guestinfo_getter, ip_show, sleeper):
    ciphertext = _load_fixture(root, marker)
    if not _self_test(ciphertext, log):
        return 1
    host = guestinfo_value(
        "guestinfo.blunix.hostname",
        getter=guestinfo_getter,
        sleeper=sleeper,
    )
    passphrase = guestinfo_value(
        "guestinfo.blunix.passphrase",
        getter=guestinfo_getter,
        sleeper=sleeper,
    )
    if not host or not passphrase:
        _say(log, "blunix: bootstrap failed closed")
        return 1
    try:
        checked = require_build_host(host)
    except BlunixError:
        _say(log, "blunix: refused hostname")
        return 1
    if checked != marker["host"]:
        _say(log, "blunix: refused hostname")
        return 1
    plain = decrypt_candidates(ciphertext, passphrase)
    if plain is None:
        _say(log, "could not decrypt")
        return 1
    _say(
        log,
        "blunix: test image decrypts the local fixture for " + marker["host"],
    )
    apply_node(plain, root, models=models, log=log)
    found = wait_global(ip_show, sleeper=sleeper)
    if found is None:
        _say(log, "blunix: no global address")
    else:
        addr, nic = found
        _say(log, "blunix: inet " + addr + " dev " + nic)
    return 0


def _boot_production(
    root,
    models,
    log,
    urlopen,
    context_factory,
    ip_show,
    sleeper,
    hostname_reader,
    passphrase_reader,
    cmdline,
    fetch_timeout,
):
    found = wait_global(ip_show, sleeper=sleeper)
    if found is None:
        _say(log, "blunix: bootstrap failed closed")
        return 1
    text = _read_cmdline(cmdline)
    if hostname_reader is None:
        hostname_reader = input
    host = ask_hostname(hostname_reader, log, _speech(text))
    if host is None:
        _say(log, "blunix: bootstrap failed closed")
        return 1
    passphrase = read_passphrase(passphrase_reader, log)
    ciphertext = fetch_https(
        host,
        urlopen=urlopen,
        context_factory=context_factory,
        timeout=fetch_timeout,
    )
    plain = decrypt_candidates(ciphertext, passphrase)
    passphrase = None
    if plain is None:
        _say(log, "could not decrypt")
        return 1
    apply_node(plain, root, models=models, log=log)
    addr, nic = found
    _say(log, "blunix: inet " + addr + " dev " + nic)
    return 0


def run_bootstrap(
    root="/",
    models=None,
    log=None,
    urlopen=None,
    context_factory=None,
    guestinfo_getter=None,
    ip_show=None,
    sleeper=None,
    hostname_reader=None,
    passphrase_reader=None,
    cmdline=None,
    fetch_timeout=30,
):
    if log is None:
        log = console_line
    if ip_show is None:
        ip_show = default_ip_show
    if sleeper is None:
        sleeper = time.sleep
    marker = read_marker(root)
    if marker is not None:
        return _boot_fixture(
            root,
            marker,
            models,
            log,
            guestinfo_getter,
            ip_show,
            sleeper,
        )
    return _boot_production(
        root,
        models,
        log,
        urlopen,
        context_factory,
        ip_show,
        sleeper,
        hostname_reader,
        passphrase_reader,
        cmdline,
        fetch_timeout,
    )

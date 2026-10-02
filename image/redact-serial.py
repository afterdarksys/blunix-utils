#!/usr/bin/env python3
"""Remove test secrets from the VMware logs and keep the public lines.

Threats: guestinfo and the root password can be copied into a serial log.
Those bytes are replaced before any line is kept. summary.txt receives only
the bootstrap lines this spike is supposed to print.
"""

import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, ".."))
_CHAR = re.compile(r"[A-Za-z0-9_-]{8,128}\Z")
_INET = re.compile(r"^blunix: inet (?!127\.)(?:\d+\.){3}\d+/\d+ dev \S+$")
# CSI and OSC from the console probe. They are not part of the sentence.
_ANSI = re.compile(
    r"\x1b\[[\x20-\x3f]*[\x20-\x2f]*[\x40-\x7e]"
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
)
# One leading console prefix. The remainder must be the whole sentence.
_FRAMING = re.compile(
    r"^(?:\[\s*\d+\.\d+\]\s+\S+:\s+|blunix login:\s+)"
)
_REQUIRED = (
    "blunix self-test: wrong passphrase: could not decrypt",
    "blunix self-test: shell script: rejected",
    "blunix: test image decrypts the local fixture for ada-1042.build.blunix.io",
    "blunix: node document is unsigned; spike is applying it without a signature",
    "blunix: disk layout recorded; systemd-repart was not executed",
    "blunix: applied node document blunix-test",
)


def _fail():
    sys.stderr.write("blunix: boot evidence incomplete\n")
    raise SystemExit(1)


def _secrets():
    found = []
    for name in ("root-password", "bootstrap-passphrase"):
        path = os.path.join(_REPO, "build", name)
        try:
            with open(path, "rb") as handle:
                raw = handle.read(512)
        except OSError:
            _fail()
        if b"\x00" in raw or len(raw) > 256:
            _fail()
        try:
            text = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            _fail()
        if not _CHAR.fullmatch(text):
            _fail()
        found.append(text.encode("ascii"))
    return found


def _redact(data, secrets):
    for secret in secrets:
        data = data.replace(secret, b"redacted")
    return data


def _read(path):
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError:
        return b""


def _visible(line):
    text = _ANSI.sub("", line).strip()
    framed = _FRAMING.match(text)
    if framed:
        text = text[framed.end():].strip()
    return text


def _lines(data):
    # CR starts a new serial record. Deleting it would glue two records together.
    text = data.decode("ascii", "replace")
    return [_visible(line) for line in text.splitlines()]


def _matched(lines):
    need = set(_REQUIRED)
    kept = []
    seen = set()
    inet = False
    for line in lines:
        item = line.strip()
        if item in need and item not in seen:
            kept.append(item)
            seen.add(item)
        elif _INET.fullmatch(item) and not inet:
            kept.append(item)
            inet = True
    complete = need.issubset(seen) and inet
    return kept, complete


def _rewrite(path, data):
    if not os.path.exists(path) and not data:
        return
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def main():
    check = False
    args = sys.argv[1:]
    if args and args[0] == "--check":
        check = True
        args = args[1:]
    if len(args) != 1 or not os.path.isdir(args[0]):
        _fail()
    vm_dir = args[0]
    secrets = _secrets()
    serial = _redact(_read(os.path.join(vm_dir, "serial.log")), secrets)
    boot = _redact(_read(os.path.join(vm_dir, "boot.log")), secrets)
    kept, complete = _matched(_lines(serial))
    if check:
        if not complete:
            raise SystemExit(1)
        return
    _rewrite(os.path.join(vm_dir, "serial.log"), serial)
    if os.path.exists(os.path.join(vm_dir, "boot.log")) or boot:
        _rewrite(os.path.join(vm_dir, "boot.log"), boot)
    summary = list(kept)
    if not complete:
        summary.append("blunix: boot evidence incomplete")
    blob = ("\n".join(summary) + "\n").encode("ascii")
    for secret in secrets:
        if secret in blob:
            _fail()
    _rewrite(os.path.join(vm_dir, "summary.txt"), blob)
    if not complete:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Create the two test secrets on the build machine.

Threats: these files are the VMware root password and the age passphrase.
They stay mode 0600 under build/, which is gitignored. They are not account
passwords and they are not written into the image by this script.
"""

import os
import re
import secrets

_HERE = os.path.dirname(os.path.abspath(__file__))
_BUILD = os.path.abspath(os.path.join(_HERE, "..", "build"))
_CHAR = re.compile(r"[A-Za-z0-9_-]{8,128}\Z")
_NAMES = ("root-password", "bootstrap-passphrase")


def _existing(path):
    try:
        with open(path, "rb") as handle:
            raw = handle.read(512)
    except OSError:
        return None
    if b"\x00" in raw or len(raw) > 256:
        return None
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    if not _CHAR.fullmatch(text):
        return None
    return text


def _write(path):
    current = _existing(path)
    if current is None:
        current = secrets.token_urlsafe(18)
        if not _CHAR.fullmatch(current):
            raise SystemExit(1)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, (current + "\n").encode("ascii"))
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def main():
    os.umask(0o077)
    os.makedirs(_BUILD, exist_ok=True)
    for name in _NAMES:
        _write(os.path.join(_BUILD, name))


if __name__ == "__main__":
    main()

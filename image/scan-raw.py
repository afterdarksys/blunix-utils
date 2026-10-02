#!/usr/bin/env python3
"""Scan the raw bytes of a disk image, free space included, for secrets.

Threats: a file deleted inside the image keeps its bytes in free blocks. The
mounted-root scan cannot see those; this one reads every byte of the image,
or of the stream `zstd -dc` makes from a .zst. It refuses a PEM private key
body (OPENSSH, RSA, EC, PKCS#8, encrypted), an OpenSSH key body without its
header, a full age secret key, a passphrase-encrypted age header (the test
fixture's header), and the two plaintext test secrets in build/. It prints a
fixed line and no bytes or offsets. A read error or a zstd failure fails
closed.

What it does not stop: a secret it has no pattern for, or one that was
compressed or encrypted inside the image. The sshd binaries carry the bare
"-----BEGIN OPENSSH PRIVATE KEY-----" marker with no body after it, and
age-keygen's help carries age's published example key; neither is a key, so
neither is refused.
"""

import os
import re
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, ".."))
_CHAR = re.compile(r"[A-Za-z0-9_-]{8,128}\Z")
_CHUNK = 8 * 1024 * 1024
_TAIL = 4096
# A marker followed by a base64 body. The sshd marker is followed by NULs.
_PEM = re.compile(rb"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----\r?\n(?:[A-Za-z0-9-]+: [^\n]{0,200}\n)*\r?\n?[A-Za-z0-9+/=]{16}")
_AGE_KEY = re.compile(rb"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}")
# age-keygen --help prints this key from age's README. It is public.
_AGE_EXAMPLE = b"AGE-SECRET-KEY-1N9JEPW6DWJ0ZQUDX63F5A03GX8QUW7PXDE39N8UYF82VZ9PC8UFS3M7XA9"
_OPENSSH_BODY = b"b3BlbnNzaC1rZXktdjE"  # base64 of "openssh-key-v1"
_AGE_SCRYPT = b"age-encryption.org/v1\n-> scrypt "
_ZERO = bytes(_CHUNK)


def _fail(message):
    sys.stderr.write(message + "\n")
    raise SystemExit(1)


def _secrets():
    found = []
    for name in ("root-password", "bootstrap-passphrase"):
        path = os.path.join(_REPO, "build", name)
        try:
            with open(path, "rb") as handle:
                raw = handle.read(512)
        except OSError:
            _fail("blunix: scan failed")
        try:
            text = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            _fail("blunix: scan failed")
        if b"\x00" in raw or not _CHAR.fullmatch(text):
            _fail("blunix: scan failed")
        found.append(text.encode("ascii"))
    return found


def check(blob, secrets):
    """The first refusal in `blob`, or None."""
    for secret in secrets:
        if secret in blob:
            return "plaintext secret in the raw image"
    if b"PRIVATE KEY-----" in blob and _PEM.search(blob):
        return "private key in the raw image"
    if _OPENSSH_BODY in blob:
        return "private key in the raw image"
    if b"AGE-SECRET-KEY-1" in blob:
        for match in _AGE_KEY.finditer(blob):
            if match.group(0) != _AGE_EXAMPLE:
                return "age secret key in the raw image"
    if _AGE_SCRYPT in blob:
        return "age fixture in the raw image"
    return None


def scan(stream, secrets):
    prev = b""
    while True:
        try:
            chunk = stream.read(_CHUNK)
        except OSError:
            _fail("blunix: scan failed")
        if not chunk:
            return
        if chunk == _ZERO[:len(chunk)]:
            prev = chunk[-_TAIL:]
            continue
        blob = prev + chunk
        found = check(blob, secrets)
        if found:
            _fail(found)
        prev = blob[-_TAIL:]


def main():
    args = sys.argv[1:]
    if len(args) != 1 or not os.path.isfile(args[0]):
        _fail("blunix: scan failed")
    path = args[0]
    secrets = _secrets()
    if not path.endswith(".zst"):
        try:
            handle = open(path, "rb")
        except OSError:
            _fail("blunix: scan failed")
        with handle:
            scan(handle, secrets)
        return
    try:
        proc = subprocess.Popen(
            ["zstd", "-dc", "-q", "--no-progress", "--", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        _fail("blunix: scan failed")
    try:
        scan(proc.stdout, secrets)
    finally:
        proc.stdout.close()
        code = proc.wait()
    if code != 0:
        _fail("blunix: scan failed")


if __name__ == "__main__":
    main()

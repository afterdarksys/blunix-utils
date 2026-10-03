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
neither is refused. libgnutls30 compiles in the fixed, public keys of its
crypto self-tests as full PEM blocks; each one is listed below by the SHA-256
of its exact BEGIN..END bytes, so only those bytes pass and any other key, or
a listed marker around a different body, is still refused. Those keys are
public, so a service that used one as its real key would pass. A block cut by a
read is held until the next read completes it; one still unfinished at the
end of the stream, or before a run of zero bytes, is refused.
"""

import hashlib
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
_PEM_KIND = re.compile(rb"-----BEGIN ([A-Z0-9 ]{0,40}PRIVATE KEY)-----")
_PEM_MAX = 16384
# The self-test keys in Debian 13's libgnutls.so.30.40.3 (libgnutls30t64
# 3.8.9) that _PEM matches: five PKCS#8, one EC, one DSA, one RSA. They are
# public constants of the GnuTLS source, not keys of this image.
_PUBLIC_KEYS = frozenset((
    "fed7079dd4491609e4c996e232f366ac434fa4cc9df19df363391d079d470964",
    "5a09eb5df3674472eda0077d83cbccef72692c3d052ab393368ac57295439c58",
    "a4d138d7ef9748464117b44fb9c0a4b5b85a1599a127d02690abaa96d03c16e6",
    "fa0b06a72461ec0a963dcfccb8d5b61bd88a6074fc7271573bff68ab86b8c1af",
    "ef237ea8db4f2ae9ee100e8ced96d29b5dceb0e6a948443e6b8a00b1791f9ec9",
    "91ea1699ff6b1a34b4a1d500a9c75a808441e47b9ea68da6fb0195e01ce1dc61",
    "7c4c63ee462e0e700cd9e29c8e0f730b3f1b484c4abdd83f1e69fcd477c061fa",
    "d039c8119a029ab9f9c83c04d67002d887b6bc6026c4264402ab27cdf24cf138",
))
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
            # Name the file, never its contents: the scan needs the build's own
            # secrets to look for them, so without them it cannot run.
            _fail("blunix: scan failed: build/" + name + " is missing or unreadable")
        try:
            text = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            _fail("blunix: scan failed")
        if b"\x00" in raw or not _CHAR.fullmatch(text):
            _fail("blunix: scan failed")
        found.append(text.encode("ascii"))
    return found


def pem_blocks(blob):
    """(start, kind, block) for each _PEM match; block is None with no END."""
    for match in _PEM.finditer(blob):
        start = match.start()
        kind = _PEM_KIND.match(blob, start).group(1)
        end = blob.find(b"-----END " + kind + b"-----", match.end(), start + _PEM_MAX)
        yield start, kind, (blob[start:end + len(kind) + 14] if end >= 0 else None)


def listed(block):
    return hashlib.sha256(block).hexdigest() in _PUBLIC_KEYS


def _private_key(blob, final):
    """True when `blob` holds a PEM private key that is not a listed public one.

    A block that starts in the last _TAIL bytes and has no END yet is left for
    the next read, which sees it whole, unless `final` says none follows.
    """
    for start, _kind, block in pem_blocks(blob):
        if block is None:
            if final or start < len(blob) - _TAIL:
                return True
            continue
        if not listed(block):
            return True
    return False


def check(blob, secrets, final=True):
    """The first refusal in `blob`, or None."""
    for secret in secrets:
        if secret in blob:
            return "plaintext secret in the raw image"
    if b"PRIVATE KEY-----" in blob and _private_key(blob, final):
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
        if not chunk or chunk == _ZERO[:len(chunk)]:
            # Nothing can finish a block held from the last read.
            found = check(prev, secrets)
            if found:
                _fail(found)
            if not chunk:
                return
            prev = chunk[-_TAIL:]
            continue
        blob = prev + chunk
        found = check(blob, secrets, final=False)
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

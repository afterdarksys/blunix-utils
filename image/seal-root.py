#!/usr/bin/env python3
"""Put the age fixture and the root password onto a mounted test root.

Threats: the passphrase and the root password are read from build/ files.
They are not taken from argv or the environment. A failure prints one fixed
line. chpasswd receives the password on stdin. The ciphertext is produced by
Debian age through the library.
"""

import os
import re
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, ".."))
_LIB = os.path.join(_REPO, "lib")
_CHAR = re.compile(r"[A-Za-z0-9_-]{8,128}\Z")
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)


def _fail():
    sys.stderr.write("blunix: seal failed\n")
    raise SystemExit(1)


def _read_secret(name):
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
    return text


def main():
    if len(sys.argv) != 2:
        _fail()
    mnt = sys.argv[1]
    if not os.path.isdir(mnt):
        _fail()
    root_pw = _read_secret("root-password")
    passphrase = _read_secret("bootstrap-passphrase")
    try:
        from blunix.age import encrypt_file

        src = os.path.join(_REPO, "models", "node", "vmware-test.yaml")
        dest = os.path.join(mnt, "usr", "share", "blunix", "bootstrap-fixture.age")
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        encrypt_file(src, dest, passphrase)
        marker_dir = os.path.join(mnt, "etc", "blunix")
        os.makedirs(marker_dir, exist_ok=True)
        marker = (
            "mode=fixture\n"
            "host=ada-1042.build.blunix.io\n"
            "fixture=/usr/share/blunix/bootstrap-fixture.age\n"
        )
        fd = os.open(
            os.path.join(marker_dir, "test-image"),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o644,
        )
        try:
            os.write(fd, marker.encode("ascii"))
        finally:
            os.close(fd)
        proc = subprocess.run(
            ["chroot", mnt, "chpasswd"],
            input=("root:" + root_pw + "\n").encode("utf-8"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            check=False,
        )
    except SystemExit:
        raise
    except Exception:
        _fail()
    if proc.returncode != 0:
        _fail()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Scan a mounted root for vendor binaries and plaintext test secrets.

Threats: a copied passphrase or root password would ship in the disk. This
script prints a fixed line and no path when that happens. Filename matches
for grok, claude, and codex are the vendor-binary check. Symlinks whose
target leaves the mount are not read. A symlink with no target has no file
content; its link text is still checked. An unreadable regular file fails
closed.

With --release it also refuses the test fixture (marker, age fixture, the
root-login sshd drop-in), any account in /etc/shadow that is not locked
(an empty password field included), /root/.ssh/authorized_keys, an sshd
config that says PermitRootLogin yes or PasswordAuthentication yes, a shipped
sshd host key, and an image with sshd but no `ssh-keygen -A` before it starts.
Free space is image/scan-raw.py's job.
"""

import glob
import os
import re
import stat
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, ".."))
_CHAR = re.compile(r"[A-Za-z0-9_-]{8,128}\Z")
_VENDOR = ("grok", "claude", "codex")


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
        if b"\x00" in raw or len(raw) > 256:
            _fail("blunix: scan failed")
        try:
            text = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            _fail("blunix: scan failed")
        if not _CHAR.fullmatch(text):
            _fail("blunix: scan failed")
        found.append(text.encode("ascii"))
    return found


def _inside(root_real, path):
    real = os.path.realpath(path)
    if real == root_real:
        return True
    return real.startswith(root_real + os.sep)


def _contains(path, needles):
    try:
        handle = open(path, "rb")
    except OSError:
        _fail("blunix: scan failed")
    try:
        prev = b""
        while True:
            try:
                chunk = handle.read(1024 * 1024)
            except OSError:
                _fail("blunix: scan failed")
            if not chunk:
                return False
            blob = prev + chunk
            for needle in needles:
                if needle in blob:
                    return True
            prev = blob[-256:]
    finally:
        handle.close()


_FIXTURE = (
    ("etc", "blunix", "test-image"),
    ("usr", "share", "blunix", "bootstrap-fixture.age"),
    ("etc", "ssh", "sshd_config.d", "00-blunix-test.conf"),
)


def _release_checks(root):
    for parts in _FIXTURE:
        if os.path.lexists(os.path.join(root, *parts)):
            _fail("test fixture in a release image")
    shadow = os.path.join(root, "etc", "shadow")
    try:
        with open(shadow, "rb") as handle:
            text = handle.read(1024 * 1024).decode("utf-8")
    except (OSError, UnicodeDecodeError):
        _fail("blunix: scan failed")
    for line in text.splitlines():
        if not line:
            continue
        fields = line.split(":")
        if len(fields) < 2:
            _fail("blunix: scan failed")
        if not fields[1].startswith(("!", "*")):
            _fail("unlocked account in a release image")
    if os.path.lexists(os.path.join(root, "root", ".ssh", "authorized_keys")):
        _fail("root ssh key in a release image")
    ssh = os.path.join(root, "etc", "ssh")
    configs = [os.path.join(ssh, "sshd_config")]
    configs += sorted(glob.glob(os.path.join(ssh, "sshd_config.d", "*")))
    for path in configs:
        if not os.path.lexists(path):
            continue
        if _sshd_opens(_read_text(root, path)):
            _fail("sshd allows root or password login in a release image")
    if glob.glob(os.path.join(ssh, "ssh_host_*")):
        _fail("sshd host key in a release image")
    if os.path.lexists(os.path.join(root, "usr", "sbin", "sshd")):
        drops = glob.glob(os.path.join(root, "etc", "systemd", "system", "ssh.service.d", "*.conf"))
        if not any("ssh-keygen -A" in _read_text(root, path) for path in drops):
            _fail("no host key generation in a release image")


def _read_text(root, path):
    if not _inside(os.path.realpath(root), path):
        _fail("blunix: scan failed")
    try:
        with open(path, "rb") as handle:
            return handle.read(1024 * 1024).decode("utf-8")
    except (OSError, UnicodeDecodeError):
        _fail("blunix: scan failed")


def _sshd_opens(text):
    for line in text.splitlines():
        words = re.split(r"[\s=]+", line.strip(), maxsplit=1)
        if len(words) != 2 or words[0].startswith("#"):
            continue
        key = words[0].lower()
        value = words[1].split("#", 1)[0].strip().strip('"').lower()
        if key in ("permitrootlogin", "passwordauthentication") and value == "yes":
            return True
    return False


def main():
    args = sys.argv[1:]
    release = bool(args) and args[0] == "--release"
    if release:
        args = args[1:]
    if len(args) != 1 or not os.path.isdir(args[0]):
        _fail("blunix: scan failed")
    root = os.path.abspath(args[0])
    root_real = os.path.realpath(root)
    needles = _secrets()
    if release:
        _release_checks(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if not _inside(root_real, dirpath):
            dirnames[:] = []
            continue
        kept = []
        for name in dirnames:
            if name in _VENDOR:
                _fail("vendor binary in image")
            child = os.path.join(dirpath, name)
            if _inside(root_real, child):
                kept.append(name)
        dirnames[:] = kept
        for name in filenames:
            path = os.path.join(dirpath, name)
            if name in _VENDOR:
                _fail("vendor binary in image")
            try:
                kind = os.lstat(path)
            except OSError:
                _fail("blunix: scan failed")
            if stat.S_ISLNK(kind.st_mode):
                try:
                    link = os.readlink(path)
                except OSError:
                    _fail("blunix: scan failed")
                encoded = link.encode("utf-8", "surrogateescape")
                for needle in needles:
                    if needle in encoded:
                        _fail("plaintext secret leaked into the image")
                if not _inside(root_real, path):
                    continue
                try:
                    info = os.stat(path)
                except OSError:
                    continue
            elif stat.S_ISREG(kind.st_mode):
                info = kind
            else:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            if not _inside(root_real, path):
                continue
            if _contains(path, needles):
                _fail("plaintext secret leaked into the image")


if __name__ == "__main__":
    main()

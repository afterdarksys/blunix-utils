"""Personal build fields: packages, an administrator, and unattended install.

Threats: a package list that becomes a shell or apt option, an administrator
that inherits root or a system account, a key field that carries a private
key or an authorized_keys option, an unattended install that erases a disk
nobody named, and a half-provisioned root that looks finished. Packages come
from a fixed allowlist and reach apt after `--`. Every command is an argv
list. The administrator key is an Ed25519 public key, decoded and checked
byte for byte. `install` is valid only with an exact `target`. Files changed
for the offline apt run are restored exactly, also on failure, and a failure
raises before bootstrap-complete is written.

What it does not stop: package versions drifting between installs. Packages
come from the image's configured Debian repositories at install time and are
not pinned; the versions apt chose are written to
/var/lib/blunix/packages.lock. Custom images from a pinned snapshot are the
reproducible path (docs/designs/blunix-personal-builds.md).
"""

from __future__ import annotations

import base64
import contextlib
import os
import re
from pathlib import Path

from blunix.cmd import run_cmd
from blunix.errors import BlunixError
from blunix.schema import require_keys, write_text

# The first-release allowlist. Names only: no versions, no options.
PACKAGES = (
    "curl", "dnsutils", "git", "htop", "jq", "nginx", "podman", "postgresql-client",
    "python3", "rsync", "strace", "tcpdump", "tmux", "vim", "wget",
)
_ADMIN_NAME = re.compile(r"[a-z][a-z0-9-]{0,30}")
_RESERVED_NAMES = frozenset((
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp",
    "proxy", "www-data", "backup", "list", "irc", "nobody", "systemd-network",
    "systemd-resolve", "systemd-timesync", "messagebus", "sshd", "_apt", "blunix",
))
_ED25519 = re.compile(r"ssh-ed25519 [A-Za-z0-9+/]{68}")
_ED25519_BLOB = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
# Installed with an administrator: the account needs sudo and a running sshd.
_ADMIN_PACKAGES = ("openssh-server", "sudo")
SSHD_CONFIG = (
    "PubkeyAuthentication yes\n"
    "PasswordAuthentication no\n"
    "KbdInteractiveAuthentication no\n"
    "PermitRootLogin no\n"
)


def parse_packages(value):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > len(PACKAGES):
        raise BlunixError("refused packages")
    if any(not isinstance(p, str) or p not in PACKAGES for p in value):
        raise BlunixError("refused packages")
    if len(set(value)) != len(value):
        raise BlunixError("refused packages")
    return sorted(value)


def parse_install(value, target):
    """`install` is the written permission to erase the exact `target`."""
    if value is None:
        return None
    if not isinstance(value, dict):
        raise BlunixError("refused install")
    require_keys(value, {"erase", "reboot"})
    if value.get("erase") is not True or not isinstance(value.get("reboot"), bool):
        raise BlunixError("refused install")
    if not target:
        raise BlunixError("refused install")
    return {"erase": True, "reboot": value["reboot"]}


def parse_admin(value):
    if value is None:
        return None
    if not isinstance(value, dict):
        raise BlunixError("refused admin")
    require_keys(value, {"name", "sshPublicKey"})
    name, key = value.get("name"), value.get("sshPublicKey")
    if not isinstance(name, str) or not _ADMIN_NAME.fullmatch(name) or name in _RESERVED_NAMES:
        raise BlunixError("refused admin")
    if not isinstance(key, str) or not _ED25519.fullmatch(key):
        raise BlunixError("refused public key")
    try:
        blob = base64.b64decode(key.split(" ")[1], validate=True)
    except ValueError:
        raise BlunixError("refused public key") from None
    if len(blob) != 51 or not blob.startswith(_ED25519_BLOB):
        raise BlunixError("refused public key")
    return {"name": name, "sshPublicKey": key}


@contextlib.contextmanager
def replacement(path, data, mode):
    """Swap in a file for the duration, then restore the file or symlink
    exactly, including after a failure."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    link = os.readlink(path) if path.is_symlink() else None
    exists = link is None and path.exists()
    original = path.read_bytes() if exists else None
    original_mode = path.stat().st_mode & 0o777 if exists else None
    if link is not None:
        path.unlink()
    try:
        path.write_bytes(data)
        path.chmod(mode)
        yield
    finally:
        if path.exists() or path.is_symlink():
            path.unlink()
        if link is not None:
            path.symlink_to(link)
        elif exists:
            path.write_bytes(original)
            path.chmod(original_mode)


def _passwd_entry(root, name):
    passwd = Path(root) / "etc" / "passwd"
    if not passwd.exists():
        return None
    for line in passwd.read_text().splitlines():
        fields = line.split(":")
        if len(fields) >= 7 and fields[0] == name:
            return fields
    return None


def provision(root, packages, admin, runner=run_cmd, log=None):
    """Install allowlisted packages and the administrator into `root`.
    Writes nothing when both are empty."""
    packages = parse_packages(packages)
    admin = parse_admin(admin)
    if not packages and admin is None:
        return None
    root = os.path.abspath(root)
    prefix = [] if root == "/" else ["chroot", root]

    def command(args, timeout=1800):
        return runner(prefix + args, check=True, timeout=timeout, capture_output=True)

    wanted = sorted(set(packages) | (set(_ADMIN_PACKAGES) if admin else set()))
    with contextlib.ExitStack() as stack:
        if prefix:
            # The written root's resolv.conf can point into /run, which is not
            # mounted there, and package scripts must not start services.
            resolv = Path("/etc/resolv.conf").read_bytes()
            stack.enter_context(replacement(Path(root) / "etc/resolv.conf", resolv, 0o644))
            stack.enter_context(
                replacement(Path(root) / "usr/sbin/policy-rc.d", b"#!/bin/sh\nexit 101\n", 0o755)
            )
        apt = ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get"]
        command(apt + ["update"])
        command(apt + ["-y", "--no-install-recommends", "-o", "Dpkg::Options::=--force-confold",
                       "install", "--"] + wanted)
        result = command(["dpkg-query", "-W", "-f=${binary:Package}=${Version}\n"], timeout=60)
        manifest = result.stdout
        if isinstance(manifest, bytes):
            manifest = manifest.decode("utf-8")
        write_text(os.path.join(root, "var/lib/blunix/packages.lock"), manifest, 0o644)
        if log is not None and packages:
            log("blunix: installed " + ", ".join(packages)
                + " from the image's Debian repositories; versions are in packages.lock and are not pinned")
        if admin is not None:
            _admin(root, admin, command)
            if log is not None:
                log("blunix: administrator " + admin["name"] + " can sign in with the SSH key; passwords are off")
    return wanted


def _admin(root, admin, command):
    name = admin["name"]
    existing = _passwd_entry(root, name)
    # Never hand sudo to a system account or an account with another home.
    if existing and (int(existing[2]) < 1000 or existing[5] != "/home/" + name):
        raise BlunixError("refused existing admin")
    if not existing:
        # No per-user group: Debian already has system groups with common
        # names (operator is gid 37), and useradd fails on a clash.
        command(["useradd", "--create-home", "--no-user-group", "--gid", "users",
                 "--shell", "/bin/bash", "--", name], timeout=60)
    entry = _passwd_entry(root, name)
    if entry is None or int(entry[2]) < 1000:
        raise BlunixError("refused existing admin")
    folder = Path(root) / "home" / name / ".ssh"
    folder.mkdir(parents=True, exist_ok=True)
    folder.chmod(0o700)
    write_text(str(folder / "authorized_keys"), admin["sshPublicKey"] + "\n", 0o600)
    command(["chown", "-R", entry[2] + ":" + entry[3], "/home/" + name + "/.ssh"], timeout=60)
    write_text(os.path.join(root, "etc/sudoers.d/blunix-admin"),
               name + " ALL=(ALL:ALL) NOPASSWD: ALL\n", 0o440)
    write_text(os.path.join(root, "etc/ssh/sshd_config.d/00-blunix-admin.conf"), SSHD_CONFIG, 0o644)
    command(["systemctl", "enable", "ssh.service"], timeout=60)

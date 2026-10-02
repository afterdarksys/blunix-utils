"""`blunix install`: the live-medium flow from blunix-install-plane.md.

Threats: an installer that erases the wrong disk, a key that leaks into a
spoken or logged line, TLS that does not verify, a LAN proxy that swaps the
document, an oversized download, and an image that was changed on the medium.
The boot medium, a disk in use, a read-only disk, and a disk smaller than the
image are never candidates. The boot medium is the disk under
/run/live/medium, any disk named by live-media=, bootfrom= or fromiso= on the
kernel command line, and any disk carrying the ISO's BLUNIX_INSTALL label, so
a stick booted with toram is still refused. A disk the document's `target`
did not name needs a typed yes, blank or not, and silence is no. Right before
the write the disks are listed again: the chosen disk must have the same
serial and size, it is opened by /dev/disk/by-id when there is one, and the
opened device's size must match, or nothing is written. The key is read with echo off, tried through keyfmt, and never
passed to a say line. Fetch is https with the default verifier and TLS 1.2 or
higher, or plain http to a proxy only when the kernel command line names one;
age is authenticated, so a swapped body does not decrypt; through a proxy the
installer also says the ciphertext's full sha256 to compare with the install
card, so a replayed older document is seen. The image's sha256
is checked before the first byte reaches the disk and again after the write.
When the medium carries only a release pin, the image streams from the
GitHub release over verified TLS, redirects stay on GitHub's release hosts,
and the stream's sha256 must match the pin on the medium: the machine trusts
a digest, never a host. A refused document, a wrong key, or a digest
mismatch applies nothing.

What it does not stop: a person who has both the URL and the key, a
malicious hypervisor or firmware, or an unsigned image. The image digest comes
from the same medium as the image, so it proves the stick is intact, not who
built it. Image signing is still open in blunix-os.md. A release download
that does not match is found only after it reached the disk; the installer
then says the disk is not bootable and applies nothing else.

Every side effect is a hook, so tests can run the flow without a disk.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import re
import select
import stat
import struct
import subprocess
import sys
import termios
import threading
import time
import urllib.parse
import urllib.request

from blunix.age import decrypt_bytes
from blunix.bootstrap import (
    decrypt_candidates,
    default_ip_show,
    fetch_https,
    read_cap,
    tls_context,
    wait_global,
)
from blunix.cmd import run_cmd
from blunix.disk import min_bytes
from blunix.errors import BlunixError
from blunix.network import parse_inline_network, write_network
from blunix.node import apply_node, check_node
from blunix.schema import expand_build_host, require_build_host

LIVE_MEDIUM = "/run/live/medium"
MEDIUM_LABEL = "BLUNIX_INSTALL"  # build-installer.sh sets it as the ISO volume id
BY_ID = "/dev/disk/by-id"
_BLKGETSIZE64 = 0x80081272
_MEDIUM_ARGS = ("live-media=", "bootfrom=", "fromiso=")
IMAGE_DIRS = (LIVE_MEDIUM + "/blunix", "/usr/share/blunix/image")
IMAGE_NAME = "blunix.raw.zst"
RELEASE_NAME = "blunix.release"
RELEASE_REPO = "/afterdarksys/blunix/releases/download/"
RELEASE_HOSTS = (
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
)
MAX_IMAGE = 2 * 1024 ** 3  # GitHub's per-asset limit
NETWORK_DIR = "/run/systemd/network"
TARGET = "/mnt/blunix-target"
LOCK = "/run/blunix-install.lock"
ROOT_LABEL = "blunix-root"
ESP_LABEL = "ESP"
ESP_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
LSBLK = [
    "lsblk",
    "-J",
    "-b",
    "-o",
    "NAME,SIZE,TYPE,MODEL,SERIAL,TRAN,RM,RO,MOUNTPOINTS,PKNAME,FSTYPE,PTTYPE,LABEL",
]
DHCP_ATTEMPTS = 7  # six pauses of five seconds: 30 s
ANSWER_TIMEOUT = 120
_MAX_LSBLK = 1024 * 1024
_CHUNK = 4 * 1024 * 1024
_SAFE = re.compile(r"[\x20-\x7e]{1,240}")
_PROXY_HOST = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*")
_PORT = re.compile(r"[1-9][0-9]{0,4}")
_HEX = re.compile(r"[0-9a-f]{64}")
_RELEASE_VERSION = re.compile(r"v?[0-9][0-9A-Za-z.+-]{0,63}")
_RELEASE_KEYS = ("version", "sha256", "size")
_SKIP = ("zram", "ram", "loop", "nbd", "sr", "fd")
_WIRED = ["en*", "eth*"]

NO_NETWORK = "blunix: no network. Type an address like 10.0.0.5/24, or press enter to try again."
ASK_GATEWAY = "blunix: gateway. Type an address like 10.0.0.1."
ASK_DNS = "blunix: dns server. Type an address like 10.0.0.1."
ASK_HOST = "blunix: build hostname."
ASK_KEY = "blunix: key. Type it. It will not be spoken."
NOTHING = "Nothing applied."


class _Stop(Exception):
    """End the flow with one sentence. Nothing after this point runs."""

    def __init__(self, sentence):
        super().__init__(sentence)
        self.sentence = sentence


def _line(message):
    if not isinstance(message, str) or not _SAFE.fullmatch(message):
        raise BlunixError("refused log line")
    print(message, flush=True)


def _read_line(timeout=None):
    """One line from the console. Silence past the timeout is an empty answer."""
    if timeout is not None:
        try:
            ready, _, _ = select.select([sys.stdin], [], [], timeout)
        except (OSError, ValueError):
            raise EOFError()
        if not ready:
            return ""
    line = sys.stdin.readline(512)
    if line == "":
        raise EOFError()
    return line


def _read_hidden():
    """Read the key with echo off. No tty means no key: fail closed."""
    fd = sys.stdin.fileno()
    if not os.isatty(fd):
        raise EOFError()
    old = termios.tcgetattr(fd)
    new = termios.tcgetattr(fd)
    new[3] &= ~(termios.ECHO | termios.ECHONL)
    try:
        termios.tcsetattr(fd, termios.TCSAFLUSH, new)
        line = sys.stdin.readline(512)
    finally:
        termios.tcsetattr(fd, termios.TCSAFLUSH, old)
        print("", flush=True)
    if line == "":
        raise EOFError()
    return line.rstrip("\r\n")


_LOCK_FD = []


def _claim():
    """Two consoles may show the prompts. The first one answered wins."""
    if _LOCK_FD:
        return True
    try:
        fd = os.open(LOCK, os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC, 0o600)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return False
    _LOCK_FD.append(fd)
    return True


def _read_cmdline():
    try:
        with open("/proc/cmdline", "r", encoding="utf-8") as handle:
            return handle.read(4096)
    except OSError:
        return ""


def _dhcp():
    write_network(parse_inline_network({"match": _WIRED, "dhcp": True}), NETWORK_DIR)
    run_cmd(["networkctl", "reload"], check=False, capture_output=True, timeout=30)


def _static(model):
    write_network(model, NETWORK_DIR)
    run_cmd(["networkctl", "reload"], check=False, capture_output=True, timeout=30)


def _lsblk():
    proc = run_cmd(LSBLK, capture_output=True, timeout=30, check=False)
    if proc.returncode != 0 or len(proc.stdout) > _MAX_LSBLK:
        raise BlunixError("disk list failed")
    return proc.stdout.decode("utf-8", "replace")


def _mount_source(path):
    try:
        proc = run_cmd(
            ["findmnt", "-n", "-o", "SOURCE", "--target", path],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout.decode("utf-8", "replace").strip()


def _reboot():
    run_cmd(["systemctl", "reboot"], check=False)


def _sync():
    run_cmd(["sync"], check=False, timeout=600)


class Hooks:
    """Every side effect of `blunix install`. Tests replace any of them."""

    def __init__(self, **overrides):
        self.say = _line
        self.read = _read_line
        self.read_key = _read_hidden
        self.claim = _claim
        self.cmdline = _read_cmdline
        self.ip_show = default_ip_show
        self.sleep = time.sleep
        self.dhcp = _dhcp
        self.static = _static
        self.lister = _lsblk
        self.mount_source = _mount_source
        self.by_id = disk_by_id
        self.find_image = find_image
        self.fetch = fetch_document
        self.decrypt = decrypt_bytes
        self.write_image = write_image
        self.open_target = open_target
        self.apply = apply_node
        self.bootloader = install_bootloader
        self.sync = _sync
        self.reboot = _reboot
        for name, value in overrides.items():
            if not hasattr(self, name):
                raise BlunixError("refused hook")
            setattr(self, name, value)


# Proxy and fetch


def parse_proxy(cmdline):
    """`blunix.proxy=HOST:PORT` from the kernel command line, or None."""
    if not isinstance(cmdline, str):
        return None
    found = None
    for token in cmdline.split():
        if token.startswith("blunix.proxy="):
            if found is not None:
                raise BlunixError("refused proxy")
            found = token[len("blunix.proxy="):]
    if found is None:
        return None
    return check_proxy(found)


def check_proxy(value):
    if not isinstance(value, str) or len(value) > 262:
        raise BlunixError("refused proxy")
    if value.startswith("["):
        host, sep, port = value[1:].partition("]:")
        if not sep:
            raise BlunixError("refused proxy")
        try:
            if ipaddress.ip_address(host).version != 6:
                raise BlunixError("refused proxy")
        except ValueError:
            raise BlunixError("refused proxy")
        host = "[" + host + "]"
    else:
        host, sep, port = value.rpartition(":")
        if not sep or not host:
            raise BlunixError("refused proxy")
        host = host.lower()
        if not _PROXY_HOST.fullmatch(host) or len(host) > 253:
            raise BlunixError("refused proxy")
    if not _PORT.fullmatch(port) or int(port) > 65535:
        raise BlunixError("refused proxy")
    return host + ":" + port


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise BlunixError("refused url")


def proxy_url(proxy, host):
    return "http://" + check_proxy(proxy) + "/v1/build/" + require_build_host(host)


def fetch_document(host, proxy=None, urlopen=None, context_factory=None, timeout=30):
    """Direct https to the build host, or the named LAN proxy. Both are capped."""
    if proxy is None:
        return fetch_https(
            host,
            urlopen=urlopen,
            context_factory=context_factory,
            timeout=timeout,
        )
    url = proxy_url(proxy, host)
    req = urllib.request.Request(
        url, method="GET", headers={"User-Agent": "blunix-install"}
    )
    if urlopen is None:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect()
        )

        def urlopen(request, timeout=timeout):
            return opener.open(request, timeout=timeout)

    resp = None
    try:
        try:
            resp = urlopen(req, timeout=timeout)
        except BlunixError:
            raise
        except Exception:
            raise BlunixError("document fetch failed")
        return read_cap(resp)
    finally:
        close = getattr(resp, "close", None)
        if close is not None:
            close()


# Image


def zstd_content_size(head):
    """Frame_Content_Size from the first zstd frame header, or None."""
    if len(head) < 6 or head[:4] != b"\x28\xb5\x2f\xfd":
        return None
    desc = head[4]
    fcs_flag = desc >> 6
    single = (desc >> 5) & 1
    dict_flag = desc & 3
    pos = 5
    if not single:
        pos += 1
    pos += (0, 1, 2, 4)[dict_flag]
    width = (1 if single else 0, 2, 4, 8)[fcs_flag]
    if width == 0 or len(head) < pos + width:
        return None
    value = int.from_bytes(head[pos:pos + width], "little")
    if width == 2:
        value += 256
    return value


def read_release(path):
    """A release pin on the medium: version=, sha256= and size= lines."""
    try:
        with open(path, "rb") as handle:
            text = handle.read(1024).decode("ascii")
    except (OSError, UnicodeDecodeError):
        raise BlunixError("image refused")
    fields = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or key in fields or key not in _RELEASE_KEYS:
            raise BlunixError("image refused")
        fields[key] = value
    if tuple(sorted(fields)) != tuple(sorted(_RELEASE_KEYS)):
        raise BlunixError("image refused")
    if not _RELEASE_VERSION.fullmatch(fields["version"]):
        raise BlunixError("image refused")
    if not _HEX.fullmatch(fields["sha256"]):
        raise BlunixError("image refused")
    if not fields["size"].isdigit() or fields["size"].startswith("0"):
        raise BlunixError("image refused")
    return {
        "url": release_url(fields["version"]),
        "version": fields["version"],
        "sha256": fields["sha256"],
        "size": int(fields["size"]),
    }


def release_url(version):
    if not isinstance(version, str) or not _RELEASE_VERSION.fullmatch(version):
        raise BlunixError("image refused")
    return "https://github.com" + RELEASE_REPO + version + "/" + IMAGE_NAME


def check_release_url(url):
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or host not in RELEASE_HOSTS:
        raise BlunixError("refused url")
    if parts.username or parts.password or parts.fragment or parts.port not in (None, 443):
        raise BlunixError("refused url")
    if host == "github.com" and not parts.path.startswith(RELEASE_REPO):
        raise BlunixError("refused url")
    return url


class _ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_release_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def find_image(dirs=IMAGE_DIRS):
    """The medium's image and .sha256, else the medium's release pin."""
    for folder in dirs:
        path = os.path.join(folder, IMAGE_NAME)
        if not os.path.isfile(path):
            continue
        try:
            with open(path + ".sha256", "rb") as handle:
                text = handle.read(512).decode("ascii")
            with open(path, "rb") as handle:
                head = handle.read(18)
        except (OSError, UnicodeDecodeError):
            raise BlunixError("image refused")
        fields = text.split()
        if not fields or not _HEX.fullmatch(fields[0]):
            raise BlunixError("image refused")
        size = zstd_content_size(head)
        if not size:
            raise BlunixError("image refused")
        return {"path": path, "sha256": fields[0], "size": size}
    for folder in dirs:
        pin = os.path.join(folder, RELEASE_NAME)
        if os.path.isfile(pin):
            return read_release(pin)
    raise BlunixError("no image")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(_CHUNK)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


class DiskChanged(BlunixError):
    """The opened device is not the disk that was listed. Nothing was written."""

    def __init__(self):
        super().__init__("disk changed")


def _open_disk(device, size):
    """O_EXCL on a block device fails if the kernel has it in use."""
    fd = os.open(device, os.O_WRONLY | os.O_EXCL | os.O_CLOEXEC)
    if size is None:
        return fd
    try:
        info = os.fstat(fd)
        if stat.S_ISBLK(info.st_mode):
            raw = fcntl.ioctl(fd, _BLKGETSIZE64, bytes(8))
            actual = struct.unpack("Q", raw)[0]
        elif stat.S_ISREG(info.st_mode):
            actual = info.st_size
        else:
            actual = -1
    except OSError:
        actual = -1
    if actual != size:
        os.close(fd)
        raise DiskChanged()
    return fd


class ImageMismatch(BlunixError):
    """The image does not match its digest. `written` says if the disk changed."""

    def __init__(self, written):
        super().__init__("image digest mismatch")
        self.written = written


def write_image(image, device, urlopen=None, context_factory=None, size=None):
    """Verify, stream `zstd -dc` into the disk, then verify the source again.

    With `size`, the opened device must be exactly that many bytes.
    """
    if "url" in image:
        return _write_release(image, device, urlopen, context_factory, size)
    if not hmac.compare_digest(sha256_file(image["path"]), image["sha256"]):
        raise ImageMismatch(False)
    fd = _open_disk(device, size)
    try:
        proc = run_cmd(
            ["zstd", "-dc", "-q", "--no-progress", "--", image["path"]],
            stdout=fd,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        os.fsync(fd)
    finally:
        os.close(fd)
    if proc.returncode != 0:
        raise BlunixError("image write failed")
    if not hmac.compare_digest(sha256_file(image["path"]), image["sha256"]):
        raise ImageMismatch(True)


def _open_release(url, urlopen, context_factory, timeout=60):
    check_release_url(url)
    context = tls_context(context_factory)
    req = urllib.request.Request(
        url, method="GET", headers={"User-Agent": "blunix-install"}
    )
    if urlopen is None:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _ReleaseRedirect(),
            urllib.request.HTTPSHandler(context=context),
        )

        def urlopen(request, timeout=timeout, context=context):
            return opener.open(request, timeout=timeout)

    try:
        return urlopen(req, timeout=timeout, context=context)
    except BlunixError:
        raise
    except Exception:
        raise BlunixError("image download failed")


def _write_release(image, device, urlopen, context_factory, size=None):
    """Stream the release asset through sha256 and `zstd -dc` into the disk."""
    fd = _open_disk(device, size)
    try:
        resp = _open_release(image["url"], urlopen, context_factory)
    except BaseException:
        os.close(fd)
        raise
    digest = hashlib.sha256()
    failed = []
    read_end, write_end = os.pipe()

    def pump():
        total = 0
        try:
            while True:
                block = resp.read(_CHUNK)
                if not block:
                    break
                total += len(block)
                if total > MAX_IMAGE:
                    raise BlunixError("image too large")
                digest.update(block)
                view = memoryview(block)
                while view:
                    view = view[os.write(write_end, view):]
        except Exception:
            failed.append(True)
        finally:
            os.close(write_end)

    worker = threading.Thread(target=pump, daemon=True)
    try:
        worker.start()
        proc = run_cmd(
            ["zstd", "-dc", "-q", "--no-progress"],
            stdin=read_end,
            stdout=fd,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        worker.join()
        os.fsync(fd)
    finally:
        os.close(read_end)
        os.close(fd)
        close = getattr(resp, "close", None)
        if close is not None:
            close()
    if failed or proc.returncode != 0:
        raise BlunixError("image write failed")
    if not hmac.compare_digest(digest.hexdigest(), image["sha256"]):
        raise ImageMismatch(True)


# Disks


def _flag(value):
    return value in (True, 1, "1", "true")


def _size(value):
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


def _clean(value, limit=40):
    if not isinstance(value, str):
        return ""
    text = "".join(ch if ch.isascii() and (ch.isalnum() or ch in " ._-") else " " for ch in value)
    return " ".join(text.split())[:limit].strip()


def _names(node):
    found = [node.get("name")]
    for child in node.get("children") or []:
        found.extend(_names(child))
    return [name for name in found if isinstance(name, str)]


def _mounted(node):
    points = node.get("mountpoints")
    if points is None and "mountpoint" in node:
        points = [node.get("mountpoint")]
    if any(point for point in points or []):
        return True
    return any(_mounted(child) for child in node.get("children") or [])


def boot_names(mount_source, cmdline=""):
    """Kernel names of the boot medium and of the device holding /.

    With toram, /run/live/medium is a copy in RAM, so the command line's
    live-media=, bootfrom= and fromiso= devices count too.
    """
    sources = [mount_source(path) for path in (LIVE_MEDIUM, "/")]
    if isinstance(cmdline, str):
        for token in cmdline.split():
            for arg in _MEDIUM_ARGS:
                if token.startswith(arg):
                    parts = token[len(arg):].split("/")
                    keep = 5 if parts[1:3] == ["dev", "disk"] else 3
                    sources.append("/".join(parts[:keep]))
    names = set()
    for source in sources:
        if isinstance(source, str) and source.startswith("/dev/"):
            names.add(os.path.basename(os.path.realpath(source)))
            names.add(os.path.basename(source))
    names.discard("")
    return names


def _labels(node):
    found = [node.get("label")]
    for child in node.get("children") or []:
        found.extend(_labels(child))
    return found


def disk_by_id(name, folder=BY_ID):
    """A /dev/disk/by-id path for the whole disk `name`, else /dev/name."""
    try:
        entries = sorted(os.listdir(folder))
    except OSError:
        return "/dev/" + name
    for entry in entries:
        if "-part" in entry:
            continue
        path = os.path.join(folder, entry)
        if os.path.basename(os.path.realpath(path)) == name:
            return path
    return "/dev/" + name


def disk_candidates(listing, boot, need):
    """Split lsblk JSON into disks that may be erased and disks that may not."""
    if isinstance(listing, (bytes, bytearray)):
        listing = listing.decode("utf-8", "replace")
    if not isinstance(listing, str) or len(listing) > _MAX_LSBLK:
        raise BlunixError("disk list failed")
    try:
        tree = json.loads(listing)
    except ValueError:
        raise BlunixError("disk list failed")
    devices = tree.get("blockdevices") if isinstance(tree, dict) else None
    if not isinstance(devices, list):
        raise BlunixError("disk list failed")
    good = []
    refused = []
    for node in devices:
        if not isinstance(node, dict) or node.get("type") != "disk":
            continue
        name = node.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9]{1,31}", name):
            continue
        if name.startswith(_SKIP):
            continue
        if boot & set(_names(node)) or MEDIUM_LABEL in _labels(node):
            refused.append((name, "boot medium"))
            continue
        if _mounted(node):
            refused.append((name, "in use"))
            continue
        if _flag(node.get("ro")):
            refused.append((name, "read-only"))
            continue
        size = _size(node.get("size"))
        if size < need:
            refused.append((name, "too small"))
            continue
        children = node.get("children") or []
        good.append(
            {
                "name": name,
                "size": size,
                "model": _clean(node.get("model")),
                "serial": _clean(node.get("serial"), 64),
                "used": bool(children or node.get("fstype") or node.get("pttype")),
            }
        )
    return good, refused


def describe(disk):
    words = [disk["name"], str(max(1, round(disk["size"] / 1e9))) + " gigabytes"]
    if disk["model"]:
        words.append(disk["model"])
    return ", ".join(words)


# The flow


class _Flow:
    def __init__(self, hooks, models):
        self.h = hooks
        self.models = models

    def say(self, sentence):
        self.h.say(sentence)

    def ask(self, sentence, timeout=None):
        self.say(sentence)
        try:
            answer = self.h.read(timeout)
        except (EOFError, OSError):
            raise _Stop("blunix: no answer. " + NOTHING)
        if not isinstance(answer, str):
            return ""
        answer = answer.strip()
        if answer and not self.h.claim():
            raise _Stop("blunix: another console is installing.")
        return answer

    def yes(self, sentence):
        """Silence, or anything but yes, is no. The question is asked twice."""
        for _ in range(2):
            answer = self.ask(sentence, ANSWER_TIMEOUT).lower()
            if answer == "yes":
                return True
            if answer == "no":
                return False
        return False

    def network(self):
        while True:
            self.h.dhcp()
            found = wait_global(self.h.ip_show, sleeper=self.h.sleep, attempts=DHCP_ATTEMPTS)
            if found is not None:
                self.say("blunix: network up at " + found[0] + " on " + found[1] + ".")
                return found
            if self.static_prompt():
                found = wait_global(self.h.ip_show, sleeper=self.h.sleep, attempts=DHCP_ATTEMPTS)
                if found is not None:
                    self.say("blunix: network up at " + found[0] + " on " + found[1] + ".")
                    return found
                self.say("blunix: that address did not come up.")

    def static_prompt(self):
        address = self.ask(NO_NETWORK)
        if not address:
            return False
        for _ in range(3):
            gateway = self.ask(ASK_GATEWAY)
            dns = self.ask(ASK_DNS)
            try:
                model = parse_inline_network(
                    {"match": _WIRED, "address": address, "gateway": gateway, "dns": [dns]}
                )
            except BlunixError:
                self.say("blunix: refused address. Try again.")
                address = self.ask(NO_NETWORK)
                if not address:
                    return False
                continue
            self.h.static(model)
            return True
        return False

    def hostname(self):
        for _ in range(3):
            typed = self.ask(ASK_HOST).lower()
            try:
                host = expand_build_host(typed)
            except BlunixError:
                self.say("blunix: refused hostname.")
                continue
            if self.yes("blunix: hostname " + host + ". Say yes to keep it."):
                return host
        raise _Stop("blunix: no hostname. " + NOTHING)

    def key(self):
        self.say(ASK_KEY)
        try:
            typed = self.h.read_key()
        except (EOFError, OSError):
            raise _Stop("blunix: no key. " + NOTHING)
        if not isinstance(typed, str) or not typed.strip():
            raise _Stop("blunix: no key. " + NOTHING)
        return typed

    def fetch(self, host, proxy):
        try:
            return self.h.fetch(host, proxy)
        except BlunixError as exc:
            if str(exc) == "document too large":
                raise _Stop("blunix: document too large. " + NOTHING)
            if str(exc) == "tls verify disabled":
                raise _Stop("blunix: tls verify disabled. " + NOTHING)
            raise _Stop("blunix: fetch failed. " + NOTHING)

    def document(self, ciphertext, typed):
        plain = decrypt_candidates(ciphertext, typed, decrypt=self.h.decrypt)
        if plain is None:
            raise _Stop("blunix: could not decrypt. " + NOTHING)
        try:
            checked = check_node(plain, self.models)
        except BlunixError:
            raise _Stop("blunix: document refused. " + NOTHING)
        return plain, checked

    def disk(self, checked, image):
        need = max(image["size"], min_bytes(checked["disk"]))
        good = self.candidates(need)
        target = checked["parsed"].get("target")
        if target is not None:
            match = [d for d in good if target in (d["name"], d["serial"])]
            if len(match) != 1:
                raise _Stop("blunix: target disk " + target + " is not usable. " + NOTHING)
            chosen = match[0]
        elif not good:
            raise _Stop("blunix: no disk fits the image. " + NOTHING)
        elif len(good) == 1:
            chosen = good[0]
        else:
            chosen = self.choose(good)
        if chosen["used"] or target is None:
            question = "blunix: erase disk " + describe(chosen) + ". Say yes to erase."
            if not self.yes(question):
                raise _Stop("blunix: disk " + chosen["name"] + " kept. " + NOTHING)
        return chosen

    def candidates(self, need):
        boot = boot_names(self.h.mount_source, self.h.cmdline())
        try:
            good, _refused = disk_candidates(self.h.lister(), boot, need)
        except (BlunixError, subprocess.TimeoutExpired, OSError):
            raise _Stop("blunix: could not list disks. " + NOTHING)
        return good

    def recheck(self, disk):
        """Minutes passed since the choice. The same disk must still be there."""
        same = [d for d in self.candidates(0) if d["name"] == disk["name"]]
        if len(same) != 1 or (same[0]["serial"], same[0]["size"]) != (disk["serial"], disk["size"]):
            raise _Stop("blunix: disk " + disk["name"] + " changed since it was chosen. " + NOTHING)
        try:
            return self.h.by_id(disk["name"])
        except OSError:
            return "/dev/" + disk["name"]

    def choose(self, good):
        for index, disk in enumerate(good, 1):
            self.say("blunix: disk " + str(index) + " is " + describe(disk) + ".")
        for _ in range(2):
            answer = self.ask("blunix: type the disk number.", ANSWER_TIMEOUT)
            if answer.isdigit() and 1 <= int(answer) <= len(good):
                return good[int(answer) - 1]
        raise _Stop("blunix: no disk chosen. " + NOTHING)

    def install(self, plain, parsed, image, disk):
        device = "/dev/" + disk["name"]
        if "url" in image:
            self.say("blunix: the image comes from release " + image["version"] + " on github.com.")
        opened = self.recheck(disk)
        self.say("blunix: writing the image to " + disk["name"] + ".")
        try:
            self.h.write_image(image, opened, size=disk["size"])
        except DiskChanged:
            raise _Stop("blunix: disk " + disk["name"] + " changed since it was chosen. " + NOTHING)
        except ImageMismatch as exc:
            if exc.written:
                raise _Stop("blunix: image digest did not match. The disk is not bootable.")
            raise _Stop("blunix: image digest did not match. " + NOTHING)
        except Exception:
            raise _Stop("blunix: image write failed. The disk is not bootable.")
        self.say("blunix: image written and verified.")
        close = None
        try:
            try:
                root, close = self.h.open_target(device)
                self.h.apply(plain, root, models=self.models, log=self.say)
                self.h.bootloader(root, device)
            except Exception:
                raise _Stop("blunix: install failed on " + disk["name"] + ". The disk is not bootable.")
        finally:
            if close is not None:
                close()
            self.h.sync()

    def run(self):
        try:
            image = self.h.find_image()
        except (BlunixError, OSError):
            raise _Stop("blunix: no image on this medium. " + NOTHING)
        try:
            proxy = parse_proxy(self.h.cmdline())
        except BlunixError:
            raise _Stop("blunix: refused proxy. " + NOTHING)
        self.network()
        if proxy is not None:
            self.say("blunix: using the proxy at " + proxy + ".")
        host = self.hostname()
        typed = self.key()
        ciphertext = self.fetch(host, proxy)
        plain, checked = self.document(ciphertext, typed)
        typed = None
        parsed = checked["parsed"]
        digest = hashlib.sha256(ciphertext).hexdigest()
        self.say("blunix: document " + parsed["name"] + " from " + host + ", digest " + digest[:12] + ".")
        if proxy is not None:
            self.say("blunix: document sha256 " + digest + ". Compare it with the install card.")
        disk = self.disk(checked, image)
        self.install(plain, parsed, image, disk)
        if self.yes("blunix: installed " + parsed["hostname"] + ". Remove the stick. Say yes to reboot."):
            self.h.reboot()
        else:
            self.say("blunix: not rebooting.")
        return 0


def run_install(hooks=None, models=None):
    if hooks is None:
        hooks = Hooks()
    try:
        return _Flow(hooks, models).run()
    except _Stop as stop:
        hooks.say(stop.sentence)
        return 1
    except Exception:
        hooks.say("blunix: install failed.")
        return 1


# Default target preparation and bootloader


def _run(argv, ok=(0,), timeout=600):
    proc = run_cmd(argv, capture_output=True, timeout=timeout, check=False)
    if proc.returncode not in ok:
        raise BlunixError("install step failed")
    return proc


def _partitions(device):
    proc = _run(["lsblk", "-J", "-b", "-o", "NAME,TYPE,LABEL,PARTTYPE", device])
    tree = json.loads(proc.stdout.decode("utf-8", "replace"))
    found = {}
    for disk in tree.get("blockdevices", []):
        for part in disk.get("children") or []:
            if part.get("type") != "part":
                continue
            label = part.get("label")
            ptype = (part.get("parttype") or "").lower()
            if label == ROOT_LABEL:
                found["root"] = part["name"]
            elif label == ESP_LABEL or ptype == ESP_TYPE:
                found["esp"] = part["name"]
    if "root" not in found:
        raise BlunixError("root partition missing")
    return found


def _partition_number(name):
    with open(os.path.join("/sys/class/block", name, "partition"), "r", encoding="ascii") as handle:
        text = handle.read(16).strip()
    if not text.isdigit():
        raise BlunixError("root partition missing")
    return text


def open_target(device, mountpoint=TARGET):
    """Grow the root to the disk, mount it with its ESP, and bind /dev /proc /sys."""
    _run(["blockdev", "--rereadpt", device])
    _run(["udevadm", "settle"], timeout=60)
    _run(["sgdisk", "-e", device])
    _run(["udevadm", "settle"], timeout=60)
    parts = _partitions(device)
    root_dev = "/dev/" + parts["root"]
    # growpart exits 1 when there is nothing to grow.
    _run(["growpart", device, _partition_number(parts["root"])], ok=(0, 1))
    _run(["udevadm", "settle"], timeout=60)
    _run(["e2fsck", "-f", "-p", root_dev], ok=(0, 1))
    _run(["resize2fs", root_dev])
    os.makedirs(mountpoint, exist_ok=True)
    mounted = []

    def close():
        for path in reversed(mounted):
            run_cmd(["umount", path], check=False, capture_output=True, timeout=60)
        mounted.clear()

    try:
        _run(["mount", root_dev, mountpoint])
        mounted.append(mountpoint)
        if "esp" in parts:
            esp = os.path.join(mountpoint, "boot", "efi")
            os.makedirs(esp, exist_ok=True)
            _run(["mount", "/dev/" + parts["esp"], esp])
            mounted.append(esp)
        for name in ("dev", "proc", "sys"):
            path = os.path.join(mountpoint, name)
            _run(["mount", "--bind", "/" + name, path])
            mounted.append(path)
    except BaseException:
        close()
        raise
    return mountpoint, close


def install_bootloader(root, device):
    """grub-install for EFI and BIOS where the image carries the modules.

    The image's own grub.cfg is the five-key access menu. update-grub runs only
    when that menu is absent, so the menu is never replaced.
    """
    done = False
    efi_dir = os.path.join(root, "boot", "efi")
    if os.path.isdir(os.path.join(root, "usr", "lib", "grub", "x86_64-efi")) and os.path.ismount(efi_dir):
        proc = run_cmd(
            [
                "chroot",
                root,
                "grub-install",
                "--target=x86_64-efi",
                "--efi-directory=/boot/efi",
                "--boot-directory=/boot",
                "--removable",
                "--no-nvram",
            ],
            capture_output=True,
            timeout=600,
            check=False,
        )
        done = done or proc.returncode == 0
    if os.path.isdir(os.path.join(root, "usr", "lib", "grub", "i386-pc")):
        proc = run_cmd(
            ["chroot", root, "grub-install", "--target=i386-pc", device],
            capture_output=True,
            timeout=600,
            check=False,
        )
        done = done or proc.returncode == 0
    if not done:
        raise BlunixError("bootloader failed")
    cfg = os.path.join(root, "boot", "grub", "grub.cfg")
    try:
        with open(cfg, "r", encoding="utf-8", errors="replace") as handle:
            menu = handle.read(65536)
    except OSError:
        menu = ""
    if "--id blunix-regular" not in menu:
        _run(["chroot", root, "update-grub"])

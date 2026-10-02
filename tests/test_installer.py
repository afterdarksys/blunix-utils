"""The install plane on the machine: build host names, inline network, the key
format, and `blunix install`.

Threats: the wrong disk erased, a key in a spoken line, TLS that does not
verify, a proxy used without being named, an oversized body, an image that
does not match its digest, and a shell script where a document belongs. Each
test drives the failure path and checks nothing was written.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import unittest
import urllib.request

from blunix.age import encrypt_bytes
from blunix.bootstrap import (
    MAX_CIPHER,
    decrypt_candidates,
    run_bootstrap,
    tls_context,
)
from blunix.cli import main
from blunix.errors import BlunixError, DecryptError
from blunix.installer import (
    ASK_HOST,
    ASK_KEY,
    MEDIUM_LABEL,
    NO_NETWORK,
    DiskChanged,
    Hooks,
    ImageMismatch,
    _NoRedirect,
    _ReleaseRedirect,
    boot_names,
    check_release_url,
    disk_by_id,
    disk_candidates,
    fetch_document,
    find_image,
    parse_proxy,
    read_release,
    release_url,
    run_install,
    write_image,
    zstd_content_size,
)
from blunix.keyfmt import canonical_key, display_key, generate_key
from blunix.network import parse_inline_network, parse_network, render_network
from blunix.node import apply_node, boot_node, parse_node
from blunix.schema import expand_build_host, load_path, load_text, require_build_host

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODELS = os.path.join(ROOT, "models")
NODE_PATH = os.path.join(MODELS, "node", "vmware-test.yaml")
GIB = 1024 ** 3
IMAGE = {"path": "/nonexistent/blunix.raw.zst", "sha256": "0" * 64, "size": 8 * GIB}
IP_UP = "2: ens3    inet 10.0.0.5/24 brd 10.0.0.255 scope global ens3\n"
HAVE_ZSTD = shutil.which("zstd") is not None
HAVE_AGE = shutil.which("age") is not None


def _node_bytes():
    with open(NODE_PATH, "rb") as handle:
        return handle.read()


def _disk(name, size, ro=False, children=None, model="Test Disk", serial="S1", mounts=None, label=None):
    return {
        "label": label,
        "name": name,
        "size": size,
        "type": "disk",
        "model": model,
        "serial": serial,
        "tran": "sata",
        "rm": False,
        "ro": ro,
        "mountpoints": mounts or [None],
        "pkname": None,
        "fstype": None,
        "pttype": "gpt" if children else None,
        "children": children or [],
    }


def _part(name, parent, mounts=None, label=None):
    return {
        "label": label,
        "name": name,
        "size": GIB,
        "type": "part",
        "ro": False,
        "mountpoints": mounts or [None],
        "pkname": parent,
    }


def _listing(*disks):
    return json.dumps({"blockdevices": list(disks)})


class _Body:
    def __init__(self, payload):
        self.payload = payload

    def read(self, n):
        data = self.payload[:n]
        self.payload = self.payload[n:]
        return data

    def close(self):
        return None


def _good_context():
    class Ctx:
        verify_mode = ssl.CERT_REQUIRED
        check_hostname = True
        minimum_version = ssl.TLSVersion.TLSv1_2

    return Ctx()


class Rig:
    """Fake machine. Records every side effect."""

    def __init__(
        self,
        answers=(),
        key="",
        cipher=b"",
        listing=None,
        cmdline="",
        ip_lines=None,
        boot_source="",
        decrypt=None,
        write=None,
        listings=None,
    ):
        self.said = []
        self.answers = list(answers)
        self.key = key
        self.cipher = cipher
        self.fetched = []
        self.written = []
        self.applied = []
        self.booted = []
        self.rebooted = []
        self.statics = []
        self.dhcp_runs = 0
        self.listed = 0
        self.ip_lines = list(ip_lines) if ip_lines is not None else None
        if listing is None:
            listing = _listing(_disk("vda", 20 * GIB))
        self.listing = listing
        self.listings = list(listings or ())
        self.root = tempfile.mkdtemp()
        kwargs = {
            "say": self.said.append,
            "read": self._read,
            "read_key": self._read_key,
            "claim": lambda: True,
            "cmdline": lambda: cmdline,
            "ip_show": self._ip,
            "sleep": lambda *_a: None,
            "dhcp": self._dhcp,
            "static": self.statics.append,
            "lister": self._list,
            "mount_source": lambda path: boot_source if path == "/run/live/medium" else "overlay",
            "by_id": lambda name: "/dev/" + name,
            "find_image": lambda: dict(IMAGE),
            "fetch": self._fetch,
            "write_image": write or self._write,
            "open_target": lambda device: (self.root, lambda: None),
            "apply": self._apply,
            "bootloader": lambda root, device: self.booted.append(device),
            "sync": lambda: None,
            "reboot": lambda: self.rebooted.append(True),
        }
        if decrypt is not None:
            kwargs["decrypt"] = decrypt
        self.hooks = Hooks(**kwargs)

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _read(self, timeout=None):
        if not self.answers:
            raise EOFError()
        return self.answers.pop(0)

    def _read_key(self):
        return self.key

    def _ip(self):
        if self.ip_lines is None:
            return IP_UP
        if self.ip_lines:
            return self.ip_lines.pop(0)
        return IP_UP

    def _dhcp(self):
        self.dhcp_runs += 1

    def _list(self):
        self.listed += 1
        if self.listings:
            return self.listings.pop(0)
        return self.listing

    def _fetch(self, host, proxy):
        self.fetched.append((host, proxy))
        return self.cipher

    def _write(self, image, device, size=None):
        self.written.append(device)

    def _apply(self, doc, root, models=None, log=None):
        self.applied.append(root)
        return apply_node(doc, root, models=MODELS, log=log)

    def run(self):
        code = run_install(self.hooks, models=MODELS)
        self.cleanup()
        return code

    def lines(self):
        return "\n".join(self.said)


class BuildHostTests(unittest.TestCase):
    def test_accepted_forms(self):
        label32 = "a" + "b" * 30 + "c"
        for host in (
            "ada.blnx.io",
            "ab.blnx.io",
            "lab-west.blnx.io",
            label32 + ".blnx.io",
            "v1.ada.blnx.io",
            "v3.ada.blnx.io",
            "v999999.ada.blnx.io",
            "ada-1042.blnx.io",
            "ada-0.blnx.io",
            "ada-1042.build.blunix.io",
        ):
            with self.subTest(host=host):
                self.assertEqual(require_build_host(host), host)

    def test_refused_forms(self):
        label33 = "a" + "b" * 31 + "c"
        for host in (
            "v0.ada.blnx.io",
            "v01.ada.blnx.io",
            "v1000000.ada.blnx.io",
            "xn--ada.blnx.io",
            "a--b.blnx.io",
            label33 + ".blnx.io",
            "ADA.blnx.io",
            "Ada.blnx.io",
            "ada.blnx.io.",
            "a.blnx.io",
            "ada-.blnx.io",
            "-ada.blnx.io",
            "1ada.blnx.io",
            "www.blnx.io",
            "proxy.blnx.io",
            "v3.blnx.io",
            "v1.v2.blnx.io",
            "x.v1.ada.blnx.io",
            "blnx.io",
            "ada.blnx.com",
            "ada.blnx.io.evil.example",
            "ada_b.blnx.io",
            " ada.blnx.io",
            # build.blunix.io is the portal now, not a build host.
            "ada.build.blunix.io",
            "v3.ada.build.blunix.io",
            "build.blunix.io",
            "ada.blunix.io",
            "ada-0.build.blunix.io.",
            "",
            None,
            42,
        ):
            with self.subTest(host=host):
                with self.assertRaises(BlunixError) as caught:
                    require_build_host(host)
                self.assertEqual(str(caught.exception), "refused hostname")

    def test_expand(self):
        self.assertEqual(expand_build_host("ada"), "ada.blnx.io")
        self.assertEqual(expand_build_host("v3.ada.blnx.io"), "v3.ada.blnx.io")
        self.assertEqual(expand_build_host("ada-1042.build.blunix.io"), "ada-1042.build.blunix.io")
        for bad in ("", "www", "v3", "a", "ADA", "ada.example.com", "ada.", "xn--x", "ada.build.blunix.io", None):
            with self.subTest(bad=bad):
                with self.assertRaises(BlunixError):
                    expand_build_host(bad)


class InlineNetworkTests(unittest.TestCase):
    def _node(self, network):
        doc = load_path(NODE_PATH)
        doc["network"] = network
        return doc

    def test_dhcp_inline_applies(self):
        doc = self._node({"match": ["en*"], "dhcp": True})
        self.assertEqual(parse_node(doc)["network"], {"match": ["en*"], "dhcp": True})
        with tempfile.TemporaryDirectory() as root:
            apply_node(doc, root, models=MODELS)
            path = os.path.join(root, "run", "systemd", "network", "10-blunix.network")
            with open(path, "r", encoding="utf-8") as handle:
                self.assertIn("DHCP=yes", handle.read())
            os.remove(path)
            boot_node(root, models=MODELS)
            self.assertTrue(os.path.isfile(path))

    def test_static_inline_renders(self):
        model = parse_inline_network(
            {"match": ["eth0"], "address": "10.0.0.5/24", "gateway": "10.0.0.1", "dns": ["10.0.0.53"]}
        )
        body = render_network(model)["10-blunix.network"]
        self.assertIn("Address=10.0.0.5/24", body)
        self.assertIn("Gateway=10.0.0.1", body)
        self.assertIn("DNS=10.0.0.53", body)

    def test_static_node_from_text(self):
        text = _node_bytes().decode("utf-8").replace(
            "network: dhcp-any\n",
            "network:\n  match:\n    - en*\n  address: 192.0.2.10/24\n"
            "  gateway: 192.0.2.1\n  dns:\n    - 192.0.2.53\n",
        )
        parsed = parse_node(load_text(text))
        self.assertEqual(parsed["network"]["address"], "192.0.2.10/24")

    def test_invalid_inline(self):
        base = {"match": ["en*"], "address": "10.0.0.5/24", "gateway": "10.0.0.1", "dns": ["10.0.0.53"]}
        cases = (
            ({"address": "10.0.0.5/33"}, "refused address"),
            ({"address": "10.0.0.5"}, "refused address"),
            ({"address": "10.0.0.500/24"}, "refused address"),
            ({"gateway": "10.0.1.1"}, "refused gateway"),
            ({"gateway": "10.0.0.5"}, "refused gateway"),
            ({"gateway": "fe80::1"}, "refused gateway"),
            ({"dns": []}, "refused dns"),
            ({"match": ["*"]}, "refused interface match"),
            ({"mtu": 9000}, "unknown field"),
            ({"kind": "Network"}, "unknown field"),
            ({"name": "x"}, "unknown field"),
            ({"dhcp": True}, "refused network"),
        )
        for change, message in cases:
            with self.subTest(change=change):
                doc = dict(base)
                doc.update(change)
                with self.assertRaises(BlunixError) as caught:
                    parse_node(self._node(doc))
                self.assertEqual(str(caught.exception), message)

    def test_key_material_name_refused(self):
        secret = "inline-wifi-secret-value"
        text = _node_bytes().decode("utf-8").replace(
            "network: dhcp-any\n",
            "network:\n  match:\n    - en*\n  dhcp: true\n  psk: " + secret + "\n",
        )
        with self.assertRaises(BlunixError) as caught:
            load_text(text)
        self.assertEqual(str(caught.exception), "refused field")
        self.assertNotIn(secret, str(caught.exception))

    def test_model_file_gateway_outside_subnet(self):
        doc = {
            "apiVersion": "blunix.dev/v1",
            "kind": "Network",
            "name": "bad",
            "match": ["en*"],
            "address": "192.0.2.10/24",
            "gateway": "198.51.100.1",
            "dns": ["192.0.2.53"],
        }
        with self.assertRaises(BlunixError) as caught:
            parse_network(doc)
        self.assertEqual(str(caught.exception), "refused gateway")

    def test_target_field(self):
        doc = load_path(NODE_PATH)
        doc["target"] = "nvme0n1"
        self.assertEqual(parse_node(doc)["target"], "nvme0n1")
        for bad in ("/dev/sda", "../sda", "", "a b", 7):
            with self.subTest(bad=bad):
                doc["target"] = bad
                with self.assertRaises(BlunixError) as caught:
                    parse_node(doc)
                self.assertEqual(str(caught.exception), "refused target")


class KeyFormatTests(unittest.TestCase):
    KEY = "k7m2q9dx4tab3fz0wnr1"

    def _decrypt_only(self, good):
        tried = []

        def decrypt(_cipher, passphrase):
            tried.append(passphrase)
            if passphrase == good:
                return b"plain"
            raise DecryptError()

        return decrypt, tried

    def test_lookalikes_hyphens_and_case(self):
        for typed in (
            "k7m2q-9dx4t-ab3fz-0wnr1",
            "K7M2Q-9DX4T-AB3FZ-OWNRL",
            "k7m2q 9dx4t ab3fz 0wnri",
            "  k7m2q9dx4tab3fzownr1  ",
        ):
            with self.subTest(typed=typed):
                self.assertEqual(canonical_key(typed), self.KEY)
                decrypt, tried = self._decrypt_only(self.KEY)
                self.assertEqual(decrypt_candidates(b"c", typed, decrypt=decrypt), b"plain")
                self.assertEqual(tried[0], self.KEY)

    def test_raw_fallback(self):
        typed = "a hand-chosen passphrase"
        self.assertIsNone(canonical_key(typed))
        decrypt, tried = self._decrypt_only(typed)
        self.assertEqual(decrypt_candidates(b"c", typed, decrypt=decrypt), b"plain")
        self.assertEqual(tried, [typed])

    def test_wrong_key_tries_at_most_two(self):
        decrypt, tried = self._decrypt_only("never")
        self.assertIsNone(decrypt_candidates(b"c", "K7M2Q-9DX4T-AB3FZ-0WNR1", decrypt=decrypt))
        self.assertEqual(tried, [self.KEY, "K7M2Q-9DX4T-AB3FZ-0WNR1"])
        decrypt, tried = self._decrypt_only("never")
        self.assertIsNone(decrypt_candidates(b"c", "", decrypt=decrypt))
        self.assertEqual(tried, [])

    @unittest.skipUnless(HAVE_AGE, "age not installed")
    def test_bootstrap_takes_the_display_form_and_a_bare_label(self):
        key = generate_key()
        cipher = encrypt_bytes(_node_bytes(), key)
        seen = []

        def urlopen(req, timeout=30, context=None):
            seen.append(req.full_url)
            return _Body(cipher)

        with tempfile.TemporaryDirectory() as root:
            logs = []
            code = run_bootstrap(
                root=root,
                models=MODELS,
                log=logs.append,
                urlopen=urlopen,
                context_factory=_good_context,
                ip_show=lambda: IP_UP,
                sleeper=lambda *_a: None,
                hostname_reader=lambda: "Ada",
                passphrase_reader=lambda: display_key(key).upper(),
                cmdline="",
            )
            self.assertEqual(code, 0)
            self.assertEqual(seen, ["https://ada.blnx.io/"])
            self.assertIn("blunix: applied node document blunix-test", logs)
            text = "\n".join(logs)
            self.assertNotIn(key, text)
            self.assertNotIn(display_key(key), text)
            self.assertNotIn(display_key(key).upper(), text)


class FetchTests(unittest.TestCase):
    HOST = "ada.blnx.io"

    def test_direct_uses_https_and_proxy_only_when_named(self):
        seen = []

        def urlopen(req, timeout=30, context=None):
            seen.append((req.full_url, context is not None))
            return _Body(b"age")

        fetch_document(self.HOST, None, urlopen=urlopen, context_factory=_good_context)
        fetch_document(self.HOST, "10.0.0.2:8080", urlopen=urlopen)
        self.assertEqual(
            seen,
            [
                ("https://ada.blnx.io/", True),
                ("http://10.0.0.2:8080/v1/build/ada.blnx.io", False),
            ],
        )

    def test_tls_verification_required(self):
        def urlopen(*_a, **_k):
            raise AssertionError("fetched without verification")

        class Broken:
            verify_mode = ssl.CERT_OPTIONAL
            check_hostname = False

        class NoHostname:
            verify_mode = ssl.CERT_REQUIRED
            check_hostname = False

        class OldTls:
            verify_mode = ssl.CERT_REQUIRED
            check_hostname = True
            minimum_version = ssl.TLSVersion.TLSv1

        for factory in (Broken, NoHostname, OldTls):
            with self.subTest(factory=factory.__name__):
                with self.assertRaises(BlunixError) as caught:
                    fetch_document(self.HOST, None, urlopen=urlopen, context_factory=factory)
                self.assertEqual(str(caught.exception), "tls verify disabled")
        context = tls_context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_oversized_refused_both_ways(self):
        def urlopen(req, timeout=30, context=None):
            return _Body(b"x" * (MAX_CIPHER + 1))

        with self.assertRaises(BlunixError) as caught:
            fetch_document(self.HOST, None, urlopen=urlopen, context_factory=_good_context)
        self.assertEqual(str(caught.exception), "document too large")
        with self.assertRaises(BlunixError) as caught:
            fetch_document(self.HOST, "10.0.0.2:8080", urlopen=urlopen)
        self.assertEqual(str(caught.exception), "document too large")

    def test_exact_cap_is_allowed(self):
        def urlopen(req, timeout=30, context=None):
            return _Body(b"x" * MAX_CIPHER)

        self.assertEqual(len(fetch_document(self.HOST, "10.0.0.2:8080", urlopen=urlopen)), MAX_CIPHER)

    def test_proxy_redirect_refused(self):
        req = urllib.request.Request("http://10.0.0.2:8080/v1/build/" + self.HOST)
        with self.assertRaises(BlunixError):
            _NoRedirect().redirect_request(req, None, 302, "Found", {}, "http://evil.example/")

    def test_proxy_refuses_a_bad_host(self):
        with self.assertRaises(BlunixError):
            fetch_document("evil.example.com", "10.0.0.2:8080", urlopen=lambda *_a, **_k: _Body(b""))

    def test_parse_proxy(self):
        self.assertIsNone(parse_proxy("boot=live quiet"))
        self.assertEqual(parse_proxy("quiet blunix.proxy=10.0.0.2:8080"), "10.0.0.2:8080")
        self.assertEqual(parse_proxy("blunix.proxy=Build-Proxy.lan:80"), "build-proxy.lan:80")
        self.assertEqual(parse_proxy("blunix.proxy=[fd00::2]:8080"), "[fd00::2]:8080")
        for bad in (
            "blunix.proxy=10.0.0.2",
            "blunix.proxy=10.0.0.2:0",
            "blunix.proxy=10.0.0.2:080",
            "blunix.proxy=10.0.0.2:70000",
            "blunix.proxy=http://10.0.0.2:80",
            "blunix.proxy=a/b:80",
            "blunix.proxy=:80",
            "blunix.proxy=[10.0.0.2]:80",
            "blunix.proxy=a:1 blunix.proxy=b:2",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(BlunixError):
                    parse_proxy(bad)


class DiskChoiceTests(unittest.TestCase):
    def test_boot_medium_never_selected(self):
        listing = _listing(
            _disk("sda", 500 * GIB),
            _disk("sdb", 64 * GIB, children=[_part("sdb1", "sdb")]),
        )
        good, refused = disk_candidates(listing, {"sdb1"}, 8 * GIB)
        self.assertEqual([d["name"] for d in good], ["sda"])
        self.assertIn(("sdb", "boot medium"), refused)
        good, refused = disk_candidates(listing, {"sdb"}, 8 * GIB)
        self.assertEqual([d["name"] for d in good], ["sda"])

    def test_mounted_read_only_small_and_virtual_refused(self):
        listing = _listing(
            _disk("sda", 500 * GIB, children=[_part("sda1", "sda", mounts=["/mnt/x"])]),
            _disk("sdb", 500 * GIB, ro=True),
            _disk("sdc", 4 * GIB),
            _disk("zram0", 500 * GIB),
            {"name": "sr0", "size": GIB, "type": "rom", "ro": True},
            {"name": "loop0", "size": GIB, "type": "loop"},
        )
        good, refused = disk_candidates(listing, set(), 8 * GIB)
        self.assertEqual(good, [])
        self.assertEqual(
            sorted(refused),
            [("sda", "in use"), ("sdb", "read-only"), ("sdc", "too small")],
        )

    def test_medium_label_is_the_boot_medium(self):
        for stick in (
            _disk("sdb", 64 * GIB, label=MEDIUM_LABEL),
            _disk("sdb", 64 * GIB, children=[_part("sdb1", "sdb", label=MEDIUM_LABEL)]),
        ):
            with self.subTest(stick=stick):
                good, refused = disk_candidates(_listing(_disk("sda", 500 * GIB), stick), set(), 8 * GIB)
                self.assertEqual([d["name"] for d in good], ["sda"])
                self.assertEqual(refused, [("sdb", "boot medium")])

    def test_boot_names_under_toram(self):
        def source(path):
            return "tmpfs" if path == "/run/live/medium" else "overlay"

        self.assertEqual(boot_names(source, "boot=live toram"), set())
        self.assertEqual(boot_names(source, "boot=live toram live-media=/dev/sdc1"), {"sdc1"})
        self.assertEqual(boot_names(source, "bootfrom=/dev/sdd"), {"sdd"})
        self.assertEqual(boot_names(source, "fromiso=/dev/sde2/images/blunix.iso"), {"sde2"})
        self.assertEqual(boot_names(source, "live-media=/dev/disk/by-uuid/nope-uuid"), {"nope-uuid"})
        self.assertEqual(boot_names(source, "live-media=LABEL=x"), set())
        self.assertEqual(boot_names(lambda path: "/dev/sdb1" if path == "/run/live/medium" else "", ""), {"sdb1"})
        good, refused = disk_candidates(
            _listing(_disk("sda", 500 * GIB), _disk("sdc", 64 * GIB, children=[_part("sdc1", "sdc")])),
            boot_names(source, "toram live-media=/dev/sdc1"),
            8 * GIB,
        )
        self.assertEqual([d["name"] for d in good], ["sda"])
        self.assertEqual(refused, [("sdc", "boot medium")])

    def test_disk_by_id(self):
        with tempfile.TemporaryDirectory() as folder:
            dev = os.path.join(folder, "dev")
            ids = os.path.join(folder, "by-id")
            os.makedirs(dev)
            os.makedirs(ids)
            for name in ("sda", "sda1", "sdb"):
                open(os.path.join(dev, name), "wb").close()
            os.symlink("../dev/sda1", os.path.join(ids, "ata-Disk_SER1-part1"))
            os.symlink("../dev/sda", os.path.join(ids, "ata-Disk_SER1"))
            os.symlink("../dev/sdb", os.path.join(ids, "ata-Disk_SER2"))
            self.assertEqual(disk_by_id("sda", ids), os.path.join(ids, "ata-Disk_SER1"))
            self.assertEqual(disk_by_id("sdb", ids), os.path.join(ids, "ata-Disk_SER2"))
            self.assertEqual(disk_by_id("vda", ids), "/dev/vda")
            self.assertEqual(disk_by_id("sda", os.path.join(folder, "missing")), "/dev/sda")

    def test_string_flags_from_older_lsblk(self):
        disk = _disk("sda", "536870912000")
        disk["ro"] = "1"
        good, refused = disk_candidates(_listing(disk), set(), 8 * GIB)
        self.assertEqual(good, [])
        self.assertEqual(refused, [("sda", "read-only")])

    def test_garbage_listing(self):
        for bad in ("", "[]", "{", '{"blockdevices": 3}', b"\xff"):
            with self.subTest(bad=bad):
                with self.assertRaises(BlunixError):
                    disk_candidates(bad, set(), 1)


@unittest.skipUnless(HAVE_AGE, "age not installed")
class InstallFlowTests(unittest.TestCase):
    KEY = generate_key()

    @classmethod
    def setUpClass(cls):
        cls.CIPHER = encrypt_bytes(_node_bytes(), cls.KEY)

    def _assert_key_hidden(self, rig):
        text = rig.lines()
        for form in (self.KEY, display_key(self.KEY), display_key(self.KEY).upper()):
            self.assertNotIn(form, text)
        self.assertNotIn(self.KEY, repr(rig.fetched))

    def test_happy_path(self):
        rig = Rig(
            answers=["ada", "yes", "yes", "yes"],
            key=display_key(self.KEY).upper(),
            cipher=self.CIPHER,
        )
        self.assertEqual(rig.run(), 0)
        self.assertEqual(rig.fetched, [("ada.blnx.io", None)])
        self.assertEqual(rig.written, ["/dev/vda"])
        self.assertEqual(rig.booted, ["/dev/vda"])
        self.assertEqual(rig.rebooted, [True])
        self.assertIn(ASK_HOST, rig.said)
        self.assertIn(ASK_KEY, rig.said)
        self.assertIn("blunix: network up at 10.0.0.5/24 on ens3.", rig.said)
        self.assertIn("blunix: hostname ada.blnx.io. Say yes to keep it.", rig.said)
        self.assertIn("blunix: erase disk vda, 21 gigabytes, Test Disk. Say yes to erase.", rig.said)
        self.assertIn("blunix: installed blunix-test. Remove the stick. Say yes to reboot.", rig.said)
        self.assertIn("blunix: applied node document blunix-test", rig.said)
        self._assert_key_hidden(rig)
        for line in rig.said:
            self.assertNotIn("\x1b", line)

    def test_no_reboot_on_silence(self):
        rig = Rig(answers=["ada", "yes", "yes", "", ""], key=self.KEY, cipher=self.CIPHER)
        self.assertEqual(rig.run(), 0)
        self.assertEqual(rig.rebooted, [])
        self.assertEqual(rig.said[-1], "blunix: not rebooting.")

    def test_hostname_silence_is_no(self):
        rig = Rig(answers=["ada", "", "", "v3.ada.blnx.io", "yes", "yes", "no"], key=self.KEY, cipher=self.CIPHER)
        self.assertEqual(rig.run(), 0)
        self.assertEqual(rig.fetched, [("v3.ada.blnx.io", None)])

    def test_bad_hostname_refused(self):
        rig = Rig(answers=["www", "ada.build.blunix.io", "v0.ada.blnx.io"], key=self.KEY, cipher=self.CIPHER)
        self.assertEqual(rig.run(), 1)
        self.assertEqual(rig.said.count("blunix: refused hostname."), 3)
        self.assertEqual(rig.said[-1], "blunix: no hostname. Nothing applied.")
        self.assertEqual(rig.fetched, [])

    def test_wrong_key_writes_nothing(self):
        wrong = generate_key()
        rig = Rig(answers=["ada", "yes"], key=display_key(wrong), cipher=self.CIPHER)
        self.assertEqual(rig.run(), 1)
        self.assertEqual(rig.said[-1], "blunix: could not decrypt. Nothing applied.")
        self.assertEqual((rig.written, rig.applied, rig.booted, rig.listed), ([], [], [], 0))
        text = rig.lines()
        self.assertNotIn(wrong, text)
        self.assertNotIn(display_key(wrong), text)

    def test_shell_script_refused(self):
        cipher = encrypt_bytes(b"#!/bin/sh\nrm -rf /\n", self.KEY)
        rig = Rig(answers=["ada", "yes"], key=self.KEY, cipher=cipher)
        self.assertEqual(rig.run(), 1)
        self.assertEqual(rig.said[-1], "blunix: document refused. Nothing applied.")
        self.assertEqual((rig.written, rig.applied, rig.booted), ([], [], []))

    def test_unknown_field_refused(self):
        cipher = encrypt_bytes(_node_bytes() + b"extra: 1\n", self.KEY)
        rig = Rig(answers=["ada", "yes"], key=self.KEY, cipher=cipher)
        self.assertEqual(rig.run(), 1)
        self.assertEqual(rig.said[-1], "blunix: document refused. Nothing applied.")
        self.assertEqual(rig.written, [])

    def test_proxy_only_when_named(self):
        rig = Rig(answers=["ada", "yes", "yes", "no"], key=self.KEY, cipher=self.CIPHER)
        rig.run()
        self.assertEqual(rig.fetched, [("ada.blnx.io", None)])
        self.assertNotIn("proxy", rig.lines())
        self.assertNotIn("install card", rig.lines())
        rig = Rig(
            answers=["ada", "yes", "yes", "no"],
            key=self.KEY,
            cipher=self.CIPHER,
            cmdline="boot=live blunix.proxy=10.0.0.2:8080",
        )
        self.assertEqual(rig.run(), 0)
        self.assertEqual(rig.fetched, [("ada.blnx.io", "10.0.0.2:8080")])
        self.assertIn("blunix: using the proxy at 10.0.0.2:8080.", rig.said)

    def test_proxy_says_the_full_digest(self):
        digest = hashlib.sha256(self.CIPHER).hexdigest()
        line = "blunix: document sha256 " + digest + ". Compare it with the install card."
        rig = Rig(
            answers=["ada", "yes", "", ""],
            key=self.KEY,
            cipher=self.CIPHER,
            cmdline="blunix.proxy=10.0.0.2:8080",
        )
        self.assertEqual(rig.run(), 1)
        self.assertEqual(rig.said.count(line), 1)
        self.assertLess(rig.said.index(line), rig.said.index("blunix: erase disk vda, 21 gigabytes, Test Disk. Say yes to erase."))
        self._assert_key_hidden(rig)

    def test_refused_proxy_stops_before_anything(self):
        rig = Rig(answers=["ada", "yes"], key=self.KEY, cipher=self.CIPHER, cmdline="blunix.proxy=evil")
        self.assertEqual(rig.run(), 1)
        self.assertEqual(rig.said, ["blunix: refused proxy. Nothing applied."])
        self.assertEqual(rig.dhcp_runs, 0)

    def test_oversized_fetch(self):
        rig = Rig(answers=["ada", "yes"], key=self.KEY)

        def big(host, proxy):
            raise BlunixError("document too large")

        rig.hooks.fetch = big
        self.assertEqual(rig.run(), 1)
        self.assertEqual(rig.said[-1], "blunix: document too large. Nothing applied.")
        self.assertEqual(rig.written, [])

    def test_boot_medium_is_never_the_target(self):
        listing = _listing(
            _disk("sda", 20 * GIB, children=[_part("sda1", "sda")]),
        )
        rig = Rig(answers=["ada", "yes"], key=self.KEY, cipher=self.CIPHER, listing=listing, boot_source="/dev/sda1")
        self.assertEqual(rig.run(), 1)
        self.assertEqual(rig.said[-1], "blunix: no disk fits the image. Nothing applied.")
        self.assertEqual(rig.written, [])

    def test_boot_medium_named_as_target_refused(self):
        cipher = encrypt_bytes(_node_bytes() + b"target: sdb\n", self.KEY)
        listing = _listing(
            _disk("sda", 20 * GIB),
            _disk("sdb", 20 * GIB, children=[_part("sdb1", "sdb")]),
        )
        rig = Rig(answers=["ada", "yes"], key=self.KEY, cipher=cipher, listing=listing, boot_source="/dev/sdb1")
        self.assertEqual(rig.run(), 1)
        self.assertEqual(rig.said[-1], "blunix: target disk sdb is not usable. Nothing applied.")
        self.assertEqual(rig.written, [])

    def test_target_picks_among_many(self):
        cipher = encrypt_bytes(_node_bytes() + b"target: SER2\n", self.KEY)
        listing = _listing(_disk("sda", 20 * GIB, serial="SER1"), _disk("sdb", 20 * GIB, serial="SER2"))
        rig = Rig(answers=["ada", "yes", "no"], key=self.KEY, cipher=cipher, listing=listing)
        self.assertEqual(rig.run(), 0)
        self.assertEqual(rig.written, ["/dev/sdb"])
        self.assertNotIn("blunix: type the disk number.", rig.said)
        self.assertNotIn("Say yes to erase", rig.lines())

    def test_read_only_disk_refused(self):
        listing = _listing(_disk("sda", 500 * GIB, ro=True))
        rig = Rig(answers=["ada", "yes"], key=self.KEY, cipher=self.CIPHER, listing=listing)
        self.assertEqual(rig.run(), 1)
        self.assertEqual(rig.said[-1], "blunix: no disk fits the image. Nothing applied.")
        self.assertEqual(rig.written, [])

    def test_too_small_disk_refused(self):
        listing = _listing(_disk("sda", 7 * GIB))
        rig = Rig(answers=["ada", "yes"], key=self.KEY, cipher=self.CIPHER, listing=listing)
        self.assertEqual(rig.run(), 1)
        self.assertEqual(rig.said[-1], "blunix: no disk fits the image. Nothing applied.")
        self.assertEqual(rig.written, [])

    def test_existing_partitions_and_silence_write_nothing(self):
        listing = _listing(
            _disk("sda", 480 * 10 ** 9, model="Samsung SSD", children=[_part("sda1", "sda")]),
        )
        rig = Rig(answers=["ada", "yes", "", ""], key=self.KEY, cipher=self.CIPHER, listing=listing)
        self.assertEqual(rig.run(), 1)
        question = "blunix: erase disk sda, 480 gigabytes, Samsung SSD. Say yes to erase."
        self.assertEqual(rig.said.count(question), 2)
        self.assertEqual(rig.said[-1], "blunix: disk sda kept. Nothing applied.")
        self.assertEqual((rig.written, rig.applied, rig.booted), ([], [], []))

    def test_existing_partitions_and_yes_erase(self):
        listing = _listing(_disk("sda", 480 * 10 ** 9, children=[_part("sda1", "sda")]))
        rig = Rig(answers=["ada", "yes", "yes", "no"], key=self.KEY, cipher=self.CIPHER, listing=listing)
        self.assertEqual(rig.run(), 0)
        self.assertEqual(rig.written, ["/dev/sda"])

    def test_many_disks_without_target_asks(self):
        listing = _listing(_disk("sda", 20 * GIB, model="Disk A"), _disk("sdb", 40 * GIB, model="Disk B"))
        rig = Rig(answers=["ada", "yes", "", ""], key=self.KEY, cipher=self.CIPHER, listing=listing)
        self.assertEqual(rig.run(), 1)
        self.assertIn("blunix: disk 1 is sda, 21 gigabytes, Disk A.", rig.said)
        self.assertIn("blunix: disk 2 is sdb, 43 gigabytes, Disk B.", rig.said)
        self.assertIn("blunix: type the disk number.", rig.said)
        self.assertEqual(rig.said[-1], "blunix: no disk chosen. Nothing applied.")
        self.assertEqual(rig.written, [])
        rig = Rig(answers=["ada", "yes", "2", "yes", "no"], key=self.KEY, cipher=self.CIPHER, listing=listing)
        self.assertEqual(rig.run(), 0)
        self.assertEqual(rig.written, ["/dev/sdb"])

    def test_blank_disk_without_target_needs_yes(self):
        rig = Rig(answers=["ada", "yes", "", ""], key=self.KEY, cipher=self.CIPHER)
        self.assertEqual(rig.run(), 1)
        question = "blunix: erase disk vda, 21 gigabytes, Test Disk. Say yes to erase."
        self.assertEqual(rig.said.count(question), 2)
        self.assertEqual(rig.said[-1], "blunix: disk vda kept. Nothing applied.")
        self.assertEqual((rig.written, rig.applied, rig.booted), ([], [], []))
        rig = Rig(answers=["ada", "yes", "no"], key=self.KEY, cipher=self.CIPHER)
        self.assertEqual(rig.run(), 1)
        self.assertEqual(rig.said[-1], "blunix: disk vda kept. Nothing applied.")
        self.assertEqual(rig.written, [])

    def test_toram_stick_is_never_the_target(self):
        # With toram, /run/live/medium is RAM: findmnt names no device.
        stick = _disk(
            "sdb",
            64 * GIB,
            children=[_part("sdb1", "sdb", label=MEDIUM_LABEL), _part("sdb2", "sdb")],
        )
        listing = _listing(_disk("sda", 20 * GIB), stick)
        rig = Rig(
            answers=["ada", "yes", "yes", "no"],
            key=self.KEY,
            cipher=self.CIPHER,
            listing=listing,
            boot_source="tmpfs",
            cmdline="boot=live toram",
        )
        self.assertEqual(rig.run(), 0)
        self.assertEqual(rig.written, ["/dev/sda"])
        self.assertNotIn("sdb", rig.lines())
        cipher = encrypt_bytes(_node_bytes() + b"target: sdb\n", self.KEY)
        rig = Rig(answers=["ada", "yes"], key=self.KEY, cipher=cipher, listing=listing, boot_source="tmpfs", cmdline="toram")
        self.assertEqual(rig.run(), 1)
        self.assertEqual(rig.said[-1], "blunix: target disk sdb is not usable. Nothing applied.")
        self.assertEqual(rig.written, [])

    def test_hot_swap_before_the_write_refused(self):
        before = _listing(_disk("sda", 20 * GIB, serial="SER1"))
        for after in (
            _listing(_disk("sda", 20 * GIB, serial="SER9")),
            _listing(_disk("sda", 40 * GIB, serial="SER1")),
            _listing(_disk("sdb", 20 * GIB, serial="SER1")),
            _listing(_disk("sda", 20 * GIB, serial="SER1", mounts=["/mnt"])),
        ):
            with self.subTest(after=after):
                rig = Rig(answers=["ada", "yes", "yes"], key=self.KEY, cipher=self.CIPHER, listings=[before, after])
                self.assertEqual(rig.run(), 1)
                self.assertEqual(rig.said[-1], "blunix: disk sda changed since it was chosen. Nothing applied.")
                self.assertEqual((rig.written, rig.applied, rig.booted), ([], [], []))
                self.assertNotIn("blunix: writing the image to sda.", rig.said)

    def test_write_opens_by_id_with_the_listed_size(self):
        seen = []
        rig = Rig(
            answers=["ada", "yes", "yes", "no"],
            key=self.KEY,
            cipher=self.CIPHER,
            write=lambda image, device, size=None: seen.append((device, size)),
        )
        rig.hooks.by_id = lambda name: "/dev/disk/by-id/virtio-S1"
        self.assertEqual(rig.run(), 0)
        self.assertEqual(seen, [("/dev/disk/by-id/virtio-S1", 20 * GIB)])
        self.assertEqual(rig.booted, ["/dev/vda"])

    def test_device_size_changed_at_open(self):
        def changed(image, device, size=None):
            raise DiskChanged()

        rig = Rig(answers=["ada", "yes", "yes"], key=self.KEY, cipher=self.CIPHER, write=changed)
        self.assertEqual(rig.run(), 1)
        self.assertEqual(rig.said[-1], "blunix: disk vda changed since it was chosen. Nothing applied.")
        self.assertEqual((rig.applied, rig.booted), ([], []))

    def test_digest_mismatch_stops_before_apply_and_bootloader(self):
        def mismatch(image, device, size=None):
            raise ImageMismatch(False)

        rig = Rig(answers=["ada", "yes", "yes"], key=self.KEY, cipher=self.CIPHER, write=mismatch)
        self.assertEqual(rig.run(), 1)
        self.assertEqual(rig.said[-1], "blunix: image digest did not match. Nothing applied.")
        self.assertEqual((rig.applied, rig.booted, rig.rebooted), ([], [], []))

    def test_no_image_stops_first(self):
        rig = Rig(answers=["ada", "yes"], key=self.KEY, cipher=self.CIPHER)

        def missing():
            raise BlunixError("no image")

        rig.hooks.find_image = missing
        self.assertEqual(rig.run(), 1)
        self.assertEqual(rig.said, ["blunix: no image on this medium. Nothing applied."])

    def test_bootloader_failure_is_said(self):
        rig = Rig(answers=["ada", "yes", "yes"], key=self.KEY, cipher=self.CIPHER)

        def fail(root, device):
            raise BlunixError("bootloader failed")

        rig.hooks.bootloader = fail
        self.assertEqual(rig.run(), 1)
        self.assertEqual(rig.said[-1], "blunix: install failed on vda. The disk is not bootable.")

    def test_static_network_prompt(self):
        rig = Rig(
            answers=["10.0.0.5/24", "10.9.9.1", "10.0.0.53", "10.0.0.5/24", "10.0.0.1", "10.0.0.53", "ada", "yes", "yes", "no"],
            key=self.KEY,
            cipher=self.CIPHER,
            ip_lines=[""] * 7,
        )
        self.assertEqual(rig.run(), 0)
        self.assertIn(NO_NETWORK, rig.said)
        self.assertIn("blunix: refused address. Try again.", rig.said)
        self.assertEqual(len(rig.statics), 1)
        self.assertEqual(rig.statics[0]["address"], "10.0.0.5/24")
        self.assertEqual(rig.statics[0]["gateway"], "10.0.0.1")

    def test_enter_retries_dhcp(self):
        rig = Rig(answers=["", "ada", "yes", "yes", "no"], key=self.KEY, cipher=self.CIPHER, ip_lines=[""] * 7)
        self.assertEqual(rig.run(), 0)
        self.assertEqual(rig.dhcp_runs, 2)
        self.assertEqual(rig.statics, [])

    def test_second_console_backs_off(self):
        rig = Rig(answers=["ada"], key=self.KEY, cipher=self.CIPHER)
        rig.hooks.claim = lambda: False
        self.assertEqual(rig.run(), 1)
        self.assertEqual(rig.said[-1], "blunix: another console is installing.")
        self.assertEqual(rig.fetched, [])

    def test_every_line_is_console_safe(self):
        rig = Rig(answers=["ada", "yes", "yes", "yes"], key=self.KEY, cipher=self.CIPHER, cmdline="blunix.proxy=10.0.0.2:8080")
        self.assertEqual(rig.run(), 0)
        for line in rig.said:
            self.assertTrue(line.startswith("blunix"), line)
            self.assertTrue(all(32 <= ord(ch) <= 126 for ch in line), line)
            self.assertLessEqual(len(line), 240)


@unittest.skipUnless(HAVE_ZSTD, "zstd not installed")
class ImageTests(unittest.TestCase):
    def _image(self, folder, raw):
        path = os.path.join(folder, "blunix.raw")
        with open(path, "wb") as handle:
            handle.write(raw)
        subprocess.run(["zstd", "-q", "-f", "-o", path + ".zst", path], check=True)
        with open(path + ".zst", "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        with open(path + ".zst.sha256", "w", encoding="ascii") as handle:
            handle.write(digest + "  blunix.raw.zst\n")
        return path + ".zst", digest

    def test_find_and_write(self):
        raw = os.urandom(4096) + b"\x00" * 65536
        with tempfile.TemporaryDirectory() as folder:
            path, digest = self._image(folder, raw)
            image = find_image((os.path.join(folder, "missing"), folder))
            self.assertEqual(image, {"path": path, "sha256": digest, "size": len(raw)})
            device = os.path.join(folder, "disk")
            open(device, "wb").close()
            write_image(image, device)
            with open(device, "rb") as handle:
                self.assertEqual(handle.read(), raw)

    def test_mismatch_writes_nothing(self):
        with tempfile.TemporaryDirectory() as folder:
            path, digest = self._image(folder, b"image-bytes" * 100)
            device = os.path.join(folder, "disk")
            with open(device, "wb") as handle:
                handle.write(b"old")
            bad = {"path": path, "sha256": "f" * 64, "size": 1100}
            with self.assertRaises(ImageMismatch) as caught:
                write_image(bad, device)
            self.assertFalse(caught.exception.written)
            with open(device, "rb") as handle:
                self.assertEqual(handle.read(), b"old")

    def test_flow_with_real_writer_and_bad_digest(self):
        if not HAVE_AGE:
            self.skipTest("age not installed")
        key = generate_key()
        with tempfile.TemporaryDirectory() as folder:
            path, _digest = self._image(folder, b"image-bytes" * 100)
            device = os.path.join(folder, "disk")
            open(device, "wb").close()
            rig = Rig(
                answers=["ada", "yes", "yes"],
                key=key,
                cipher=encrypt_bytes(_node_bytes(), key),
                write=lambda image, _dev, size=None: write_image(image, device),
            )
            rig.hooks.find_image = lambda: {"path": path, "sha256": "0" * 64, "size": GIB}
            self.assertEqual(rig.run(), 1)
            self.assertEqual(rig.said[-1], "blunix: image digest did not match. Nothing applied.")
            self.assertEqual(os.path.getsize(device), 0)
            self.assertEqual((rig.applied, rig.booted), ([], []))

    def test_device_size_must_match_at_open(self):
        raw = b"image-bytes" * 100
        with tempfile.TemporaryDirectory() as folder:
            path, digest = self._image(folder, raw)
            image = {"path": path, "sha256": digest, "size": len(raw)}
            device = os.path.join(folder, "disk")
            with open(device, "wb") as handle:
                handle.write(b"o" * 4096)
            for size in (4095, 4097, 0):
                with self.subTest(size=size):
                    with self.assertRaises(DiskChanged):
                        write_image(image, device, size=size)
                    with open(device, "rb") as handle:
                        self.assertEqual(handle.read(), b"o" * 4096)
            release = {"url": ReleaseTests.URL, "version": "v0.1.0", "sha256": digest, "size": len(raw)}

            def urlopen(*_a, **_k):
                raise AssertionError("downloaded for a changed disk")

            with self.assertRaises(DiskChanged):
                write_image(release, device, urlopen=urlopen, context_factory=_good_context, size=1)
            write_image(image, device, size=4096)
            with open(device, "rb") as handle:
                self.assertEqual(handle.read(len(raw)), raw)

    def test_bad_digest_file_and_missing_image(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(BlunixError) as caught:
                find_image((folder,))
            self.assertEqual(str(caught.exception), "no image")
            path, _digest = self._image(folder, b"x" * 100)
            with open(path + ".sha256", "w", encoding="ascii") as handle:
                handle.write("not-a-digest\n")
            with self.assertRaises(BlunixError) as caught:
                find_image((folder,))
            self.assertEqual(str(caught.exception), "image refused")

    def test_content_size(self):
        self.assertIsNone(zstd_content_size(b"not zstd at all"))


class ReleaseTests(unittest.TestCase):
    URL = "https://github.com/afterdarksys/blunix/releases/download/v0.1.0/blunix.raw.zst"

    def _pin(self, folder, text):
        path = os.path.join(folder, "blunix.release")
        with open(path, "w", encoding="ascii") as handle:
            handle.write(text)
        return path

    def test_pin_is_the_fallback(self):
        digest = "a" * 64
        with tempfile.TemporaryDirectory() as folder:
            self._pin(folder, "version=v0.1.0\nsha256=" + digest + "\nsize=8589934592\n")
            image = find_image((folder,))
        self.assertEqual(
            image,
            {"url": self.URL, "version": "v0.1.0", "sha256": digest, "size": 8 * GIB},
        )

    def test_medium_image_wins_over_the_pin(self):
        if not HAVE_ZSTD:
            self.skipTest("zstd not installed")
        with tempfile.TemporaryDirectory() as folder:
            ImageTests()._image(folder, b"x" * 100)
            self._pin(folder, "version=v0.1.0\nsha256=" + "a" * 64 + "\nsize=100\n")
            self.assertNotIn("url", find_image((folder,)))

    def test_bad_pins(self):
        good = {"version": "v0.1.0", "sha256": "a" * 64, "size": "100"}
        cases = (
            {"version": "latest"},
            {"version": "../../evil"},
            {"version": "v0.1.0/../x"},
            {"sha256": "A" * 64},
            {"sha256": "a" * 63},
            {"size": "0"},
            {"size": "-1"},
            {"extra": "1"},
        )
        for change in cases:
            with self.subTest(change=change):
                fields = dict(good)
                fields.update(change)
                text = "".join(key + "=" + value + "\n" for key, value in fields.items())
                with tempfile.TemporaryDirectory() as folder:
                    path = self._pin(folder, text)
                    with self.assertRaises(BlunixError):
                        read_release(path)
        with tempfile.TemporaryDirectory() as folder:
            path = self._pin(folder, "version=v1\nversion=v2\nsha256=" + "a" * 64 + "\nsize=1\n")
            with self.assertRaises(BlunixError):
                read_release(path)

    def test_release_urls(self):
        self.assertEqual(release_url("v0.1.0"), self.URL)
        for good in (
            self.URL,
            "https://objects.githubusercontent.com/github-production-release-asset/1?X-Amz-Signature=abc",
            "https://release-assets.githubusercontent.com/github-production-release-asset/1?sp=r",
        ):
            with self.subTest(good=good):
                self.assertEqual(check_release_url(good), good)
        for bad in (
            "http://github.com/afterdarksys/blunix/releases/download/v0.1.0/blunix.raw.zst",
            "https://github.com/evil/blunix/releases/download/v0.1.0/blunix.raw.zst",
            "https://github.com.evil.example/afterdarksys/blunix/releases/download/v1/x",
            "https://user@github.com/afterdarksys/blunix/releases/download/v1/x",
            "https://github.com:8443/afterdarksys/blunix/releases/download/v1/x",
            "https://evil.example/x",
            "https://raw.githubusercontent.com/afterdarksys/blunix/main/x",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(BlunixError):
                    check_release_url(bad)
        req = urllib.request.Request(self.URL)
        with self.assertRaises(BlunixError):
            _ReleaseRedirect().redirect_request(req, None, 302, "Found", {}, "https://evil.example/x")

    def test_release_download_needs_verified_tls(self):
        class Broken:
            verify_mode = ssl.CERT_NONE
            check_hostname = False

        def urlopen(*_a, **_k):
            raise AssertionError("downloaded without verification")

        with tempfile.TemporaryDirectory() as folder:
            device = os.path.join(folder, "disk")
            open(device, "wb").close()
            image = {"url": self.URL, "version": "v0.1.0", "sha256": "a" * 64, "size": 1}
            with self.assertRaises(BlunixError) as caught:
                write_image(image, device, urlopen=urlopen, context_factory=Broken)
            self.assertEqual(str(caught.exception), "tls verify disabled")
            self.assertEqual(os.path.getsize(device), 0)

    @unittest.skipUnless(HAVE_ZSTD, "zstd not installed")
    def test_release_stream_is_verified(self):
        raw = os.urandom(2048) + b"\x00" * 8192
        with tempfile.TemporaryDirectory() as folder:
            path, digest = ImageTests()._image(folder, raw)
            with open(path, "rb") as handle:
                blob = handle.read()
            seen = []

            def urlopen(req, timeout=60, context=None):
                seen.append((req.full_url, context.verify_mode))
                return _Body(blob)

            device = os.path.join(folder, "disk")
            open(device, "wb").close()
            image = {"url": self.URL, "version": "v0.1.0", "sha256": digest, "size": len(raw)}
            write_image(image, device, urlopen=urlopen, context_factory=_good_context)
            self.assertEqual(seen, [(self.URL, ssl.CERT_REQUIRED)])
            with open(device, "rb") as handle:
                self.assertEqual(handle.read(), raw)
            image["sha256"] = "b" * 64
            with self.assertRaises(ImageMismatch) as caught:
                write_image(image, device, urlopen=urlopen, context_factory=_good_context)
            self.assertTrue(caught.exception.written)

    @unittest.skipUnless(HAVE_AGE, "age not installed")
    def test_flow_says_the_release_and_the_mismatch(self):
        key = generate_key()

        def mismatch(image, device, size=None):
            raise ImageMismatch(True)

        rig = Rig(answers=["ada", "yes", "yes"], key=key, cipher=encrypt_bytes(_node_bytes(), key), write=mismatch)
        rig.hooks.find_image = lambda: {"url": self.URL, "version": "v0.1.0", "sha256": "a" * 64, "size": GIB}
        self.assertEqual(rig.run(), 1)
        self.assertIn("blunix: the image comes from release v0.1.0 on github.com.", rig.said)
        self.assertEqual(rig.said[-1], "blunix: image digest did not match. The disk is not bootable.")
        self.assertEqual((rig.applied, rig.booted), ([], []))


class InstallerSourceTests(unittest.TestCase):
    def test_commands_go_through_run_cmd(self):
        path = os.path.join(ROOT, "lib", "blunix", "installer.py")
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
        for token in ("subprocess.run(", "Popen(", "os.system", "shell=True", "CERT_NONE", "getpass"):
            self.assertNotIn(token, text)


class CliInstallTests(unittest.TestCase):
    def test_proxy_not_installed(self):
        saved = sys.modules.get("blunix.proxy", "absent")
        sys.modules["blunix.proxy"] = None
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                code = main(["proxy", "serve"])
        finally:
            if saved == "absent":
                del sys.modules["blunix.proxy"]
            else:
                sys.modules["blunix.proxy"] = saved
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "blunix: proxy not installed\n")

    def test_install_takes_no_arguments(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["install", "now"]), 1)
            self.assertEqual(main(["install", "--passphrase", "x"]), 1)


if __name__ == "__main__":
    unittest.main()

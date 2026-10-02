"""Build-proxy checks: site parsing, key handling, publish, serve, dnsmasq.

Threats: the proxy must not leak an account or build key, must not relay
anything but contract build hosts, must not serve outside --media, and must
stop when a label belongs to someone else. These tests prove the refusals.
"""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import io
import json
import os
import shutil
import socket
import ssl
import stat
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from blunix.errors import BlunixError
from blunix.proxy import cmd_init, cmd_plan, cmd_publish, main
from blunix.proxy_boot import render_dnsmasq, render_ipxe
from blunix.proxy_config import (
    Api,
    check_api_url,
    check_key,
    fingerprint,
    load_config,
    read_key_file,
)
from blunix.proxy_serve import BuildFetcher, ProxyServer, RateLimiter, verify_media
from blunix.proxy_site import (
    build_host_kind,
    check_label,
    normalize_mac,
    parse_site,
    render_node,
    validate_node,
)

KEY = "blx_" + "A" * 20 + "b" * 20 + "-_9"
AGE = b"age-encryption.org/v1\n-> scrypt c2FsdA 18\nbody\n"

SITE = b"""
defaults:
  disk: metal-luks
  access: regular
  dns: [192.0.2.53]
machines:
  - mac: "00:50:56:AA:BB:01"
    label: ada
    hostname: ada-1
    network: {address: 192.0.2.21/24, gateway: 192.0.2.1}
  - mac: "00-50-56-aa-bb-02"
    label: grace
    hostname: grace-1
    dhcp: true
"""

MACHINE = """  - mac: "00:50:56:aa:bb:{n}"
    label: {label}
    hostname: {host}
    dhcp: true
"""


def _site(*machines, defaults="defaults: {disk: cloud-vm, access: regular}\n"):
    body = defaults + "machines:\n" + "".join(machines)
    return body.encode("utf-8")


def _m(n, label=None, host=None):
    return MACHINE.format(n=n, label=label or "m" + n, host=host or "h" + n)


class _Quiet:
    def log_message(self, *args):
        return


class SiteTests(unittest.TestCase):
    def refused(self, data, needle):
        with self.assertRaises(BlunixError) as caught:
            parse_site(data)
        self.assertIn(needle, str(caught.exception))

    def test_good_site(self):
        site = parse_site(SITE)
        ada, grace = site["machines"]
        self.assertEqual(ada["mac"], "00:50:56:aa:bb:01")
        self.assertEqual(grace["mac"], "00:50:56:aa:bb:02")
        self.assertEqual(ada["dns"], ["192.0.2.53"])
        self.assertTrue(grace["dhcp"])

    def test_duplicates(self):
        self.refused(_site(_m("01", "ada"), _m("01", "bob")), "duplicate mac")
        dup_mac = _m("01", "ada") + _m("02", "bob").replace("00:50:56:aa:bb:02", "005056AABB01")
        self.refused(_site(dup_mac), "duplicate mac")
        self.refused(_site(_m("01", "ada"), _m("02", "ada")), "duplicate label")
        self.refused(_site(_m("01", "ada", "x"), _m("02", "bob", "x")), "duplicate hostname")
        self.refused(b"machines: []\nmachines: []\n", "duplicate key")
        self.refused(_site(_m("01").replace("dhcp: true", "dhcp: true\n    dhcp: true")), "duplicate key")

    def test_bad_labels(self):
        for label in ("a", "Ada", "www", "proxy", "v12", "a--b", "xn--abc", "-ab", "ab-",
                      "a" * 33, "ada.x", "1ab"):
            with self.subTest(label=label):
                with self.assertRaises(BlunixError):
                    check_label(label)
                self.refused(_site(_m("01", label)), "refused label")
        self.assertEqual(check_label("ada-1042"), "ada-1042")

    def test_unknown_keys(self):
        self.refused(_site(_m("01")) + b"extra: 1\n", "unknown key")
        self.refused(_site(_m("01").replace("dhcp: true", "dhcp: true\n    passwd: x")), "unknown key")
        self.refused(_site(_m("01"), defaults="defaults: {ai: default}\n"), "unknown key")
        net = """  - mac: "00:50:56:aa:bb:09"
    label: ada
    hostname: ada
    network: {address: 192.0.2.5/24, gateway: 192.0.2.1, dns: [192.0.2.53], mtu: 9000}
"""
        self.refused(_site(net), "unknown key")

    def test_bad_network(self):
        def one(net):
            return _site('  - mac: "00:50:56:aa:bb:09"\n    label: ada\n    hostname: ada\n'
                         "    network: " + net + "\n")

        self.refused(one("{address: 192.0.2.5, gateway: 192.0.2.1, dns: [192.0.2.53]}"), "address")
        self.refused(one("{address: 192.0.2.300/24, gateway: 192.0.2.1, dns: [192.0.2.53]}"), "address")
        self.refused(one("{address: 192.0.2.5/33, gateway: 192.0.2.1, dns: [192.0.2.53]}"), "address")
        self.refused(one("{address: 192.0.2.5/24, gateway: 198.51.100.1, dns: [192.0.2.53]}"), "gateway")
        self.refused(one("{address: 192.0.2.5/24, gateway: 192.0.2.5, dns: [192.0.2.53]}"), "gateway")
        self.refused(one("{address: 192.0.2.0/24, gateway: 192.0.2.1, dns: [192.0.2.53]}"), "address")
        self.refused(one("{address: 192.0.2.5/24, gateway: 192.0.2.1}"), "needs dns")
        self.refused(one("{address: 192.0.2.5/24, gateway: 192.0.2.1, dns: [nope]}"), "dns")
        both = _m("01").replace("dhcp: true", "dhcp: true\n    network: {address: 192.0.2.5/24}")
        self.refused(_site(both), "exactly one")

    def test_duplicate_address(self):
        a = '  - mac: "00:50:56:aa:bb:01"\n    label: ada\n    hostname: ada\n' \
            "    network: {address: 192.0.2.5/24, gateway: 192.0.2.1, dns: [192.0.2.53]}\n"
        b = a.replace("bb:01", "bb:02").replace("ada", "bob")
        self.refused(_site(a, b), "duplicate address")

    def test_mac_rules(self):
        self.assertEqual(normalize_mac("0050.56aa.bb01".replace(".", "")), "00:50:56:aa:bb:01")
        for bad in ("01:00:5e:00:00:01", "00:00:00:00:00:00", "00:50:56:aa:bb", "00:50-56:aa:bb:01",
                    "zz:50:56:aa:bb:01", "00:50:56:aa:bb:01 "):
            with self.subTest(mac=bad):
                with self.assertRaises(BlunixError):
                    normalize_mac(bad)
        # YAML 1.1 reads this unquoted MAC as a base-60 integer.
        unquoted = _m("01").replace('"00:50:56:aa:bb:01"', "10:20:30:40:50:59")
        self.refused(_site(unquoted), "quoted")

    def test_aliases_and_junk(self):
        self.refused(b"defaults: &d {disk: cloud-vm}\nmachines:\n  - *d\n", "not valid yaml")
        self.refused(b"\xff\xfe", "utf-8")
        self.refused(b"x" * (256 * 1024 + 1), "too large")
        self.refused(b"- a\n", "mapping")
        self.refused(_site(_m("01"), defaults="defaults: {channel: beta}\n"), "channel")

    def test_node_document_uses_inline_network(self):
        site = parse_site(SITE)
        ada = site["machines"][0]
        data = render_node(ada)
        self.assertIn(b"address: 192.0.2.21/24", data)
        self.assertNotIn(b"static-single", data)
        # Contract: the inline network form validates with the installer's parser.
        parsed = validate_node(ada, data)
        self.assertEqual(parsed["hostname"], "ada-1")
        self.assertIn(b"network: dhcp-any", render_node(site["machines"][1]))
        validate_node(site["machines"][1], render_node(site["machines"][1]))

    def test_unknown_model_refused(self):
        site = parse_site(_site(_m("01"), defaults="defaults: {disk: nope, access: regular}\n"))
        machine = site["machines"][0]
        with self.assertRaises(BlunixError):
            validate_node(machine, render_node(machine))


class KeyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _key_file(self, text, mode):
        path = os.path.join(self.tmp, "key")
        with open(path, "w") as handle:
            handle.write(text)
        os.chmod(path, mode)
        return path

    def test_key_file_perms(self):
        for mode in (0o644, 0o640, 0o604, 0o660):
            with self.subTest(mode=oct(mode)):
                path = self._key_file(KEY + "\n", mode)
                with self.assertRaises(BlunixError) as caught:
                    read_key_file(path)
                self.assertIn("group or others", str(caught.exception))
                self.assertNotIn(KEY, str(caught.exception))
        self.assertEqual(read_key_file(self._key_file(KEY + "\n", 0o600)), KEY)

    def test_key_file_symlink_refused(self):
        real = self._key_file(KEY, 0o600)
        link = os.path.join(self.tmp, "link")
        os.symlink(real, link)
        with self.assertRaises(BlunixError):
            read_key_file(link)

    def test_join_token_refused(self):
        join = "blx_join_" + "a" * 34
        with self.assertRaises(BlunixError) as caught:
            check_key(join)
        self.assertIn("blx_join_", str(caught.exception))
        with self.assertRaises(BlunixError):
            read_key_file(self._key_file(join, 0o600))
        for bad in ("", "blx_short", KEY + "x", "Bearer " + KEY, KEY[:-1] + "!"):
            with self.assertRaises(BlunixError):
                check_key(bad)

    def test_key_never_on_argv(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["init", "--key", KEY]), 1)
            self.assertEqual(main(["init", "--key-file=" + KEY]), 1)
            self.assertEqual(main(["proxy", "plan", KEY]), 1)
        self.assertNotIn(KEY, err.getvalue())
        self.assertIn("never from the command line", err.getvalue())

    def test_init_writes_private_files(self):
        config = os.path.join(self.tmp, "cfg", "proxy.yaml")
        key_file = os.path.join(self.tmp, "cfg", "proxy.key")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cmd_init(
                {"config": config, "key-file": key_file, "api": "http://localhost:8787"},
                read_secret=lambda: KEY,
            )
        self.assertEqual(stat.S_IMODE(os.stat(config).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(key_file).st_mode), 0o600)
        self.assertNotIn(KEY, out.getvalue())
        self.assertIn(fingerprint(KEY), out.getvalue())
        with open(config) as handle:
            self.assertNotIn(KEY, handle.read())
        loaded = load_config(config)
        self.assertEqual(loaded["api"], "http://localhost:8787")
        self.assertEqual(read_key_file(loaded["key_file"]), KEY)
        with self.assertRaises(BlunixError):
            cmd_init({"config": config, "key-file": os.path.join(self.tmp, "k2")},
                     read_secret=lambda: "blx_join_" + "a" * 34)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "k2")))

    def test_init_refuses_open_existing_key_file(self):
        path = self._key_file(KEY, 0o644)
        with self.assertRaises(BlunixError):
            cmd_init({"config": os.path.join(self.tmp, "c.yaml"), "key-file": path},
                     read_secret=lambda: KEY)

    def test_api_url_rules(self):
        self.assertEqual(check_api_url("https://api.blunix.io"), "https://api.blunix.io")
        self.assertEqual(check_api_url("http://localhost:8787/"), "http://localhost:8787")
        self.assertEqual(check_api_url("http://127.0.0.1:8787"), "http://127.0.0.1:8787")
        for bad in ("http://api.blunix.io", "http://192.168.1.5:8787", "ftp://x",
                    "https://u:p@api.blunix.io", "https://api.blunix.io/v1?x=1",
                    "https://api.blunix.io/other", "http://localhost.evil.com"):
            with self.subTest(url=bad):
                with self.assertRaises(BlunixError):
                    check_api_url(bad)


class _FakeApi:
    """In-process stand-in for api.blunix.io/v1, on localhost."""

    def __init__(self, others=(), mine=()):
        self.others = set(others)
        self.mine = set(mine)
        self.versions = {}
        self.requests = []
        self.bad_sha = False
        self.drop_after_commit = False
        api = self

        class Handler(_Quiet, BaseHTTPRequestHandler):
            def _reply(self, status, doc=None):
                body = json.dumps(doc).encode() if doc is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _body(self):
                length = int(self.headers.get("Content-Length", "0"))
                data = self.rfile.read(length)
                api.requests.append((self.command, self.path, str(self.headers), data))
                return data

            def _authed(self):
                if self.headers.get("Authorization") != "Bearer " + KEY:
                    self._reply(401, {"error": "unauthorized"})
                    return False
                return True

            def do_GET(self):
                self._body()
                if not self._authed():
                    return
                if self.path == "/v1/hosts":
                    self._reply(200, {"hosts": [{"label": l, "latest": None} for l in sorted(api.mine)]})
                else:
                    self._reply(404, {"error": "not found"})

            def do_POST(self):
                data = self._body()
                if not self._authed():
                    return
                if self.path == "/v1/hosts":
                    label = json.loads(data)["label"]
                    if label in api.others or label in api.mine:
                        self._reply(409, {"error": "taken"})
                        return
                    api.mine.add(label)
                    self._reply(201, {"label": label})
                    return
                parts = self.path.split("/")
                if len(parts) == 5 and parts[4] == "builds" and parts[3] in api.mine:
                    if self.headers.get("Content-Type") != "application/octet-stream":
                        self._reply(400, {"error": "refused ciphertext"})
                        return
                    if not data.startswith(b"age-encryption.org/v1\n"):
                        self._reply(400, {"error": "refused ciphertext"})
                        return
                    label = parts[3]
                    version = api.versions.get(label, 0) + 1
                    api.versions[label] = version
                    if api.drop_after_commit:
                        # Committed, then the connection drops before any answer.
                        self.close_connection = True
                        return
                    sha = hashlib.sha256(data).hexdigest()
                    if api.bad_sha:
                        sha = "0" * 64
                    self._reply(201, {"version": version, "sha256": sha, "size": len(data),
                                      "url": "x", "pinnedUrl": "y"})
                    return
                self._reply(404, {"error": "not found"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = "http://127.0.0.1:" + str(self.server.server_address[1])

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def seen(self):
        blob = b""
        for method, path, headers, data in self.requests:
            blob += method.encode() + path.encode() + headers.encode() + data
        return blob


def _fake_encrypt(doc, key):
    return AGE + hashlib.sha256(doc).digest()


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.site = os.path.join(self.tmp, "site.yaml")
        with open(self.site, "wb") as handle:
            handle.write(SITE)

    def _api(self, **kw):
        fake = _FakeApi(**kw)
        self.addCleanup(fake.close)
        return fake, Api(fake.url, KEY)

    def _publish(self, api, out, encrypt=_fake_encrypt, site=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cmd_publish(site or self.site, {"out": out}, api=api, encrypt=encrypt)
        return code, stdout.getvalue() + stderr.getvalue()

    def _keys(self, out):
        with open(os.path.join(out, "keys.txt")) as handle:
            text = handle.read()
        return text, [line.split(": ", 1)[1] for line in text.splitlines() if line.startswith("Key: ")]

    def test_publish_happy_path(self):
        fake, api = self._api()
        out = os.path.join(self.tmp, "out")
        code, output = self._publish(api, out)
        self.assertEqual(code, 0)
        keys_path = os.path.join(out, "keys.txt")
        self.assertEqual(stat.S_IMODE(os.stat(keys_path).st_mode), 0o600)
        text, keys = self._keys(out)
        self.assertEqual(len(keys), 2)
        self.assertIn("Latest URL: https://ada.blnx.io/", text)
        self.assertIn("Pinned URL: https://v1.ada.blnx.io/", text)
        self.assertIn("Machine hostname: ada-1", text)
        with open(os.path.join(out, "state.json")) as handle:
            state_text = handle.read()
        state = json.loads(state_text)["published"]
        self.assertEqual([r["version"] for r in state], [1, 1])
        self.assertEqual(state[0]["pinnedUrl"], "https://v1.ada.blnx.io/")
        for display in keys:
            canonical = display.replace("-", "")
            for blob in (state_text, output, fake.seen().decode("utf-8", "replace")):
                self.assertNotIn(display, blob)
                self.assertNotIn(canonical, blob)
        self.assertNotIn(KEY, output + state_text)
        self.assertIn("publish again uploads new versions", output)
        # Second run: new versions; the same --out is refused so no card is lost.
        code, _ = self._publish(api, os.path.join(self.tmp, "out2"))
        self.assertEqual(code, 0)
        _, keys2 = self._keys(os.path.join(self.tmp, "out2"))
        self.assertNotEqual(keys, keys2)
        self.assertEqual(fake.versions, {"ada": 2, "grace": 2})
        with self.assertRaises(BlunixError):
            self._publish(api, out)

    def test_label_owned_by_other_stops(self):
        fake, api = self._api(others={"grace"})
        out = os.path.join(self.tmp, "out")
        code, output = self._publish(api, out)
        self.assertEqual(code, 1)
        self.assertIn("grace belongs to another account", output)
        self.assertEqual(fake.versions, {"ada": 1})
        _, keys = self._keys(out)
        self.assertEqual(len(keys), 1)
        with open(os.path.join(out, "state.json")) as handle:
            self.assertEqual(len(json.load(handle)["published"]), 1)
        self.assertFalse(any(p.startswith("/v1/hosts/grace") for _, p, _, _ in fake.requests))

    def test_label_already_mine_continues(self):
        fake, api = self._api(mine={"ada"})
        code, _ = self._publish(api, os.path.join(self.tmp, "out"))
        self.assertEqual(code, 0)
        self.assertEqual(fake.versions, {"ada": 1, "grace": 1})

    def test_invalid_site_makes_no_call(self):
        fake, api = self._api()
        bad = os.path.join(self.tmp, "bad.yaml")
        with open(bad, "wb") as handle:
            handle.write(_site(_m("01"), defaults="defaults: {disk: nope, access: regular}\n"))
        with self.assertRaises(BlunixError):
            self._publish(api, os.path.join(self.tmp, "out"), site=bad)
        self.assertEqual(fake.requests, [])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "out")))

    def test_wrong_key_and_bad_result(self):
        fake = _FakeApi()
        self.addCleanup(fake.close)
        wrong = Api(fake.url, "blx_" + "z" * 43)
        with self.assertRaises(BlunixError) as caught:
            wrong.list_labels()
        self.assertEqual(str(caught.exception), "api refused the account key")
        fake.bad_sha = True
        with self.assertRaises(BlunixError) as caught:
            self._publish(Api(fake.url, KEY), os.path.join(self.tmp, "out"))
        self.assertIn("does not match", str(caught.exception))

    def test_key_is_on_disk_when_the_upload_answer_is_lost(self):
        fake, api = self._api()
        fake.drop_after_commit = True
        out = os.path.join(self.tmp, "out")
        with self.assertRaises(BlunixError) as caught:
            self._publish(api, out)
        self.assertEqual(str(caught.exception), "api unreachable")
        self.assertEqual(fake.versions, {"ada": 1})
        text, keys = self._keys(out)
        self.assertEqual(len(keys), 1)
        self.assertEqual(len(keys[0].replace("-", "")), 20)
        self.assertIn("Install card for ada. Pending", text)
        self.assertIn("Not confirmed", text)
        self.assertNotIn("Published:", text)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(out, "keys.txt")).st_mode), 0o600)

    def test_pending_card_precedes_the_upload(self):
        _, api = self._api()
        out = os.path.join(self.tmp, "out")
        seen = []
        real = api.upload

        def upload(label, ciphertext):
            with open(os.path.join(out, "keys.txt")) as handle:
                seen.append(handle.read())
            return real(label, ciphertext)

        api.upload = upload
        code, _ = self._publish(api, out)
        self.assertEqual(code, 0)
        self.assertIn("Key: ", seen[0])
        self.assertNotIn("Published:", seen[0])
        text, _ = self._keys(out)
        self.assertEqual(text.count("Published: "), 2)
        self.assertNotIn("Not confirmed", text)

    def test_non_age_output_refused(self):
        _, api = self._api()
        with self.assertRaises(BlunixError):
            self._publish(api, os.path.join(self.tmp, "out"), encrypt=lambda d, k: d)

    def test_unreachable_api(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        with self.assertRaises(BlunixError) as caught:
            Api("http://127.0.0.1:" + str(port), KEY, timeout=2).list_labels()
        self.assertEqual(str(caught.exception), "api unreachable")

    def test_plan_prints_and_checks(self):
        _, api = self._api(mine={"ada"})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cmd_plan(self.site, {"check": True}, api=api), 0)
        text = out.getvalue()
        self.assertIn("label ada", text)
        self.assertIn("already yours", text)
        self.assertIn("would be reserved", text)
        self.assertIn("new versions", text)

    @unittest.skipUnless(shutil.which("age"), "age not installed here; runs in image/run-unit-tests.sh")
    def test_publish_with_real_age(self):
        from blunix.age import decrypt_bytes, encrypt_bytes
        from blunix.keyfmt import passphrase_candidates
        from blunix.schema import load_bytes

        fake, api = self._api()
        out = os.path.join(self.tmp, "out")
        code, _ = self._publish(api, out, encrypt=encrypt_bytes)
        self.assertEqual(code, 0)
        _, keys = self._keys(out)
        uploads = [d for m, p, _, d in fake.requests if p.endswith("/builds")]
        doc = load_bytes(decrypt_bytes(uploads[0], passphrase_candidates(keys[0])[0]))
        self.assertEqual(doc["hostname"], "ada-1")
        self.assertEqual(doc["network"]["address"], "192.0.2.21/24")


MEDIA = {"vmlinuz": b"KERNEL", "initrd.img": b"INITRD", "blunix.squashfs": b"SQUASH"}


def _media(root, sums=True):
    for name, data in MEDIA.items():
        with open(os.path.join(root, name), "wb") as handle:
            handle.write(data)
    if sums:
        with open(os.path.join(root, "SHA256SUMS"), "w") as handle:
            for name, data in MEDIA.items():
                handle.write(hashlib.sha256(data).hexdigest() + "  " + name + "\n")


class _FakeResp:
    def __init__(self, status=200, body=AGE, length=None):
        self.status = status
        self._body = body
        self._length = length

    def getheader(self, name):
        return self._length

    def read(self, n):
        data, self._body = self._body[:n], self._body[n:]
        return data

    def close(self):
        return


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class ServeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.media = os.path.join(self.tmp, "media")
        os.mkdir(self.media)
        _media(self.media)
        with open(os.path.join(self.media, "keys.txt"), "w") as handle:
            handle.write("Key: k7m2q-9dx4t-ab3fz-0wnr8\n")
        with open(os.path.join(self.tmp, "secret"), "w") as handle:
            handle.write("outside")
        self.calls = []
        self.upstream = {"status": 200, "body": AGE, "length": None}
        self.clock = _Clock()

        def opener(host, context, timeout, connect_to):
            self.calls.append(host)
            return _FakeResp(self.upstream["status"], self.upstream["body"], self.upstream["length"])

        self.log = []
        self.server = ProxyServer(
            ("127.0.0.1", 0),
            site=parse_site(SITE),
            media=self.media,
            advertise="192.0.2.5:8750",
            fetcher=BuildFetcher(opener=opener, clock=self.clock),
            limiter=RateLimiter(capacity=1000),
            log=self.log.append,
        )
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def get(self, path, method="GET", headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, resp.read(), resp
        finally:
            conn.close()

    def raw(self, data):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(data)
            chunks = []
            while True:
                try:
                    block = sock.recv(65536)
                except ConnectionResetError:
                    break
                if not block:
                    break
                chunks.append(block)
        return b"".join(chunks)

    def test_healthz(self):
        self.assertEqual(self.get("/healthz")[:2], (200, b"ok\n"))

    def test_open_proxy_refused(self):
        for host in (
            "evil.com",
            "blnx.io",
            "www.blnx.io",
            "blnx.io.evil.com",
            "ada.blnx.io.evil.com",
            "evilblnx.io",
            "ada.evilblnx.io",
            "ada.build.blunix.io",
            "v3.ada.build.blunix.io",
            "build.blunix.io",
            "ADA.blnx.io",
            "ada.BLNX.io",
            "Ada.blnx.io",
            "ada.blnx.io.",
            "ada.blnx.io:443",
            "user@ada.blnx.io",
            "ada.blnx.io@evil.com",
            "1.2.3.4",
            "127.0.0.1",
            "[::1]",
            "v1.blnx.io",
            "v0.ada.blnx.io",
            "v01.ada.blnx.io",
            "v1234567.ada.blnx.io",
            "x.ada.blnx.io",
            "a.b.ada.blnx.io",
            "xn--ada.blnx.io",
            "ada.blnx.io/../evil.com",
            "%61da.blnx.io",
            "ada%2eblnx.io",
            "ada-1042.build.blunix.io.evil.com",
            "",
        ):
            with self.subTest(host=host):
                status, body, _ = self.get("/v1/build/" + host)
                self.assertEqual(status, 404)
                self.assertEqual(body, b"")
        self.assertEqual(self.raw(b"GET http://evil.com/ HTTP/1.1\r\nHost: evil.com\r\n\r\n")[:12],
                         b"HTTP/1.0 404")
        self.assertEqual(self.raw(b"CONNECT evil.com:443 HTTP/1.1\r\n\r\n")[:12], b"HTTP/1.0 405")
        self.assertEqual(self.get("/v1/build/ada.blnx.io?x=1")[0], 404)
        self.assertEqual(self.calls, [])

    def test_relay_and_cache(self):
        status, body, resp = self.get("/v1/build/ada.blnx.io")
        self.assertEqual(status, 200)
        self.assertEqual(body, AGE)
        self.assertEqual(resp.getheader("Content-Type"), "application/octet-stream")
        self.assertEqual(resp.getheader("X-Blunix-Sha256"), hashlib.sha256(AGE).hexdigest())
        self.get("/v1/build/ada.blnx.io")
        self.assertEqual(self.calls, ["ada.blnx.io"])
        self.clock.now += 61
        self.get("/v1/build/ada.blnx.io")
        self.assertEqual(len(self.calls), 2)
        self.get("/v1/build/v3.ada.blnx.io")
        self.clock.now += 3599
        self.get("/v1/build/v3.ada.blnx.io")
        self.assertEqual(self.calls.count("v3.ada.blnx.io"), 1)
        self.assertEqual(self.get("/v1/build/v3.ada.blnx.io", "HEAD")[:2], (200, b""))

    def test_pinned_cache_expires_after_an_hour(self):
        self.get("/v1/build/v3.ada.blnx.io")
        self.clock.now += 3601
        self.upstream["status"] = 404
        self.assertEqual(self.get("/v1/build/v3.ada.blnx.io")[0], 404)
        self.assertEqual(self.calls.count("v3.ada.blnx.io"), 2)

    def test_legacy_build_host_not_relayed(self):
        for host in ("ada-1042.build.blunix.io", "name-1.build.blunix.io"):
            with self.subTest(host=host):
                self.assertEqual(self.get("/v1/build/" + host)[:2], (404, b""))
        self.assertEqual(self.calls, [])

    def test_upstream_refusals(self):
        self.upstream["body"] = AGE + b"x" * (256 * 1024)
        self.assertEqual(self.get("/v1/build/big.blnx.io")[:2], (502, b""))
        self.upstream.update(body=AGE, length=str(10 ** 7))
        self.assertEqual(self.get("/v1/build/len.blnx.io")[0], 502)
        self.upstream.update(body=b"#!/bin/sh\nrm -rf /\n", length=None)
        self.assertEqual(self.get("/v1/build/sh.blnx.io")[0], 502)
        self.upstream.update(status=404, body=b"")
        self.assertEqual(self.get("/v1/build/gone.blnx.io")[0], 404)
        self.upstream.update(status=302)
        self.assertEqual(self.get("/v1/build/moved.blnx.io")[0], 502)

    def test_tls_failure_is_502_without_cleartext(self):
        seen = []
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)

        def plain():
            # A plain-HTTP upstream: records what arrives, answers in cleartext.
            for _ in range(2):
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                conn.settimeout(3)
                try:
                    seen.append(conn.recv(4096))
                    conn.sendall(b"HTTP/1.0 200 OK\r\n\r\n" + AGE)
                except OSError:
                    pass
                conn.close()

        threading.Thread(target=plain, daemon=True).start()
        self.addCleanup(listener.close)
        fetcher = BuildFetcher(context_factory=ssl.create_default_context,
                               connect_to=listener.getsockname(), timeout=5)
        self.assertEqual(fetcher.get("ada.blnx.io"), (502, None, None))
        self.assertTrue(seen)
        for data in seen:
            self.assertNotIn(b"GET /", data)

        def unverified():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx

        calls = []
        fetcher = BuildFetcher(context_factory=unverified,
                               opener=lambda *a: calls.append(a) or _FakeResp())
        self.assertEqual(fetcher.get("ada.blnx.io"), (502, None, None))
        self.assertEqual(calls, [])

    def test_netconfig(self):
        status, body, resp = self.get("/v1/netconfig/00-50-56-AA-BB-01")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"address": "192.0.2.21/24", "gateway": "192.0.2.1",
                                            "dns": ["192.0.2.53"]})
        self.assertEqual(self.get("/v1/netconfig/00:50:56:aa:bb:99")[0], 404)
        self.assertEqual(self.get("/v1/netconfig/00:50:56:aa:bb:02")[0], 404)
        self.assertEqual(self.get("/v1/netconfig/../../etc/passwd")[0], 404)

    def test_media_traversal(self):
        for name, data in MEDIA.items():
            self.assertEqual(self.get("/media/" + name)[:2], (200, data))
        # Swapped after the startup check: a symlink out, and new bytes in place.
        os.remove(os.path.join(self.media, "initrd.img"))
        os.symlink(os.path.join(self.tmp, "secret"), os.path.join(self.media, "initrd.img"))
        with open(os.path.join(self.media, "vmlinuz"), "wb") as handle:
            handle.write(b"EVIL KERNEL")
        for path in ("/media/../secret", "/media/..%2fsecret", "/media/%2e%2e/secret",
                     "/media/keys.txt", "/media/initrd.img", "/media//etc/passwd",
                     "/media/vmlinuz/..", "/media/", "/keys.txt", "/media/SHA256SUMS",
                     "/media/vmlinuz"):
            with self.subTest(path=path):
                status, body, _ = self.get(path)
                self.assertEqual(status, 404)
                self.assertNotIn(b"outside", body)
                self.assertNotIn(b"k7m2q", body)
                self.assertNotIn(b"EVIL", body)
        self.assertTrue(any("vmlinuz changed since startup" in line for line in self.log))

    def test_boot_ipxe(self):
        status, body, _ = self.get("/v1/boot.ipxe")
        self.assertEqual(status, 200)
        text = body.decode()
        self.assertTrue(text.startswith("#!ipxe\n"))
        self.assertIn("kernel http://192.0.2.5:8750/media/vmlinuz", text)
        self.assertIn("blunix.proxy=192.0.2.5:8750", text)
        # live-boot reads fetch=, and nothing else, to find the squashfs.
        self.assertIn(" boot=live ", text)
        self.assertIn("fetch=http://192.0.2.5:8750/media/blunix.squashfs", text)
        self.assertNotIn("blunix.media=", text)
        self.assertIn("initrd http://192.0.2.5:8750/media/initrd.img", text)

    def test_boot_ipxe_never_trusts_the_host_header(self):
        self.server.advertise = None
        for host in ("10.1.1.1:8750", "evil.example:80", "evil_host:1"):
            with self.subTest(host=host):
                self.assertEqual(self.get("/v1/boot.ipxe", headers={"Host": host})[:2], (404, b""))
        self.assertTrue(any("boot.ipxe needs --advertise" in line for line in self.log))

    def test_boot_ipxe_address_comes_from_a_specific_listen(self):
        server = ProxyServer(("127.0.0.1", 0), log=self.log.append)
        self.addCleanup(server.server_close)
        self.assertEqual(server.advertise, "127.0.0.1:" + str(server.server_address[1]))

        class Unbound(ProxyServer):
            def server_bind(self):
                return

            def server_activate(self):
                return

        for wildcard in ("0.0.0.0", ""):
            with self.subTest(listen=wildcard):
                server = Unbound((wildcard, 8750), log=self.log.append)
                self.addCleanup(server.server_close)
                self.assertIsNone(server.advertise)

    def test_connection_cap_closes_fast(self):
        server = ProxyServer(("127.0.0.1", 0), advertise="192.0.2.5:8750",
                             limiter=RateLimiter(capacity=1000), log=self.log.append,
                             max_connections=1)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        hold = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.addCleanup(hold.close)
        hold.sendall(b"GET /heal")
        deadline = time.monotonic() + 5
        while server._slots._value != 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(server._slots._value, 0)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as extra:
            extra.sendall(b"GET /healthz HTTP/1.0\r\n\r\n")
            start = time.monotonic()
            try:
                got = extra.recv(100)
            except ConnectionResetError:
                got = b""
            self.assertEqual(got, b"")
            self.assertLess(time.monotonic() - start, 2)
        hold.sendall(b"thz HTTP/1.0\r\n\r\n")
        self.assertTrue(hold.recv(100).startswith(b"HTTP/1.0 200"))
        hold.close()
        deadline = time.monotonic() + 5
        while server._slots._value != 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/healthz")
        self.assertEqual(conn.getresponse().status, 200)
        conn.close()

    def test_whole_request_deadline(self):
        self.server.request_deadline = 0.5
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            start = time.monotonic()
            got = b""
            # A trickle that resets any per-read timeout, one byte at a time.
            for byte in b"GET /healthz HTTP/1.0\r\nX-Slow: yes":
                try:
                    sock.sendall(bytes([byte]))
                except OSError:
                    break
                time.sleep(0.05)
            try:
                got = sock.recv(100)
            except ConnectionResetError:
                got = b""
            self.assertEqual(got, b"")
            self.assertLess(time.monotonic() - start, 4)
        self.assertTrue(any("passed the request deadline" in line for line in self.log))

    def test_limits_and_methods(self):
        for method in ("POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH"):
            self.assertEqual(self.get("/healthz", method)[0], 405)
        self.assertIn(b" 414", self.raw(b"GET /" + b"a" * 5000 + b" HTTP/1.0\r\n\r\n")[:20])
        many = b"".join(b"X-H" + str(i).encode() + b": " + b"v" * 100 + b"\r\n" for i in range(90))
        self.assertIn(b" 431", self.raw(b"GET /healthz HTTP/1.0\r\n" + many + b"\r\n")[:20])
        self.server.limiter = RateLimiter(capacity=2, refill=0.0)
        codes = [self.get("/healthz")[0] for _ in range(4)]
        self.assertEqual(codes, [200, 200, 429, 429])

    def test_access_log_has_no_query_or_body(self):
        self.get("/v1/netconfig/zz?token=hunter2secret", headers={"Authorization": "Bearer " + KEY})
        joined = "\n".join(self.log)
        self.assertIn("GET /v1/netconfig/zz 404", joined)
        self.assertNotIn("hunter2secret", joined)
        self.assertNotIn(KEY, joined)

    def test_build_host_kinds(self):
        self.assertEqual(build_host_kind("ada.blnx.io"), "latest")
        self.assertEqual(build_host_kind("v3.ada.blnx.io"), "pinned")
        self.assertEqual(build_host_kind("v999999.ada.blnx.io"), "pinned")
        for host in ("ada.build.blunix.io", "blnx.io", "evilblnx.io", "blnx.io.evil.com",
                     "ada-1042.build.blunix.io"):
            with self.assertRaises(BlunixError):
                build_host_kind(host)


class RateLimiterTests(unittest.TestCase):
    def test_full_table_evicts_the_oldest_not_all(self):
        limiter = RateLimiter(capacity=1, refill=0.0, max_buckets=3)
        self.assertTrue(limiter.allow("a"))
        self.assertFalse(limiter.allow("a"))
        self.assertTrue(limiter.allow("b"))
        self.assertFalse(limiter.allow("a"))
        self.assertTrue(limiter.allow("c"))
        # A new IP evicts b, the least recently seen. a stays limited.
        self.assertTrue(limiter.allow("d"))
        self.assertFalse(limiter.allow("a"))
        self.assertTrue(limiter.allow("b"))
        # A flood of new IPs never resets a busy bucket that keeps being seen.
        for n in range(50):
            self.assertFalse(limiter.allow("a"))
            limiter.allow("flood" + str(n))
        self.assertFalse(limiter.allow("a"))


class MediaSumsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.media = os.path.join(self.tmp, "media")
        os.mkdir(self.media)

    def _serve(self, **kw):
        server = ProxyServer(("127.0.0.1", 0), media=self.media, advertise="192.0.2.5:8750",
                             log=lambda line: None, **kw)
        server.server_close()
        return server

    def test_good_sums_starts(self):
        _media(self.media)
        self.assertEqual(sorted(self._serve().media_ids), sorted(MEDIA))

    def test_sums_from_another_path_with_other_entries(self):
        _media(self.media, sums=False)
        sums = os.path.join(self.tmp, "SHA256SUMS")
        with open(sums, "w") as handle:
            handle.write(hashlib.sha256(b"iso").hexdigest() + "  blunix-installer.iso\n")
            for name, data in MEDIA.items():
                handle.write(hashlib.sha256(data).hexdigest() + " *" + name + "\n")
        self.assertEqual(sorted(self._serve(sums=sums).media_ids), sorted(MEDIA))

    def test_mismatch_refuses(self):
        _media(self.media)
        with open(os.path.join(self.media, "blunix.squashfs"), "ab") as handle:
            handle.write(b"x")
        with self.assertRaises(BlunixError) as caught:
            self._serve()
        self.assertEqual(str(caught.exception),
                         "media: blunix.squashfs does not match SHA256SUMS; refusing to start")

    def test_missing_sums_refuses(self):
        _media(self.media, sums=False)
        with self.assertRaises(BlunixError) as caught:
            self._serve()
        self.assertIn("no SHA256SUMS", str(caught.exception))

    def test_missing_entry_file_or_bad_line_refuses(self):
        _media(self.media)
        path = os.path.join(self.media, "SHA256SUMS")
        with open(path) as handle:
            good = handle.read()
        cases = {
            "no entry for initrd.img": "".join(l + "\n" for l in good.splitlines() if "initrd" not in l),
            "not a single sha256 entry": good + "zz  vmlinuz\n",
            "not a single sha256 entry ": good + good.splitlines()[0] + "\n",
        }
        for want, text in cases.items():
            with self.subTest(want=want):
                with open(path, "w") as handle:
                    handle.write(text)
                with self.assertRaises(BlunixError) as caught:
                    self._serve()
                self.assertIn(want.strip(), str(caught.exception))
        with open(path, "w") as handle:
            handle.write(good)
        os.remove(os.path.join(self.media, "initrd.img"))
        with self.assertRaises(BlunixError) as caught:
            self._serve()
        self.assertIn("initrd.img is missing", str(caught.exception))
        target = os.path.join(self.tmp, "initrd.real")
        with open(target, "wb") as handle:
            handle.write(MEDIA["initrd.img"])
        os.symlink(target, os.path.join(self.media, "initrd.img"))
        with self.assertRaises(BlunixError) as caught:
            self._serve()
        self.assertIn("missing or a symlink", str(caught.exception))

    def test_cli_refuses_with_one_sentence(self):
        _media(self.media)
        with open(os.path.join(self.media, "vmlinuz"), "wb") as handle:
            handle.write(b"swapped")
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = main(["serve", "--media", self.media, "--listen", "127.0.0.1:8750"])
        self.assertEqual(code, 1)
        self.assertEqual(err.getvalue(),
                         "blunix proxy: media: vmlinuz does not match SHA256SUMS; refusing to start\n")
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            self.assertEqual(main(["serve", "--sums", "x", "--listen", "127.0.0.1:8750"]), 1)
        self.assertIn("give both", err.getvalue())


class DnsmasqTests(unittest.TestCase):
    def test_render(self):
        site = parse_site(SITE)
        text = render_dnsmasq(site, "192.0.2.5:8750", interface="eth1")
        lines = text.splitlines()
        self.assertIn("port=0", lines)
        self.assertIn("# Netboot is for trusted LANs only until images are signed: media travels over plain http.",
                      lines)
        self.assertIn("dhcp-host=00:50:56:aa:bb:01,set:blx-ada,192.0.2.21,ada-1,12h", lines)
        self.assertIn("dhcp-host=00:50:56:aa:bb:02,set:blx-grace,grace-1", lines)
        self.assertIn("dhcp-option=tag:blx-ada,option:router,192.0.2.1", lines)
        self.assertIn("dhcp-range=192.0.2.0,static,255.255.255.0,12h", lines)
        self.assertIn("dhcp-boot=tag:known,tag:ipxe,http://192.0.2.5:8750/v1/boot.ipxe", lines)
        self.assertIn("dhcp-boot=tag:known,tag:!ipxe,tag:efi64,ipxe.efi", lines)
        self.assertIn("dhcp-boot=tag:known,tag:!ipxe,tag:!efi64,undionly.kpxe", lines)
        self.assertIn("interface=eth1", lines)
        ranged = render_dnsmasq(site, "192.0.2.5:8750", dhcp_range="192.0.2.100,192.0.2.150")
        self.assertIn("dhcp-range=192.0.2.100,192.0.2.150,12h", ranged.splitlines())
        self.assertIn("blunix.proxy=192.0.2.5:8750", render_ipxe("192.0.2.5:8750"))

    def test_refusals(self):
        site = parse_site(SITE)
        for kwargs in ({"interface": "eth1\ndhcp-script=/bin/sh"}, {"interface": "-x"},
                       {"dhcp_range": "192.0.2.9,192.0.2.1"}, {"dhcp_range": "a,b"},
                       {"tftp_root": "/srv/../etc"}, {"tftp_root": "relative"}):
            with self.subTest(**kwargs):
                with self.assertRaises(BlunixError):
                    render_dnsmasq(site, "192.0.2.5:8750", **kwargs)
        dhcp_only = parse_site(_site(_m("01")))
        with self.assertRaises(BlunixError):
            render_dnsmasq(dhcp_only, "192.0.2.5:8750")

    def test_cli(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        site = os.path.join(tmp, "site.yaml")
        with open(site, "wb") as handle:
            handle.write(SITE)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(main(["dnsmasq", site, "--proxy", "192.0.2.5:8750"]), 0)
            self.assertEqual(main(["dnsmasq", site, "--config", os.path.join(tmp, "none")]), 1)
            self.assertEqual(main(["dnsmasq", site, "--proxy", "evil host:1"]), 1)
        self.assertIn("port=0", out.getvalue())
        self.assertIn("give --proxy", err.getvalue())


class SourceTests(unittest.TestCase):
    def test_proxy_modules(self):
        lib = os.path.join(os.path.dirname(__file__), "..", "lib", "blunix")
        for name in sorted(os.listdir(lib)):
            if not name.startswith("proxy") or not name.endswith(".py"):
                continue
            with open(os.path.join(lib, name), encoding="utf-8") as handle:
                text = handle.read()
            self.assertIn("Threats:", text, name)
            for token in ("shell=True", "os.system", "CERT_NONE", "check_hostname = False",
                          "_create_unverified_context", "logging."):
                self.assertFalse(token in text, name + " contains " + token)


if __name__ == "__main__":
    unittest.main()

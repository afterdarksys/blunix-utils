"""Fail-closed checks for the node document, age, and the test-image bootstrap.

Threats: a document can smuggle key material, a second secret, or a shell
script. These tests reject that input and check that a wrong passphrase does
not apply. They do not log passphrase bytes.
"""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import io
import os
import ssl
import stat
import tarfile
import tempfile
import unittest
import urllib.request

from blunix.access import (
    SPEECH_UNITS,
    load_access,
    parse_access,
    plan_access,
    profile_from_cmdline,
    select_font,
)
from blunix.age import decrypt_bytes, decrypt_to_file, encrypt_bytes
from blunix.ai import artifact_url, digest_matches, install_ai, parse_ai
from blunix.ai import _check_url
from blunix.bootstrap import (
    MAX_CIPHER,
    _Redirect,
    check_fetch_url,
    fetch_https,
    read_marker,
    run_bootstrap,
)
from blunix.cli import main
from blunix.console import console_line
from blunix.disk import load_disk, parse_disk, parse_size, render_disk
from blunix.errors import BlunixError, DecryptError
from blunix.gui import apply_gui
from blunix.network import check_match, load_network, parse_network, render_network
from blunix.tools import _check_url as tool_check_url
from blunix.tools import artifact_url as tool_artifact_url
from blunix.tools import extract_named, install_tools, load_tools, parse_tools
from blunix.node import apply_node, parse_node
from blunix.schema import MAX_DOCUMENT, load_bytes, load_path, load_text, require_build_host

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODELS = os.path.join(ROOT, "models")
LIB = os.path.join(ROOT, "lib", "blunix")
HOST = "ada-1042.build.blunix.io"
SECRET = "super-secret-value-xyz"


def _good_context():
    class Ctx:
        verify_mode = ssl.CERT_REQUIRED
        check_hostname = True

    return Ctx()


class _Body:
    def __init__(self, payload):
        self.payload = payload
        self.closed = False

    def read(self, _n):
        data = self.payload
        self.payload = b""
        return data

    def close(self):
        self.closed = True


class SchemaTests(unittest.TestCase):
    def test_duplicate_key(self):
        with self.assertRaises(BlunixError) as caught:
            load_text("name: one\nname: two\n")
        self.assertEqual(str(caught.exception), "duplicate key")

    def test_alias_refused(self):
        with self.assertRaises(BlunixError) as caught:
            load_text("a: &a 1\nb: *a\n")
        self.assertEqual(str(caught.exception), "rejected plaintext")

    def test_unknown_field(self):
        text = (
            "apiVersion: blunix.dev/v1\nkind: Node\nname: blunix-test\n"
            "hostname: blunix-test\ndisk: cloud-vm\nnetwork: dhcp-any\n"
            "access: regular\nai: default\nextra: 1\n"
            "update:\n  url: https://updates.blunix.io/blunix\n  channel: stable\n"
            "sysexts: []\n"
        )
        with self.assertRaises(BlunixError) as caught:
            parse_node(load_text(text))
        self.assertEqual(str(caught.exception), "unknown field")

    def test_banned_names_hide_the_value(self):
        keys = ("password", "api-key", "API_KEY", "Private-Key", "xai_api_key")
        for key in keys:
            with self.subTest(key=key):
                with self.assertRaises(BlunixError) as caught:
                    load_text(key + ": " + SECRET + "\n")
                self.assertEqual(str(caught.exception), "refused field")
                self.assertNotIn(SECRET, str(caught.exception))

    def test_nested_password_hides_the_value(self):
        with self.assertRaises(BlunixError) as caught:
            load_text("outer:\n  password: " + SECRET + "\n")
        self.assertEqual(str(caught.exception), "refused field")
        self.assertNotIn(SECRET, str(caught.exception))

    def test_merge_key_is_unknown(self):
        text = (
            "apiVersion: blunix.dev/v1\nkind: Node\nname: blunix-test\n"
            "hostname: blunix-test\n<<:\n  extra: 1\n"
            "disk: cloud-vm\nnetwork: dhcp-any\naccess: regular\nai: default\n"
            "update:\n  url: https://updates.blunix.io/blunix\n  channel: stable\n"
            "sysexts: []\n"
        )
        with self.assertRaises(BlunixError) as caught:
            parse_node(load_text(text))
        self.assertEqual(str(caught.exception), "unknown field")

    def test_shell_elf_and_nul(self):
        for payload in (b"#!/bin/sh\n", b"\x7fELF", b"a\x00b"):
            with self.subTest(payload=payload[:4]):
                with self.assertRaises(BlunixError) as caught:
                    load_bytes(payload)
                self.assertEqual(str(caught.exception), "rejected plaintext")

    def test_build_host(self):
        self.assertEqual(require_build_host(HOST), HOST)
        for bad in (
            "ADA-1.build.blunix.io",
            "ada-1042.build.blunix.com",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(BlunixError) as caught:
                    require_build_host(bad)
                self.assertEqual(str(caught.exception), "refused hostname")


class DiskTests(unittest.TestCase):
    def test_sizes(self):
        self.assertEqual(parse_size("512M"), 536870912)
        self.assertEqual(parse_size("1G"), 1073741824)
        for bad in ("100K", "512", "0512M"):
            with self.subTest(bad=bad):
                with self.assertRaises(BlunixError) as caught:
                    parse_size(bad)
                self.assertEqual(str(caught.exception), "refused size")

    def test_esp_must_be_first(self):
        doc = {
            "apiVersion": "blunix.dev/v1",
            "kind": "Disk",
            "name": "cloud-vm",
            "partitions": [
                {"name": "var", "type": "var-x86-64", "size": "1G", "format": "ext4", "weight": 1000},
                {"name": "esp", "type": "esp", "size": "512M", "format": "vfat"},
            ],
        }
        with self.assertRaises(BlunixError) as caught:
            parse_disk(doc)
        self.assertEqual(str(caught.exception), "esp must be first")

    def test_two_weights(self):
        doc = {
            "apiVersion": "blunix.dev/v1",
            "kind": "Disk",
            "name": "cloud-vm",
            "partitions": [
                {"name": "esp", "type": "esp", "size": "512M", "format": "vfat"},
                {"name": "var", "type": "var-x86-64", "size": "1G", "format": "ext4", "weight": 1000},
                {"name": "varb", "type": "var-x86-64", "size": "1G", "format": "ext4", "weight": 1000},
            ],
        }
        with self.assertRaises(BlunixError) as caught:
            parse_disk(doc)
        self.assertEqual(str(caught.exception), "refused weight")

    def test_verity_without_hash(self):
        doc = {
            "apiVersion": "blunix.dev/v1",
            "kind": "Disk",
            "name": "cloud-vm",
            "partitions": [
                {"name": "esp", "type": "esp", "size": "512M", "format": "vfat"},
                {
                    "name": "root-a",
                    "type": "root-x86-64",
                    "size": "2G",
                    "format": "erofs",
                    "verity": "missing-hash",
                    "read_only": True,
                },
                {"name": "var", "type": "var-x86-64", "size": "1G", "format": "ext4", "weight": 1000},
            ],
        }
        with self.assertRaises(BlunixError) as caught:
            parse_disk(doc)
        self.assertEqual(str(caught.exception), "refused verity")

    def test_cloud_vm_render(self):
        files = render_disk(load_disk(MODELS, "cloud-vm"))
        self.assertEqual(sorted(files)[0], "10-esp.conf")
        var = files["60-var.conf"]
        self.assertIn("Weight=1000", var)
        self.assertNotIn("SizeMaxBytes", var)
        self.assertNotIn("Encrypt", var)
        root = files["20-root-a.conf"]
        verity = files["30-root-a-verity.conf"]
        self.assertIn("ReadOnly=yes", root)
        self.assertIn("Verity=data", root)
        self.assertIn("VerityMatchKey=root-a", root)
        self.assertIn("Verity=hash", verity)
        self.assertIn("VerityMatchKey=root-a", verity)
        self.assertIn("SizeMinBytes=536870912", files["10-esp.conf"])
        self.assertIn("SizeMinBytes=1073741824", var)
        joined = "\n".join(files.values())
        self.assertNotIn("Encrypt", joined)

    def test_metal_luks_encrypts_var_only(self):
        files = render_disk(load_disk(MODELS, "metal-luks"))
        self.assertIn("Encrypt=tpm2", files["60-var.conf"])
        self.assertNotIn("Encrypt", files["20-root-a.conf"])
        self.assertNotIn("Encrypt", files["40-root-b.conf"])


class NetworkTests(unittest.TestCase):
    def test_dhcp_and_static_refused(self):
        doc = load_path(os.path.join(MODELS, "network", "dhcp-any.yaml"))
        doc["address"] = "192.0.2.10/24"
        doc["gateway"] = "192.0.2.1"
        doc["dns"] = ["192.0.2.53"]
        with self.assertRaises(BlunixError) as caught:
            parse_network(doc)
        self.assertEqual(str(caught.exception), "refused network")

    def test_match_refused(self):
        for pattern in ("*", "veth0", "docker0", "br-lan"):
            with self.subTest(pattern=pattern):
                with self.assertRaises(BlunixError) as caught:
                    check_match(pattern)
                self.assertEqual(str(caught.exception), "refused interface match")

    def test_dhcp_render(self):
        body = render_network(load_network(MODELS, "dhcp-any"))["10-blunix.network"]
        self.assertIn("DHCP=yes", body)
        self.assertIn("Name=en*", body)
        self.assertIn("Name=eth*", body)

    def test_static_render(self):
        body = render_network(load_network(MODELS, "static-single"))["10-blunix.network"]
        self.assertIn("Address=192.0.2.10/24", body)
        self.assertIn("Gateway=192.0.2.1", body)
        self.assertIn("DNS=192.0.2.53", body)
        self.assertIn("Name=en*", body)
        self.assertNotIn("eth*", body)


class AccessTests(unittest.TestCase):
    def test_yaml_mismatch(self):
        doc = load_path(os.path.join(MODELS, "access", "regular.yaml"))
        doc["speech"] = True
        with self.assertRaises(BlunixError) as caught:
            parse_access(doc)
        self.assertEqual(str(caught.exception), "refused access profile")

    def test_unknown_cmdline_is_regular(self):
        self.assertEqual(profile_from_cmdline("quiet blunix.access=nope"), "regular")
        self.assertEqual(profile_from_cmdline(""), "regular")
        self.assertEqual(profile_from_cmdline(None), "regular")

    def test_speech_plan_never_starts_orca(self):
        plan = plan_access(load_access(MODELS, "full-speech"), "/no/such/fonts")
        self.assertEqual(plan["start"], SPEECH_UNITS)
        self.assertNotIn("orca", " ".join(plan["start"]))
        self.assertNotIn("emacspeak", " ".join(plan["start"]))

    def test_large_print_font(self):
        with tempfile.TemporaryDirectory() as directory:
            preferred = os.path.join(directory, "Lat15-Terminus32x16.psf.gz")
            other = os.path.join(directory, "b32.psf.gz")
            open(preferred, "wb").close()
            open(other, "wb").close()
            self.assertEqual(select_font(directory), preferred)
            os.remove(preferred)
            open(os.path.join(directory, "a32.psf"), "wb").close()
            self.assertEqual(os.path.basename(select_font(directory)), "a32.psf")


class AiTests(unittest.TestCase):
    def test_enabled_requires_digest(self):
        doc = {
            "apiVersion": "blunix.dev/v1",
            "kind": "AiTools",
            "name": "default",
            "enabled": True,
            "tools": [{"name": "grok", "version": "1.0.0"}],
        }
        with self.assertRaises(BlunixError) as caught:
            parse_ai(doc)
        self.assertEqual(str(caught.exception), "refused digest")

    def test_bad_digest(self):
        doc = {
            "apiVersion": "blunix.dev/v1",
            "kind": "AiTools",
            "name": "default",
            "enabled": True,
            "tools": [{"name": "grok", "version": "1.0.0", "digest": "sha256:abcd"}],
        }
        with self.assertRaises(BlunixError) as caught:
            parse_ai(doc)
        self.assertEqual(str(caught.exception), "refused digest")

    def test_urls_and_versions(self):
        grok = artifact_url("grok", "1.2.3")
        claude = artifact_url("claude", "1.2.3")
        codex = artifact_url("codex", "1.2.3")
        self.assertEqual(_check_url("grok", grok), "x.ai")
        self.assertEqual(_check_url("claude", claude), "storage.googleapis.com")
        self.assertEqual(_check_url("codex", codex), "github.com")
        for version in ("../x", ".."):
            with self.subTest(version=version):
                with self.assertRaises(BlunixError) as caught:
                    artifact_url("grok", version)
                self.assertEqual(str(caught.exception), "refused version")

    def test_digest_compare(self):
        payload = b"blunix-test-bytes"
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        self.assertTrue(digest_matches(digest, payload))
        tampered = bytearray(payload)
        tampered[-1] ^= 0x01
        self.assertEqual(len(tampered), len(payload))
        self.assertFalse(digest_matches(digest, bytes(tampered)))

    def test_disabled_removes_link_without_fetch(self):
        with tempfile.TemporaryDirectory() as root:
            link_dir = os.path.join(root, "var", "lib", "blunix", "ai", "bin")
            os.makedirs(link_dir)
            link = os.path.join(link_dir, "grok")
            os.symlink("/nonexistent", link)
            calls = []
            model = parse_ai(load_path(os.path.join(MODELS, "ai", "default.yaml")))
            install_ai(model, root, fetch=lambda *args: calls.append(args))
            self.assertFalse(os.path.lexists(link))
            self.assertEqual(calls, [])


class NodeTests(unittest.TestCase):
    def _node(self):
        return load_path(os.path.join(MODELS, "node", "vmware-test.yaml"))

    def test_http_update_and_sysexts(self):
        http_doc = self._node()
        http_doc["update"] = {"url": "http://updates.blunix.io/blunix", "channel": "stable"}
        with self.assertRaises(BlunixError) as caught:
            parse_node(http_doc)
        self.assertEqual(str(caught.exception), "refused update")
        sysext = self._node()
        sysext["sysexts"] = ["speakup"]
        with self.assertRaises(BlunixError) as caught:
            parse_node(sysext)
        self.assertEqual(str(caught.exception), "refused sysexts")

    def test_partial_apply_writes_nothing(self):
        doc = self._node()
        doc["disk"] = "no-such-layout"
        with tempfile.TemporaryDirectory() as root:
            logs = []
            with self.assertRaises(BlunixError) as caught:
                apply_node(doc, root, models=MODELS, log=logs.append)
            self.assertEqual(str(caught.exception), "model not found")
            self.assertFalse(os.path.exists(os.path.join(root, "var", "lib", "blunix", "node.yaml")))
            self.assertFalse(os.path.isdir(os.path.join(root, "usr", "lib", "repart.d")))
            self.assertEqual(logs, [])

    def test_apply_records_layout(self):
        with tempfile.TemporaryDirectory() as root:
            logs = []
            apply_node(self._node(), root, models=MODELS, log=logs.append)
            hostname = os.path.join(root, "etc", "hostname")
            with open(hostname, "r", encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "blunix-test\n")
            self.assertTrue(os.path.isfile(os.path.join(root, "usr", "lib", "repart.d", "10-esp.conf")))
            network = os.path.join(root, "run", "systemd", "network", "10-blunix.network")
            with open(network, "r", encoding="utf-8") as handle:
                self.assertIn("DHCP=yes", handle.read())
            state = os.path.join(root, "var", "lib", "blunix")
            self.assertTrue(os.path.isfile(os.path.join(state, "node.yaml")))
            with open(os.path.join(state, "bootstrap-complete"), "r", encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "applied\n")
            with open(os.path.join(root, "etc", "blunix", "access.profile"), "r", encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "regular\n")
            self.assertEqual(
                logs,
                [
                    "blunix: node document is unsigned; spike is applying it without a signature",
                    "blunix: disk layout recorded; systemd-repart was not executed",
                    "blunix: applied node document blunix-test",
                ],
            )


class AgeTests(unittest.TestCase):
    def test_roundtrip_and_failures(self):
        passphrase = "test-passphrase-value"
        blob = encrypt_bytes(b"hello-node\n", passphrase)
        self.assertNotIn(passphrase.encode("ascii"), blob)
        self.assertEqual(decrypt_bytes(blob, passphrase), b"hello-node\n")
        tampered = bytearray(blob)
        tampered[-1] ^= 0x01
        with self.assertRaises(DecryptError):
            decrypt_bytes(bytes(tampered), passphrase)
        with self.assertRaises(DecryptError) as caught:
            decrypt_bytes(blob, "wrong-passphrase-value")
        self.assertEqual(str(caught.exception), "could not decrypt")
        self.assertNotIn(passphrase, str(caught.exception))

    def test_full_size_document_decrypts(self):
        # The ciphertext of a document at the document cap is over 64 KiB.
        # Decrypt caps ciphertext, not the document size.
        passphrase = "test-passphrase-value"
        document = b"#" * (64 * 1024 - 16)
        blob = encrypt_bytes(document, passphrase)
        self.assertGreater(len(blob), 64 * 1024)
        self.assertEqual(decrypt_bytes(blob, passphrase), document)
        with self.assertRaises(DecryptError):
            decrypt_bytes(b"x" * (256 * 1024 + 1), passphrase)

    def test_empty_passphrase(self):
        import blunix.age as age_mod

        called = []
        original = age_mod.shutil.which

        def which(name):
            called.append(name)
            return original(name)

        age_mod.shutil.which = which
        try:
            with self.assertRaises(DecryptError):
                decrypt_bytes(b"age-ciphertext", "")
            with self.assertRaises(BlunixError) as caught:
                encrypt_bytes(b"", "")
            self.assertIs(type(caught.exception), BlunixError)
            self.assertEqual(str(caught.exception), "age encrypt failed")
        finally:
            age_mod.shutil.which = original
        self.assertEqual(called, [])

    def test_oversize_does_not_call_age(self):
        import blunix.age as age_mod

        called = []
        original = age_mod.shutil.which

        def which(name):
            called.append(name)
            return original(name)

        age_mod.shutil.which = which
        try:
            with self.assertRaises(DecryptError):
                decrypt_bytes(b"x" * (age_mod._MAX_CIPHER + 1), "pw")
            with self.assertRaises(BlunixError):
                encrypt_bytes(b"x" * (MAX_DOCUMENT + 1), "pw")
        finally:
            age_mod.shutil.which = original
        self.assertEqual(called, [])

    def test_decrypt_to_file_mode(self):
        passphrase = "file-passphrase-value"
        blob = encrypt_bytes(b"node: 1\n", passphrase)
        with tempfile.TemporaryDirectory() as directory:
            dest = os.path.join(directory, "plain.yaml")
            decrypt_to_file(blob, passphrase, dest)
            self.assertEqual(stat.S_IMODE(os.stat(dest).st_mode), 0o600)
            missing = os.path.join(directory, "missing.yaml")
            with self.assertRaises(DecryptError):
                decrypt_to_file(blob, "", missing)
            self.assertFalse(os.path.exists(missing))


class BootstrapTests(unittest.TestCase):
    def _cipher(self, root, passphrase):
        source = os.path.join(MODELS, "node", "vmware-test.yaml")
        with open(source, "rb") as handle:
            plain = handle.read()
        blob = encrypt_bytes(plain, passphrase)
        path = os.path.join(root, "usr", "share", "blunix", "bootstrap-fixture.age")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(blob)

    def _marker(self, root, fixture="/usr/share/blunix/bootstrap-fixture.age"):
        path = os.path.join(root, "etc", "blunix", "test-image")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("mode=fixture\nhost=" + HOST + "\nfixture=" + fixture + "\n")

    def test_shadow_marker_refused(self):
        with tempfile.TemporaryDirectory() as root:
            self._marker(root, fixture="/etc/shadow")
            with self.assertRaises(BlunixError) as caught:
                read_marker(root)
            self.assertEqual(str(caught.exception), "refused marker")

    def test_fixture_applies_without_fetch(self):
        passphrase = "fixture-passphrase-value"
        seen = []

        def getter(key):
            seen.append(key)
            if key.endswith("hostname"):
                return HOST + "\n"
            if key.endswith("passphrase"):
                return passphrase
            return None

        def urlopen(*_args, **_kwargs):
            raise AssertionError("fixture fetched")

        with tempfile.TemporaryDirectory() as root:
            self._marker(root)
            self._cipher(root, passphrase)
            logs = []
            code = run_bootstrap(
                root=root,
                models=MODELS,
                log=logs.append,
                urlopen=urlopen,
                guestinfo_getter=getter,
                ip_show=lambda: "2: ens33 inet 192.168.64.12/24 scope global ens33\n",
                sleeper=lambda *_args: None,
            )
            self.assertEqual(code, 0)
            self.assertIn("guestinfo.blunix.hostname", seen)
            self.assertIn("guestinfo.blunix.passphrase", seen)
            self.assertIn("blunix self-test: wrong passphrase: could not decrypt", logs)
            self.assertIn("blunix self-test: shell script: rejected", logs)
            self.assertIn("blunix: test image decrypts the local fixture for " + HOST, logs)
            self.assertIn("blunix: applied node document blunix-test", logs)
            self.assertIn("blunix: inet 192.168.64.12/24 dev ens33", logs)
            self.assertTrue(os.path.isfile(os.path.join(root, "var", "lib", "blunix", "bootstrap-complete")))

    def test_missing_guestinfo_keeps_self_test(self):
        passphrase = "missing-guestinfo-value"
        with tempfile.TemporaryDirectory() as root:
            self._marker(root)
            self._cipher(root, passphrase)
            logs = []
            code = run_bootstrap(
                root=root,
                models=MODELS,
                log=logs.append,
                guestinfo_getter=lambda _key: None,
                ip_show=lambda: "",
                sleeper=lambda *_args: None,
            )
            self.assertEqual(code, 1)
            self.assertIn("blunix self-test: wrong passphrase: could not decrypt", logs)
            self.assertIn("blunix self-test: shell script: rejected", logs)
            self.assertIn("blunix: bootstrap failed closed", logs)
            self.assertFalse(os.path.exists(os.path.join(root, "var", "lib", "blunix", "bootstrap-complete")))

    def test_hostname_mismatch_hides_the_value(self):
        passphrase = "mismatch-passphrase-value"
        other = "zzz-9.build.blunix.io"

        def getter(key):
            if key.endswith("hostname"):
                return other
            if key.endswith("passphrase"):
                return passphrase
            return None

        with tempfile.TemporaryDirectory() as root:
            self._marker(root)
            self._cipher(root, passphrase)
            logs = []
            code = run_bootstrap(
                root=root,
                models=MODELS,
                log=logs.append,
                guestinfo_getter=getter,
                ip_show=lambda: "",
                sleeper=lambda *_args: None,
            )
            self.assertEqual(code, 1)
            self.assertIn("blunix: refused hostname", logs)
            self.assertNotIn(other, "\n".join(logs))

    def test_production_does_not_call_guestinfo(self):
        def getter(_key):
            raise AssertionError("production called guestinfo")

        recorded = []

        def urlopen(req, timeout=30, context=None):
            recorded.append(req.full_url)
            return _Body(b"")

        with tempfile.TemporaryDirectory() as root:
            logs = []
            code = run_bootstrap(
                root=root,
                models=MODELS,
                log=logs.append,
                urlopen=urlopen,
                context_factory=_good_context,
                guestinfo_getter=getter,
                ip_show=lambda: "2: ens33 inet 192.0.2.10/24 scope global ens33\n",
                sleeper=lambda *_args: None,
                hostname_reader=lambda: HOST,
                passphrase_reader=lambda: "not-the-key",
                cmdline="",
            )
            self.assertEqual(code, 1)
            self.assertEqual(recorded, ["https://" + HOST + "/"])
            self.assertIn("could not decrypt", logs)

    def test_fetch_refuses_http_and_insecure_tls(self):
        with self.assertRaises(BlunixError) as caught:
            check_fetch_url("http://" + HOST + "/", HOST)
        self.assertEqual(str(caught.exception), "refused url")

        def urlopen(*_args, **_kwargs):
            raise AssertionError("urlopen")

        class Broken:
            verify_mode = ssl.CERT_NONE
            check_hostname = False

        with self.assertRaises(BlunixError) as caught:
            fetch_https(HOST, urlopen=urlopen, context_factory=Broken)
        self.assertEqual(str(caught.exception), "tls verify disabled")

    def test_fetch_caps_the_body_and_records_no_passphrase(self):
        passphrase = "fetch-passphrase-value"
        recorded = []

        def urlopen(req, timeout=30, context=None):
            recorded.append(req.full_url)
            recorded.append(req.data)
            recorded.append(tuple(req.headers.items()))
            return _Body(b"x" * (MAX_CIPHER + 1))

        with self.assertRaises(BlunixError) as caught:
            fetch_https(HOST, urlopen=urlopen, context_factory=_good_context)
        self.assertEqual(str(caught.exception), "document too large")
        blob = repr(recorded)
        self.assertNotIn(passphrase, blob)

    def test_redirect_stays_on_the_assigned_host(self):
        handler = _Redirect(HOST)
        req = urllib.request.Request("https://" + HOST + "/", method="GET")
        redirected = handler.redirect_request(
            req, None, 302, "Found", {}, "https://" + HOST + "/"
        )
        self.assertEqual(redirected.get_full_url(), "https://" + HOST + "/")
        for target in ("https://evil.example/", "https://" + HOST + "/?x=1"):
            with self.subTest(target=target):
                with self.assertRaises(BlunixError) as caught:
                    handler.redirect_request(req, None, 302, "Found", {}, target)
                self.assertEqual(str(caught.exception), "refused url")


class CliTests(unittest.TestCase):
    def test_passphrase_flag_refused(self):
        code = main(["--passphrase", "nope"])
        self.assertEqual(code, 1)

    def test_disk_check(self):
        code = main(["disk", "check", "cloud-vm", "--models", MODELS])
        self.assertEqual(code, 0)


def _gzip_tar(entries):
    plain = io.BytesIO()
    with tarfile.open(fileobj=plain, mode="w:") as tar:
        for entry in entries:
            info = tarfile.TarInfo(entry["name"])
            if entry.get("kind") == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = entry.get("link", "bin/adssh")
                tar.addfile(info)
                continue
            data = entry["data"]
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", mtime=0) as handle:
        handle.write(plain.getvalue())
    return compressed.getvalue()


def _tools_doc(**overrides):
    tool = {
        "name": "adssh",
        "repo": "adssh",
        "version": "v0.9.0",
        "asset": "adssh_v0.9.0_linux_amd64.tar.gz",
        "default": False,
        "files": [
            {"archive": "adssh_v0.9.0_linux_amd64/bin/adssh", "dest": "adssh"},
            {"archive": "adssh_v0.9.0_linux_amd64/bin/adssh-mcp", "dest": "adssh-mcp"},
        ],
    }
    tool.update(overrides)
    return {
        "apiVersion": "blunix.dev/v1",
        "kind": "GithubTools",
        "name": "default",
        "tools": [tool],
    }


def _adssh_blob():
    blob = _gzip_tar(
        [
            {"name": "adssh_v0.9.0_linux_amd64/bin/adssh", "data": b"adssh-bin"},
            {"name": "adssh_v0.9.0_linux_amd64/bin/adssh-mcp", "data": b"mcp-bin"},
            {"name": "adssh_v0.9.0_linux_amd64/install.sh", "data": b"DO-NOT-RUN"},
        ]
    )
    return blob, "sha256:" + hashlib.sha256(blob).hexdigest()


def _rel_luminance(hex_color):
    value = hex_color.lstrip("#")
    channels = [int(value[index:index + 2], 16) / 255 for index in (0, 2, 4)]
    linear = []
    for channel in channels:
        if channel <= 0.04045:
            linear.append(channel / 12.92)
        else:
            linear.append(((channel + 0.055) / 1.055) ** 2.4)
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(foreground, background):
    lighter = max(_rel_luminance(foreground), _rel_luminance(background))
    darker = min(_rel_luminance(foreground), _rel_luminance(background))
    return (lighter + 0.05) / (darker + 0.05)


class ToolTests(unittest.TestCase):
    def test_shipped_pin_is_optional_and_has_no_digest(self):
        model = load_tools(MODELS, "default")
        self.assertEqual([tool["name"] for tool in model["tools"]], ["adssh"])
        tool = model["tools"][0]
        self.assertFalse(tool["default"])
        self.assertNotIn("digest", tool)
        self.assertEqual(tool["version"], "v0.9.0")
        url = (
            "https://github.com/afterdarksys/adssh/releases/download/"
            "v0.9.0/adssh_v0.9.0_linux_amd64.tar.gz"
        )
        self.assertEqual(tool["url"], url)
        self.assertNotIn("/releases/latest", tool["url"])
        self.assertEqual(tool_artifact_url("adssh", "v0.9.0", tool["asset"]), url)

    def test_default_apply_does_not_fetch(self):
        def fetch(*_args):
            raise AssertionError("network")

        with tempfile.TemporaryDirectory() as root:
            linked = install_tools(load_tools(MODELS, "default"), root, fetch=fetch)
            self.assertEqual(linked, [])
            self.assertFalse(os.path.isdir(os.path.join(root, "var", "lib", "blunix", "tools")))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = main(["tools", "apply", "--models", MODELS, "--root", root])
            self.assertEqual(code, 0)
            text = buf.getvalue()
            self.assertIn("blunix: tools idle", text)
            self.assertIn("blunix: tool adssh waiting on a digest", text)

    def test_named_apply_without_a_digest_writes_nothing(self):
        def fetch(*_args):
            raise AssertionError("network")

        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(BlunixError) as caught:
                install_tools(
                    load_tools(MODELS, "default"), root, names=["adssh"], fetch=fetch
                )
            self.assertEqual(str(caught.exception), "refused digest")
            self.assertFalse(os.path.isdir(os.path.join(root, "var", "lib", "blunix", "tools")))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = main(["tools", "apply", "adssh", "--models", MODELS, "--root", root])
            self.assertEqual(code, 1)
            self.assertIn("blunix: refused digest", buf.getvalue())

    def test_pinned_archive_links_the_two_binaries(self):
        blob, digest = _adssh_blob()
        calls = []

        def fetch(name, url):
            calls.append((name, url))
            return blob

        model = parse_tools(_tools_doc(digest=digest, default=True))
        with tempfile.TemporaryDirectory() as root:
            linked = install_tools(model, root, fetch=fetch)
            self.assertEqual(linked, ["adssh", "adssh-mcp"])
            self.assertEqual(
                calls,
                [(
                    "adssh",
                    "https://github.com/afterdarksys/adssh/releases/download/"
                    "v0.9.0/adssh_v0.9.0_linux_amd64.tar.gz",
                )],
            )
            tools = os.path.join(root, "var", "lib", "blunix", "tools")
            self.assertFalse(os.path.isdir(os.path.join(tools, "stage")))
            for dest, payload in (("adssh", b"adssh-bin"), ("adssh-mcp", b"mcp-bin")):
                final = os.path.join(tools, "adssh", "v0.9.0", dest)
                link = os.path.join(tools, "bin", dest)
                with open(final, "rb") as handle:
                    self.assertEqual(handle.read(), payload)
                self.assertEqual(stat.S_IMODE(os.stat(final).st_mode), 0o755)
                self.assertEqual(
                    os.readlink(link), os.path.join("..", "adssh", "v0.9.0", dest)
                )
            for dirpath, _dirs, filenames in os.walk(tools):
                self.assertNotIn("install.sh", filenames)
                for filename in filenames:
                    path = os.path.join(dirpath, filename)
                    if os.path.islink(path):
                        continue
                    with open(path, "rb") as handle:
                        self.assertNotIn(b"DO-NOT-RUN", handle.read())

    def test_bad_digest_writes_nothing(self):
        blob, _digest = _adssh_blob()
        model = parse_tools(_tools_doc(digest="sha256:" + ("ab" * 32), default=True))
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(BlunixError) as caught:
                install_tools(model, root, fetch=lambda _name, _url: blob)
            self.assertEqual(str(caught.exception), "refused digest")
            self.assertFalse(os.path.isdir(os.path.join(root, "var", "lib", "blunix", "tools")))

    def test_latest_other_org_and_install_asset_refused(self):
        refused = (
            ({"version": "latest"}, "refused version"),
            ({"repo": "afterdarksys/adssh"}, "refused repo"),
            ({"asset": "adssh.zip"}, "refused asset"),
            ({"asset": "install.tar.gz"}, "refused asset"),
            ({"asset": "adssh-install.tar.gz"}, "refused asset"),
        )
        for overrides, message in refused:
            with self.subTest(overrides=overrides):
                with self.assertRaises(BlunixError) as caught:
                    parse_tools(_tools_doc(**overrides))
                self.assertEqual(str(caught.exception), message)
        with self.assertRaises(BlunixError) as caught:
            tool_artifact_url("adssh", "latest", "adssh_v0.9.0_linux_amd64.tar.gz")
        self.assertEqual(str(caught.exception), "refused version")

    def test_url_refuses_http_other_hosts_and_latest(self):
        refused = (
            "http://github.com/afterdarksys/adssh/releases/download/v0.9.0/adssh.tar.gz",
            "https://evil.example/afterdarksys/adssh/releases/download/v0.9.0/a.tar.gz",
            "https://github.com/afterdarksys/adssh/releases/latest/download/a.tar.gz",
            "https://example.com/adssh.tar.gz",
        )
        for url in refused:
            with self.subTest(url=url):
                with self.assertRaises(BlunixError) as caught:
                    tool_check_url(url)
                self.assertEqual(str(caught.exception), "refused tool url")

    def test_symlink_and_dotdot_refuse_the_whole_archive(self):
        wanted = ["adssh_v0.9.0_linux_amd64/bin/adssh"]
        symlink = _gzip_tar(
            [
                {"name": "adssh_v0.9.0_linux_amd64/bin/adssh", "data": b"adssh-bin"},
                {
                    "name": "adssh_v0.9.0_linux_amd64/bin/escape",
                    "kind": "symlink",
                    "link": "adssh",
                },
            ]
        )
        dotdot = _gzip_tar(
            [
                {"name": "adssh_v0.9.0_linux_amd64/bin/adssh", "data": b"adssh-bin"},
                {"name": "adssh_v0.9.0_linux_amd64/../../etc/cron.d/adssh", "data": b"nope"},
            ]
        )
        for blob in (symlink, dotdot):
            with self.subTest(blob=hashlib.sha256(blob).hexdigest()[:8]):
                with self.assertRaises(BlunixError) as caught:
                    extract_named(blob, wanted)
                self.assertEqual(str(caught.exception), "refused archive")
                digest = "sha256:" + hashlib.sha256(blob).hexdigest()
                model = parse_tools(
                    _tools_doc(
                        digest=digest,
                        files=[{"archive": wanted[0], "dest": "adssh"}],
                    )
                )
                with tempfile.TemporaryDirectory() as root:
                    with self.assertRaises(BlunixError) as caught:
                        install_tools(model, root, names=["adssh"], fetch=lambda _n, _u: blob)
                    self.assertEqual(str(caught.exception), "refused archive")
                    self.assertFalse(
                        os.path.isdir(os.path.join(root, "var", "lib", "blunix", "tools", "bin"))
                    )


class GuiTests(unittest.TestCase):
    def test_cloud_root_stages_the_theme_and_does_not_select_it(self):
        with tempfile.TemporaryDirectory() as root:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = main(["gui", "apply", "--root", root])
            self.assertEqual(code, 0)
            self.assertIn("graphical session absent", buf.getvalue())
            self.assertFalse(apply_gui(root))
            theme = os.path.join(root, "usr", "share", "themes", "Blunix")
            self.assertTrue(os.path.isfile(os.path.join(theme, "index.theme")))
            self.assertFalse(os.path.exists(os.path.join(root, "etc", "gtk-3.0", "settings.ini")))
            self.assertFalse(os.path.exists(os.path.join(root, "etc", "profile.d", "blunix-gui.sh")))

    def test_graphical_session_selects_the_blue_theme(self):
        with tempfile.TemporaryDirectory() as root:
            orca = os.path.join(root, "usr", "bin", "orca")
            os.makedirs(os.path.dirname(orca))
            open(orca, "wb").close()
            self.assertTrue(apply_gui(root))
            settings = os.path.join(root, "etc", "gtk-4.0", "settings.ini")
            with open(settings, "r", encoding="utf-8") as handle:
                text = handle.read()
            self.assertIn("gtk-theme-name=Blunix", text)
            self.assertIn("Sans 14", text)
            self.assertIn("blunix-gui", text.splitlines()[0])
            profile = os.path.join(root, "etc", "profile.d", "blunix-gui.sh")
            with open(profile, "r", encoding="utf-8") as handle:
                self.assertIn("export GTK_THEME=Blunix", handle.read())
            css_path = os.path.join(root, "usr", "share", "themes", "Blunix", "gtk-4.0", "gtk.css")
            with open(css_path, "r", encoding="utf-8") as handle:
                css = handle.read()
            for color in ("#12161a", "#f3efe6", "#1a4568", "#d2ee9a"):
                self.assertIn(color, css)
            self.assertGreaterEqual(_contrast("#f3efe6", "#12161a"), 7)
            self.assertGreaterEqual(_contrast("#f3efe6", "#1a4568"), 7)

    def test_removing_the_session_clears_only_our_files(self):
        with tempfile.TemporaryDirectory() as root:
            orca = os.path.join(root, "usr", "bin", "orca")
            os.makedirs(os.path.dirname(orca))
            open(orca, "wb").close()
            self.assertTrue(apply_gui(root))
            foreign = os.path.join(root, "etc", "gtk-4.0", "settings.ini")
            kept = "[Settings]\ngtk-theme-name=Adwaita\n"
            with open(foreign, "w", encoding="utf-8") as handle:
                handle.write(kept)
            os.remove(orca)
            self.assertFalse(apply_gui(root))
            with open(foreign, "r", encoding="utf-8") as handle:
                self.assertEqual(handle.read(), kept)
            self.assertFalse(os.path.exists(os.path.join(root, "etc", "profile.d", "blunix-gui.sh")))
            self.assertTrue(
                os.path.isfile(os.path.join(root, "usr", "share", "themes", "Blunix", "index.theme"))
            )

    def test_theme_css_contrast(self):
        css_dir = os.path.join(ROOT, "image", "gui", "Blunix")
        paths = (
            os.path.join(css_dir, "gtk-3.0", "gtk.css"),
            os.path.join(css_dir, "gtk-4.0", "gtk.css"),
        )
        with open(paths[0], "r", encoding="utf-8") as handle:
            gtk3 = handle.read()
        with open(paths[1], "r", encoding="utf-8") as handle:
            gtk4 = handle.read()
        self.assertEqual(gtk3, gtk4)
        self.assertTrue(gtk4.startswith("/* blunix-gui */"))
        for color in ("#12161a", "#1b2127", "#f3efe6", "#1a4568", "#8eb4d4", "#d2ee9a"):
            self.assertIn(color, gtk4)
        self.assertGreaterEqual(_contrast("#f3efe6", "#12161a"), 7)
        self.assertGreaterEqual(_contrast("#f3efe6", "#1a4568"), 7)
        self.assertGreaterEqual(_contrast("#d2ee9a", "#12161a"), 7)
        self.assertGreaterEqual(_contrast("#8eb4d4", "#12161a"), 7)


# brand/ lives only in the distribution (afterdarksys/blunix); this file syncs
# there and the test runs against the real assets. Here there is nothing to check.
@unittest.skipUnless(os.path.isdir(os.path.join(ROOT, "brand")), "brand/ is in the distribution only")
class BrandTests(unittest.TestCase):
    def test_the_word_is_outlined_type_beside_the_mark(self):
        for name in ("mark.jpg", "logo-mark.svg", "logo-horizontal.svg"):
            self.assertTrue(os.path.isfile(os.path.join(ROOT, "brand", name)))
        with open(os.path.join(ROOT, "brand", "wordmark.svg"), "r", encoding="utf-8") as handle:
            svg = handle.read()
        # Outlined to paths: no font dependency, no live text, no raster.
        self.assertIn("<path", svg)
        self.assertNotIn("<text", svg)
        self.assertNotIn("<image", svg)


class SourceTests(unittest.TestCase):
    def test_library_has_no_banned_calls(self):
        banned = (
            "shell=True",
            "os.system",
            "AGE_PASSPHRASE",
            "CERT_NONE",
            "InsecureSkipVerify",
            "check_hostname = False",
        )
        for name in os.listdir(LIB):
            if not name.endswith(".py"):
                continue
            with open(os.path.join(LIB, name), "r", encoding="utf-8") as handle:
                text = handle.read()
            for token in banned:
                self.assertNotIn(token, text, name + " contains " + token)

    def test_console_line_refuses_a_newline(self):
        with self.assertRaises(BlunixError) as caught:
            console_line("blunix: secret\nvalue")
        self.assertEqual(str(caught.exception), "refused log line")


if __name__ == "__main__":
    unittest.main()

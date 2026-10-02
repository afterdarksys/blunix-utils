"""Fail-closed checks for the mounted-root secret scan.

Threats: a dangling symlink is not file content, a link that leaves the
mount must not be followed, and a secret in a regular file or in link text
must still be rejected. These tests do not print secret bytes.
"""

import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCAN = os.path.join(ROOT, "image", "scan-root.py")


def _secret(name):
    path = os.path.join(ROOT, "build", name)
    with open(path, "rb") as handle:
        raw = handle.read(512)
    return raw.decode("ascii").strip().encode("ascii")


class ScanRootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.needles = []
        for name in ("root-password", "bootstrap-passphrase"):
            try:
                cls.needles.append(_secret(name))
            except (OSError, UnicodeError):
                raise AssertionError("test secret missing")

    def _run(self, root, release=False):
        argv = [sys.executable, SCAN] + (["--release"] if release else []) + [root]
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        err = proc.stderr.decode("ascii", "replace").strip()
        return proc.returncode, err

    def test_dangling_symlink_is_not_content(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "etc"))
            os.symlink("../proc/self/mounts", os.path.join(root, "etc", "mtab"))
            code, err = self._run(root)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")

    def test_secret_in_regular_file(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "note")
            with open(path, "wb") as handle:
                handle.write(b"prefix " + self.needles[0] + b" suffix\n")
            code, err = self._run(root)
        self.assertEqual(code, 1)
        self.assertEqual(err, "plaintext secret leaked into the image")

    def test_secret_in_link_text(self):
        with tempfile.TemporaryDirectory() as root:
            os.symlink(self.needles[1].decode("ascii"), os.path.join(root, "leak"))
            code, err = self._run(root)
        self.assertEqual(code, 1)
        self.assertEqual(err, "plaintext secret leaked into the image")

    def test_outside_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as outside:
            leaked = os.path.join(outside, "hidden")
            with open(leaked, "wb") as handle:
                handle.write(self.needles[0])
            with tempfile.TemporaryDirectory() as root:
                os.symlink(leaked, os.path.join(root, "via"))
                code, err = self._run(root)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")

    def test_vendor_filename(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "grok"), "wb") as handle:
                handle.write(b"x")
            code, err = self._run(root)
        self.assertEqual(code, 1)
        self.assertEqual(err, "vendor binary in image")


    def _release_root(self, root, shadow="root:!:20000:0:99999:7:::\nnobody:*:20000::::::\n"):
        os.makedirs(os.path.join(root, "etc"))
        with open(os.path.join(root, "etc", "shadow"), "w", encoding="ascii") as handle:
            handle.write(shadow)

    def test_release_accepts_a_locked_root(self):
        with tempfile.TemporaryDirectory() as root:
            self._release_root(root)
            code, err = self._run(root, release=True)
        self.assertEqual((code, err), (0, ""))

    def test_release_refuses_the_fixture(self):
        for parts in (
            ("etc", "blunix", "test-image"),
            ("usr", "share", "blunix", "bootstrap-fixture.age"),
            ("etc", "ssh", "sshd_config.d", "00-blunix-test.conf"),
        ):
            with self.subTest(path="/".join(parts)):
                with tempfile.TemporaryDirectory() as root:
                    self._release_root(root)
                    path = os.path.join(root, *parts)
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "wb") as handle:
                        handle.write(b"x")
                    code, err = self._run(root, release=True)
                    self.assertEqual((code, err), (1, "test fixture in a release image"))
                    code, err = self._run(root)
                    self.assertEqual(code, 0)

    def test_release_refuses_an_unlocked_account(self):
        for shadow in (
            "root:$y$j9T$abc$def:20000:0:99999:7:::\n",
            "root::20000:0:99999:7:::\n",
            "root:!:20000::::::\nops:$6$x$y:20000::::::\n",
        ):
            with self.subTest(shadow=shadow.split(":")[0]):
                with tempfile.TemporaryDirectory() as root:
                    self._release_root(root, shadow)
                    code, err = self._run(root, release=True)
                    self.assertEqual((code, err), (1, "unlocked account in a release image"))

    def _write(self, root, parts, text):
        path = os.path.join(root, *parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="ascii") as handle:
            handle.write(text)

    def test_release_refuses_root_authorized_keys(self):
        with tempfile.TemporaryDirectory() as root:
            self._release_root(root)
            self._write(root, ("root", ".ssh", "authorized_keys"), "ssh-ed25519 AAAA test\n")
            self.assertEqual(self._run(root, release=True), (1, "root ssh key in a release image"))

    def test_release_refuses_root_or_password_sshd(self):
        for parts, text in (
            (("etc", "ssh", "sshd_config"), "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n"),
            (("etc", "ssh", "sshd_config"), "permitrootlogin=YES # old\n"),
            (("etc", "ssh", "sshd_config.d", "10-x.conf"), "PasswordAuthentication yes\n"),
            (("etc", "ssh", "sshd_config"), "Match User ops\n  PasswordAuthentication \"yes\"\n"),
        ):
            with self.subTest(text=text):
                with tempfile.TemporaryDirectory() as root:
                    self._release_root(root)
                    self._write(root, parts, text)
                    self.assertEqual(
                        self._run(root, release=True),
                        (1, "sshd allows root or password login in a release image"),
                    )

    def test_release_accepts_closed_sshd(self):
        with tempfile.TemporaryDirectory() as root:
            self._release_root(root)
            self._write(
                root,
                ("etc", "ssh", "sshd_config"),
                "#PermitRootLogin yes\n#PasswordAuthentication yes\nPermitRootLogin prohibit-password\n"
                "PasswordAuthentication no\nKbdInteractiveAuthentication no\n",
            )
            self.assertEqual(self._run(root, release=True), (0, ""))

    def test_release_refuses_a_host_key(self):
        for name in ("ssh_host_ed25519_key", "ssh_host_rsa_key.pub"):
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as root:
                    self._release_root(root)
                    self._write(root, ("etc", "ssh", name), "x\n")
                    self.assertEqual(self._run(root, release=True), (1, "sshd host key in a release image"))

    def test_release_needs_first_boot_host_keys(self):
        with tempfile.TemporaryDirectory() as root:
            self._release_root(root)
            self._write(root, ("usr", "sbin", "sshd"), "")
            self.assertEqual(self._run(root, release=True), (1, "no host key generation in a release image"))
            self._write(
                root,
                ("etc", "systemd", "system", "ssh.service.d", "hostkeys.conf"),
                "[Service]\nExecStartPre=\nExecStartPre=/usr/bin/ssh-keygen -A\n",
            )
            self.assertEqual(self._run(root, release=True), (0, ""))

    def test_release_without_shadow_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            code, err = self._run(root, release=True)
        self.assertEqual((code, err), (1, "blunix: scan failed"))


if __name__ == "__main__":
    unittest.main()

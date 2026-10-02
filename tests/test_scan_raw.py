"""The raw byte scan of a disk image, free space included.

Threats: a key deleted inside the image stays in a free block; a zstd stream
hides it from a plain grep; a key split across two reads. Every key here is
synthetic, built at run time from random bytes, and nothing prints it.
"""

import base64
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCAN = os.path.join(ROOT, "image", "scan-raw.py")
HAVE_EXT4 = shutil.which("mke2fs") is not None and shutil.which("debugfs") is not None
HAVE_ZSTD = shutil.which("zstd") is not None
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _secret(name):
    with open(os.path.join(ROOT, "build", name), "rb") as handle:
        return handle.read(512).decode("ascii").strip().encode("ascii")


def _pem(kind, body=None, headers=b""):
    body = body if body is not None else os.urandom(300)
    text = base64.encodebytes(body)
    return b"-----BEGIN " + kind + b"-----\n" + headers + text + b"-----END " + kind + b"-----\n"


def _openssh_key():
    return _pem(b"OPENSSH PRIVATE KEY", b"openssh-key-v1\x00" + os.urandom(300))


def _age_key():
    return ("AGE-SECRET-KEY-1" + "".join(secrets.choice(BECH32) for _ in range(58)).upper()).encode("ascii")


class ScanRawTests(unittest.TestCase):
    def _run(self, path):
        proc = subprocess.run(
            [sys.executable, SCAN, path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        return proc.returncode, proc.stderr.decode("ascii", "replace").strip()

    def _blob(self, folder, payload, name="disk.raw"):
        path = os.path.join(folder, name)
        with open(path, "wb") as handle:
            handle.write(os.urandom(65536) + b"\x00" * 65536 + payload + b"\x00" * 4096)
        return path

    def test_clean_image_and_shipped_constants_pass(self):
        # sshd's bare marker, libcrypto's PEM names, libgio's suffix, age's
        # help text and its README example key are in every Debian image.
        constants = (
            b"\x00-----BEGIN OPENSSH PRIVATE KEY-----\n\x00\x00\x00\x00-----END OPENSSH PRIVATE KEY-----\n\x00",
            b"RSA PRIVATE KEY\x00EC PRIVATE KEY\x00X9.42 DH PARAMETERS\x00",
            b"GTlsCertificate\x00PRIVATE KEY-----\x00-----BEGIN \x00-----END \x00",
            b"use a passphraseAGE-SECRET-KEY-1regexp: Compile(",
            b'secret keys ("AGE-SECRET-KEY-1..."),\n',
            b"\n    AGE-SECRET-KEY-1N9JEPW6DWJ0ZQUDX63F5A03GX8QUW7PXDE39N8UYF82VZ9PC8UFS3M7XA9\n",
            b"age-encryption.org/v1\nreflectlite.Value.Elem",
        )
        with tempfile.TemporaryDirectory() as folder:
            path = self._blob(folder, b"".join(constants))
            self.assertEqual(self._run(path), (0, ""))

    def test_refusals(self):
        cases = (
            (_openssh_key(), "private key in the raw image"),
            (_pem(b"RSA PRIVATE KEY"), "private key in the raw image"),
            (_pem(b"EC PRIVATE KEY"), "private key in the raw image"),
            (_pem(b"PRIVATE KEY"), "private key in the raw image"),
            (_pem(b"ENCRYPTED PRIVATE KEY"), "private key in the raw image"),
            (_pem(b"RSA PRIVATE KEY", headers=b"Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\n"), "private key in the raw image"),
            (_openssh_key().split(b"\n", 1)[1], "private key in the raw image"),
            (_age_key(), "age secret key in the raw image"),
            (b"age-encryption.org/v1\n-> scrypt c2FsdA 18\n", "age fixture in the raw image"),
            (b"x" + _secret("root-password") + b"x", "plaintext secret in the raw image"),
            (_secret("bootstrap-passphrase"), "plaintext secret in the raw image"),
        )
        for payload, message in cases:
            with self.subTest(message=message, head=payload[:24]):
                with tempfile.TemporaryDirectory() as folder:
                    self.assertEqual(self._run(self._blob(folder, payload)), (1, message))

    def test_key_across_a_read_boundary(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "disk.raw")
            with open(path, "wb") as handle:
                handle.write(b"\xa5" * (8 * 1024 * 1024 - 30) + _openssh_key() + b"\x00" * 4096)
            self.assertEqual(self._run(path), (1, "private key in the raw image"))

    @unittest.skipUnless(HAVE_EXT4, "e2fsprogs not installed")
    def test_deleted_key_in_ext4_free_space(self):
        key = _openssh_key()
        with tempfile.TemporaryDirectory() as folder:
            tree = os.path.join(folder, "root")
            os.makedirs(os.path.join(tree, "etc", "ssh"))
            with open(os.path.join(tree, "etc", "hostname"), "wb") as handle:
                handle.write(b"blunix\n")
            clean = os.path.join(folder, "clean.raw")
            subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-d", tree, clean, "16M"], check=True)
            self.assertEqual(self._run(clean), (0, ""))
            with open(os.path.join(tree, "etc", "ssh", "ssh_host_ed25519_key"), "wb") as handle:
                handle.write(key)
            image = os.path.join(folder, "disk.raw")
            subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-d", tree, image, "16M"], check=True)
            subprocess.run(
                ["debugfs", "-w", "-R", "rm /etc/ssh/ssh_host_ed25519_key", image],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            listed = subprocess.run(
                ["debugfs", "-R", "ls -l /etc/ssh", image],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            ).stdout
            self.assertNotIn(b"ssh_host_ed25519_key", listed)
            with open(image, "rb") as handle:
                self.assertIn(key, handle.read())
            self.assertEqual(self._run(image), (1, "private key in the raw image"))
            if HAVE_ZSTD:
                subprocess.run(["zstd", "-q", "-f", "-o", image + ".zst", image], check=True)
                self.assertEqual(self._run(image + ".zst"), (1, "private key in the raw image"))

    @unittest.skipUnless(HAVE_ZSTD, "zstd not installed")
    def test_zst_stream_is_decompressed(self):
        with tempfile.TemporaryDirectory() as folder:
            # Seed a repeated, non-secret prefix so zstd encodes the real key's
            # prefix as a match. Random surrounding bytes alone sometimes make
            # zstd store the entire key literally, making this assertion flaky.
            path = self._blob(folder, b"AGE-SECRET-KEY-0" * 1024 + _age_key())
            subprocess.run(["zstd", "-q", "-f", "-o", path + ".zst", path], check=True)
            with open(path + ".zst", "rb") as handle:
                self.assertNotIn(b"AGE-SECRET-KEY-1", handle.read())
            self.assertEqual(self._run(path + ".zst"), (1, "age secret key in the raw image"))
            clean = self._blob(folder, b"", name="clean.raw")
            subprocess.run(["zstd", "-q", "-f", "-o", clean + ".zst", clean], check=True)
            self.assertEqual(self._run(clean + ".zst"), (0, ""))

    def test_unreadable_input_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(self._run(os.path.join(folder, "missing.raw")), (1, "blunix: scan failed"))
            if HAVE_ZSTD:
                bad = os.path.join(folder, "bad.raw.zst")
                with open(bad, "wb") as handle:
                    handle.write(b"\x28\xb5\x2f\xfd" + os.urandom(64))
                self.assertEqual(self._run(bad), (1, "blunix: scan failed"))


if __name__ == "__main__":
    unittest.main()

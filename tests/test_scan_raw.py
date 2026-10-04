"""The raw byte scan of a disk image, free space included.

Threats: a key deleted inside the image stays in a free block; a zstd stream
hides it from a plain grep; a key split across two reads; a listed public
key used to wave through any other bytes. Every key here is synthetic, built
at run time from random bytes, and nothing prints it.
"""

import base64
import contextlib
import glob
import hashlib
import importlib.util
import io
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
# Whatever libgnutls30 Debian ships now, not one pinned file name: a point
# release renames the file, and that is when a stale allowlist must show up.
GNUTLS = sorted(glob.glob("/usr/lib/*-linux-gnu/libgnutls.so.30.*"))
# CI sets this so a missing library fails instead of skipping.
REQUIRE_GNUTLS = os.environ.get("BLUNIX_REQUIRE_SCAN_TOOLS") == "1"


def _module():
    spec = importlib.util.spec_from_file_location("scan_raw", SCAN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
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
            # Headers of any number or length: refused on the first header line.
            (_pem(b"RSA PRIVATE KEY", headers=b"".join(b"X-Pad-%d: %s\n" % (n, b"a" * 150) for n in range(40)) + b"\n"), "private key in the raw image"),
            (_pem(b"PRIVATE KEY", headers=b"Comment: " + b"c" * 300 + b"\n\n"), "private key in the raw image"),
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

    def _listed(self, block):
        # The real listed blocks are GnuTLS's public self-test keys; a public
        # repo cannot carry a PEM key, so list a synthetic block's hash instead.
        scan = _module()
        scan._PUBLIC_KEYS = frozenset((hashlib.sha256(block).hexdigest(),))
        return scan

    def _scan(self, scan, data):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            try:
                scan.scan(io.BytesIO(data), [])
            except SystemExit as exit:
                return (exit.code, err.getvalue().strip())
        return (0, "")

    def test_listed_public_key_passes_and_nothing_else(self):
        # The libgnutls layout: NUL padding, a PEM block, then "\n\x00".
        block = _pem(b"PRIVATE KEY", os.urandom(90)).rstrip(b"\n")
        scan = self._listed(block)
        self.assertIsNone(scan.check(b"\x00" * 16 + block + b"\n\x00", []))
        self.assertIsNone(scan.check(block + block, []))
        altered = block.replace(b"\n", b"\nA", 1)
        refused = "private key in the raw image"
        self.assertEqual(scan.check(altered, []), refused)
        self.assertEqual(scan.check(block + b"\n" + _pem(b"PRIVATE KEY"), []), refused)
        self.assertEqual(scan.check(_pem(b"PRIVATE KEY"), []), refused)
        self.assertEqual(scan.check(block[:-10], []), refused)
        self.assertEqual(_module().check(block, []), refused)

    def test_listed_public_key_across_a_read_boundary(self):
        block = _pem(b"RSA PRIVATE KEY", os.urandom(1200)).rstrip(b"\n")
        scan = self._listed(block)
        chunk = scan._CHUNK
        for cut in (5, 40, 100, len(block) // 2, len(block) - 3):
            with self.subTest(cut=cut):
                data = b"\xa5" * (chunk - cut) + block + b"\n\x00" + b"\xa5" * 64
                self.assertEqual(self._scan(scan, data), (0, ""))
        refused = (1, "private key in the raw image")
        # Cut by the end of the stream, or by a zero chunk no END can follow.
        self.assertEqual(self._scan(scan, b"\xa5" * (chunk - 100) + block[:-20]), refused)
        self.assertEqual(self._scan(scan, b"\xa5" * (chunk - 100) + block[:200] + bytes(chunk)), refused)
        self.assertEqual(self._scan(scan, block[:-20]), refused)
        # A real key right behind a listed block, both across the boundary.
        tail = b"\n\x00" + _pem(b"EC PRIVATE KEY")
        self.assertEqual(self._scan(scan, b"\xa5" * (chunk - 100) + block + tail), refused)
        # A re-encoded copy of a listed block is not the listed bytes.
        self.assertEqual(scan.check(block.replace(b"\n", b"\r\n"), []), "private key in the raw image")

    @unittest.skipUnless(GNUTLS or REQUIRE_GNUTLS, "Debian 13 libgnutls30t64 not installed")
    def test_shipped_libgnutls_passes(self):
        self.assertTrue(GNUTLS, "BLUNIX_REQUIRE_SCAN_TOOLS=1 but no libgnutls.so.30.* found")
        for path in GNUTLS:
            with self.subTest(path=path):
                self.assertEqual(self._run(path), (0, ""))

    def test_headed_key_across_a_read_boundary(self):
        # Over 4 KiB of headers, the BEGIN line before the read boundary and
        # the body far after it: the header pattern is short, so it still fits.
        key = _pem(b"RSA PRIVATE KEY", headers=b"".join(b"X-Pad-%d: %s\n" % (n, b"a" * 150) for n in range(40)) + b"\n")
        for cut in (5, 40, 60, 2000, 6300):
            with self.subTest(cut=cut):
                with tempfile.TemporaryDirectory() as folder:
                    path = os.path.join(folder, "disk.raw")
                    with open(path, "wb") as handle:
                        handle.write(b"\xa5" * (8 * 1024 * 1024 - cut) + key + b"\x00" * 64)
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
            code, err = self._run(os.path.join(folder, "missing.raw"))
            self.assertEqual(code, 1)
            self.assertTrue(err.startswith("blunix: scan failed"), err)
            if HAVE_ZSTD:
                bad = os.path.join(folder, "bad.raw.zst")
                with open(bad, "wb") as handle:
                    handle.write(b"\x28\xb5\x2f\xfd" + os.urandom(64))
                code, err = self._run(bad)
                self.assertEqual(code, 1)
                self.assertTrue(err.startswith("blunix: scan failed"), err)


if __name__ == "__main__":
    unittest.main()

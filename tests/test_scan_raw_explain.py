"""scan-raw-explain.py: find what a raw-scan refusal is, and which file holds it.

Threats: the tool reads images that may hold a real key and prints to logs, so
no key bytes may reach its output; its hits must be the gate's hits; a deleted
key must show as free space, not vanish. Every key here is synthetic.
"""

import base64
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOL = os.path.join(ROOT, "image", "scan-raw-explain.py")
HAVE_EXT4 = all(shutil.which(t) for t in ("mke2fs", "debugfs", "sfdisk"))
# CI sets this so missing e2fsprogs/sfdisk fails instead of skipping.
REQUIRE_EXT4 = os.environ.get("BLUNIX_REQUIRE_SCAN_TOOLS") == "1"
HAVE_ZSTD = shutil.which("zstd") is not None


def _pem(kind, body, newline=True):
    text = base64.encodebytes(body) if newline else base64.b64encode(body)
    sep = b"\n" if newline else b""
    return b"-----BEGIN " + kind + b"-----" + sep + text + b"-----END " + kind + b"-----" + sep


class ExplainTests(unittest.TestCase):
    def _run(self, *args):
        proc = subprocess.run([sys.executable, TOOL, *args], capture_output=True, check=False)
        return proc.returncode, proc.stdout.decode(), proc.stderr.decode()

    def _assert_no_key_bytes(self, out, *keys):
        for key in keys:
            for line in key.split(b"\n")[1:-2]:
                if len(line) >= 16:
                    self.assertNotIn(line.decode(), out)

    def test_blocks_lists_every_marker_with_hash_and_state(self):
        rsa = _pem(b"RSA PRIVATE KEY", os.urandom(600))
        ec = _pem(b"EC PRIVATE KEY", os.urandom(120), newline=False)
        cut = b"-----BEGIN PRIVATE KEY-----\n" + base64.b64encode(os.urandom(60)) + b"\n"
        data = b"\x00" * 100 + rsa + b"\x00" * 7 + ec + b"\x00" + cut
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "lib.so")
            with open(path, "wb") as handle:
                handle.write(data)
            code, out, _err = self._run("blocks", path)
            self.assertEqual(code, 0)
            lines = [line.split("\t") for line in out.splitlines()]
            self.assertEqual(len(lines), 3)
            self.assertEqual(lines[0][:3], ["100", "RSA PRIVATE KEY", str(len(rsa) - 1)])
            self.assertEqual(lines[0][4:], ["matched", "unlisted"])
            self.assertEqual(len(lines[0][3]), 64)
            self.assertEqual(lines[1][1], "EC PRIVATE KEY")
            self.assertEqual(lines[1][4], "not matched")
            self.assertEqual(lines[2][2:4], ["no END", "-"])
            self._assert_no_key_bytes(out, rsa)

            tar = os.path.join(folder, "rootfs.tar")
            with tarfile.open(tar, "w") as archive:
                archive.add(path, arcname="./usr/lib/lib.so")
            code, member_out, _err = self._run("blocks", tar, "--member", "/usr/lib/lib.so")
            self.assertEqual((code, member_out), (0, out))

    def test_locate_raw_offsets_match_the_gate(self):
        key = _pem(b"PRIVATE KEY", os.urandom(300))
        with tempfile.TemporaryDirectory() as folder:
            clean = os.path.join(folder, "clean.raw")
            with open(clean, "wb") as handle:
                handle.write(b"\xa5" * 4096)
            code, out, _err = self._run("locate", clean)
            self.assertEqual((code, out.strip()), (0, "0 hit(s), 0 refused"))

            path = os.path.join(folder, "disk.raw")
            # One key across the 8 MiB read boundary, one well past it.
            first = 8 * 1024 * 1024 - 50
            with open(path, "wb") as handle:
                handle.write(b"\xa5" * first + key + b"\xa5" * 5000 + key + b"\xa5" * 64)
            code, out, _err = self._run("locate", path)
            self.assertEqual(code, 1)
            lines = out.splitlines()
            self.assertEqual(lines[-1], "2 hit(s), 2 refused")
            offsets = [int(line.split("\t")[0]) for line in lines[:-1]]
            self.assertEqual(offsets, [first, first + len(key) + 5000])
            self.assertTrue(all("\tPRIVATE KEY\tREFUSED\t" in line for line in lines[:-1]))
            self._assert_no_key_bytes(out, key)

            if HAVE_ZSTD:
                subprocess.run(["zstd", "-q", "-f", "-o", path + ".zst", path], check=True)
                code, zout, _err = self._run("locate", path + ".zst")
                self.assertEqual(code, 1)
                self.assertEqual([line.split("\t")[0] for line in zout.splitlines()[:-1]],
                                 [str(o) for o in offsets])
                self.assertIn("decompress to map files", zout)

    @unittest.skipUnless(HAVE_EXT4 or REQUIRE_EXT4, "e2fsprogs/sfdisk not installed")
    def test_locate_maps_hits_to_files_and_free_space(self):
        kept = _pem(b"OPENSSH PRIVATE KEY", b"openssh-key-v1\x00" + os.urandom(300))
        gone = _pem(b"EC PRIVATE KEY", os.urandom(121))
        with tempfile.TemporaryDirectory() as folder:
            tree = os.path.join(folder, "root")
            os.makedirs(os.path.join(tree, "etc", "ssh"))
            for name, key in (("kept_key", kept), ("gone_key", gone)):
                with open(os.path.join(tree, "etc", "ssh", name), "wb") as handle:
                    handle.write(key)
            image = os.path.join(folder, "disk.raw")
            with open(image, "wb") as handle:
                handle.truncate(40 * 1024 * 1024)
            subprocess.run(["sfdisk", "-q", image], input=b"label: gpt\nstart=2048, size=65536\n",
                           check=True, capture_output=True)
            start = 2048 * 512
            subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-E", "offset=%d" % start,
                            "-d", tree, image, "32M"], check=True, capture_output=True)
            subprocess.run(["debugfs", "-w", "-R", "rm /etc/ssh/gone_key", "%s?offset=%d" % (image, start)],
                           check=True, capture_output=True)
            code, out, _err = self._run("locate", image)
            self.assertEqual(code, 1)
            self.assertIn("partition 1: /etc/ssh/kept_key (inode", out)
            self.assertIn("partition 1: free space or metadata", out)
            self.assertIn("OPENSSH PRIVATE KEY", out)
            self.assertIn("OPENSSH key body", out)
            self.assertIn("EC PRIVATE KEY", out)
            self._assert_no_key_bytes(out, kept, gone)


if __name__ == "__main__":
    unittest.main()

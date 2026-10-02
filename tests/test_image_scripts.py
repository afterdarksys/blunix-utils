"""Static checks on the image build scripts that a unit test can reach.

Threats: a test build overwriting build/release/ with a fixture disk and a
valid SHA256SUMS; an ISO label the installer does not know; netboot media
missing from SHA256SUMS; a raw disk kept without the raw byte scan.
"""

import os
import re
import unittest

from blunix.installer import MEDIUM_LABEL

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), "r", encoding="utf-8") as handle:
        return handle.read()


class InstallerScriptTests(unittest.TestCase):
    def setUp(self):
        self.text = _read("image", "build-installer.sh")

    def test_only_release_writes_build_release(self):
        lines = self.text.splitlines()
        hits = [i for i, line in enumerate(lines) if re.search(r"^\s*DEST=/src/build/release\b", line)]
        self.assertEqual(len(hits), 1)
        self.assertEqual(lines[hits[0] - 3].strip(), 'if [ "$RELEASE" -eq 1 ]; then')
        self.assertIn("DEST=/src/build/test\nTAG=-TEST\n", self.text)
        # Every write under build/release goes through $DEST.
        for line in lines:
            if "/src/build/release" in line and "DEST=" not in line:
                self.assertNotRegex(line, r"(cp|rm|mkdir|install|>)\s")
        self.assertIn('if [ "$RELEASE" -ne 1 ] && [ "$DEST" != /src/build/test ]; then', self.text)
        for name in ('iso_name="blunix-installer$TAG.iso"', 'zst_name="blunix$TAG.raw.zst"', 'sums="SHA256SUMS$TAG"'):
            self.assertIn(name, self.text)

    def test_netboot_media_in_sha256sums(self):
        self.assertIn('assets="$assets vmlinuz initrd.img blunix.squashfs"', self.text)
        self.assertIn('sha256sum -- $assets > "$sums"', self.text)

    def test_iso_label_is_the_installer_label(self):
        self.assertIn("LABEL=" + MEDIUM_LABEL + "\n", self.text)
        self.assertEqual(self.text.count('-volid "$LABEL"'), 2)

    def test_release_payload_is_raw_scanned(self):
        self.assertIn('python3 /src/image/scan-raw.py "$RAW"', self.text)
        self.assertIn('python3 /src/image/scan-raw.py "$ZST"', self.text)


class DiskScriptTests(unittest.TestCase):
    def test_strip_zero_and_scan(self):
        text = _read("image", "build-test-disk.sh")
        strip = text.index('rm -f "$ROOTFS"/etc/ssh/ssh_host_*')
        self.assertLess(strip, text.index('rsync -aHAX --delete "$ROOTFS/" "$MNT/"'))
        self.assertLess(text.index('umount "$MNT"\nzerofree "$PART2"'), text.index('python3 /src/image/scan-raw.py "$DISK"'))
        self.assertLess(text.index('python3 /src/image/scan-raw.py "$DISK"'), text.index('cp --sparse=always "$DISK" "$OUTPUT"'))
        self.assertIn("ExecStartPre=/usr/bin/ssh-keygen -A", _read("image", "test", "ssh-hostkeys.conf"))


class ReleaseTextTests(unittest.TestCase):
    def test_ipxe_says_trusted_lans_only(self):
        self.assertIn("Netboot is for trusted LANs only until images are signed.", _read("image", "ipxe", "blunix.ipxe"))

    def test_release_notes(self):
        text = _read("image", "release", "RELEASE-NOTES.md")
        for phrase in (
            "unsigned test release",
            "boots on UEFI and on BIOS",
            "An installed disk boots on UEFI only.",
            "Netboot is for trusted LANs only until images are signed.",
            "asks on tty1",
            "sha256sum -c",
            "SHA256SUMS",
            "Debian 13",
        ):
            self.assertIn(phrase, text)


if __name__ == "__main__":
    unittest.main()

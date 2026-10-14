"""Personal builds: packages, an administrator, and unattended install.

Threats: a package list that reaches apt as an option, an administrator that
inherits a system account, a key field with authorized_keys options, an
unattended install without a named disk, a provisioning failure that leaves
bootstrap-complete behind, and an installer that stops asking blind users to
confirm the build address. Each is refused or checked here. The real chroot
run is image/test-personal-provision.sh.
"""

from __future__ import annotations

import base64
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from blunix.errors import BlunixError
from blunix.node import apply_node, parse_node
from blunix.personal import PACKAGES, parse_admin, parse_install, parse_packages, provision, replacement
from blunix.profile import render_node
from blunix.schema import expand_build_host, load_path
from test_installer import GIB, MODELS, Rig, _disk, _listing, _node_bytes, _part

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures", "profiles")
PUBLIC_KEY = "ssh-ed25519 " + base64.b64encode(
    bytes.fromhex("0000000b7373682d6564323535313900000020") + b"x" * 32
).decode()


def personal_doc(**changes):
    doc = yaml.safe_load(_node_bytes())
    doc.update(target="S1", install={"erase": True, "reboot": False})
    doc.update(changes)
    return doc


class ParseTests(unittest.TestCase):
    def test_packages(self):
        self.assertEqual(parse_packages(["git", "curl"]), ["curl", "git"])
        self.assertEqual(parse_packages(None), [])
        for value in ("git", ["git", "git"], ["--help"], ["git;id"], ["git curl"], [3], ["netcat"],
                      list(PACKAGES) + ["git"]):
            with self.subTest(value=value):
                with self.assertRaises(BlunixError):
                    parse_packages(value)

    def test_admin(self):
        self.assertEqual(parse_admin({"name": "operator", "sshPublicKey": PUBLIC_KEY})["name"], "operator")
        for name in ("root", "nobody", "sshd", "blunix", "Operator", "1op", "", "a" * 32):
            with self.subTest(name=name):
                with self.assertRaises(BlunixError):
                    parse_admin({"name": name, "sshPublicKey": PUBLIC_KEY})
        wrong_type = "ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x07ssh-rsa" + b"x" * 40).decode()
        for key in ("ssh-ed25519 " + "A" * 68, "-----BEGIN OPENSSH PRIVATE KEY-----", PUBLIC_KEY + "\ncommand=x",
                    PUBLIC_KEY + " user@host", "no-pty " + PUBLIC_KEY, wrong_type, None):
            with self.subTest(key=key):
                with self.assertRaises(BlunixError):
                    parse_admin({"name": "operator", "sshPublicKey": key})
        with self.assertRaises(BlunixError):
            parse_admin({"name": "operator", "sshPublicKey": PUBLIC_KEY, "password": "x"})

    def test_install_needs_a_target_and_explicit_erase(self):
        self.assertEqual(parse_install({"erase": True, "reboot": True}, "S1"), {"erase": True, "reboot": True})
        self.assertIsNone(parse_install(None, None))
        for value, target in (({"erase": True, "reboot": False}, None), ({"erase": False, "reboot": False}, "S1"),
                              ({"erase": "yes", "reboot": False}, "S1"), ({"erase": True}, "S1"),
                              ({"erase": True, "reboot": 1}, "S1"), ({"erase": True, "reboot": False, "x": 1}, "S1")):
            with self.subTest(value=value, target=target):
                with self.assertRaises(BlunixError):
                    parse_install(value, target)

    def test_node_carries_the_fields(self):
        parsed = parse_node(load_path(os.path.join(FIXTURES, "personal-node.yaml")))
        self.assertEqual(parsed["packages"], ["curl", "git"])
        self.assertEqual(parsed["admin"]["name"], "operator")
        self.assertEqual(parsed["install"], {"erase": True, "reboot": False})
        plain = parse_node(yaml.safe_load(_node_bytes()))
        self.assertEqual((plain["packages"], plain["admin"], plain["install"]), ([], None, None))

    def test_profile_packages_reach_the_rendered_node(self):
        node = render_node(load_path(os.path.join(FIXTURES, "profile-packages.yaml")), "ada", "ada-1")
        self.assertEqual(node["packages"], ["git", "tmux", "vim"])
        self.assertNotIn("admin", node)

    def test_https_build_address(self):
        self.assertEqual(expand_build_host("https://ada.blnx.io/"), "ada.blnx.io")
        self.assertEqual(expand_build_host("https://v2.ada.blnx.io"), "v2.ada.blnx.io")
        for value in ("http://ada.blnx.io/", "https://ada.blnx.io/x", "https://evil@ada.blnx.io/",
                      "https://ada.blnx.io/?q=x", "https://ada.blnx.io:443/", "https://", "https:///"):
            with self.subTest(value=value):
                with self.assertRaises(BlunixError):
                    expand_build_host(value)


class ProvisionTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", self.root], check=False))

    def runner(self, calls, fail_on=None, passwd_line=None):
        def run(argv, **kwargs):
            calls.append(list(argv))
            self.assertEqual(argv[:2], ["chroot", self.root])
            self.assertTrue(kwargs.get("check"))
            self.assertNotIn("shell", kwargs)
            if fail_on and fail_on in argv:
                raise subprocess.CalledProcessError(1, argv)
            if "useradd" in argv and passwd_line:
                with open(os.path.join(self.root, "etc/passwd"), "a") as fh:
                    fh.write(passwd_line + "\n")
            stdout = b"git=1:2.47\n" if "dpkg-query" in argv else b""
            return subprocess.CompletedProcess(argv, 0, stdout=stdout)
        return run

    def test_nothing_to_do_runs_nothing(self):
        calls = []
        self.assertIsNone(provision(self.root, [], None, self.runner(calls)))
        self.assertEqual(calls, [])

    def test_packages_after_double_dash_and_dns_policy_restored_on_failure(self):
        etc = Path(self.root) / "etc"
        etc.mkdir()
        (etc / "resolv.conf").symlink_to("/run/systemd/resolve/stub-resolv.conf")
        calls = []
        with self.assertRaises(subprocess.CalledProcessError):
            provision(self.root, ["git"], None, self.runner(calls, fail_on="install"))
        install = calls[1]
        self.assertIn("DEBIAN_FRONTEND=noninteractive", install)
        self.assertEqual(install[-2:], ["--", "git"])
        self.assertTrue((etc / "resolv.conf").is_symlink())
        self.assertFalse((Path(self.root) / "usr/sbin/policy-rc.d").exists())
        self.assertFalse((Path(self.root) / "var/lib/blunix/packages.lock").exists())

    def test_admin_account_key_sudo_and_sshd(self):
        etc = Path(self.root) / "etc"
        etc.mkdir()
        (etc / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
        calls = []
        said = []
        wanted = provision(self.root, ["git"], {"name": "operator", "sshPublicKey": PUBLIC_KEY},
                           self.runner(calls, passwd_line="operator:x:1000:1000::/home/operator:/bin/bash"),
                           log=said.append)
        self.assertEqual(wanted, ["git", "openssh-server", "sudo"])
        keys = Path(self.root) / "home/operator/.ssh/authorized_keys"
        self.assertEqual(keys.read_text(), PUBLIC_KEY + "\n")
        self.assertEqual(keys.stat().st_mode & 0o777, 0o600)
        self.assertEqual((etc / "sudoers.d/blunix-admin").read_text(), "operator ALL=(ALL:ALL) NOPASSWD: ALL\n")
        self.assertEqual((etc / "sudoers.d/blunix-admin").stat().st_mode & 0o777, 0o440)
        sshd = (etc / "ssh/sshd_config.d/00-blunix-admin.conf").read_text()
        for line in ("PasswordAuthentication no", "PermitRootLogin no", "KbdInteractiveAuthentication no"):
            self.assertIn(line, sshd)
        self.assertIn(["chroot", self.root, "systemctl", "enable", "ssh.service"], calls)
        useradd = next(c for c in calls if "useradd" in c)
        # Debian ships a system group named operator; a per-user group would clash.
        self.assertIn("--no-user-group", useradd)
        self.assertEqual(useradd[-2:], ["--", "operator"])
        self.assertEqual((Path(self.root) / "var/lib/blunix/packages.lock").read_text(), "git=1:2.47\n")
        self.assertTrue(any("not pinned" in line for line in said))
        self.assertFalse(any(PUBLIC_KEY in line for line in said))

    def test_existing_system_account_is_refused(self):
        etc = Path(self.root) / "etc"
        etc.mkdir()
        (etc / "passwd").write_text("operator:x:998:998::/var/lib/operator:/usr/sbin/nologin\n")
        with self.assertRaises(BlunixError) as ctx:
            provision(self.root, [], {"name": "operator", "sshPublicKey": PUBLIC_KEY}, self.runner([]))
        self.assertEqual(str(ctx.exception), "refused existing admin")
        self.assertFalse((etc / "sudoers.d/blunix-admin").exists())

    def test_replacement_restores_files_symlinks_and_modes(self):
        path = Path(self.root) / "file"
        path.write_bytes(b"original")
        path.chmod(0o640)
        with self.assertRaises(RuntimeError):
            with replacement(path, b"temporary", 0o755):
                raise RuntimeError()
        self.assertEqual((path.read_bytes(), path.stat().st_mode & 0o777), (b"original", 0o640))
        path.unlink()
        path.symlink_to("/nonexistent")
        with replacement(path, b"temporary", 0o644):
            self.assertFalse(path.is_symlink())
        self.assertEqual(os.readlink(path), "/nonexistent")
        missing = Path(self.root) / "new"
        with replacement(missing, b"temporary", 0o644):
            self.assertTrue(missing.exists())
        self.assertFalse(missing.exists())

    def test_failed_provision_never_marks_bootstrap_complete(self):
        with patch("blunix.node.provision", side_effect=BlunixError("failed")):
            with self.assertRaises(BlunixError):
                apply_node(personal_doc(packages=["git"]), self.root, models=MODELS)
        self.assertFalse((Path(self.root) / "var/lib/blunix/bootstrap-complete").exists())


class UnattendedInstallTests(unittest.TestCase):
    """The installer still asks for the address, confirms it aloud, and asks
    for the key. After decryption, `install` replaces the erase and reboot
    questions."""

    def rig(self, doc, answers, listing=None):
        rig = Rig(answers=answers, key="k", cipher=b"cipher",
                  decrypt=lambda *_: yaml.safe_dump(doc).encode(),
                  listing=listing or _listing(_disk("vda", 20 * GIB, children=[_part("vda1", "vda")], serial="S1")))
        rig.hooks.apply = lambda *_a, **_kw: None
        return rig

    def test_used_target_is_erased_without_a_question_and_reboot_follows_the_document(self):
        for reboot in (False, True):
            with self.subTest(reboot=reboot):
                doc = personal_doc(install={"erase": True, "reboot": reboot})
                rig = self.rig(doc, ["https://ada.blnx.io/", "yes"])
                self.assertEqual(rig.run(), 0)
                self.assertEqual(rig.written, ["/dev/vda"])
                self.assertEqual(rig.rebooted, [True] if reboot else [])
                self.assertIn("blunix: hostname ada.blnx.io. Say yes to keep it.", rig.said)
                self.assertIn("blunix: the document authorizes erasing disk vda, 21 gigabytes, Test Disk.", rig.said)
                self.assertFalse(any("Say yes to erase" in line for line in rig.said))
                self.assertFalse(any("Say yes to reboot" in line for line in rig.said))

    def test_address_confirmation_is_kept(self):
        rig = self.rig(personal_doc(), ["ada", "no", "ada", "no", "ada", "no"])
        self.assertEqual(rig.run(), 1)
        self.assertEqual(rig.said[-1], "blunix: no hostname. Nothing applied.")
        self.assertEqual(rig.written, [])

    def test_unattended_never_picks_another_disk(self):
        for listing in (_listing(_disk("vda", 20 * GIB, serial="OTHER")),
                        _listing(_disk("vda", 20 * GIB, serial="S1", ro=True))):
            rig = self.rig(personal_doc(), ["ada", "yes"], listing=listing)
            self.assertEqual(rig.run(), 1)
            self.assertEqual(rig.said[-1], "blunix: target disk S1 is not usable. Nothing applied.")
            self.assertEqual(rig.written, [])

    def test_an_offered_address_still_needs_yes(self):
        doc = personal_doc()
        rig = self.rig(doc, ["yes"])
        rig.hooks.cmdline = lambda: "boot=live blunix.build=ada.blnx.io blunix.access=full-speech"
        self.assertEqual(rig.run(), 0)
        self.assertIn("blunix: the build proxy offers ada.blnx.io. Say yes to use it.", rig.said)
        self.assertNotIn("blunix: build hostname.", rig.said)
        rig = self.rig(doc, ["no", "ada", "yes"])
        rig.hooks.cmdline = lambda: "blunix.build=other.blnx.io"
        self.assertEqual(rig.run(), 0)
        self.assertIn("blunix: build hostname.", rig.said)
        self.assertIn("blunix: hostname ada.blnx.io. Say yes to keep it.", rig.said)

    def test_a_bad_offered_address_is_refused_not_used(self):
        for cmdline in ("blunix.build=evil.example.com", "blunix.build=ada.blnx.io blunix.build=b.blnx.io",
                        "blunix.build=https://ada.blnx.io/"):
            with self.subTest(cmdline=cmdline):
                rig = self.rig(personal_doc(), ["ada", "yes"])
                rig.hooks.cmdline = lambda c=cmdline: c
                self.assertEqual(rig.run(), 0)
                self.assertIn("blunix: refused the offered build address.", rig.said)
                self.assertFalse(any("offers" in line for line in rig.said))

    def test_without_install_the_questions_stay(self):
        doc = personal_doc()
        del doc["install"]
        rig = self.rig(doc, ["ada", "yes", "yes", "no"])
        self.assertEqual(rig.run(), 0)
        self.assertIn("blunix: erase disk vda, 21 gigabytes, Test Disk. Say yes to erase.", rig.said)
        self.assertIn("blunix: installed blunix-test. Remove the stick. Say yes to reboot.", rig.said)


if __name__ == "__main__":
    unittest.main()

"""Configurable build-proxy: profiles in site files, interface match, the
boot: section, and plan --explain.

Threats: a profile path that escapes the site directory, a boot value that
adds a dnsmasq line or a second kernel directive, and a precedence rule that
silently picks a value the operator did not mean. Each is refused or shown.
"""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import tempfile
import unittest

from blunix.errors import BlunixError
from blunix.proxy import cmd_plan
from blunix.proxy_boot import render_dnsmasq, render_ipxe
from blunix.proxy_site import load_site, parse_boot, parse_site, render_node, validate_node

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures", "profiles")
MODELS = os.path.join(HERE, "..", "models")

SERVER_PROFILE = """{"apiVersion": "blunix.dev/v1", "kind": "Profile", "name": "server",
 "disk": "cloud-vm", "network": {"match": ["ens3"], "dhcp": true}, "access": "advanced",
 "ai": "default", "update": {"url": "https://updates.blunix.io/blunix", "channel": "stable"},
 "sysexts": []}
"""
STATIC_PROFILE = """apiVersion: blunix.dev/v1
kind: Profile
name: fixed
disk: cloud-vm
network: static-single
access: regular
ai: default
update: {url: "https://updates.blunix.io/blunix", channel: stable}
sysexts: []
"""


def machine(n, extra=""):
    return ('  - mac: "00:50:56:aa:bb:0' + str(n) + '"\n    label: m' + str(n)
            + "\n    hostname: h" + str(n) + "\n" + extra)


class Lab(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        os.makedirs(os.path.join(self.dir, "profiles"))
        shutil.copy(os.path.join(FIXTURES, "lab-speech.yaml"), os.path.join(self.dir, "profiles"))
        shutil.copy(os.path.join(FIXTURES, "bad-rocky.yaml"), os.path.join(self.dir, "profiles"))
        self.write("profiles/server.json", SERVER_PROFILE)
        self.write("profiles/fixed.yaml", STATIC_PROFILE)

    def write(self, name, text):
        path = os.path.join(self.dir, name)
        with open(path, "w") as fh:
            fh.write(text)
        return path

    def site(self, text):
        return load_site(self.write("site.yaml", text))

    def refused(self, text, needle):
        with self.assertRaises(BlunixError) as ctx:
            self.site(text)
        self.assertIn(needle, str(ctx.exception))


class ProfilePrecedenceTests(Lab):
    def test_default_profile_fills_gaps_and_site_defaults_win(self):
        s = self.site("defaults: {profile: profiles/lab-speech.yaml, access: regular}\nmachines:\n"
                      + machine(1))
        m = s["machines"][0]
        self.assertEqual((m["disk"], m["access"], m["dhcp"]), ("metal-luks", "regular", True))
        self.assertEqual(m["sources"]["disk"], "profile profiles/lab-speech.yaml")
        self.assertEqual(m["sources"]["access"], "defaults")
        self.assertEqual(m["sources"]["network"], "profile profiles/lab-speech.yaml")
        validate_node(m, render_node(m), MODELS)

    def test_machine_profile_beats_site_defaults_and_machine_fields_beat_both(self):
        s = self.site(
            "defaults: {profile: profiles/lab-speech.yaml, disk: metal-luks, access: regular}\n"
            "machines:\n"
            + machine(1, "    profile: profiles/server.json\n")
            + machine(2, "    profile: profiles/server.json\n    access: large-print\n")
        )
        own, override = s["machines"]
        self.assertEqual((own["disk"], own["access"], own["match"]), ("cloud-vm", "advanced", ["ens3"]))
        self.assertEqual(own["sources"]["disk"], "profile profiles/server.json")
        self.assertEqual((override["access"], override["sources"]["access"]), ("large-print", "machine"))
        doc = render_node(own)
        self.assertIn(b"- ens3", doc)
        self.assertIn(b"dhcp: true", doc)
        validate_node(own, doc, MODELS)

    def test_a_static_profile_cannot_stand_in_for_a_machine_network(self):
        self.refused("defaults: {profile: profiles/fixed.yaml}\nmachines:\n" + machine(1),
                     "give exactly one of network or dhcp")

    def test_no_profile_keeps_the_old_rules(self):
        s = self.site("defaults: {disk: cloud-vm, access: regular}\nmachines:\n"
                      + machine(1, "    dhcp: true\n"))
        m = s["machines"][0]
        self.assertIn(b"network: dhcp-any", render_node(m))
        self.assertEqual((m["sources"]["ai"], m["profile"]), ("built-in", None))


class ProfilePathTests(Lab):
    def test_paths_that_leave_the_site_directory_or_are_not_profiles(self):
        outside = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, outside)
        shutil.copy(os.path.join(FIXTURES, "lab-speech.yaml"), outside)
        os.symlink(os.path.join(outside, "lab-speech.yaml"), os.path.join(self.dir, "profiles", "link.yaml"))
        for path, needle in (
            ("/etc/passwd.yaml", "refused profile path"),
            ("../x.yaml", "refused profile path"),
            ("profiles/../profiles/lab-speech.yaml", "refused profile path"),
            ("profiles/lab-speech.txt", "refused profile path"),
            ("profiles/missing.yaml", "profile not found"),
            ("profiles/link.yaml", "profile not found inside"),
        ):
            with self.subTest(path=path):
                self.refused("defaults: {profile: " + path + "}\nmachines:\n" + machine(1), needle)

    def test_a_bad_profile_names_itself(self):
        self.refused("machines:\n" + machine(1, "    profile: profiles/bad-rocky.yaml\n"),
                     "machine 1: profile profiles/bad-rocky.yaml: refused distribution")

    def test_bytes_without_a_path_cannot_name_a_profile(self):
        with self.assertRaises(BlunixError) as ctx:
            parse_site(b"defaults: {profile: profiles/lab-speech.yaml}\nmachines:\n" + machine(1).encode())
        self.assertIn("profile needs the site file's path", str(ctx.exception))


class MatchTests(Lab):
    def test_match_from_defaults_and_machine(self):
        s = self.site(
            "defaults: {disk: cloud-vm, access: regular, match: [eth*], dns: [192.0.2.53]}\nmachines:\n"
            + machine(1, "    dhcp: true\n")
            + machine(2, "    match: [enp1s0]\n    network: {address: 192.0.2.22/24, gateway: 192.0.2.1}\n")
        )
        dhcp, static = s["machines"]
        self.assertIn(b"- eth*", render_node(dhcp))
        self.assertIn(b"- enp1s0", render_node(static))
        for m in s["machines"]:
            validate_node(m, render_node(m), MODELS)

    def test_bad_match(self):
        for value in ("[]", "[wlan0]", '["en*; reboot"]', "en*"):
            with self.subTest(value=value):
                self.refused("defaults: {disk: cloud-vm, access: regular}\nmachines:\n"
                             + machine(1, "    dhcp: true\n    match: " + value + "\n"), "match")


class BootTests(Lab):
    def test_builtins(self):
        boot, sources = parse_boot(None)
        self.assertEqual(boot["console"], ["tty0", "ttyS0,115200"])
        self.assertEqual(set(sources.values()), {"built-in"})
        line = render_ipxe("192.0.2.5:8750").splitlines()[2]
        self.assertIn("blunix.access=regular console=tty0 console=ttyS0,115200", line)

    def test_site_boot_reaches_ipxe_and_dnsmasq(self):
        s = self.site(
            "defaults: {disk: cloud-vm, access: regular, dns: [192.0.2.53]}\n"
            "boot: {access: full-speech, console: [tty1], args: [quiet, loglevel=3], lease: 30m,"
            " tftp_root: /srv/blunix-tftp}\n"
            "machines:\n" + machine(1, "    network: {address: 192.0.2.21/24, gateway: 192.0.2.1}\n")
        )
        ipxe = render_ipxe("192.0.2.5:8750", s["boot"])
        self.assertIn("blunix.access=full-speech console=tty1 quiet loglevel=3", ipxe)
        self.assertNotIn("ttyS0", ipxe)
        conf = render_dnsmasq(s, "192.0.2.5:8750").splitlines()
        self.assertIn("dhcp-range=192.0.2.0,static,255.255.255.0,30m", conf)
        self.assertIn("tftp-root=/srv/blunix-tftp", conf)
        self.assertIn("tftp-root=/srv/other", render_dnsmasq(s, "192.0.2.5:8750", tftp_root="/srv/other"))

    def test_refusals(self):
        for boot, needle in (
            ("{shell: x}", "unknown key in boot"),
            ("{access: Full}", "refused boot access"),
            ("{console: [ttyUSB0]}", "refused boot console"),
            ("{console: []}", "refused boot console"),
            ('{args: ["quiet initrd=evil"]}', "refused boot arg"),
            ('{args: ["a\\nkernel x"]}', "refused boot arg"),
            ("{args: [fetch=http://evil/x]}", "is set by the proxy"),
            ("{args: [blunix.access=advanced]}", "is set by the proxy"),
            ("{lease: 12d}", "refused boot lease"),
            ("{lease: '12h\\nenable-ra'}", "refused boot lease"),
            ("{tftp_root: /srv/../etc}", "refused boot tftp_root"),
            ("{tftp_root: srv}", "refused boot tftp_root"),
        ):
            with self.subTest(boot=boot):
                self.refused("boot: " + boot + "\nmachines:\n" + machine(1, "    dhcp: true\n"), needle)


class ExplainTests(Lab):
    def test_explain_names_every_source(self):
        path = self.write(
            "site.yaml",
            "defaults: {profile: profiles/lab-speech.yaml, access: regular}\n"
            "boot: {lease: 2h}\nmachines:\n" + machine(1),
        )
        out = io.StringIO()
        old = os.environ.get("BLUNIX_MODELS")
        os.environ["BLUNIX_MODELS"] = MODELS
        self.addCleanup(lambda: os.environ.pop("BLUNIX_MODELS") if old is None
                        else os.environ.__setitem__("BLUNIX_MODELS", old))
        with contextlib.redirect_stdout(out):
            self.assertEqual(cmd_plan(path, {"explain": True}), 0)
        text = out.getvalue()
        for line in (
            "explain m1 (machine 1, 00:50:56:aa:bb:01):",
            "  disk metal-luks (profile profiles/lab-speech.yaml)",
            "  access regular (defaults)",
            "  network dhcp (profile profiles/lab-speech.yaml)",
            "  match en*, eth* (built-in)",
            "  lease 2h (site boot)",
            "  console tty0, ttyS0,115200 (built-in)",
        ):
            self.assertIn("blunix proxy: " + line, text)
        self.assertIn("publish would reserve", text)

    def test_plan_without_explain_is_unchanged(self):
        path = self.write("site.yaml", "defaults: {disk: cloud-vm, access: regular}\nmachines:\n"
                          + machine(1, "    dhcp: true\n"))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cmd_plan(path, {})
        self.assertNotIn("explain", out.getvalue())


if __name__ == "__main__":
    unittest.main()

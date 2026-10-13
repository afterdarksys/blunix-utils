"""Build profiles: a template plus a label and hostname becomes a node document.

Threats: a profile that smuggles a hostname, a secret field, an unknown
distribution, or a channel the image does not serve. These tests refuse each,
and check that YAML and JSON give the same outcome through the shared cases in
tests/fixtures/profiles/cases.json, which the portal is meant to reuse.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import unittest

import yaml

from blunix.cli import main
from blunix.errors import BlunixError
from blunix.node import parse_node
from blunix.profile import check_document, render_node
from blunix.schema import load_path, load_text

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures", "profiles")
MODELS = os.path.join(HERE, "..", "models")


def fixture(name):
    return os.path.join(FIXTURES, name)


class SharedCases(unittest.TestCase):
    def test_every_shared_case(self):
        with open(fixture("cases.json")) as fh:
            cases = json.load(fh)["cases"]
        self.assertGreater(len(cases), 0)
        for case in cases:
            with self.subTest(file=case["file"]):
                if case["ok"]:
                    kind, _ = check_document(load_path(fixture(case["file"])), MODELS)
                    self.assertEqual(kind, case["kind"])
                else:
                    with self.assertRaises(BlunixError) as ctx:
                        check_document(load_path(fixture(case["file"])), MODELS)
                    self.assertEqual(str(ctx.exception), case["error"])

    def test_yaml_and_json_profiles_render_the_same_node(self):
        a = render_node(load_path(fixture("lab-speech.yaml")), "ada", "ada-1")
        b = render_node(load_path(fixture("lab-speech.json")), "ada", "ada-1")
        self.assertEqual(a, b)


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.profile = load_path(fixture("lab-speech.yaml"))

    def test_render_is_a_valid_node_without_distribution(self):
        node = render_node(self.profile, "ada", "ada-1", target="nvme0n1")
        self.assertEqual(node["kind"], "Node")
        self.assertEqual((node["name"], node["hostname"], node["target"]), ("ada", "ada-1", "nvme0n1"))
        self.assertNotIn("distribution", node)
        parse_node(node)

    def test_render_refuses_bad_label_hostname_and_target(self):
        for label, hostname, target, message in (
            ("api", "ada-1", None, "refused hostname"),
            ("v3", "ada-1", None, "refused hostname"),
            ("ada", "Ada_1", None, "refused hostname"),
            ("ada", "ada-1", "/dev/sda", "refused target"),
        ):
            with self.subTest(label=label, hostname=hostname, target=target):
                with self.assertRaises(BlunixError) as ctx:
                    render_node(self.profile, label, hostname, target)
                self.assertEqual(str(ctx.exception), message)

    def test_a_node_is_not_a_profile(self):
        with self.assertRaises(BlunixError) as ctx:
            render_node(load_path(fixture("ada-node.yaml")), "ada", "ada-1")
        self.assertEqual(str(ctx.exception), "unknown field")


class CliTests(unittest.TestCase):
    def run_cli(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(argv)
        return code, out.getvalue()

    def test_check_accepts_profile_and_node(self):
        for name, said in (("lab-speech.json", "profile lab-speech"), ("ada-node.yaml", "node ada")):
            code, out = self.run_cli(["profile", "check", "--file", fixture(name), "--models", MODELS])
            self.assertEqual(code, 0)
            self.assertIn("blunix: " + said + " accepted", out)

    def test_check_refuses_a_bad_profile(self):
        code, _ = self.run_cli(["profile", "check", "--file", fixture("bad-rocky.yaml"), "--models", MODELS])
        self.assertEqual(code, 1)

    def test_render_yaml_and_json_round_trip(self):
        for fmt, load in (("yaml", load_text), ("json", json.loads)):
            code, out = self.run_cli([
                "profile", "render", "--file", fixture("lab-speech.yaml"),
                "--label", "grace", "--hostname", "grace-1", "--format", fmt,
            ])
            self.assertEqual(code, 0)
            node = load(out)
            parse_node(node)
            self.assertEqual(node["name"], "grace")

    def test_render_needs_label_and_hostname_and_a_known_format(self):
        base = ["profile", "render", "--file", fixture("lab-speech.yaml")]
        for extra in ([], ["--label", "ada"], ["--label", "ada", "--hostname", "ada-1", "--format", "toml"]):
            with self.subTest(extra=extra):
                code, out = self.run_cli(base + extra)
                self.assertEqual(code, 1)
                self.assertNotIn("apiVersion", out)

    def test_help_lists_profile(self):
        _, out = self.run_cli(["--help"])
        self.assertIn("profile check", out)
        self.assertIn("profile render", out)


if __name__ == "__main__":
    unittest.main()

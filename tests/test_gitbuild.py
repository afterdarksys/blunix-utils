"""Offline source-build, ownership, upgrade, and failure recovery tests."""

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from blunix import gitbuild as gb
from blunix import gitbuild_install as gi
from blunix.errors import BlunixError


class GitbuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name).resolve()
        self.root = self.work / "root"
        self.source = self.work / "source"
        self.source.mkdir()
        self.user = patch("blunix.gitbuild.os.geteuid", return_value=1000)
        self.user.start()
        self.addCleanup(self.user.stop)

    def bundle(self, label="one", body="first", config="default=1\n", product="demo"):
        source = self.work / ("src-" + label)
        source.mkdir()
        (source / "demo.sh").write_text('#!/bin/sh\nprintf "%s\\n" ' + body + "\n")
        (source / "config").write_text(config)
        (source / "library").write_text("library")
        (source / "gitbuild.yaml").write_text(
            json.dumps(
                {
                    "version": 1,
                    "product": product,
                    "system": "bash",
                    "files": [
                        {"source": "demo.sh", "dest": "bin/demo"},
                        {"source": "demo.sh", "dest": "sbin/demod"},
                        {"source": "library", "dest": "lib/library"},
                        {"source": "config", "dest": "etc/demo.conf"},
                    ],
                }
            )
        )
        output = self.work / label
        gb.build_source(source, output, "afterdarksys/demo", "v1", "a" * 40)
        return output

    def final(self):
        return self.root / "usr/local/afterdarksys/demo"

    def test_end_to_end_build_install_execute_verify_remove(self):
        bundle = self.bundle()
        gi.install(bundle, self.root)
        local = self.root / "usr/local"
        self.assertEqual(
            os.readlink(local / "bin/demo"), "../afterdarksys/demo/bin/demo"
        )
        self.assertEqual(
            os.readlink(local / "sbin/demod"), "../afterdarksys/demo/sbin/demod"
        )
        self.assertEqual(os.readlink(local / "lib/demo"), "../afterdarksys/demo/lib")
        self.assertEqual(os.readlink(local / "etc/demo"), "../afterdarksys/demo/etc")
        self.assertEqual(
            subprocess.check_output([local / "bin/demo"], text=True), "first\n"
        )
        self.assertEqual(gi.verify("demo", self.root)["changed"], [])
        self.assertEqual(gi.installed(self.root)[0]["product"], "demo")
        gi.remove("demo", self.root)
        self.assertFalse((local / "bin/demo").exists())
        self.assertEqual((local / "etc/demo/demo.conf").read_text(), "default=1\n")
        self.assertEqual(gi.installed(self.root)[0]["status"], "config-only")
        gi.remove("demo", self.root, purge=True)
        self.assertEqual(gi.installed(self.root), [])
        self.assertFalse(os.path.lexists(local / "etc/demo"))

    def test_upgrade_preserves_edits_and_offers_new_defaults(self):
        gi.install(self.bundle(), self.root)
        (self.final() / "etc/demo.conf").write_text("my setting\n")
        result = gi.install(
            self.bundle("two", body="second", config="default=2\n"), self.root
        )
        self.assertEqual(result["config_preserved"], ["etc/demo.conf"])
        self.assertEqual((self.final() / "etc/demo.conf").read_text(), "my setting\n")
        self.assertEqual(
            (self.final() / "etc/demo.conf.gitbuild-new").read_text(), "default=2\n"
        )
        self.assertEqual(
            subprocess.check_output([self.root / "usr/local/bin/demo"], text=True),
            "second\n",
        )
        self.assertEqual(gi.verify("demo", self.root)["changed"], [])
        # An unresolved candidate must not be overwritten on the next upgrade.
        with self.assertRaises(BlunixError):
            gi.install(self.bundle("three", config="default=3\n"), self.root)
        self.assertEqual((self.final() / "etc/demo.conf").read_text(), "my setting\n")

    def test_unchanged_defaults_upgrade_and_reinstall_is_idempotent(self):
        one, two = self.bundle(), self.bundle("two", config="new\n")
        gi.install(one, self.root)
        gi.install(two, self.root)
        gi.install(two, self.root)
        self.assertEqual((self.final() / "etc/demo.conf").read_text(), "new\n")
        self.assertEqual(gi.verify("demo", self.root)["links_changed"], [])

    def test_user_added_config_survives_multiple_upgrades(self):
        gi.install(self.bundle(), self.root)
        (self.final() / "etc/local.conf").write_text("mine")
        for label in ("two", "three"):
            gi.install(self.bundle(label), self.root)
            self.assertEqual((self.final() / "etc/local.conf").read_text(), "mine")

    def test_reinstall_after_remove_preserves_config(self):
        one = self.bundle()
        gi.install(one, self.root)
        gi.remove("demo", self.root)
        gi.install(self.bundle("two", config="new default"), self.root)
        self.assertEqual((self.final() / "etc/demo.conf").read_text(), "default=1\n")

    def test_collision_does_not_touch_existing_file(self):
        path = self.root / "usr/local/bin/demo"
        path.parent.mkdir(parents=True)
        path.write_text("not yours")
        with self.assertRaisesRegex(BlunixError, "collision"):
            gi.install(self.bundle(), self.root)
        self.assertEqual(path.read_text(), "not yours")
        self.assertFalse(self.final().exists())

    def test_two_products_cannot_own_same_command(self):
        gi.install(self.bundle(), self.root)
        with self.assertRaisesRegex(BlunixError, "collision"):
            gi.install(self.bundle("other", product="other"), self.root)
        self.assertEqual(gi.verify("demo", self.root)["changed"], [])

    def test_unmanaged_product_directory_is_preserved(self):
        self.final().mkdir(parents=True)
        (self.final() / "mine").write_text("mine")
        with self.assertRaises(BlunixError):
            gi.install(self.bundle(), self.root)
        self.assertEqual((self.final() / "mine").read_text(), "mine")

    def test_modified_export_blocks_remove(self):
        gi.install(self.bundle(), self.root)
        path = self.root / "usr/local/bin/demo"
        path.unlink()
        path.write_text("mine")
        with self.assertRaisesRegex(BlunixError, "collision"):
            gi.remove("demo", self.root, True)
        self.assertEqual(path.read_text(), "mine")
        self.assertTrue(self.final().exists())

    def test_exception_rolls_back_product_and_all_links(self):
        gi.install(self.bundle(), self.root)
        bundle = self.bundle("two", body="second")
        original = Path.symlink_to
        failed = False

        def fail_once(path, target, **kwargs):
            nonlocal failed
            if path.name == "demo" and path.parent.name == "lib" and not failed:
                failed = True
                raise OSError("injected publish failure")
            return original(path, target, **kwargs)

        with patch.object(Path, "symlink_to", fail_once), self.assertRaises(OSError):
            gi.install(bundle, self.root)
        self.assertTrue(failed)
        self.assertEqual(gi.verify("demo", self.root)["changed"], [])
        self.assertEqual(gi.verify("demo", self.root)["links_changed"], [])
        self.assertEqual(
            subprocess.check_output([self.root / "usr/local/bin/demo"], text=True),
            "first\n",
        )

    def test_failed_rollback_keeps_recovery_copy(self):
        gi.install(self.bundle(), self.root)
        bundle = self.bundle("two", body="second")
        original = Path.symlink_to
        failed = False

        def fail_publish_and_restore(path, target, **kwargs):
            nonlocal failed
            if path.name == "demo" and path.parent.name == "lib":
                failed = True
                raise OSError("publication and rollback failure")
            return original(path, target, **kwargs)

        with (
            patch.object(Path, "symlink_to", fail_publish_and_restore),
            self.assertRaisesRegex(BlunixError, "recovery files retained"),
        ):
            gi.install(bundle, self.root)
        self.assertTrue(failed)
        backups = list(self.final().parent.glob(".transaction-*/previous/bin/demo"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(subprocess.check_output([backups[0]], text=True), "first\n")

    def test_tampered_bundle_refused_before_target_writes(self):
        bundle = self.bundle()
        (bundle / "payload/bin/demo").write_text("tampered")
        with self.assertRaisesRegex(BlunixError, "inventory mismatch"):
            gi.install(bundle, self.root)
        self.assertFalse(self.root.exists())

    def test_wrong_architecture_is_refused(self):
        bundle = self.bundle()
        doc = json.loads((bundle / "bundle.json").read_text())
        doc["machine"] = "wrong"
        (bundle / "bundle.json").write_text(json.dumps(doc))
        with self.assertRaisesRegex(BlunixError, "platform"):
            gi.install(bundle, self.root)

    def test_symlink_ancestor_does_not_escape_root(self):
        outside = self.work / "outside"
        outside.mkdir()
        (self.root / "usr").mkdir(parents=True)
        (self.root / "usr/local").symlink_to(outside)
        with self.assertRaisesRegex(BlunixError, "symlink"):
            gi.install(self.bundle(), self.root)
        self.assertEqual(list(outside.iterdir()), [])

    def test_product_symlink_is_refused(self):
        bundle = self.bundle()
        self.final().parent.mkdir(parents=True)
        self.final().symlink_to(self.source)
        with self.assertRaisesRegex(BlunixError, "symlink"):
            gi.install(bundle, self.root)

    def test_unsafe_payloads(self):
        for kind in ("escape", "absolute", "fifo", "setuid", "config-link"):
            with self.subTest(kind=kind):
                bundle = self.bundle(kind)
                path = bundle / "payload/lib/unsafe"
                if kind == "escape":
                    path.symlink_to("../../../outside")
                elif kind == "absolute":
                    path.symlink_to("/etc/passwd")
                elif kind == "fifo":
                    os.mkfifo(path)
                elif kind == "setuid":
                    path.write_text("data")
                    path.chmod(0o4755)
                    if not path.stat().st_mode & 0o4000:
                        self.skipTest(
                            "filesystem strips setuid bits; exercised on Linux"
                        )
                else:
                    (bundle / "payload/etc/link").symlink_to("../lib/library")
                with self.assertRaises(BlunixError):
                    gi.inventory(bundle / "payload")

    def test_verify_detects_content_and_missing_links(self):
        gi.install(self.bundle(), self.root)
        (self.final() / "bin/demo").write_text("modified")
        (self.root / "usr/local/sbin/demod").unlink()
        result = gi.verify("demo", self.root)
        self.assertIn("bin/demo", result["changed"])
        self.assertEqual(result["links_changed"], ["sbin/demod"])

    def test_repository_allowlist_and_manifest_paths(self):
        for value in (
            "evil/demo",
            "https://github.com.evil/afterdarksys/demo",
            "afterdarksys/../demo",
            "git@github.com:afterdarksys/demo",
            "afterdarksys/demo?x",
            "afterdarksys/-x",
        ):
            with self.subTest(value=value), self.assertRaises(BlunixError):
                gb.repository(value)
        self.assertEqual(
            gb.repository("https://github.com/straticus1/demo.git"), "straticus1/demo"
        )
        for value in ("../outside", "/etc/passwd", "bin/../x", "bin//x"):
            with self.assertRaises(BlunixError):
                gb.relative(value)

    def test_ambiguous_repo_requires_manifest(self):
        (self.source / "go.mod").touch()
        (self.source / "package.json").touch()
        with self.assertRaisesRegex(BlunixError, "ambiguous"):
            gb.recipe(self.source, "demo")

    def test_root_build_is_refused(self):
        with (
            patch("blunix.gitbuild.os.geteuid", return_value=0),
            self.assertRaisesRegex(BlunixError, "non-root"),
        ):
            gb.prepare("afterdarksys/demo", "main", self.work / "out")

    def test_custom_commands_build_into_stage_and_failure_leaves_no_bundle(self):
        spec = {
            "version": 1,
            "system": "custom",
            "commands": [["sh", "-c", 'printf data > "$GITBUILD_STAGE/lib/result"']],
        }
        (self.source / "gitbuild.yaml").write_text(json.dumps(spec))
        out = self.work / "custom"
        gb.build_source(self.source, out, "straticus1/demo", "main", "a" * 40)
        self.assertEqual((out / "payload/lib/result").read_text(), "data")
        spec["commands"] = [["sh", "-c", "exit 1"]]
        (self.source / "gitbuild.yaml").write_text(json.dumps(spec))
        with self.assertRaises(BlunixError):
            gb.build_source(
                self.source, self.work / "failed", "straticus1/demo", "main", "a" * 40
            )
        self.assertFalse((self.work / "failed").exists())

    def test_destdir_recipe(self):
        (self.source / "gitbuild.yaml").write_text(
            json.dumps(
                {
                    "version": 1,
                    "system": "custom",
                    "commands": [
                        [
                            "sh",
                            "-c",
                            'mkdir -p "$DESTDIR$PREFIX/lib"; printf data > "$DESTDIR$PREFIX/lib/result"',
                        ]
                    ],
                }
            )
        )
        out = self.work / "custom"
        gb.build_source(self.source, out, "straticus1/demo", "main", "a" * 40)
        self.assertEqual((out / "payload/lib/result").read_text(), "data")

    def test_go_rust_python_node_php_adapters(self):
        for system in ("go", "rust", "python", "node", "php"):
            with self.subTest(system=system):
                source = self.work / system
                source.mkdir()
                spec = {"version": 1, "system": system, "product": "demo"}
                if system == "php":
                    (source / "composer.json").write_text("{}")
                    (source / "demo.php").write_text(
                        '#!/usr/bin/env php\n<?php echo "ok";'
                    )
                    spec["files"] = [{"source": "demo.php", "dest": "bin/demo"}]
                (source / "gitbuild.yaml").write_text(json.dumps(spec))
                calls = []

                def fake_run(args, cwd, env, calls=calls, system=system, source=source):
                    calls.append(args)
                    stage = Path(env["GITBUILD_STAGE"])
                    if system == "go":
                        Path(args[args.index("-o") + 1]).write_text("binary")
                        Path(args[args.index("-o") + 1]).chmod(0o755)
                    elif system == "rust":
                        path = source / "target/release/demo"
                        path.parent.mkdir(parents=True)
                        path.write_text("binary")
                        path.chmod(0o755)
                    elif system == "python":
                        target = stage / "lib/python"
                        info = target / "demo-1.0.dist-info"
                        info.mkdir(parents=True)
                        (info / "METADATA").write_text("Name: demo\nVersion: 1.0\n")
                        (info / "entry_points.txt").write_text(
                            "[console_scripts]\ndemo = demomod:main\n"
                        )
                        (target / "demomod.py").write_text(
                            'def main():\n    print("python works")\n'
                        )
                    elif system == "node":
                        (source / "package.json").write_text(
                            json.dumps({"bin": {"demo": "./demo.js"}})
                        )
                        (source / "demo.js").write_text(
                            '#!/usr/bin/env node\nconsole.log("node works");\n'
                        )

                out = self.work / ("out-" + system)
                with patch("blunix.gitbuild.run", side_effect=fake_run):
                    gb.build_source(source, out, "afterdarksys/demo", "v1", "a" * 40)
                self.assertTrue(calls)
                self.assertTrue((out / "payload/bin/demo").is_file())
                if system in ("python", "node"):
                    gi.install(out, self.root)
                    self.assertEqual(
                        subprocess.check_output(
                            [self.root / "usr/local/bin/demo"], text=True
                        ),
                        system + " works\n",
                    )
                    gi.remove("demo", self.root, True)

    def test_checkout_records_actual_commit_without_network(self):
        # Real local Git fixture; only the HTTPS fetch transport is substituted.
        repo = self.work / "upstream"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        (repo / "gitbuild.yaml").write_text(
            json.dumps(
                {
                    "version": 1,
                    "system": "bash",
                    "files": [{"source": "demo.sh", "dest": "bin/demo"}],
                }
            )
        )
        (repo / "demo.sh").write_text("#!/bin/sh\necho checkout\n")
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.test",
                "commit",
                "-qm",
                "fixture",
            ],
            check=True,
        )
        commit = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
        ).strip()
        real_run = gb.run

        def local_fetch(args, cwd, env):
            self.assertNotIn("GIT_DIR", env)
            self.assertNotIn("GIT_WORK_TREE", env)
            if "fetch" in args:
                self.assertIn("https://github.com/straticus1/demo.git", args)
                args = ["git", "fetch", "--depth=1", str(repo), commit]
            return real_run(args, cwd, env)

        with (
            patch("blunix.gitbuild.run", side_effect=local_fetch),
            patch.dict(
                os.environ,
                {"GIT_DIR": "/not-the-checkout", "GIT_WORK_TREE": "/not-the-checkout"},
            ),
        ):
            doc = gb.prepare("straticus1/demo", commit, self.work / "prepared")
        self.assertEqual(doc["commit"], commit)
        gi.install(self.work / "prepared", self.root)
        self.assertEqual(
            subprocess.check_output([self.root / "usr/local/bin/demo"], text=True),
            "checkout\n",
        )

    def test_cli_and_blunix_dispatch(self):
        from blunix.cli import main

        bundle = self.bundle()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(["gitbuild", "install", str(bundle), "--root", str(self.root)]), 0
            )
            self.assertEqual(gb.main(["verify", "demo", "--root", str(self.root)]), 0)
            self.assertEqual(gb.main(["list", "--root", str(self.root)]), 0)
        (self.final() / "lib/library").write_text("changed")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(gb.main(["verify", "demo", "--root", str(self.root)]), 1)


if __name__ == "__main__":
    unittest.main()

"""Exercise real Git repositories, including unrelated staged work and conflicts."""

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "sync_dist", Path(__file__).resolve().parents[1] / "sync-to-dist.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.src, self.dst = self.root / "utils", self.root / "dist"
        for root in (self.src, self.dst):
            root.mkdir()
            self.git(root, "init", "-q")
            self.git(root, "config", "user.name", "Fixture")
            self.git(root, "config", "user.email", "fixture@example.test")
            (root / "README").write_text("original")
            self.commit(root)
        (self.src / "lib").mkdir()
        (self.src / "lib/tool.py").write_text("one")
        (self.src / "dist-map.json").write_text(
            json.dumps(
                {"version": 1, "mappings": [{"source": "lib", "target": "lib/blunix"}]}
            )
        )
        self.commit(self.src)

    def git(self, root, *args):
        return subprocess.check_output(
            ["git", "-C", str(root), *args], stderr=subprocess.PIPE
        ).decode()

    def commit(self, root):
        self.git(root, "add", ".")
        self.git(root, "commit", "-qm", "fixture")

    def test_sync_idempotent_and_preserves_unrelated_index(self):
        (self.dst / "README").write_text("staged unrelated")
        self.git(self.dst, "add", "README")
        result = module.sync(self.src, self.dst)
        self.assertEqual(result["status"], "committed")
        self.assertEqual(self.git(self.dst, "show", "HEAD:README"), "original")
        self.assertEqual(self.git(self.dst, "show", ":README"), "staged unrelated")
        self.assertEqual((self.dst / "lib/blunix/tool.py").read_text(), "one")
        self.assertEqual(module.sync(self.src, self.dst)["status"], "up-to-date")

    def test_conflict_changes_nothing(self):
        module.sync(self.src, self.dst)
        target = self.dst / "lib/blunix/tool.py"
        target.write_text("local edit")
        (self.src / "lib/tool.py").write_text("two")
        self.commit(self.src)
        head = self.git(self.dst, "rev-parse", "HEAD")
        with self.assertRaisesRegex(module.SyncError, "conflict"):
            module.sync(self.src, self.dst)
        self.assertEqual(target.read_text(), "local edit")
        self.assertEqual(head, self.git(self.dst, "rev-parse", "HEAD"))

    def test_owned_deletion_keeps_unmanaged_sibling(self):
        module.sync(self.src, self.dst)
        (self.dst / "lib/blunix/unmanaged").write_text("mine")
        (self.src / "lib/tool.py").unlink()
        (self.src / "lib/new.py").write_text("new")
        self.commit(self.src)
        module.sync(self.src, self.dst)
        self.assertFalse((self.dst / "lib/blunix/tool.py").exists())
        self.assertEqual((self.dst / "lib/blunix/unmanaged").read_text(), "mine")

    def test_dry_run_writes_no_distribution_files(self):
        result = module.sync(self.src, self.dst, dry_run=True)
        self.assertIn("lib/blunix/tool.py", result["paths"])
        self.assertFalse((self.dst / "lib").exists())
        self.assertFalse((self.dst / module.RECEIPT).exists())

    def test_commit_failure_rolls_back(self):
        hook = self.dst / ".git/hooks/pre-commit"
        hook.write_text("#!/bin/sh\nexit 1\n")
        hook.chmod(0o755)
        with self.assertRaises(module.SyncError):
            module.sync(self.src, self.dst)
        self.assertFalse((self.dst / "lib/blunix/tool.py").exists())
        self.assertFalse((self.dst / module.RECEIPT).exists())
        self.assertEqual(self.git(self.dst, "diff", "--cached", "--name-only"), "")

    def test_dirty_source_and_staged_target_refused(self):
        (self.src / "lib/tool.py").write_text("dirty")
        with self.assertRaisesRegex(module.SyncError, "commit source"):
            module.sync(self.src, self.dst)
        self.commit(self.src)
        module.sync(self.src, self.dst)
        (self.dst / "lib/blunix/tool.py").write_text("staged")
        self.git(self.dst, "add", "lib/blunix/tool.py")
        with self.assertRaisesRegex(module.SyncError, "already staged"):
            module.sync(self.src, self.dst)

    def test_bootstrap_adopts_known_existing_changes(self):
        target = self.dst / "lib/blunix/tool.py"
        target.parent.mkdir(parents=True)
        target.write_text("baseline")
        (self.src / "dist-baseline.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "files": {"lib/blunix/tool.py": module.fingerprint(target)},
                }
            )
        )
        self.commit(self.src)
        module.sync(self.src, self.dst, bootstrap=True)
        self.assertEqual(target.read_text(), "one")

    def test_symlink_and_traversal_refused(self):
        (self.dst / "lib").symlink_to(self.src / "lib")
        with self.assertRaisesRegex(module.SyncError, "symlink"):
            module.sync(self.src, self.dst)
        for value in ("../bad", ".git/config", "/tmp/bad"):
            with self.assertRaises(module.SyncError):
                module.relative(value)


if __name__ == "__main__":
    unittest.main()

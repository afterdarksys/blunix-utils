import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from blunix import ops
from blunix.cli import main


class OpsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "etc").mkdir()
        (self.root / "etc/shadow").write_text("DO_NOT_DISCLOSE_THIS_CREDENTIAL")
        (self.root / "etc/shadow").chmod(0o666)

    def test_security_and_support_never_disclose_file_contents(self):
        result = ops.security(self.root)
        self.assertTrue(result["findings"])
        output = self.root / "report.json"
        ops.support(self.root, output)
        report = output.read_text()
        self.assertNotIn("DO_NOT_DISCLOSE", report)
        self.assertIn("excess permissions", report)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            ops.support(self.root, output)

    def test_no_following_shadow_symlinks(self):
        path = self.root / "etc/shadow"
        path.unlink()
        path.symlink_to("/etc/shadow")
        report = ops.security(self.root)
        self.assertEqual(report["findings"][0]["issue"], "symlink in protected path")

    def test_cli_and_missing_tools(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["doctor", "--root", str(self.root)]), 0)
            self.assertEqual(main(["integrity", "check", "--root", str(self.root)]), 0)
            self.assertEqual(main(["security", "audit", "--root", str(self.root)]), 1)
        with patch("blunix.ops.shutil.which", return_value=None):
            self.assertEqual(ops.disks()["status"], "unavailable")
            self.assertEqual(ops.admin()["status"], "unavailable")

    def test_failed_service_is_not_reported_healthy(self):
        with patch(
            "blunix.ops.command",
            return_value={
                "status": "ok",
                "output": "LoadState=loaded\nActiveState=failed\nResult=exit-code\n",
            },
        ):
            self.assertEqual(ops.admin()["status"], "findings")

    def test_disk_parser_uses_fixed_readonly_command(self):
        with patch(
            "blunix.ops.command",
            return_value={"status": "ok", "output": '{"blockdevices": []}'},
        ) as cmd:
            self.assertEqual(ops.disks()["devices"], [])
            self.assertEqual(cmd.call_args[0][0][0], "lsblk")
        with patch(
            "blunix.ops.command", return_value={"status": "ok", "output": "invalid"}
        ):
            self.assertEqual(ops.disks()["status"], "error")


    def test_old_lsblk_falls_back_to_mountpoint_with_the_same_shape(self):
        old = '{"blockdevices": [{"kname": "sda", "mountpoint": null, "children": [{"kname": "sda1", "mountpoint": "/"}]}]}'
        with patch(
            "blunix.ops.command",
            side_effect=[{"status": "error", "tool": "lsblk"}, {"status": "ok", "output": old}],
        ) as cmd:
            devices = ops.disks()["devices"]
        self.assertEqual(cmd.call_args_list[0][0][0][-1].split(",")[-1], "MOUNTPOINTS")
        self.assertEqual(cmd.call_args_list[1][0][0][-1].split(",")[-1], "MOUNTPOINT")
        self.assertEqual(devices[0]["mountpoints"], [None])
        self.assertEqual(devices[0]["children"][0]["mountpoints"], ["/"])
        self.assertNotIn("mountpoint", devices[0]["children"][0])
        with patch("blunix.ops.command", return_value={"status": "error", "tool": "lsblk"}):
            self.assertEqual(ops.disks()["status"], "error")

    def test_unreadable_protected_path_is_a_finding_not_a_crash(self):
        real = Path.is_symlink

        def denied(path):
            if path.name == "root":
                raise PermissionError(13, "Permission denied")
            return real(path)

        with patch.object(Path, "is_symlink", denied):
            result = ops.security(self.root)
            self.assertIn({"path": "/root/.ssh", "issue": "unreadable metadata"}, result["findings"])
            self.assertEqual(result["status"], "findings")
            out = self.root / "support.json"
            self.assertEqual(ops.support(self.root, out)["status"], "ok")

    def test_help_prints_usage_and_runs_nothing(self):
        for arg in ("--help", "-h", "help"):
            buf = io.StringIO()
            with patch("blunix.cli.run_bootstrap") as boot, contextlib.redirect_stdout(buf):
                self.assertEqual(main([arg]), 0)
            boot.assert_not_called()
            self.assertIn("usage: blunix", buf.getvalue())
            self.assertIn("security audit", buf.getvalue())

if __name__ == "__main__":
    unittest.main()

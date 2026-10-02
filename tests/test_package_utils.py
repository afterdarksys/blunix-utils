"""The standalone package must run and remain verifiable after normal use."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from blunix.gitbuild import build_source
from blunix.gitbuild_install import install, verify


class PackageTests(unittest.TestCase):
    def test_relocatable_launchers_models_and_integrity(self):
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as work:
            folder = Path(work)
            with patch("blunix.gitbuild.os.geteuid", return_value=1000):
                build_source(
                    source,
                    folder / "bundle",
                    "afterdarksys/blunix-utils",
                    "test",
                    "a" * 40,
                )
            install(folder / "bundle", folder / "root")
            env = dict(os.environ)
            env.pop("PYTHONDONTWRITEBYTECODE", None)
            for command in (
                [
                    str(folder / "root/usr/local/bin/blunix"),
                    "doctor",
                    "--root",
                    str(folder / "root"),
                ],
                [str(folder / "root/usr/local/bin/blunix-disk"), "check", "cloud-vm"],
            ):
                subprocess.run(command, env=env, check=True, stdout=subprocess.DEVNULL)
            report = verify("blunix-utils", folder / "root")
            self.assertEqual(report["changed"], [])
            self.assertEqual(report["links_changed"], [])


if __name__ == "__main__":
    unittest.main()

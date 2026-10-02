"""Opt-in offline builds using real Go, Rust, Node, Python, Bash and PHP tools.

BLUNIX_TOOLCHAIN_TESTS=1 enables these on a builder with the tools installed.
The project fixtures have no external dependencies; no network is required.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from blunix.gitbuild import build_source
from blunix.gitbuild_install import install


@unittest.skipUnless(
    os.environ.get("BLUNIX_TOOLCHAIN_TESTS") == "1", "opt-in toolchain smoke tests"
)
class ToolchainSmokeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name).resolve()
        self.source = self.work / "source"
        self.source.mkdir()
        self.env = patch.dict(
            os.environ,
            {
                "GOCACHE": str(self.work / "go-cache"),
                "GOPROXY": "off",
                "GOSUMDB": "off",
                "PIP_NO_INDEX": "1",
                "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                "npm_config_cache": str(self.work / "npm-cache"),
                "npm_config_audit": "false",
                "npm_config_fund": "false",
                "CARGO_NET_OFFLINE": "true",
            },
        )
        self.env.start()
        self.addCleanup(self.env.stop)

    def write(self, name, data):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)

    def exercise(self):
        # Unit tests may run under root in Debian CI; all commands use local,
        # test-owned fixtures. Public build CLI still refuses root.
        with patch("blunix.gitbuild.os.geteuid", return_value=1000):
            build_source(
                self.source, self.work / "bundle", "afterdarksys/demo", "test", "a" * 40
            )
        install(self.work / "bundle", self.work / "root")
        command = self.work / "root/usr/local/bin/demo"
        self.assertEqual(
            subprocess.check_output([command], text=True).strip(), "hello gitbuild"
        )

    @unittest.skipUnless(shutil.which("go"), "Go missing")
    def test_go(self):
        self.write("go.mod", "module example.test/demo\n\ngo 1.20\n")
        self.write(
            "main.go",
            'package main\nimport "fmt"\nfunc main() { fmt.Println("hello gitbuild") }\n',
        )
        self.exercise()

    @unittest.skipUnless(shutil.which("cargo"), "Cargo missing")
    def test_rust(self):
        self.write(
            "Cargo.toml",
            '[package]\nname = "demo"\nversion = "0.1.0"\nedition = "2021"\n',
        )
        self.write("src/main.rs", 'fn main() { println!("hello gitbuild"); }\n')
        subprocess.run(
            ["cargo", "generate-lockfile", "--offline"], cwd=self.source, check=True
        )
        self.exercise()

    @unittest.skipUnless(
        shutil.which("npm") and shutil.which("node"), "Node/npm missing"
    )
    def test_node(self):
        pkg = {"name": "demo", "version": "1.0.0", "bin": {"demo": "cli.js"}}
        self.write("package.json", json.dumps(pkg))
        self.write(
            "package-lock.json",
            json.dumps(
                {
                    "name": "demo",
                    "version": "1.0.0",
                    "lockfileVersion": 3,
                    "requires": True,
                    "packages": {"": pkg},
                }
            ),
        )
        self.write("cli.js", '#!/usr/bin/env node\nconsole.log("hello gitbuild");\n')
        self.exercise()

    def test_python(self):
        check = subprocess.run(
            ["python3", "-m", "pip", "--version"], capture_output=True, check=False
        )
        if check.returncode:
            self.skipTest("Python pip missing")
        # Minimal PEP 517 backend creates a real wheel without downloading build dependencies.
        self.write(
            "pyproject.toml",
            '[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = ["."]\n',
        )
        self.write(
            "backend.py",
            """import os, zipfile

def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    name = "demo-1.0-py3-none-any.whl"
    files = {
        "demo.py": 'def main():\\n    print("hello gitbuild")\\n',
        "demo-1.0.dist-info/METADATA": "Metadata-Version: 2.1\\nName: demo\\nVersion: 1.0\\n",
        "demo-1.0.dist-info/WHEEL": "Wheel-Version: 1.0\\nGenerator: test\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n",
        "demo-1.0.dist-info/entry_points.txt": "[console_scripts]\\ndemo = demo:main\\n",
    }
    files["demo-1.0.dist-info/RECORD"] = "".join(path + ",,\\n" for path in files) + "demo-1.0.dist-info/RECORD,,\\n"
    with zipfile.ZipFile(os.path.join(wheel_directory, name), "w") as wheel:
        for path, content in files.items():
            wheel.writestr(path, content)
    return name
""",
        )
        self.exercise()

    @unittest.skipUnless(shutil.which("bash"), "Bash missing")
    def test_bash(self):
        self.write("demo.sh", '#!/usr/bin/env bash\nprintf "%s\\n" "hello gitbuild"\n')
        self.write(
            "gitbuild.yaml",
            json.dumps(
                {
                    "version": 1,
                    "system": "bash",
                    "files": [{"source": "demo.sh", "dest": "bin/demo"}],
                }
            ),
        )
        self.exercise()

    @unittest.skipUnless(shutil.which("php"), "PHP missing")
    def test_php(self):
        self.write("demo.php", '#!/usr/bin/env php\n<?php echo "hello gitbuild\\n";\n')
        self.write(
            "gitbuild.yaml",
            json.dumps(
                {
                    "version": 1,
                    "system": "php",
                    "files": [{"source": "demo.php", "dest": "bin/demo"}],
                }
            ),
        )
        self.exercise()


if __name__ == "__main__":
    unittest.main()

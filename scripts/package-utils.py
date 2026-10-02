#!/usr/bin/env python3
"""Stage standalone runtime tools for Gitbuild; image builders remain source tools."""

import os
import shutil
from pathlib import Path

source = Path(__file__).resolve().parents[1]
stage = Path(os.environ["GITBUILD_STAGE"])
shutil.copytree(
    source / "lib/blunix",
    stage / "lib/python/blunix",
    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
)
shutil.copytree(source / "models", stage / "lib/models")
shutil.copytree(source / "image/gui", stage / "lib/image/gui")
for launcher in (source / "apply").iterdir():
    if not launcher.is_file():
        continue
    name = launcher.name
    module = "blunix.gitbuild" if name == "gitbuild" else "blunix.cli"
    prefix = [name.removeprefix("blunix-")] if name.startswith("blunix-") else []
    body = f"""#!/usr/bin/env python3
import os, sys
sys.dont_write_bytecode = True
from pathlib import Path
base = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(base / "lib/python"))
os.environ.setdefault("BLUNIX_MODELS", str(base / "lib/models"))
from {module} import main
raise SystemExit(main({prefix!r} + sys.argv[1:]))
"""
    dest = stage / "bin" / name
    dest.write_text(body)
    dest.chmod(0o755)

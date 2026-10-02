"""Subprocess helper. Commands are argument lists. The shell is never used."""

import subprocess

from blunix.errors import BlunixError


def run_cmd(argv, **kwargs):
    if not isinstance(argv, (list, tuple)) or not argv:
        raise BlunixError("refused command")
    if any(not isinstance(arg, str) for arg in argv):
        raise BlunixError("refused command")
    if kwargs.get("shell"):
        raise BlunixError("refused command")
    kwargs["shell"] = False
    return subprocess.run(argv, **kwargs)

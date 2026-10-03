"""Command entry. Renders a model or applies one document, then exits.

There is no --passphrase flag. The passphrase is read from the console or,
on the test image, from guestinfo inside bootstrap.
"""

from __future__ import annotations

import sys

from blunix.access import apply_access, boot_access, load_access
from blunix.ai import install_ai, parse_ai
from blunix.bootstrap import run_bootstrap
from blunix.console import console_line
from blunix.disk import load_disk, write_disk
from blunix.errors import BlunixError, DecryptError
from blunix.gui import apply_gui
from blunix.network import load_network, write_network
from blunix.node import apply_node, boot_node
from blunix.schema import load_path, models_dir
from blunix.tools import install_tools, load_tools

_FLAGS = {"--root", "--dest", "--models", "--file"}


def _safe_log(message):
    if not isinstance(message, str) or not message:
        message = "bootstrap failed closed"
    line = message if message.startswith("blunix") else "blunix: " + message
    try:
        console_line(line)
    except BlunixError:
        console_line("blunix: bootstrap failed closed")


def _parse(argv):
    positional = []
    opts = {}
    index = 0
    while index < len(argv):
        item = argv[index]
        if item.startswith("-"):
            if item not in _FLAGS:
                raise BlunixError("refused command")
            if index + 1 >= len(argv) or argv[index + 1].startswith("-"):
                raise BlunixError("refused command")
            opts[item[2:]] = argv[index + 1]
            index += 2
            continue
        positional.append(item)
        index += 1
    return positional, opts


def _disk(rest, opts):
    if len(rest) != 2 or rest[0] not in ("check", "render"):
        raise BlunixError("refused command")
    model = load_disk(models_dir(opts.get("models")), rest[1])
    if rest[0] == "check":
        print("blunix: disk " + model["name"], flush=True)
        return 0
    dest = opts.get("dest")
    if not dest:
        raise BlunixError("refused command")
    write_disk(model, dest)
    print("blunix: disk layout recorded; systemd-repart was not executed", flush=True)
    return 0


def _net(rest, opts):
    if len(rest) != 2 or rest[0] != "render":
        raise BlunixError("refused command")
    dest = opts.get("dest")
    if not dest:
        raise BlunixError("refused command")
    model = load_network(models_dir(opts.get("models")), rest[1])
    write_network(model, dest)
    return 0


def _access(rest, opts):
    if not rest or rest[0] not in ("boot", "render"):
        raise BlunixError("refused command")
    root = opts.get("root", "/")
    if rest[0] == "boot":
        if len(rest) != 1:
            raise BlunixError("refused command")
        try:
            boot_access(root, log=console_line)
        except BlunixError as exc:
            _safe_log(str(exc))
        return 0
    if len(rest) != 2:
        raise BlunixError("refused command")
    model = load_access(models_dir(opts.get("models")), rest[1])
    apply_access(model, root, log=console_line)
    return 0


def _ai(rest, opts):
    if rest != ["apply"]:
        raise BlunixError("refused command")
    path = opts.get("file")
    if not path:
        raise BlunixError("refused command")
    model = parse_ai(load_path(path))
    install_ai(model, opts.get("root", "/"))
    if model["enabled"]:
        print("blunix: ai linked", flush=True)
    else:
        print("blunix: ai disabled", flush=True)
    return 0


def _gui(rest, opts):
    if rest != ["apply"]:
        raise BlunixError("refused command")
    root = opts.get("root", "/")
    if apply_gui(root):
        print("blunix: blue theme selected", flush=True)
    else:
        print("blunix: graphical session absent; blue theme not selected", flush=True)
    return 0


def _tools(rest, opts):
    if not rest or rest[0] != "apply":
        raise BlunixError("refused command")
    names = rest[1:]
    model = load_tools(models_dir(opts.get("models")), "default")
    linked = install_tools(model, opts.get("root", "/"), names or None)
    if linked:
        print("blunix: tools linked " + " ".join(linked), flush=True)
    else:
        print("blunix: tools idle", flush=True)
    if not names:
        for tool in model["tools"]:
            if not tool["default"] and "digest" not in tool:
                print(
                    "blunix: tool " + tool["name"] + " waiting on a digest",
                    flush=True,
                )
    return 0


def _node(rest, opts):
    if not rest or rest[0] not in ("apply", "boot") or len(rest) != 1:
        raise BlunixError("refused command")
    root = opts.get("root", "/")
    if rest[0] == "boot":
        return boot_node(root, models=opts.get("models"), log=console_line)
    path = opts.get("file")
    if not path:
        raise BlunixError("refused command")
    apply_node(load_path(path), root, models=opts.get("models"), log=console_line)
    return 0


def _proxy(rest):
    try:
        import blunix.proxy as proxy
    except ImportError:
        print("blunix: proxy not installed", flush=True)
        return 2
    return proxy.main(rest)


def _install(rest, opts):
    if rest:
        raise BlunixError("refused command")
    from blunix.installer import run_install

    return run_install(models=opts.get("models"))


USAGE = """usage: blunix COMMAND
  doctor [--root ROOT]                executables available and filesystem capacity
  security audit [--root ROOT]        protected-path ownership and permission checks
  integrity check [PRODUCT] [--root ROOT]
                                      Gitbuild file and link drift
  admin status                        selected systemd service states
  disk inspect                        read-only block device and mount metadata
  support collect --output FILE [--root ROOT]
                                      mode-0600 JSON report, no secrets, logs or addresses
  proxy help                          build-proxy for static-address and netboot LANs
  gitbuild --help                     source builds and installed product checks
  disk check|render, net render, access boot|render, ai apply, gui apply,
  tools apply, node apply|boot        image and installer steps (see blunix.io/tools)
With no command, blunix runs the installer bootstrap."""


def _dispatch(argv):
    if any(arg == "--passphrase" or arg.startswith("--passphrase=") for arg in argv):
        raise BlunixError("refused command")
    # Help is a fixed text: it reads nothing and runs nothing. Bare `blunix` stays
    # the installer bootstrap, which the image depends on.
    if argv and argv[0] in ("help", "-h", "--help"):
        print(USAGE, flush=True)
        return 0
    if argv and argv[0] == "proxy":
        return _proxy(argv[1:])
    if argv and argv[0] == "gitbuild":
        from blunix.gitbuild import main as gitbuild_main

        return gitbuild_main(argv[1:])
    if argv and (argv[0] in {"doctor", "security", "integrity", "admin", "support"}
                 or argv[:2] == ["disk", "inspect"]):
        from blunix.ops import main as ops_main

        return ops_main(argv)
    positional, opts = _parse(argv)
    if not positional or positional[0] == "bootstrap":
        if positional and positional[0] == "bootstrap" and len(positional) != 1:
            raise BlunixError("refused command")
        if positional and positional[0] != "bootstrap":
            raise BlunixError("refused command")
        return run_bootstrap(
            root=opts.get("root", "/"),
            models=opts.get("models"),
            log=console_line,
        )
    group = positional[0]
    rest = positional[1:]
    if group == "disk":
        return _disk(rest, opts)
    if group == "net":
        return _net(rest, opts)
    if group == "access":
        return _access(rest, opts)
    if group == "ai":
        return _ai(rest, opts)
    if group == "gui":
        return _gui(rest, opts)
    if group == "tools":
        return _tools(rest, opts)
    if group == "node":
        return _node(rest, opts)
    if group == "install":
        return _install(rest, opts)
    raise BlunixError("refused command")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    try:
        code = _dispatch(list(argv))
    except DecryptError:
        console_line("could not decrypt")
        return 1
    except BlunixError as exc:
        _safe_log(str(exc))
        return 1
    if code is None:
        return 0
    return int(code)

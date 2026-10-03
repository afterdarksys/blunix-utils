"""Git source preparation and CLI. Builds execute trusted repository code as a
normal user. Installation consumes a checked bundle and runs no build hooks.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from blunix.errors import BlunixError
from blunix.gitbuild_install import (
    install,
    installed,
    inventory,
    product_name,
    remove,
    verify,
)
from blunix.schema import load_path

OWNERS = {"straticus1", "afterdarksys"}
SYSTEMS = {"go", "rust", "python", "node", "bash", "php", "custom"}


def repository(value):
    """Accept owner/repo or a canonical HTTPS GitHub URL, never arbitrary URLs."""
    if not isinstance(value, str):
        raise BlunixError("gitbuild: invalid repository")
    value = value.removeprefix("https://github.com/").removesuffix(".git")
    parts = value.split("/")
    if (
        len(parts) != 2
        or parts[0] not in OWNERS
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", parts[1])
        or ".." in parts[1]
    ):
        raise BlunixError(
            "gitbuild: repository must belong to straticus1 or afterdarksys"
        )
    return "/".join(parts)


def relative(value):
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or any(p in ("", ".", "..") for p in value.split("/"))
        or "\\" in value
        or any(ord(c) < 32 for c in value)
    ):
        raise BlunixError("gitbuild: invalid relative path")
    return value


def run(args, cwd, env=None):
    try:
        result = subprocess.run(
            args, cwd=cwd, env=env, check=True, stdin=subprocess.DEVNULL, timeout=3600
        )
        return result
    except FileNotFoundError:
        raise BlunixError("gitbuild: missing executable " + args[0]) from None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise BlunixError("gitbuild: command failed: " + args[0]) from None


def checkout(repo, ref, dest):
    repo = repository(repo)
    if (
        not isinstance(ref, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,199}", ref)
        or ".." in ref
        or "//" in ref
    ):
        raise BlunixError("gitbuild: invalid ref")
    # No implicit submodule execution, credential prompts, or cross-host redirects.
    # Inherited GIT_DIR/WORK_TREE/INDEX_FILE must never redirect this checkout
    # into the operator's existing repository.
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    env.update(
        GIT_TERMINAL_PROMPT="0",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_COUNT="0",
    )
    git = [
        "git",
        "-c",
        "http.followRedirects=false",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "core.hooksPath=/dev/null",
    ]
    dest.mkdir()
    run(git + ["init", "--quiet"], dest, env)
    run(
        git + ["fetch", "--depth=1", "https://github.com/" + repo + ".git", ref],
        dest,
        env,
    )
    run(git + ["checkout", "--detach", "FETCH_HEAD"], dest, env)
    return subprocess.check_output(
        git + ["rev-parse", "HEAD"], cwd=dest, env=env, text=True
    ).strip()


def recipe(source, name, manifest=None):
    path = Path(manifest) if manifest else source / "gitbuild.yaml"
    doc = load_path(str(path)) if path.exists() else {}
    if manifest and not path.is_file():
        raise BlunixError("gitbuild: manifest missing")
    allowed = {"version", "product", "system", "commands", "files", "target"}
    if set(doc) - allowed or (doc and doc.get("version") != 1):
        raise BlunixError("gitbuild: unsupported manifest fields or version")
    product = product_name(doc.get("product", name.lower().replace("_", "-")))
    system = doc.get("system")
    if system is None:
        markers = {
            "go": ["go.mod"],
            "rust": ["Cargo.toml"],
            "python": ["pyproject.toml", "setup.py"],
            "node": ["package.json"],
            "php": ["composer.json"],
        }
        detected = [
            key
            for key, paths in markers.items()
            if any((source / p).is_file() for p in paths)
        ]
        if len(detected) != 1:
            raise BlunixError(
                "gitbuild: ambiguous build; add gitbuild.yaml with system and files"
            )
        system = detected[0]
    if not isinstance(system, str) or system not in SYSTEMS:
        raise BlunixError("gitbuild: unsupported build system")
    commands = doc.get("commands", [])
    if not isinstance(commands, list) or any(
        not isinstance(cmd, list)
        or not cmd
        or any(not isinstance(arg, str) or not arg or "\x00" in arg for arg in cmd)
        for cmd in commands
    ):
        raise BlunixError("gitbuild: commands must be argument arrays")
    files = doc.get("files", [])
    if not isinstance(files, list):
        raise BlunixError("gitbuild: files must be a list")
    for item in files:
        if not isinstance(item, dict) or set(item) != {"source", "dest"}:
            raise BlunixError("gitbuild: files need source and dest")
        relative(item["source"])
        relative(item["dest"])
        if item["dest"].split("/")[0] not in {"bin", "sbin", "lib", "etc"}:
            raise BlunixError("gitbuild: destination must be in bin, sbin, lib or etc")
    target = doc.get("target", ".")
    if not isinstance(target, str) or (target != "." and relative(target) != target):
        raise BlunixError("gitbuild: invalid target")
    if system in {"bash", "php"} and not files:
        raise BlunixError("gitbuild: bash and php recipes require explicit files")
    if system == "custom" and not commands:
        raise BlunixError("gitbuild: custom recipes require commands")
    return {
        "product": product,
        "system": system,
        "commands": commands,
        "files": files,
        "target": target,
    }


def copy_artifact(source, dest, source_root):
    if not source.resolve().is_relative_to(source_root.resolve()):
        raise BlunixError("gitbuild: artifact escapes checkout")
    if dest.exists() or dest.is_symlink():
        raise BlunixError("gitbuild: duplicate artifact " + str(dest))
    dest.parent.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        shutil.copytree(source, dest, symlinks=True)
    elif source.is_file():
        shutil.copyfile(source, dest)
        dest.chmod(source.stat().st_mode & 0o777)
    else:
        raise BlunixError("gitbuild: artifact missing " + str(source))


def python_scripts(payload):
    target = payload / "lib/python"
    for dist in importlib.metadata.distributions(path=[str(target)]):
        for entry in dist.entry_points:
            if entry.group != "console_scripts":
                continue
            name = product_name(entry.name)
            module, sep, attr = entry.value.partition(":")
            attr = attr.split("[")[0].strip()
            if (
                not sep
                or not re.fullmatch(r"[A-Za-z_][\w.]*", module)
                or not re.fullmatch(r"[A-Za-z_][\w.]*", attr)
            ):
                raise BlunixError("gitbuild: unsupported Python entry point")
            script = payload / "bin" / name
            if script.exists():
                raise BlunixError("gitbuild: duplicate Python entry point")
            script.write_text(
                "#!/usr/bin/env python3\nimport sys, pathlib, importlib\n"
                "sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'lib/python'))\n"
                f"entry = importlib.import_module({module!r})\n"
                f"for part in {attr!r}.split('.'):\n    entry = getattr(entry, part)\n"
                "sys.exit(entry())\n"
            )
            script.chmod(0o755)
    # pip-generated scripts contain build-machine interpreter paths.
    shutil.rmtree(target / "bin", ignore_errors=True)


def build_source(source, output, repo, ref, commit, manifest=None):
    """Build an already checked-out source tree; used after checkout and in tests."""
    if os.geteuid() == 0:
        raise BlunixError("gitbuild: run source builds as a non-root user")
    repo = repository(repo)
    source, output = Path(source).resolve(), Path(output).absolute()
    if output.resolve().is_relative_to(source):
        raise BlunixError("gitbuild: output must be outside the source tree")
    if output.exists() or output.is_symlink():
        raise BlunixError("gitbuild: output already exists")
    spec = recipe(source, repo.split("/")[1], manifest)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".gitbuild-", dir=output.parent) as work:
        bundle = Path(work) / "bundle"
        payload = bundle / "payload"
        for area in ("bin", "sbin", "lib", "etc"):
            (payload / area).mkdir(parents=True)
        env = dict(
            os.environ,
            PREFIX="/usr/local/afterdarksys/" + spec["product"],
            DESTDIR=str(bundle / "destdir"),
            GITBUILD_STAGE=str(payload),
            GITBUILD_SOURCE=str(source),
        )
        system = spec["system"]
        if spec["commands"]:
            # Environment variables are available to scripts; arguments are never eval'd.
            for command in spec["commands"]:
                run(command, source, env)
        elif system == "go":
            run(
                [
                    "go",
                    "build",
                    "-trimpath",
                    "-o",
                    str(payload / "bin" / spec["product"]),
                    "./" + spec["target"],
                ],
                source,
                env,
            )
        elif system == "rust":
            run(["cargo", "build", "--release", "--locked"], source, env)
            if not spec["files"]:
                copy_artifact(
                    source / "target/release" / spec["product"],
                    payload / "bin" / spec["product"],
                    source,
                )
        elif system == "python":
            run(
                [
                    "python3",
                    "-m",
                    "pip",
                    "install",
                    "--no-compile",
                    "--target",
                    str(payload / "lib/python"),
                    ".",
                ],
                source,
                env,
            )
            python_scripts(payload)
        elif system == "node":
            run(["npm", "ci"], source, env)
            run(["npm", "run", "build", "--if-present"], source, env)
            run(["npm", "prune", "--omit=dev"], source, env)
            app = payload / "lib/node"
            shutil.copytree(
                source,
                app,
                symlinks=True,
                ignore=shutil.ignore_patterns(".git", "gitbuild.yaml"),
            )
            pkg = json.loads((app / "package.json").read_text())
            bins = pkg.get("bin", {})
            if isinstance(bins, str):
                bins = {spec["product"]: bins}
            if not isinstance(bins, dict):
                raise BlunixError("gitbuild: invalid package.json bin")
            for name, path in bins.items():
                name = product_name(name)
                path = relative(
                    path.removeprefix("./") if isinstance(path, str) else path
                )
                entry = app / path
                if not entry.is_file() or not entry.resolve().is_relative_to(
                    app.resolve()
                ):
                    raise BlunixError("gitbuild: missing or escaping Node entry point")
                entry.chmod(0o755)
                (payload / "bin" / name).symlink_to("../lib/node/" + path)
        elif system == "php" and (source / "composer.json").exists():
            run(
                [
                    "composer",
                    "install",
                    "--no-dev",
                    "--prefer-dist",
                    "--no-interaction",
                ],
                source,
                env,
            )
        for item in spec["files"]:
            dest = payload / item["dest"]
            copy_artifact(source / item["source"], dest, source)
            if item["dest"].split("/")[0] in {"bin", "sbin"} and dest.is_file():
                dest.chmod(0o755)
        # Support conventional DESTDIR/PREFIX installs from custom commands.
        staged_prefix = Path(env["DESTDIR"]) / env["PREFIX"].lstrip("/")
        if staged_prefix.exists():
            for area in staged_prefix.iterdir():
                if area.name not in {"bin", "sbin", "lib", "etc"} or not area.is_dir():
                    raise BlunixError("gitbuild: unsupported staged install directory")
                for child in area.iterdir():
                    copy_artifact(
                        child, payload / area.name / child.name, staged_prefix
                    )
        entries = inventory(payload)
        if not any(item["kind"] == "file" for item in entries.values()):
            raise BlunixError("gitbuild: build produced no files")
        import platform

        metadata = {
            "version": 1,
            "product": spec["product"],
            "repository": repo,
            "ref": ref,
            "commit": commit,
            "system": system,
            "platform": platform.system(),
            "machine": platform.machine(),
            "files": entries,
        }
        (bundle / "bundle.json").write_text(json.dumps(metadata, indent=2) + "\n")
        os.rename(bundle, output)
    return metadata


def prepare(repo, ref, output, manifest=None):
    if os.geteuid() == 0:
        raise BlunixError("gitbuild: run source builds as a non-root user")
    repo = repository(repo)
    with tempfile.TemporaryDirectory(prefix="gitbuild-source-") as work:
        source = Path(work) / "source"
        commit = checkout(repo, ref, source)
        return build_source(source, output, repo, ref, commit, manifest)


def doctor(system=None):
    requirements = {
        "go": ["go"],
        "rust": ["cargo", "rustc"],
        "python": ["python3"],
        "node": ["node", "npm"],
        "bash": ["bash"],
        "php": ["php", "composer"],
        "custom": [],
    }
    names = {"git", "python3"}
    for selected in [system] if system else requirements:
        names.update(requirements[selected])
    found = {name: shutil.which(name) for name in sorted(names)}
    missing = [name for name, path in found.items() if path is None]
    if system in (None, "python") and found["python3"]:
        check = subprocess.run(
            [found["python3"], "-m", "pip", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        if check.returncode:
            missing.append("python3 -m pip")
    return {
        "tools": found,
        "missing": missing,
        "note": "Checks executable availability; recipes may need additional headers and tools.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="gitbuild", description="Build and manage After Dark source packages"
    )
    sub = parser.add_subparsers(dest="action", required=True)
    build = sub.add_parser(
        "prepare",
        aliases=["build"],
        help="check out a GitHub ref and create an install bundle",
    )
    build.add_argument("repository")
    build.add_argument(
        "--ref", required=True, help="tag, branch or commit (resolved commit recorded)"
    )
    build.add_argument("--output", required=True)
    build.add_argument(
        "--manifest",
        help="local recipe override for repositories without gitbuild.yaml",
    )
    add = sub.add_parser("install", help="install a prepared bundle and record its file baseline")
    add.add_argument("bundle")
    rm = sub.add_parser("remove", help="remove an installed product")
    rm.add_argument("product")
    rm.add_argument("--purge", action="store_true", help="also delete configuration")
    ls = sub.add_parser("list", help="list installed products")
    check = sub.add_parser("verify", help="compare an installed product with its baseline")
    check.add_argument("product")
    doctor_parser = sub.add_parser("doctor", help="report available build tools")
    doctor_parser.add_argument("--system", choices=sorted(SYSTEMS))
    for command in (add, rm, ls, check):
        command.add_argument("--root", default="/", help="target filesystem root")
    args = parser.parse_args(argv)
    try:
        if args.action in {"prepare", "build"}:
            result = prepare(args.repository, args.ref, args.output, args.manifest)
        elif args.action == "install":
            result = install(args.bundle, args.root)
        elif args.action == "remove":
            result = remove(args.product, args.root, args.purge)
        elif args.action == "list":
            result = installed(args.root)
        elif args.action == "doctor":
            result = doctor(args.system)
            print(json.dumps(result, indent=2))
            return int(bool(result["missing"]))
        else:
            result = verify(args.product, args.root)
            print(json.dumps(result, indent=2))
            return int(bool(result["changed"] or result["links_changed"]))
        print(json.dumps(result, indent=2))
        return 0
    except (BlunixError, OSError, ValueError) as exc:
        print("gitbuild: " + str(exc).removeprefix("gitbuild: "), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Filesystem-only gitbuild package manager. No install hooks or source execution.

A global flock serializes cooperating installers. Exceptions roll back package
and link changes; this is not a power-loss journal or a sandbox for hostile users
who can concurrently write the target root. Install only trusted build bundles.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path

from blunix.errors import BlunixError

AREAS = {"bin", "sbin", "lib", "etc"}
RECEIPT = ".gitbuild.json"


def product_name(value):
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", value)
        or ".." in value
    ):
        raise BlunixError("gitbuild: invalid product or command name")
    return value


def inventory(root, receipt=False):
    """Hash regular files; reject special files, unsafe modes and escaping links."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise BlunixError("gitbuild: payload must be a real directory")
    result = {}
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(parent) / name
            rel = path.relative_to(root).as_posix()
            if receipt and rel == RECEIPT:
                continue
            parts = rel.split("/")
            if parts[0] not in AREAS or any(ord(c) < 32 for c in rel) or "\\" in rel:
                raise BlunixError("gitbuild: unsupported payload path " + rel)
            info = path.lstat()
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                try:
                    safe = (
                        path.resolve().is_relative_to(root.resolve()) and path.exists()
                    )
                except (OSError, RuntimeError):
                    safe = False
                if os.path.isabs(target) or not safe or parts[0] == "etc":
                    raise BlunixError("gitbuild: unsafe symlink " + rel)
                item = {"kind": "link", "target": target}
            elif stat.S_ISDIR(info.st_mode):
                if mode & 0o7000:
                    raise BlunixError("gitbuild: special directory permissions")
                item = {"kind": "dir", "mode": mode}
            elif stat.S_ISREG(info.st_mode):
                if mode & 0o7000:
                    raise BlunixError("gitbuild: special file permissions")
                digest = hashlib.sha256()
                with path.open("rb") as handle:
                    for block in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(block)
                item = {"kind": "file", "sha256": digest.hexdigest(), "mode": mode}
            else:
                raise BlunixError("gitbuild: special file " + rel)
            if len(parts) == 1 and item["kind"] != "dir":
                raise BlunixError("gitbuild: payload areas must be directories")
            if parts[0] in {"bin", "sbin"} and len(parts) > 1:
                if len(parts) != 2 or not path.is_file():
                    raise BlunixError("gitbuild: bin and sbin contain commands only")
                product_name(parts[1])
                if not path.stat().st_mode & 0o111:
                    raise BlunixError("gitbuild: command is not executable " + rel)
            result[rel] = item
    return dict(sorted(result.items()))


def read_json(path):
    path = Path(path)
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > 32 * 1024 * 1024
    ):
        raise BlunixError("gitbuild: missing or invalid metadata")
    doc = json.loads(path.read_text())
    if not isinstance(doc, dict) or doc.get("version") != 1:
        raise BlunixError("gitbuild: unsupported metadata")
    product_name(doc.get("product"))
    if not isinstance(doc.get("files"), dict):
        raise BlunixError("gitbuild: invalid file inventory")
    return doc


def links_for(doc):
    product = product_name(doc["product"])
    result = {}
    for name in doc["files"]:
        parts = name.split("/")
        if parts[0] in {"bin", "sbin"} and len(parts) == 2:
            product_name(parts[1])
            result[name] = "../afterdarksys/" + product + "/" + name
    for area in ("lib", "etc"):
        if any(name.startswith(area + "/") for name in doc["files"]):
            result[area + "/" + product] = "../afterdarksys/" + product + "/" + area
    return result


def safe_directory(path, create=False):
    """Refuse symlink ancestors, including dangling links, before any writes."""
    path = Path(path).absolute()
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor /= part
        if cursor.is_symlink():
            raise BlunixError("gitbuild: symlink in target directory " + str(cursor))
        if cursor.exists():
            if not cursor.is_dir():
                raise BlunixError("gitbuild: target is not a directory")
        elif create:
            cursor.mkdir(mode=0o755)
    return path


def local_root(root, create=False):
    # Resolve the explicitly selected root (e.g. macOS /tmp); descendants must be real.
    root = Path(root).resolve()
    return safe_directory(root / "usr/local", create)


@contextmanager
def locked(local):
    base = safe_directory(local / "afterdarksys", True)
    fd = os.open(base / ".gitbuild.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise BlunixError("gitbuild: invalid lock file")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield base
    finally:
        os.close(fd)


def previous(final, product):
    if final.is_symlink():
        raise BlunixError("gitbuild: product directory is a symlink")
    if not final.exists():
        return None
    old = read_json(final / RECEIPT)
    if old["product"] != product:
        raise BlunixError("gitbuild: product ownership mismatch")
    return old


@contextmanager
def transaction(base):
    work = Path(tempfile.mkdtemp(prefix=".transaction-", dir=base))
    try:
        yield work
    except BaseException as exc:
        if (work / "previous").exists():
            # Never delete the surviving package if rollback itself failed.
            raise BlunixError(
                "gitbuild: rollback incomplete; recovery files retained at " + str(work)
            ) from exc
        shutil.rmtree(work, ignore_errors=True)
        raise
    else:
        shutil.rmtree(work)


def check_links(local, old_links, new_links):
    for name in old_links.keys() | new_links.keys():
        path = local / name
        safe_directory(path.parent)
        if os.path.lexists(path) and (
            name not in old_links
            or not path.is_symlink()
            or os.readlink(path) != old_links[name]
        ):
            raise BlunixError("gitbuild: refusing link collision " + str(path))


def publish(local, final, stage, old, new, work):
    """Publish a prepared tree with exception rollback of both tree and exports."""
    old_links = links_for(old) if old else {}
    new_links = links_for(new) if new else {}
    check_links(local, old_links, new_links)
    snapshot = {
        name: os.readlink(local / name) if (local / name).is_symlink() else None
        for name in old_links.keys() | new_links.keys()
    }
    backup = work / "previous"
    moved_old = moved_new = False
    touched = []
    try:
        if old:
            os.rename(final, backup)
            moved_old = True
        if stage is not None:
            os.rename(stage, final)
            moved_new = True
        for name in sorted(snapshot):
            path = local / name
            safe_directory(path.parent, True)
            touched.append(name)
            if os.path.lexists(path):
                path.unlink()
            if name in new_links:
                path.symlink_to(new_links[name])
    except BaseException:
        for name in reversed(touched):
            path = local / name
            if path.is_symlink():
                path.unlink()
            if snapshot[name] is not None:
                path.symlink_to(snapshot[name])
        if moved_new:
            shutil.rmtree(final)
        if moved_old:
            os.rename(backup, final)
        raise


def preserve_config(final, stage, old):
    if not (final / "etc").exists():
        return []
    current = inventory(final, receipt=True)
    preserved = []
    for name, item in current.items():
        if not name.startswith("etc/") or item["kind"] != "file":
            continue
        baseline = old.get("defaults", old["files"]).get(name)
        if item == baseline and old.get("status") != "config-only":
            continue
        dest = stage / name
        # Reject a file/directory change rather than silently discarding either side.
        safe_directory(dest.parent, True)
        if dest.exists():
            if not dest.is_file() or dest.is_symlink():
                raise BlunixError("gitbuild: configuration type changed " + name)
            if dest.read_bytes() != (final / name).read_bytes():
                candidate = dest.with_name(dest.name + ".gitbuild-new")
                if (
                    candidate.exists()
                    or candidate.is_symlink()
                    or candidate.relative_to(stage).as_posix() in current
                ):
                    raise BlunixError(
                        "gitbuild: configuration candidate already exists " + name
                    )
                dest.rename(candidate)
        shutil.copy2(final / name, dest)
        preserved.append(name)
    return preserved


def install(bundle, root="/"):
    bundle = Path(bundle).resolve()
    doc = read_json(bundle / "bundle.json")
    required = {
        "version",
        "product",
        "repository",
        "ref",
        "commit",
        "system",
        "platform",
        "machine",
        "files",
    }
    if set(doc) != required:
        raise BlunixError("gitbuild: invalid bundle metadata fields")
    from blunix.gitbuild import repository

    repository(doc.get("repository"))
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", str(doc.get("commit", ""))):
        raise BlunixError("gitbuild: invalid source commit")
    if (
        doc.get("platform") != platform.system()
        or doc.get("machine") != platform.machine()
    ):
        raise BlunixError("gitbuild: bundle platform does not match this installer")
    if inventory(bundle / "payload") != doc["files"]:
        raise BlunixError("gitbuild: bundle inventory mismatch")
    # Derived rather than accepted from bundle metadata.
    doc = {
        key: doc[key]
        for key in (
            "version",
            "product",
            "repository",
            "ref",
            "commit",
            "system",
            "platform",
            "machine",
            "files",
        )
    }
    local = local_root(root, True)
    with locked(local) as base, transaction(base) as work:
        final = base / doc["product"]
        old = previous(final, doc["product"])
        check_links(local, links_for(old) if old else {}, links_for(doc))
        stage = work / "next"
        shutil.copytree(bundle / "payload", stage, symlinks=True)
        # Recheck the copy, not merely the source bundle.
        if inventory(stage) != doc["files"]:
            raise BlunixError("gitbuild: staged inventory mismatch")
        preserved = preserve_config(final, stage, old) if old else []
        actual = inventory(stage)
        # Retained user configuration also owns its exported configuration directory.
        record = dict(
            doc,
            status="installed",
            config_preserved=preserved,
            defaults={
                name: item
                for name, item in doc["files"].items()
                if name.startswith("etc/")
            },
        )
        record["files"] = actual
        (stage / RECEIPT).write_text(json.dumps(record, indent=2) + "\n")
        (stage / RECEIPT).chmod(0o644)
        publish(local, final, stage, old, record, work)
    return {
        "product": doc["product"],
        "commit": doc["commit"],
        "status": "installed",
        "config_preserved": preserved,
    }


def remove(product, root="/", purge=False):
    product = product_name(product)
    local = local_root(root)
    if not (local / "afterdarksys").exists():
        raise BlunixError("gitbuild: product is not installed")
    with locked(local) as base, transaction(base) as work:
        final = base / product
        old = previous(final, product)
        if old is None:
            raise BlunixError("gitbuild: product is not installed")
        inventory(final, receipt=True)
        stage = new = None
        if not purge and (final / "etc").exists() and any((final / "etc").iterdir()):
            stage = work / "next"
            stage.mkdir()
            shutil.copytree(final / "etc", stage / "etc", symlinks=True)
            new = dict(old, status="config-only", files=inventory(stage))
            (stage / RECEIPT).write_text(json.dumps(new, indent=2) + "\n")
        publish(local, final, stage, old, new, work)
    return {"product": product, "status": "config-only" if new else "removed"}


def installed(root="/"):
    local = local_root(root)
    base = safe_directory(local / "afterdarksys")
    if not base.exists():
        return []
    result = []
    for path in sorted(base.iterdir()):
        if not path.name.startswith(".") and (path / RECEIPT).exists():
            doc = previous(path, path.name)
            result.append(
                {key: doc[key] for key in ("product", "repository", "commit", "status")}
            )
    return result


def verify(product, root="/"):
    product = product_name(product)
    local = local_root(root)
    final = safe_directory(local / "afterdarksys") / product
    doc = previous(final, product)
    if doc is None:
        raise BlunixError("gitbuild: product is not installed")
    actual = inventory(final, receipt=True)
    changed = [
        name
        for name in sorted(actual.keys() | doc["files"].keys())
        if actual.get(name) != doc["files"].get(name)
    ]
    links_changed = []
    for name, target in links_for(doc).items():
        path = local / name
        safe_directory(path.parent)
        if not path.is_symlink() or os.readlink(path) != target:
            links_changed.append(name)
    return {"product": product, "changed": changed, "links_changed": links_changed}

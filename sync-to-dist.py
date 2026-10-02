#!/usr/bin/env python3
"""Copy committed utility sources into a distribution and commit only owned paths."""

import argparse
import fcntl
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

RECEIPT = ".blunix-utils-sync.json"


class SyncError(Exception):
    pass


def git(root, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_LITERAL_PATHSPECS"] = "1"
    result = subprocess.run(
        ["git", "-C", str(root), *args], env=env, capture_output=True, check=False
    )
    if result.returncode:
        raise SyncError(
            result.stderr.decode(errors="replace").strip() or "git command failed"
        )
    return result.stdout.decode()


def relative(value):
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or "\\" in value
        or any(p in ("", ".", "..", ".git") for p in value.split("/"))
        or any(ord(c) < 32 for c in value)
    ):
        raise SyncError("invalid mapped path")
    return value


def safe_path(root, name):
    path = root
    for part in relative(name).split("/"):
        path /= part
        if path.is_symlink():
            raise SyncError("symlink refused: " + name)
    if path.exists() and not path.is_file():
        raise SyncError("expected a regular file: " + name)
    return path


def fingerprint(path):
    if not path.exists():
        return None
    return {
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "executable": bool(path.stat().st_mode & 0o111),
    }


def read_json(path):
    if path.is_symlink():
        raise SyncError("symlinked metadata refused")
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or data.get("version") != 1:
        raise SyncError("unsupported manifest version")
    return data


def source_files(source):
    doc = read_json(source / "dist-map.json")
    files = {}
    excluded = set(doc.get("exclude", []))
    tracked = git(source, "ls-files", "-z").split("\0")
    for mapping in doc["mappings"]:
        src, dest = relative(mapping["source"]), relative(mapping["target"])
        matched = False
        for name in tracked:
            if (
                not name
                or name in excluded
                or not (name == src or name.startswith(src + "/"))
            ):
                continue
            matched = True
            target = relative(dest + name[len(src) :])
            if target == RECEIPT or target in files:
                raise SyncError("duplicate or reserved destination: " + target)
            path = safe_path(source, name)
            if not path.is_file():
                raise SyncError("source file missing: " + name)
            files[target] = (path, fingerprint(path))
        if not matched:
            raise SyncError("mapping has no tracked source files: " + src)
    return files


def sync(source, dist, dry_run=False, bootstrap=False, message=None):
    source, dist = Path(source).resolve(), Path(dist).resolve()
    if source == dist or source.is_relative_to(dist) or dist.is_relative_to(source):
        raise SyncError("source and distribution must be separate repositories")
    for root in (source, dist):
        if Path(git(root, "rev-parse", "--show-toplevel").strip()).resolve() != root:
            raise SyncError("expected a repository root: " + str(root))
    if git(source, "status", "--porcelain", "--untracked-files=normal").strip():
        raise SyncError("commit source changes before syncing")
    git(dist, "symbolic-ref", "--quiet", "HEAD")
    git_dir = Path(git(dist, "rev-parse", "--absolute-git-dir").strip())
    if any(
        (git_dir / p).exists()
        for p in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "rebase-merge", "rebase-apply")
    ):
        raise SyncError("distribution has an unfinished Git operation")
    fd = os.open(
        git_dir / "blunix-utils-sync.lock",
        os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
        0o600,
    )
    with os.fdopen(fd, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _sync(source, dist, dry_run, bootstrap, message)


def _sync(source, dist, dry_run, bootstrap, message):
    commit = git(source, "rev-parse", "HEAD").strip()
    files = source_files(source)
    receipt_path = safe_path(dist, RECEIPT)
    if receipt_path.exists():
        if git(dist, "diff", "HEAD", "--", RECEIPT).strip():
            raise SyncError("distribution sync receipt has local edits")
        if bootstrap:
            raise SyncError("--bootstrap is only valid for the first sync")
        old = read_json(receipt_path)["files"]
    elif bootstrap:
        old = read_json(source / "dist-baseline.json")["files"]
    else:
        old = {}
    names = set(files) | set(old)
    staged = set(git(dist, "diff", "--cached", "--name-only", "-z").split("\0"))
    if staged & (names | {RECEIPT}):
        raise SyncError(
            "managed distribution paths already staged; commit or unstage them first"
        )
    changes = {}
    conflicts = []
    for name in sorted(names):
        path = safe_path(dist, name)
        current = fingerprint(path)
        wanted = files[name][1] if name in files else None
        baseline = old.get(name)
        # First adoption only accepts identical content or the captured extraction baseline.
        if current != wanted and current != baseline:
            conflicts.append(name)
        if current != wanted:
            changes[name] = files[name][0].read_bytes() if name in files else None
    if conflicts:
        raise SyncError(
            "distribution edits conflict with source: " + ", ".join(conflicts)
        )
    receipt = {
        "version": 1,
        "source_commit": commit,
        "files": {name: item[1] for name, item in sorted(files.items())},
    }
    receipt_bytes = (json.dumps(receipt, indent=2) + "\n").encode()
    if not receipt_path.exists() or receipt_path.read_bytes() != receipt_bytes:
        changes[RECEIPT] = receipt_bytes
    # Include identical adopted files that differ from Git HEAD (initial extraction).
    dirty = set(git(dist, "diff", "--name-only", "-z").split("\0"))
    dirty.update(
        git(dist, "ls-files", "--others", "--exclude-standard", "-z").split("\0")
    )
    commit_paths = sorted(set(changes) | (dirty & names))
    result = {"source_commit": commit, "paths": commit_paths, "dry_run": dry_run}
    if dry_run or not commit_paths:
        result["status"] = "planned" if dry_run else "up-to-date"
        return result
    snapshot = {}
    for name in changes:
        path = safe_path(dist, name)
        snapshot[name] = (
            (path.read_bytes(), path.stat().st_mode & 0o777) if path.exists() else None
        )
    with tempfile.TemporaryDirectory(prefix="blunix-sync-") as work:
        body = Path(work) / "message"
        body.write_text(
            (message or "Sync blunix-utils at " + commit[:12])
            + "\n\nSource-Commit: "
            + commit
            + "\n"
        )
        try:
            for name, data in changes.items():
                path = safe_path(dist, name)
                if data is None:
                    if path.exists():
                        path.unlink()
                    continue
                path.parent.mkdir(parents=True, exist_ok=True)
                fd, temp = tempfile.mkstemp(prefix=".sync-", dir=path.parent)
                try:
                    with os.fdopen(fd, "wb") as handle:
                        handle.write(data)
                    os.chmod(
                        temp,
                        0o755
                        if name in files and files[name][1]["executable"]
                        else 0o644,
                    )
                    os.replace(temp, path)
                finally:
                    if os.path.exists(temp):
                        os.unlink(temp)
            git(dist, "add", "--", *commit_paths)
            # --only commits exactly these working-tree paths, preserving unrelated staged work.
            git(dist, "commit", "--only", "--file", str(body), "--", *commit_paths)
        except BaseException:
            git(dist, "reset", "--quiet", "HEAD", "--", *commit_paths)
            for name, saved in snapshot.items():
                path = dist / name
                if saved is None:
                    if path.exists():
                        path.unlink()
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(saved[0])
                    path.chmod(saved[1])
            raise
    result.update(
        status="committed", distribution_commit=git(dist, "rev-parse", "HEAD").strip()
    )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dist", type=Path, default=Path(__file__).resolve().parent.parent / "blunix"
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="adopt captured pre-extraction distribution files",
    )
    parser.add_argument("--message")
    args = parser.parse_args()
    try:
        print(
            json.dumps(
                sync(
                    Path(__file__).resolve().parent,
                    args.dist,
                    args.dry_run,
                    args.bootstrap,
                    args.message,
                ),
                indent=2,
            )
        )
        return 0
    except (SyncError, OSError, ValueError, KeyError) as exc:
        parser.exit(1, "sync-to-dist: " + str(exc) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())

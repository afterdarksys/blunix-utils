"""Read-only administration and diagnostic helpers; reports contain no file bodies."""

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from blunix.errors import BlunixError
from blunix.gitbuild_install import installed, verify

TOOLS = (
    "age",
    "git",
    "lsblk",
    "findmnt",
    "systemctl",
    "ip",
    "ss",
    "journalctl",
    "sha256sum",
)
SERVICES = (
    "ssh.service",
    "systemd-resolved.service",
    "systemd-networkd.service",
    "blunix-bootstrap.service",
    "blunix-access.service",
)


def command(argv):
    if shutil.which(argv[0]) is None:
        return {"status": "unavailable", "tool": argv[0]}
    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "error", "tool": argv[0]}
    if proc.returncode or len(proc.stdout) > 1024 * 1024:
        return {"status": "error", "tool": argv[0]}
    return {"status": "ok", "output": proc.stdout.decode("utf-8", "replace")}


def doctor(root):
    root = Path(root).resolve(strict=True)
    fs = os.statvfs(root)
    return {
        "status": "ok",
        "root": str(root),
        "tools_on_operator_host": {name: bool(shutil.which(name)) for name in TOOLS},
        "root_free_bytes": fs.f_bavail * fs.f_frsize,
        "root_free_inodes": fs.f_favail,
        "note": "Availability and capacity checks; not a full system health assessment.",
    }


def security(root):
    root = Path(root).resolve(strict=True)
    findings = []
    checks = {
        "etc/shadow": 0o640,
        "etc/gshadow": 0o640,
        "root/.ssh": 0o700,
        "usr/local/afterdarksys": 0o755,
    }
    checked = []
    for name, allowed in checks.items():
        path = root
        unsafe = False
        for part in name.split("/"):
            path /= part
            if path.is_symlink():
                findings.append(
                    {"path": "/" + name, "issue": "symlink in protected path"}
                )
                unsafe = True
                break
        if unsafe:
            continue
        try:
            info = path.stat()
        except FileNotFoundError:
            continue
        except OSError:
            findings.append({"path": "/" + name, "issue": "unreadable metadata"})
            continue
        checked.append("/" + name)
        mode = stat.S_IMODE(info.st_mode)
        if mode & ~allowed:
            findings.append(
                {"path": "/" + name, "issue": "excess permissions", "mode": oct(mode)}
            )
        if info.st_uid != 0:
            findings.append({"path": "/" + name, "issue": "not owned by root"})
    return {
        "status": "findings" if findings else ("ok" if checked else "unavailable"),
        "scope": "permission and ownership checks only; no configuration bodies read",
        "checked": checked,
        "findings": findings,
    }


def integrity(root, product=None):
    products = [product] if product else [item["product"] for item in installed(root)]
    reports = []
    for name in products:
        try:
            item = verify(name, root)
            item["status"] = (
                "changed" if item["changed"] or item["links_changed"] else "ok"
            )
        except (OSError, BlunixError, ValueError, KeyError):
            item = {"product": name, "status": "error"}
        reports.append(item)
    return {
        "status": "findings" if any(p["status"] != "ok" for p in reports) else "ok",
        "scope": "gitbuild packages only; receipts are local baselines, not signatures",
        "products": reports,
    }


def disks():
    result = command(
        ["lsblk", "--json", "--bytes", "--output", "KNAME,TYPE,SIZE,RO,RM,MOUNTPOINTS"]
    )
    if result["status"] == "ok":
        try:
            return {
                "status": "ok",
                "devices": json.loads(result["output"])["blockdevices"],
            }
        except (ValueError, KeyError):
            return {"status": "error", "tool": "lsblk"}
    return result


def admin():
    reports = {}
    for unit in SERVICES:
        result = command(
            [
                "systemctl",
                "show",
                unit,
                "--no-pager",
                "--property=LoadState,ActiveState,SubState,Result",
            ]
        )
        if result["status"] == "ok":
            result = {
                "status": "ok",
                "properties": dict(
                    line.split("=", 1)
                    for line in result["output"].splitlines()
                    if "=" in line
                ),
            }
        if result["status"] == "ok":
            props = result["properties"]
            if props.get("ActiveState") == "failed" or props.get(
                "Result", "success"
            ) not in ("", "success"):
                result["status"] = "findings"
            elif props.get("LoadState") != "loaded":
                result["status"] = "unavailable"
        reports[unit] = result
    status = (
        "findings"
        if any(r["status"] == "findings" for r in reports.values())
        else (
            "ok"
            if all(r["status"] == "ok" for r in reports.values())
            else "unavailable"
        )
    )
    return {"status": status, "services": reports}


def support(root, output):
    report = {
        "version": 1,
        "doctor": doctor(root),
        "security": security(root),
        "integrity": integrity(root),
        "omitted": [
            "configuration bodies",
            "journal logs",
            "credentials",
            "environment variables",
            "process arguments",
            "network addresses",
        ],
    }
    data = (json.dumps(report, indent=2) + "\n").encode()
    if len(data) > 1024 * 1024:
        raise BlunixError("support report exceeds 1 MiB")
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    return {"status": "ok", "output": str(output), "bytes": len(data)}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="blunix")
    sub = parser.add_subparsers(dest="group", required=True)
    doc = sub.add_parser("doctor")
    sec = sub.add_parser("security")
    sec.add_argument("action", choices=["audit"])
    integ = sub.add_parser("integrity")
    integ.add_argument("action", choices=["check"])
    integ.add_argument("product", nargs="?")
    adm = sub.add_parser("admin")
    adm.add_argument("action", choices=["status"])
    disk = sub.add_parser("disk")
    disk.add_argument("action", choices=["inspect"])
    sup = sub.add_parser("support")
    sup.add_argument("action", choices=["collect"])
    sup.add_argument("--output", required=True)
    for item in (doc, sec, integ, sup):
        item.add_argument("--root", default="/")
    args = parser.parse_args(argv)
    try:
        if args.group == "doctor":
            result = doctor(args.root)
        elif args.group == "security":
            result = security(args.root)
        elif args.group == "integrity":
            result = integrity(args.root, args.product)
        elif args.group == "admin":
            result = admin()
        elif args.group == "disk":
            result = disks()
        else:
            result = support(args.root, args.output)
        print(json.dumps(result, indent=2))
        return 0 if result["status"] == "ok" else 1
    except (OSError, BlunixError, ValueError, KeyError) as exc:
        print("blunix: diagnostic failed (" + type(exc).__name__ + ")", file=sys.stderr)
        return 1

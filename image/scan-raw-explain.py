#!/usr/bin/env python3
"""Explain a scan-raw.py refusal: where the hit is, and what file holds it.

scan-raw.py prints one fixed line and no offsets, so a refused release says
nothing about where to look. This is the tool for that moment:

  scan-raw-explain.py locate IMAGE
      Every hit scan-raw.py would refuse on, by byte offset, with its kind and,
      for an uncompressed image, the partition and the file that holds it (via
      debugfs on ext2/3/4), or "free space" for a deleted file's bytes. A .zst
      gives offsets in the decompressed stream only; decompress it to map
      files. Exit 1 when any hit is not a listed public key.

  scan-raw-explain.py blocks FILE [--member PATH]
      Every "-----BEGIN ...PRIVATE KEY-----" block in FILE (or in PATH inside
      the tar FILE, e.g. build/rootfs.tar), with its offset, kind, length,
      SHA-256 of the exact BEGIN..END bytes, whether scan-raw.py's pattern
      matches it, and whether _PUBLIC_KEYS lists it. A matched, unlisted block
      that is a vendor's public constant (a self-test key) goes into
      _PUBLIC_KEYS by that hash, and nothing else does.

Threats: this reads images that may hold a real leaked key, and its output
lands in terminals and logs. It prints offsets, kinds, lengths, hashes and
paths, never key bytes. It uses the scanner's own patterns, imported from
scan-raw.py, so it cannot drift from what the gate refuses. Hashes of a key
block do not reveal the key.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tarfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_MARKER = re.compile(rb"-----BEGIN ([A-Z0-9 ]{0,40}PRIVATE KEY)-----")


def _scanner():
    spec = importlib.util.spec_from_file_location("scan_raw", os.path.join(_HERE, "scan-raw.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _secrets(scan):
    # The build's test secrets, when present; without them, keys only.
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            return scan._secrets()
    except SystemExit:
        return []


def _hits(scan, blob, base, final, secrets):
    """(absolute offset, kind, listed) for each refusal pattern in `blob`."""
    edge = len(blob) if final else len(blob) - scan._PEM_MAX
    for start, kind, block in scan.pem_blocks(blob):
        if start < edge:
            name = kind.decode("ascii") + (" (no END)" if block is None else "")
            yield base + start, name, block is not None and scan.listed(block)
    for match in scan._PEM_HEADER.finditer(blob):
        if match.start() < edge:
            yield base + match.start(), "PEM key with headers", False
    for pattern, name in ((scan._OPENSSH_BODY, "OPENSSH key body"), (scan._AGE_SCRYPT, "age fixture")):
        for match in re.finditer(re.escape(pattern), blob):
            if match.start() < edge:
                yield base + match.start(), name, False
    for match in scan._AGE_KEY.finditer(blob):
        if match.start() < edge and match.group(0) != scan._AGE_EXAMPLE:
            yield base + match.start(), "age secret key", False
    for number, secret in enumerate(secrets):
        for match in re.finditer(re.escape(secret), blob):
            if match.start() < edge:
                yield base + match.start(), "build secret %d" % number, False


def _stream_hits(scan, stream, secrets):
    keep = scan._PEM_MAX
    prev, base, seen = b"", 0, set()
    while True:
        chunk = stream.read(scan._CHUNK)
        blob = prev + chunk
        for hit in _hits(scan, blob, base, not chunk, secrets):
            if hit[:2] not in seen:
                seen.add(hit[:2])
                yield hit
        if not chunk:
            return
        cut = max(0, len(blob) - keep)
        prev, base = blob[cut:], base + cut


def _partitions(image):
    """(start byte, size bytes, number) per partition, or the whole image."""
    try:
        out = subprocess.run(["sfdisk", "-J", image], capture_output=True, check=True).stdout
        table = json.loads(out)["partitiontable"]
    except (OSError, subprocess.CalledProcessError, ValueError, KeyError):
        return [(0, os.path.getsize(image), 0)]
    sector = table.get("sectorsize", 512)
    found = []
    for number, part in enumerate(table.get("partitions", []), 1):
        found.append((part["start"] * sector, part["size"] * sector, number))
    return found or [(0, os.path.getsize(image), 0)]


def _debugfs(image, offset, request):
    target = image if offset == 0 else "%s?offset=%d" % (image, offset)
    proc = subprocess.run(["debugfs", "-R", request, target], capture_output=True, check=False)
    return proc.returncode, proc.stdout.decode("utf-8", "replace")


def _owner(image, start, offset, cache):
    """The path holding byte `offset` of an ext filesystem at `start`, or why not."""
    if start not in cache:
        code, out = _debugfs(image, start, "stats")
        match = re.search(r"^Block size:\s+(\d+)", out, re.M)
        cache[start] = int(match.group(1)) if code == 0 and match else None
    size = cache[start]
    if size is None:
        return "not ext2/3/4 (or debugfs missing)"
    block = (offset - start) // size
    _code, out = _debugfs(image, start, "icheck %d" % block)
    match = re.search(r"^%d\s+(\d+)" % block, out, re.M)
    if not match:
        return "free space or metadata (block %d)" % block
    inode = match.group(1)
    _code, out = _debugfs(image, start, "ncheck %s" % inode)
    match = re.search(r"^%s\s+(\S.*)$" % inode, out, re.M)
    return "%s (inode %s, block %d)" % (match.group(1) if match else "unlinked", inode, block)


def locate(image):
    scan = _scanner()
    secrets = _secrets(scan)
    zst = image.endswith(".zst")
    if zst:
        proc = subprocess.Popen(["zstd", "-dc", "-q", "--no-progress", "--", image], stdout=subprocess.PIPE)
        hits = list(_stream_hits(scan, proc.stdout, secrets))
        proc.stdout.close()
        if proc.wait() != 0:
            sys.stderr.write("blunix: zstd failed\n")
            return 2
    else:
        with open(image, "rb") as handle:
            hits = list(_stream_hits(scan, handle, secrets))
    parts = [] if zst else _partitions(image)
    cache, refused = {}, 0
    for offset, kind, ok in sorted(hits):
        refused += not ok
        where = "decompress to map files" if zst else "outside every partition"
        for start, size, number in parts:
            if start <= offset < start + size:
                where = "partition %d: %s" % (number, _owner(image, start, offset, cache))
                break
        print("%d\t%s\t%s\t%s" % (offset, kind, "listed" if ok else "REFUSED", where))
    print("%d hit(s), %d refused" % (len(hits), refused))
    return 1 if refused else 0


def blocks(path, member):
    scan = _scanner()
    if member:
        with tarfile.open(path) as tar:
            handle = tar.extractfile(member if member.startswith("./") else "./" + member.lstrip("/"))
            data = handle.read()
    else:
        with open(path, "rb") as handle:
            data = handle.read()
    matched = {start: block for start, _kind, block in scan.pem_blocks(data)}
    for marker in _MARKER.finditer(data):
        start, kind = marker.start(), marker.group(1)
        end = data.find(b"-----END " + kind + b"-----", marker.end(), start + scan._PEM_MAX)
        block = data[start:end + len(kind) + 14] if end >= 0 else None
        digest = hashlib.sha256(block).hexdigest() if block else "-"
        state = "matched" if start in matched else "not matched"
        print("%d\t%s\t%s\t%s\t%s\t%s" % (
            start, kind.decode("ascii"), len(block) if block else "no END", digest, state,
            "listed" if block and scan.listed(block) else "unlisted"))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("locate", help="hits in a raw image, mapped to files")
    one.add_argument("image")
    two = sub.add_parser("blocks", help="PEM private-key blocks in a file, with hashes")
    two.add_argument("file")
    two.add_argument("--member", help="path inside the tar FILE")
    args = parser.parse_args()
    if args.command == "locate":
        return locate(args.image)
    return blocks(args.file, args.member)


if __name__ == "__main__":
    sys.exit(main())

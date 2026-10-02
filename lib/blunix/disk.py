"""Threats: a disk model decides partition sizes and which slot is encrypted.
Unknown fields and a second grow weight are refused. Rendering writes
systemd-repart drop-ins and does not run systemd-repart.

What it does not stop: calling systemd-repart by hand on a disk you care
about. The test image masks that service.
"""

from __future__ import annotations

import os

from blunix.errors import BlunixError
from blunix.schema import (
    load_path,
    model_path,
    require_bool,
    require_header,
    require_keys,
    require_name,
    write_text,
)

_DISK_KEYS = {"apiVersion", "kind", "name", "partitions"}
_PART_KEYS = {
    "name",
    "type",
    "size",
    "format",
    "verity",
    "read_only",
    "weight",
    "encrypt",
}
_TYPES = {
    "esp": "vfat",
    "root-x86-64": "erofs",
    "root-x86-64-verity": None,
    "var-x86-64": "ext4",
}
_SUFFIX = {"M": 1024 * 1024, "G": 1024 ** 3, "T": 1024 ** 4}
_MIB = 1024 * 1024


def parse_size(value):
    if not isinstance(value, str) or len(value) < 2 or not value[:-1].isdigit():
        raise BlunixError("refused size")
    if value[0] == "0":
        raise BlunixError("refused size")
    suffix = value[-1]
    if suffix not in _SUFFIX:
        raise BlunixError("refused size")
    number = int(value[:-1])
    size = number * _SUFFIX[suffix]
    if size % _MIB != 0:
        raise BlunixError("refused size")
    return size


def _partition(raw, index):
    if not isinstance(raw, dict):
        raise BlunixError("refused partition")
    require_keys(raw, _PART_KEYS)
    name = require_name(raw.get("name"), "partition")
    ptype = raw.get("type")
    if ptype not in _TYPES:
        raise BlunixError("refused partition type")
    if "size" not in raw:
        raise BlunixError("refused size")
    size = parse_size(raw["size"])
    weight = raw.get("weight", 0)
    if not isinstance(weight, int) or isinstance(weight, bool) or weight < 0:
        raise BlunixError("refused weight")
    if weight not in (0, 1000):
        raise BlunixError("refused weight")
    encrypt = raw.get("encrypt")
    if encrypt is not None and encrypt != "tpm2":
        raise BlunixError("refused encrypt")
    verity = raw.get("verity")
    if verity is not None:
        verity = require_name(verity, "verity")
    read_only = raw.get("read_only")
    if read_only is not None:
        read_only = require_bool(read_only, "read_only")
    fmt = raw.get("format")
    expect = _TYPES[ptype]
    if expect is None:
        if fmt is not None or verity is not None or read_only or encrypt:
            raise BlunixError("refused verity partition")
    else:
        if fmt != expect:
            raise BlunixError("refused format")
    if ptype == "root-x86-64":
        if verity is None or read_only is not True:
            raise BlunixError("refused root partition")
    elif verity is not None or read_only:
        raise BlunixError("refused partition")
    if ptype != "var-x86-64" and (weight or encrypt):
        raise BlunixError("refused partition")
    if ptype == "var-x86-64" and read_only:
        raise BlunixError("refused partition")
    return {
        "name": name,
        "type": ptype,
        "size": size,
        "weight": weight,
        "encrypt": encrypt,
        "verity": verity,
        "read_only": bool(read_only),
        "format": fmt,
        "index": index,
    }


def parse_disk(doc):
    if not isinstance(doc, dict):
        raise BlunixError("rejected plaintext")
    require_keys(doc, _DISK_KEYS)
    require_header(doc, "Disk")
    name = require_name(doc.get("name"), "name")
    parts = doc.get("partitions")
    if not isinstance(parts, list) or not parts or len(parts) > 16:
        raise BlunixError("refused partitions")
    parsed = [_partition(raw, i) for i, raw in enumerate(parts)]
    names = [part["name"] for part in parsed]
    if len(set(names)) != len(names):
        raise BlunixError("refused partition")
    if parsed[0]["type"] != "esp":
        raise BlunixError("esp must be first")
    if sum(1 for part in parsed if part["type"] == "esp") != 1:
        raise BlunixError("refused esp")
    growers = [part for part in parsed if part["weight"]]
    if len(growers) != 1 or growers[0]["type"] != "var-x86-64":
        raise BlunixError("refused weight")
    by_name = {part["name"]: part for part in parsed}
    seen_hash = {}
    for part in parsed:
        if part["type"] != "root-x86-64":
            continue
        target = by_name.get(part["verity"])
        if target is None or target["type"] != "root-x86-64-verity":
            raise BlunixError("refused verity")
        if part["verity"] in seen_hash:
            raise BlunixError("refused verity")
        seen_hash[part["verity"]] = part["name"]
    hashes = [part for part in parsed if part["type"] == "root-x86-64-verity"]
    if len(hashes) != len(seen_hash):
        raise BlunixError("refused verity")
    return {"name": name, "partitions": parsed}


def min_bytes(model):
    """The smallest disk this layout fits on: every partition at its floor."""
    return sum(part["size"] for part in model["partitions"])


def load_disk(models, name):
    doc = load_path(model_path(models, "disk", name))
    parsed = parse_disk(doc)
    if parsed["name"] != name:
        raise BlunixError("refused name")
    return parsed


def _conf(part, match_key):
    lines = [
        "[Partition]",
        "Type=" + part["type"],
        "Label=" + part["name"],
        "SizeMinBytes=" + str(part["size"]),
    ]
    if part["weight"] == 0:
        lines.append("SizeMaxBytes=" + str(part["size"]))
    if part["format"]:
        lines.append("Format=" + part["format"])
    if part["read_only"]:
        lines.append("ReadOnly=yes")
    if part["type"] == "root-x86-64":
        lines.append("Verity=data")
        lines.append("VerityMatchKey=" + match_key)
    elif part["type"] == "root-x86-64-verity":
        lines.append("Verity=hash")
        lines.append("VerityMatchKey=" + match_key)
    if part["encrypt"]:
        lines.append("Encrypt=tpm2")
    lines.append("Weight=" + str(part["weight"]))
    return "\n".join(lines) + "\n"


def render_disk(model):
    match = {}
    for part in model["partitions"]:
        if part["type"] == "root-x86-64-verity":
            for data in model["partitions"]:
                if data.get("verity") == part["name"]:
                    match[part["name"]] = data["name"]
        elif part["verity"]:
            match[part["name"]] = part["name"]
    files = {}
    for part in model["partitions"]:
        filename = "{:02d}-{}.conf".format((part["index"] + 1) * 10, part["name"])
        files[filename] = _conf(part, match.get(part["name"], part["name"]))
    return files


def write_disk(model, dest):
    os.makedirs(dest, exist_ok=True)
    files = render_disk(model)
    for name, body in files.items():
        write_text(os.path.join(dest, name), body)
    return files

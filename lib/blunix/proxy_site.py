"""Site file, label, and build-host rules for the build-proxy.

Threats: a site file is operator input and can be wrong in ways that erase
the wrong machine or publish to the wrong label. This parser refuses unknown
keys, duplicate YAML keys, aliases, duplicate MACs, labels, hostnames and
addresses, labels outside the contract rule, bad CIDRs, and a gateway outside
the subnet. The build-host check is what keeps `serve` from being an open
proxy: only `{label}.blnx.io` and `v{n}.{label}.blnx.io` pass, lowercase
ASCII only. The legacy `name-N.build.blunix.io` form is not relayed.

A site file may name Profile files (`profile:`). A profile path must be
relative to the site file, stay inside its directory after symlinks resolve,
and end in .yaml, .yml or .json; it is read with the node document loader.
Precedence for every node field is machine, then site defaults, then the
default profile, then the built-in value, and each machine records where each value
came from so `plan --explain` can say so. A machine's own `profile:` beats
the site defaults; the site's default profile does not. The `boot:` section only takes
values that cannot add a line to dnsmasq or a second kernel directive.

What it does not stop: a well-formed site file that maps a MAC to the wrong
machine. The installer still asks before it erases a disk.
"""

from __future__ import annotations

import ipaddress
import os
import re

import yaml

from blunix.errors import BlunixError
from blunix.network import check_match, parse_network
from blunix.schema import (
    API_VERSION,
    UniqueKeyLoader,
    load_bytes,
    load_path,
    require_build_host,
    require_name,
)

MAX_SITE = 256 * 1024
MAX_MACHINES = 256
BUILD_DOMAIN = "blnx.io"
UPDATE_URL = "https://updates.blunix.io/blunix"
RESERVED = frozenset(
    "www api updates log mail build portal admin root blunix proxy status".split()
)

_LABEL = re.compile(r"[a-z][a-z0-9-]{0,30}[a-z0-9]")
_VERSION_LABEL = re.compile(r"v[0-9]+")
_PINNED = re.compile(r"v[1-9][0-9]{0,5}")
_MAC_COLON = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")
_MAC_DASH = re.compile(r"[0-9a-f]{2}(-[0-9a-f]{2}){5}")
_MAC_BARE = re.compile(r"[0-9a-f]{12}")
# Same rule as node.py: a kernel disk name or a serial, never a path.
_TARGET = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}")

_TOP_KEYS = {"defaults", "machines", "boot"}
_DEFAULT_KEYS = {"disk", "access", "channel", "dns", "match", "profile"}
_MACHINE_KEYS = {
    "mac", "label", "hostname", "network", "dhcp", "disk", "access", "target", "match", "profile",
}
_NET_KEYS = {"address", "gateway", "dns"}
_BOOT_KEYS = {"access", "console", "args", "lease", "tftp_root"}
_PROFILE_FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,200}\.(ya?ml|json)")
_CONSOLE = re.compile(r"tty[0-9]{1,2}|ttyS[0-9]{1,2}(,[0-9]{4,7}(n8)?)?")
_ARG = re.compile(r"[a-z][a-z0-9_.-]{0,40}(=[A-Za-z0-9_.,:/+-]{1,80})?")
_MANAGED_ARGS = {"boot", "fetch", "initrd", "noeject", "console", "blunix.proxy", "blunix.access"}
_LEASE = re.compile(r"[1-9][0-9]{0,3}[mh]|infinite")
_TFTP_ROOT = re.compile(r"/[A-Za-z0-9._/-]{0,200}")

# Built-in values, used when no machine entry, site default or profile sets one.
BUILTIN = {
    "ai": "default",
    "update": {"url": UPDATE_URL, "channel": "stable"},
    "dhcp_match": ["en*", "eth*"],
    "static_match": ["en*"],
}
BOOT_BUILTIN = {
    "access": "regular",
    "console": ["tty0", "ttyS0,115200"],
    "args": [],
    "lease": "12h",
    "tftp_root": "/srv/tftp",
}


def check_label(value):
    if (
        not isinstance(value, str)
        or not _LABEL.fullmatch(value)
        or "--" in value
        or value in RESERVED
        or _VERSION_LABEL.fullmatch(value)
    ):
        raise BlunixError("refused label")
    return value


def build_host_kind(host):
    """Return "latest" or "pinned" for a build host, or refuse."""
    if not isinstance(host, str) or len(host) > 253:
        raise BlunixError("refused hostname")
    # The installer's own check must agree before this one classifies.
    require_build_host(host)
    suffix = "." + BUILD_DOMAIN
    if not host.endswith(suffix):
        raise BlunixError("refused hostname")
    parts = host[: -len(suffix)].split(".")
    if len(parts) == 1:
        check_label(parts[0])
        return "latest"
    if len(parts) == 2 and _PINNED.fullmatch(parts[0]):
        check_label(parts[1])
        return "pinned"
    raise BlunixError("refused hostname")


def latest_url(label):
    return "https://" + check_label(label) + "." + BUILD_DOMAIN + "/"


def pinned_url(label, version):
    if isinstance(version, bool) or not isinstance(version, int) or not 1 <= version <= 999999:
        raise BlunixError("refused version")
    return "https://v" + str(version) + "." + check_label(label) + "." + BUILD_DOMAIN + "/"


def normalize_mac(value):
    if not isinstance(value, str) or len(value) > 17:
        raise BlunixError("refused mac")
    raw = value.lower()
    if _MAC_COLON.fullmatch(raw) or _MAC_DASH.fullmatch(raw):
        digits = raw.replace(":", "").replace("-", "")
    elif _MAC_BARE.fullmatch(raw):
        digits = raw
    else:
        raise BlunixError("refused mac")
    if int(digits[:2], 16) & 1 or digits == "0" * 12:
        raise BlunixError("refused mac")
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def _fail(index, what):
    if index is None:
        raise BlunixError("site file: " + what)
    raise BlunixError("site file: machine " + str(index) + ": " + what)


def _keys(value, allowed, index, what):
    if not isinstance(value, dict):
        _fail(index, what + " must be a mapping")
    if any(key not in allowed for key in value):
        _fail(index, "unknown key in " + what)


def _name(value, index, what):
    try:
        return require_name(value, what)
    except BlunixError:
        _fail(index, "refused " + what)


def _dns(value, index):
    if not isinstance(value, list) or not value or len(value) > 4:
        _fail(index, "dns must be a list of one to four addresses")
    out = []
    for item in value:
        try:
            addr = ipaddress.ip_address(item) if isinstance(item, str) else None
        except ValueError:
            addr = None
        if addr is None or addr.is_multicast or addr.is_unspecified:
            _fail(index, "refused dns")
        out.append(str(addr))
    return out


def _static(net, label, dns, index):
    doc = {
        "apiVersion": API_VERSION,
        "kind": "Network",
        "name": label,
        "match": ["en*"],
        "address": net.get("address"),
        "gateway": net.get("gateway"),
        "dns": dns,
    }
    try:
        parsed = parse_network(doc)
    except BlunixError as exc:
        _fail(index, str(exc))
    iface = ipaddress.ip_interface(parsed["address"])
    gateway = ipaddress.ip_address(parsed["gateway"])
    if gateway not in iface.network:
        _fail(index, "gateway outside subnet")
    if iface.version == 4 and iface.network.prefixlen < 31:
        if iface.ip in (iface.network.network_address, iface.network.broadcast_address):
            _fail(index, "refused address")
    return parsed


def _load_profile(value, base_dir, index, cache):
    """Read a Profile named by a site file. Returns (profile, display name)."""
    from blunix.profile import parse_profile

    if base_dir is None:
        _fail(index, "profile needs the site file's path; use load_site")
    if (
        not isinstance(value, str)
        or not _PROFILE_FILE.fullmatch(value)
        or any(part in ("", ".", "..") for part in value.split("/"))
    ):
        _fail(index, "refused profile path")
    root = os.path.realpath(base_dir)
    path = os.path.realpath(os.path.join(root, value))
    if os.path.commonpath([root, path]) != root or not os.path.isfile(path):
        _fail(index, "profile not found inside the site file's directory")
    if path not in cache:
        try:
            cache[path] = parse_profile(load_path(path))
        except BlunixError as exc:
            _fail(index, "profile " + value + ": " + str(exc))
    return cache[path], "profile " + value


def _match(value, index):
    if not isinstance(value, list) or not value or len(value) > 8:
        _fail(index, "match must be a list of one to eight interface patterns")
    try:
        return [check_match(item) for item in value]
    except BlunixError:
        _fail(index, "refused match")


def _profile_network(profile):
    """A profile's network, as (dhcp, match) when it is a DHCP network that
    suits every machine, else None."""
    net = profile.get("network")
    if net == "dhcp-any":
        return True, None
    if isinstance(net, dict) and net.get("dhcp") is True:
        return True, list(net.get("match") or [])
    return None


def _pick(name, raw, defaults, profile, builtin, own_profile=False):
    """Machine first. A machine's own profile beats the site defaults; the
    site's default profile does not. Then the built-in value."""
    if name in raw:
        return raw[name], "machine"
    order = ["profile", "defaults"] if own_profile else ["defaults", "profile"]
    for where in order:
        if where == "defaults" and name in defaults:
            return defaults[name], defaults["_sources"][name]
        if where == "profile" and profile is not None and name in profile[0]:
            return profile[0][name], profile[1]
    return builtin, "built-in"


def parse_boot(raw):
    """The netboot settings. Returns (boot, sources)."""
    if raw is None:
        raw = {}
    _keys(raw, _BOOT_KEYS, None, "boot")
    boot = {}
    sources = {}
    for key, builtin in BOOT_BUILTIN.items():
        boot[key] = raw.get(key, builtin)
        sources[key] = "site boot" if key in raw else "built-in"
    boot["access"] = _name(boot["access"], None, "boot access")
    console = boot["console"]
    if (
        not isinstance(console, list) or not 1 <= len(console) <= 4
        or not all(isinstance(c, str) and _CONSOLE.fullmatch(c) for c in console)
    ):
        _fail(None, "refused boot console")
    args = boot["args"]
    if not isinstance(args, list) or len(args) > 16:
        _fail(None, "boot args must be a list of at most 16 kernel arguments")
    for arg in args:
        if not isinstance(arg, str) or not _ARG.fullmatch(arg):
            _fail(None, "refused boot arg")
        if arg.split("=", 1)[0] in _MANAGED_ARGS:
            _fail(None, "boot arg " + arg.split("=", 1)[0] + " is set by the proxy")
    if not isinstance(boot["lease"], str) or not _LEASE.fullmatch(boot["lease"]):
        _fail(None, "refused boot lease")
    root = boot["tftp_root"]
    if not isinstance(root, str) or not _TFTP_ROOT.fullmatch(root) or ".." in root:
        _fail(None, "refused boot tftp_root")
    return boot, sources


def _machine(raw, index, defaults, base_dir=None, cache=None):
    _keys(raw, _MACHINE_KEYS, index, "machine")
    mac_raw = raw.get("mac")
    if not isinstance(mac_raw, str):
        _fail(index, "mac must be a quoted string")
    try:
        mac = normalize_mac(mac_raw)
    except BlunixError:
        _fail(index, "refused mac")
    try:
        label = check_label(raw.get("label"))
    except BlunixError:
        _fail(index, "refused label")
    hostname = _name(raw.get("hostname"), index, "hostname")
    profile = None
    own = "profile" in raw
    if own:
        profile = _load_profile(raw["profile"], base_dir, index, {} if cache is None else cache)
    elif defaults.get("_profile") is not None:
        profile = defaults["_profile"]
    sources = {}
    disk, sources["disk"] = _pick("disk", raw, defaults, profile, None, own)
    disk = _name(disk, index, "disk")
    access, sources["access"] = _pick("access", raw, defaults, profile, None, own)
    access = _name(access, index, "access")
    ai, sources["ai"] = _pick("ai", {}, {"_sources": {}}, profile, BUILTIN["ai"])
    update, sources["update"] = _pick("update", {}, {"_sources": {}}, profile, BUILTIN["update"])
    packages, sources["packages"] = _pick("packages", {}, {"_sources": {}}, profile, [])
    update = dict(update)
    if "channel" in defaults:
        update["channel"] = defaults["channel"]
    target = raw.get("target")
    if target is not None:
        if not isinstance(target, str) or not _TARGET.fullmatch(target):
            _fail(index, "refused target")
    has_net = "network" in raw
    has_dhcp = "dhcp" in raw
    if has_net and has_dhcp:
        _fail(index, "give exactly one of network or dhcp")
    profile_net = _profile_network(profile[0]) if profile is not None else None
    match = None
    profile_match = profile_net[1] if profile_net is not None and profile_net[1] else None
    if "match" in raw:
        match, sources["match"] = _match(raw["match"], index), "machine"
    elif own and profile_match:
        match, sources["match"] = profile_match, profile[1]
    elif "match" in defaults:
        match, sources["match"] = defaults["match"], defaults["_sources"]["match"]
    elif profile_match:
        match, sources["match"] = profile_match, profile[1]
    machine = {
        "index": index,
        "mac": mac,
        "label": label,
        "hostname": hostname,
        "disk": disk,
        "access": access,
        "ai": ai,
        "update": update,
        "packages": list(packages),
        "channel": update["channel"],
        "target": target,
        "match": match,
        "profile": profile[1][len("profile "):] if profile is not None else None,
        "sources": sources,
    }
    if not has_net and not has_dhcp:
        if profile_net is None:
            _fail(index, "give exactly one of network or dhcp")
        machine["dhcp"] = True
        sources["network"] = profile[1]
        return machine
    if has_dhcp:
        if raw.get("dhcp") is not True:
            _fail(index, "dhcp must be true")
        machine["dhcp"] = True
        sources["network"] = "machine"
        return machine
    sources["network"] = "machine"
    net = raw.get("network")
    _keys(net, _NET_KEYS, index, "network")
    if "dns" in net:
        dns = _dns(net.get("dns"), index)
    elif defaults.get("dns"):
        dns = defaults["dns"]
    else:
        _fail(index, "static network needs dns here or in defaults")
    parsed = _static(net, label, dns, index)
    machine.update(
        dhcp=False,
        address=parsed["address"],
        gateway=parsed["gateway"],
        dns=parsed["dns"],
    )
    return machine


def parse_site(data, base_dir=None):
    if not isinstance(data, (bytes, bytearray)):
        _fail(None, "not readable")
    if len(data) > MAX_SITE:
        _fail(None, "too large")
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        _fail(None, "not utf-8")
    try:
        doc = yaml.load(text, Loader=UniqueKeyLoader)
    except Exception as exc:
        if str(exc) == "duplicate key":
            _fail(None, "duplicate key")
        _fail(None, "not valid yaml")
    _keys(doc, _TOP_KEYS, None, "top level")
    raw_defaults = doc.get("defaults", {})
    _keys(raw_defaults, _DEFAULT_KEYS, None, "defaults")
    defaults = {"_sources": {}, "_profile": None}
    if "channel" in raw_defaults:
        if raw_defaults["channel"] != "stable":
            _fail(None, "refused channel")
        defaults["channel"] = "stable"
    for key in ("disk", "access"):
        if key in raw_defaults:
            defaults[key] = _name(raw_defaults[key], None, key)
            defaults["_sources"][key] = "defaults"
    if "dns" in raw_defaults:
        defaults["dns"] = _dns(raw_defaults["dns"], None)
    if "match" in raw_defaults:
        defaults["match"] = _match(raw_defaults["match"], None)
        defaults["_sources"]["match"] = "defaults"
    cache = {}
    if "profile" in raw_defaults:
        defaults["_profile"] = _load_profile(raw_defaults["profile"], base_dir, None, cache)
    boot, boot_sources = parse_boot(doc.get("boot"))
    machines = doc.get("machines")
    if not isinstance(machines, list) or not machines:
        _fail(None, "machines must be a non-empty list")
    if len(machines) > MAX_MACHINES:
        _fail(None, "too many machines")
    seen = {"mac": set(), "label": set(), "hostname": set(), "address": set()}
    out = []
    for index, raw in enumerate(machines, 1):
        machine = _machine(raw, index, defaults, base_dir, cache)
        for key in ("mac", "label", "hostname"):
            if machine[key] in seen[key]:
                _fail(index, "duplicate " + key)
            seen[key].add(machine[key])
        if not machine["dhcp"]:
            addr = str(ipaddress.ip_interface(machine["address"]).ip)
            if addr in seen["address"]:
                _fail(index, "duplicate address")
            seen["address"].add(addr)
        out.append(machine)
    public = {k: v for k, v in defaults.items() if not k.startswith("_")}
    return {"defaults": public, "machines": out, "boot": boot, "boot_sources": boot_sources}


def load_site(path):
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_SITE + 1)
    except OSError:
        raise BlunixError("site file unreadable") from None
    return parse_site(data, os.path.dirname(os.path.abspath(path)))


def render_node(machine):
    """The node document for one machine, using the inline network form."""
    match = machine.get("match")
    if machine["dhcp"]:
        network = {"match": list(match), "dhcp": True} if match else "dhcp-any"
    else:
        network = {
            "match": list(match or BUILTIN["static_match"]),
            "address": machine["address"],
            "gateway": machine["gateway"],
            "dns": list(machine["dns"]),
        }
    update = machine.get("update") or BUILTIN["update"]
    doc = {
        "apiVersion": API_VERSION,
        "kind": "Node",
        "name": machine["label"],
        "hostname": machine["hostname"],
        "disk": machine["disk"],
        "network": network,
        "access": machine["access"],
        "ai": machine.get("ai", BUILTIN["ai"]),
        "update": {"url": update["url"], "channel": update["channel"]},
        "sysexts": [],
    }
    if machine.get("target"):
        doc["target"] = machine["target"]
    if machine.get("packages"):
        doc["packages"] = list(machine["packages"])
    return yaml.safe_dump(doc, sort_keys=False).encode("utf-8")


def validate_node(machine, data, models=None):
    """Parse the rendered document with the installer's own rules."""
    from blunix.access import load_access
    from blunix.ai import load_ai
    from blunix.disk import load_disk
    from blunix.node import parse_node
    from blunix.schema import models_dir

    try:
        parsed = parse_node(load_bytes(data))
        root = models_dir(models)
        load_disk(root, parsed["disk"])
        load_access(root, parsed["access"])
        load_ai(root, parsed["ai"])
    except BlunixError as exc:
        _fail(machine["index"], "node document refused: " + str(exc))
    return parsed

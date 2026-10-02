"""Site file, label, and build-host rules for the build-proxy.

Threats: a site file is operator input and can be wrong in ways that erase
the wrong machine or publish to the wrong label. This parser refuses unknown
keys, duplicate YAML keys, aliases, duplicate MACs, labels, hostnames and
addresses, labels outside the contract rule, bad CIDRs, and a gateway outside
the subnet. The build-host check is what keeps `serve` from being an open
proxy: only `{label}.blnx.io` and `v{n}.{label}.blnx.io` pass, lowercase
ASCII only. The legacy `name-N.build.blunix.io` form is not relayed.

What it does not stop: a well-formed site file that maps a MAC to the wrong
machine. The installer still asks before it erases a disk.
"""

from __future__ import annotations

import ipaddress
import re

import yaml

from blunix.errors import BlunixError
from blunix.network import parse_network
from blunix.schema import (
    API_VERSION,
    UniqueKeyLoader,
    load_bytes,
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

_TOP_KEYS = {"defaults", "machines"}
_DEFAULT_KEYS = {"disk", "access", "channel", "dns"}
_MACHINE_KEYS = {"mac", "label", "hostname", "network", "dhcp", "disk", "access", "target"}
_NET_KEYS = {"address", "gateway", "dns"}


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


def _machine(raw, index, defaults):
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
    disk = _name(raw.get("disk", defaults.get("disk")), index, "disk")
    access = _name(raw.get("access", defaults.get("access")), index, "access")
    target = raw.get("target")
    if target is not None:
        if not isinstance(target, str) or not _TARGET.fullmatch(target):
            _fail(index, "refused target")
    has_net = "network" in raw
    has_dhcp = "dhcp" in raw
    if has_net == has_dhcp:
        _fail(index, "give exactly one of network or dhcp")
    machine = {
        "index": index,
        "mac": mac,
        "label": label,
        "hostname": hostname,
        "disk": disk,
        "access": access,
        "channel": defaults["channel"],
        "target": target,
    }
    if has_dhcp:
        if raw.get("dhcp") is not True:
            _fail(index, "dhcp must be true")
        machine["dhcp"] = True
        return machine
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


def parse_site(data):
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
    defaults = {"channel": raw_defaults.get("channel", "stable")}
    if defaults["channel"] != "stable":
        _fail(None, "refused channel")
    for key in ("disk", "access"):
        if key in raw_defaults:
            defaults[key] = _name(raw_defaults[key], None, key)
    if "dns" in raw_defaults:
        defaults["dns"] = _dns(raw_defaults["dns"], None)
    machines = doc.get("machines")
    if not isinstance(machines, list) or not machines:
        _fail(None, "machines must be a non-empty list")
    if len(machines) > MAX_MACHINES:
        _fail(None, "too many machines")
    seen = {"mac": set(), "label": set(), "hostname": set(), "address": set()}
    out = []
    for index, raw in enumerate(machines, 1):
        machine = _machine(raw, index, defaults)
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
    return {"defaults": defaults, "machines": out}


def load_site(path):
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_SITE + 1)
    except OSError:
        raise BlunixError("site file unreadable") from None
    return parse_site(data)


def render_node(machine):
    """The node document for one machine, using the inline network form."""
    if machine["dhcp"]:
        network = "dhcp-any"
    else:
        network = {
            "match": ["en*"],
            "address": machine["address"],
            "gateway": machine["gateway"],
            "dns": list(machine["dns"]),
        }
    doc = {
        "apiVersion": API_VERSION,
        "kind": "Node",
        "name": machine["label"],
        "hostname": machine["hostname"],
        "disk": machine["disk"],
        "network": network,
        "access": machine["access"],
        "ai": "default",
        "update": {"url": UPDATE_URL, "channel": machine["channel"]},
        "sysexts": [],
    }
    if machine.get("target"):
        doc["target"] = machine["target"]
    return yaml.safe_dump(doc, sort_keys=False).encode("utf-8")


def validate_node(machine, data, models=None):
    """Parse the rendered document with the installer's own rules."""
    from blunix.access import load_access
    from blunix.disk import load_disk
    from blunix.node import parse_node
    from blunix.schema import models_dir

    try:
        parsed = parse_node(load_bytes(data))
        root = models_dir(models)
        load_disk(root, parsed["disk"])
        load_access(root, parsed["access"])
    except BlunixError as exc:
        _fail(machine["index"], "node document refused: " + str(exc))
    return parsed

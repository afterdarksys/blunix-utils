"""Build profiles: reusable templates that become node documents.

Threats: a profile is untrusted input, read from YAML or JSON by the same
loader as a node document, so oversized input, duplicate keys, aliases and
key-material field names are refused before this module sees it. A profile
carries no hostname, label or disk target; those are supplied when it is
rendered, and the rendered document is checked by parse_node like any other
node document. Nothing here encrypts, uploads, or applies.

`distribution:` is reserved for a second host distribution. Only `debian` is
accepted, and it is not copied into the rendered node document, so documents
rendered today stay valid on images that predate the field.
"""

from __future__ import annotations

import json

import yaml

from blunix.errors import BlunixError
from blunix.node import check_node, coerce_doc, parse_node
from blunix.schema import (
    API_VERSION,
    check_label,
    require_header,
    require_keys,
    require_name,
)

DISTRIBUTIONS = ("debian",)

_PROFILE_KEYS = {
    "apiVersion",
    "kind",
    "name",
    "distribution",
    "disk",
    "network",
    "access",
    "ai",
    "update",
    "sysexts",
}
# The node fields a profile supplies, in node document order.
_CARRIED = ("disk", "network", "access", "ai", "update", "sysexts")


def parse_profile(doc):
    """Check a Profile's own fields. Returns the document with the
    distribution filled in."""
    if not isinstance(doc, dict):
        raise BlunixError("rejected plaintext")
    require_keys(doc, _PROFILE_KEYS)
    require_header(doc, "Profile")
    require_name(doc.get("name"), "name")
    distribution = doc.get("distribution", "debian")
    if distribution not in DISTRIBUTIONS:
        raise BlunixError("refused distribution")
    for key in _CARRIED:
        if key not in doc:
            raise BlunixError("refused " + key)
    out = dict(doc)
    out["distribution"] = distribution
    return out


def render_node(profile, label, hostname, target=None):
    """Merge a profile with one machine's label and hostname. The result is a
    plain Node document that has already passed parse_node."""
    parsed = parse_profile(coerce_doc(profile))
    check_label(label)
    require_name(hostname, "hostname")
    node = {"apiVersion": API_VERSION, "kind": "Node", "name": label, "hostname": hostname}
    for key in _CARRIED:
        node[key] = parsed[key]
    if target is not None:
        node["target"] = target
    parse_node(node)
    return node


def check_document(doc, models=None):
    """Check a Profile or a Node, including every model it names. Writes
    nothing. Returns (kind, name)."""
    original = coerce_doc(doc)
    kind = original.get("kind")
    if kind == "Node":
        check_node(original, models)
        return "Node", original["name"]
    if kind == "Profile":
        # Placeholders only exist to reach the model checks; they are not output.
        check_node(render_node(original, "check", "check"), models)
        return "Profile", original["name"]
    raise BlunixError("refused kind")


def dump(doc, fmt):
    if fmt == "yaml":
        return yaml.safe_dump(doc, sort_keys=False)
    if fmt == "json":
        return json.dumps(doc, indent=2) + "\n"
    raise BlunixError("refused format")

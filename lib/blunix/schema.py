"""Threats: a node document is untrusted. This parser rejects oversized input,
unknown fields, duplicate keys, YAML aliases, and field names that would carry
key material. It does not decrypt, fetch, or apply.

What it does not stop: a document that is well-formed and still points the
update URL at a host the operator did not intend. Signing that document is
still open. This spike refuses the document shape, and says so when it applies.
"""

from __future__ import annotations

import os
import re

import yaml

from blunix.errors import BlunixError

API_VERSION = "blunix.dev/v1"
MAX_DOCUMENT = 64 * 1024

# Whole tokens after case-folding and turning hyphens into underscores.
_BANNED = (
    "private_key",
    "psk",
    "password",
    "token",
    "api_key",
    "passphrase",
    "recovery_token",
    "key_file",
    "secret",
    "wifi_psk",
)

_NAME = re.compile(r"[a-z]([a-z0-9-]{0,61}[a-z0-9])?")
# One ASCII DNS label, 2 to 32 characters. See blunix-install-plane.md, Names.
_LABEL = re.compile(r"[a-z][a-z0-9-]{0,30}[a-z0-9]")
_VERSION = re.compile(r"v([1-9][0-9]{0,5})")
_LEGACY_HOST = re.compile(
    r"([a-z][a-z0-9]{1,20})-([1-9][0-9]{0,5})\.build\.blunix\.io"
)
# User build hosts live on their own registrable domain. build.blunix.io is
# the web portal, not a build host.
_BUILD_SUFFIX = ".blnx.io"
_RESERVED = frozenset(
    (
        "www",
        "api",
        "updates",
        "log",
        "mail",
        "build",
        "portal",
        "admin",
        "root",
        "blunix",
        "proxy",
        "status",
    )
)


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML that refuses aliases and duplicate keys."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.events.AliasEvent):
            self.get_event()
            raise _RefusedYaml("rejected plaintext")
        return super().compose_node(parent, index)


class _RefusedYaml(Exception):
    def __init__(self, message):
        super().__init__(message)


def _construct_mapping(loader, node, deep=False):
    if not isinstance(node, yaml.MappingNode):
        raise _RefusedYaml("rejected plaintext")
    mapping = {}
    for key_node, value_node in node.value:
        # PyYAML tags "<<" as a merge. Keep it as a plain key so it fails closed.
        if key_node.tag == "tag:yaml.org,2002:merge":
            if not isinstance(key_node, yaml.ScalarNode) or key_node.value != "<<":
                raise _RefusedYaml("rejected plaintext")
            key = "<<"
        else:
            key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise _RefusedYaml("rejected plaintext")
        if key in mapping:
            raise _RefusedYaml("duplicate key")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _norm_key(key):
    return str(key).strip().lower().replace("-", "_")


def _banned(key):
    norm = _norm_key(key)
    for word in _BANNED:
        if re.search(r"(^|_)" + re.escape(word) + r"($|_)", norm):
            return True
    return False


def reject_banned(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if _banned(key):
                raise BlunixError("refused field")
            reject_banned(item)
    elif isinstance(value, list):
        for item in value:
            reject_banned(item)


def load_text(text):
    if not isinstance(text, str):
        raise BlunixError("rejected plaintext")
    raw = text.encode("utf-8")
    if len(raw) > MAX_DOCUMENT:
        raise BlunixError("document too large")
    try:
        doc = yaml.load(text, Loader=UniqueKeyLoader)
    except _RefusedYaml as exc:
        raise BlunixError(str(exc)) from None
    except yaml.YAMLError:
        raise BlunixError("rejected plaintext") from None
    if not isinstance(doc, dict):
        raise BlunixError("rejected plaintext")
    reject_banned(doc)
    return doc


def load_bytes(data):
    if not isinstance(data, (bytes, bytearray)):
        raise BlunixError("rejected plaintext")
    if len(data) > MAX_DOCUMENT:
        raise BlunixError("document too large")
    if data.startswith(b"#!") or data.startswith(b"\x7fELF") or b"\x00" in data:
        raise BlunixError("rejected plaintext")
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        raise BlunixError("rejected plaintext") from None
    return load_text(text)


def load_path(path):
    try:
        size = os.path.getsize(path)
    except OSError:
        raise BlunixError("document unreadable")
    if size > MAX_DOCUMENT:
        raise BlunixError("document too large")
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_DOCUMENT + 1)
    except OSError:
        raise BlunixError("document unreadable")
    return load_bytes(data)


def require_keys(doc, allowed):
    unknown = [key for key in doc.keys() if key not in allowed]
    if unknown:
        raise BlunixError("unknown field")


def require_header(doc, kind):
    if doc.get("apiVersion") != API_VERSION:
        raise BlunixError("refused apiVersion")
    if doc.get("kind") != kind:
        raise BlunixError("refused kind")


def require_name(value, what="name"):
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise BlunixError("refused " + what)
    return value


def check_label(value):
    if not isinstance(value, str) or not _LABEL.fullmatch(value):
        raise BlunixError("refused hostname")
    if "--" in value or value in _RESERVED or re.fullmatch(r"v[0-9]+", value):
        raise BlunixError("refused hostname")
    return value


def require_build_host(value):
    """Accept {label}.blnx.io, v{n}.{label}.blnx.io, and the legacy
    name-1042.build.blunix.io fixture form. Nothing is lowercased or trimmed
    here."""
    if not isinstance(value, str) or len(value) > 64:
        raise BlunixError("refused hostname")
    if _LEGACY_HOST.fullmatch(value):
        return value
    if not value.endswith(_BUILD_SUFFIX):
        raise BlunixError("refused hostname")
    parts = value[: -len(_BUILD_SUFFIX)].split(".")
    if len(parts) == 2:
        if not _VERSION.fullmatch(parts[0]):
            raise BlunixError("refused hostname")
        check_label(parts[1])
        return value
    if len(parts) == 1:
        check_label(parts[0])
        return value
    raise BlunixError("refused hostname")


def expand_build_host(typed):
    """A bare label becomes {label}.blnx.io. Anything else must already be a
    build host."""
    if not isinstance(typed, str):
        raise BlunixError("refused hostname")
    if "." not in typed:
        return check_label(typed) + _BUILD_SUFFIX
    return require_build_host(typed)


def require_bool(value, what):
    if not isinstance(value, bool):
        raise BlunixError("refused " + what)
    return value


def models_dir(explicit=None):
    if explicit:
        if not os.path.isdir(explicit):
            raise BlunixError("models directory not found")
        return explicit
    env = os.environ.get("BLUNIX_MODELS")
    candidates = []
    if env:
        candidates.append(env)
    candidates.append("/usr/share/blunix/models")
    here = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "models"))
    candidates.append(here)
    for candidate in candidates:
        if os.path.isdir(candidate):
            return candidate
    raise BlunixError("models directory not found")


def model_path(models, kind, name):
    require_name(name, kind)
    path = os.path.join(models, kind, name + ".yaml")
    root = os.path.realpath(models)
    real = os.path.realpath(path)
    if not real.startswith(root + os.sep):
        raise BlunixError("refused model path")
    if not os.path.isfile(real):
        raise BlunixError("model not found")
    return real


def write_bytes(path, data, mode=0o644):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, mode)


def write_text(path, text, mode=0o644):
    write_bytes(path, text.encode("utf-8"), mode)

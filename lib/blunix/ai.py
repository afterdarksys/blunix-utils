"""Threats: vendor CLIs are downloaded, not built into the image. A tool is
linked only after its sha256 matches the pin with a constant-time compare.
Any other host, a missing digest, or a bad digest leaves /var unchanged.

The URL paths for Grok, Claude, and Codex are the public installer layouts.
A wrong path has to fail the fetch. This module does not run an upstream
install script.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import ssl
import urllib.parse
import urllib.request

from blunix.errors import BlunixError
from blunix.schema import (
    load_path,
    model_path,
    require_bool,
    require_header,
    require_keys,
    require_name,
)

MAX_ARTIFACT = 256 * 1024 * 1024
_TOOLS = ("grok", "claude", "codex")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_AI_KEYS = {"apiVersion", "kind", "name", "enabled", "tools"}
_TOOL_KEYS = {"name", "version", "digest"}

# Redirects stay inside the host set for that vendor. GitHub release downloads
# hop to objects.githubusercontent.com. A hop to any other host is refused.
REDIRECT_HOSTS = {
    "grok": {"x.ai"},
    "claude": {"storage.googleapis.com"},
    "codex": {
        "github.com",
        "release-assets.githubusercontent.com",
        "objects.githubusercontent.com",
        "github-releases.githubusercontent.com",
        "releases.openai.com",
    },
}


def _version(value):
    if not isinstance(value, str) or not _VERSION.fullmatch(value) or ".." in value:
        raise BlunixError("refused version")
    return value


def artifact_url(name, version):
    version = _version(version)
    if name == "grok":
        # Platform string is not verified against a published checksum.
        return "https://x.ai/cli/grok-" + version + "-linux-amd64"
    if name == "claude":
        # Bucket path is the public installer layout and is not re-verified here.
        return (
            "https://storage.googleapis.com/"
            "claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/"
            "claude-code-releases/" + version + "/linux-x64/claude"
        )
    if name == "codex":
        # Asset path is not verified. A 404 or a bad digest fails closed.
        return (
            "https://github.com/openai/codex/releases/download/rust-v"
            + version
            + "/codex-x86_64-unknown-linux-musl.tar.gz"
        )
    raise BlunixError("refused tool")


def _check_url(name, url):
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or host not in REDIRECT_HOSTS[name]:
        raise BlunixError("refused tool url")
    if parts.username or parts.password:
        raise BlunixError("refused tool url")
    return host


class _Redirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed):
        super().__init__()
        self.allowed = allowed

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlsplit(newurl)
        host = (parts.hostname or "").lower()
        if parts.scheme != "https" or host not in self.allowed:
            raise BlunixError("refused redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def digest_matches(expected, data):
    if not isinstance(expected, str) or not _DIGEST.fullmatch(expected):
        return False
    if not isinstance(data, (bytes, bytearray)):
        return False
    want = expected.split(":", 1)[1]
    got = hashlib.sha256(data).hexdigest()
    return hmac.compare_digest(want, got)


def _read_limited(resp, limit):
    chunks = []
    total = 0
    while True:
        block = resp.read(65536)
        if not block:
            break
        total += len(block)
        if total > limit:
            raise BlunixError("response too large")
        chunks.append(block)
    return b"".join(chunks)


def default_fetch(name, url, timeout=60):
    host = _check_url(name, url)
    context = ssl.create_default_context()
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise BlunixError("tls verify disabled")
    opener = urllib.request.build_opener(
        _Redirect(REDIRECT_HOSTS[name]), urllib.request.HTTPSHandler(context=context)
    )
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "blunix-ai"})
    if host != urllib.parse.urlsplit(url).hostname:
        raise BlunixError("refused tool url")
    try:
        with opener.open(req, timeout=timeout) as resp:
            return _read_limited(resp, MAX_ARTIFACT)
    except BlunixError:
        raise
    except Exception:
        raise BlunixError("tool fetch failed")


def parse_ai(doc):
    if not isinstance(doc, dict):
        raise BlunixError("rejected plaintext")
    require_keys(doc, _AI_KEYS)
    require_header(doc, "AiTools")
    name = require_name(doc.get("name"), "name")
    enabled = require_bool(doc.get("enabled"), "enabled")
    tools = doc.get("tools")
    if not isinstance(tools, list) or len(tools) > 3:
        raise BlunixError("refused tools")
    parsed = []
    seen = set()
    for raw in tools:
        if not isinstance(raw, dict):
            raise BlunixError("refused tool")
        require_keys(raw, _TOOL_KEYS if enabled else _TOOL_KEYS | {"digest"})
        # digest is required when enabled and optional when disabled.
        allowed = set(_TOOL_KEYS)
        if not enabled:
            allowed = {"name", "version", "digest"}
        require_keys(raw, allowed)
        tool = raw.get("name")
        if tool not in _TOOLS or tool in seen:
            raise BlunixError("refused tool")
        seen.add(tool)
        item = {"name": tool, "version": _version(raw.get("version"))}
        if enabled or "digest" in raw:
            digest = raw.get("digest")
            if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
                raise BlunixError("refused digest")
            item["digest"] = digest
        elif enabled:
            raise BlunixError("refused digest")
        if enabled and "digest" not in item:
            raise BlunixError("refused digest")
        # Building the URL refuses a version that would escape the allowlist.
        item["url"] = artifact_url(tool, item["version"])
        _check_url(tool, item["url"])
        parsed.append(item)
    if enabled:
        for item in parsed:
            if "digest" not in item:
                raise BlunixError("refused digest")
    return {"name": name, "enabled": enabled, "tools": parsed}


def load_ai(models, name):
    parsed = parse_ai(load_path(model_path(models, "ai", name)))
    if parsed["name"] != name:
        raise BlunixError("refused name")
    return parsed


def _links(root):
    return os.path.join(root, "var", "lib", "blunix", "ai", "bin")


def remove_links(root):
    path = _links(root)
    if not os.path.isdir(path):
        return
    for name in _TOOLS:
        link = os.path.join(path, name)
        if os.path.islink(link):
            os.remove(link)


def install_ai(model, root, fetch=None):
    """Link pinned tools, or remove the links when the model is disabled.

    A failed digest or fetch writes nothing. Existing links stay until every
    tool in this run has been checked.
    """
    if not model["enabled"]:
        remove_links(root)
        return []
    if fetch is None:
        fetch = default_fetch
    staged = []
    base = os.path.join(root, "var", "lib", "blunix", "ai")
    stage = os.path.join(base, "stage")
    os.makedirs(stage, exist_ok=True)
    try:
        for tool in model["tools"]:
            data = fetch(tool["name"], tool["url"])
            if not digest_matches(tool["digest"], data):
                raise BlunixError("refused digest")
            filename = tool["name"] + "-" + tool["version"]
            path = os.path.join(stage, filename)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o755)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)
            os.chmod(path, 0o755)
            staged.append((tool["name"], path))
        link_dir = _links(root)
        os.makedirs(link_dir, exist_ok=True)
        linked = {name for name, _ in staged}
        for name in _TOOLS:
            link = os.path.join(link_dir, name)
            if name not in linked and os.path.islink(link):
                os.remove(link)
        for name, path in staged:
            link = os.path.join(link_dir, name)
            if os.path.islink(link) or os.path.exists(link):
                os.remove(link)
            os.symlink(path, link)
        return [name for name, _ in staged]
    except Exception:
        for _, path in staged:
            if os.path.exists(path):
                os.remove(path)
        raise

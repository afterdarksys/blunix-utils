"""Threats: After Dark tools are downloaded from GitHub, not built into the
image and not installed by an upstream script. A tool is linked only after
its sha256 matches the pin with a constant-time compare. The org is fixed.
A missing digest, a bad digest, another host, or a tarball that contains a
symlink or a path escape leaves /var unchanged.

What it does not stop: a pin a human reviewed that is itself the wrong
release. "latest" is not a version this module will fetch.
"""

from __future__ import annotations

import gzip
import io
import os
import re
import shutil
import ssl
import tarfile
import urllib.parse
import urllib.request

from blunix.ai import digest_matches
from blunix.errors import BlunixError
from blunix.schema import (
    load_path,
    model_path,
    require_bool,
    require_header,
    require_keys,
    require_name,
    write_bytes,
)

ORG = "afterdarksys"
MAX_ARTIFACT = 64 * 1024 * 1024
MAX_UNCOMPRESSED = 128 * 1024 * 1024
MAX_MEMBERS = 256
MAX_TOOLS = 16
_VERSION = re.compile(r"v?[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_ASSET = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_REPO = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_DEST = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_DOC_KEYS = {"apiVersion", "kind", "name", "tools"}
_TOOL_KEYS = {"name", "repo", "version", "asset", "default", "files", "digest"}
_FILE_KEYS = {"archive", "dest"}

REDIRECT_HOSTS = {
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
    "github-releases.githubusercontent.com",
}


def _version(value):
    if not isinstance(value, str) or value == "latest" or not _VERSION.fullmatch(value):
        raise BlunixError("refused version")
    if ".." in value:
        raise BlunixError("refused version")
    return value


def _asset(value):
    if not isinstance(value, str) or value == "latest" or not _ASSET.fullmatch(value):
        raise BlunixError("refused asset")
    if not value.endswith(".tar.gz"):
        raise BlunixError("refused asset")
    if value.endswith((".sh", ".bash", ".py")) or "install" in value.lower():
        raise BlunixError("refused asset")
    return value


def _repo(value):
    if not isinstance(value, str) or not _REPO.fullmatch(value):
        raise BlunixError("refused repo")
    return value


def _archive_path(value):
    if not isinstance(value, str) or "/" not in value or value.startswith("/"):
        raise BlunixError("refused archive path")
    parts = value.split("/")
    if any(not _PART.fullmatch(part) for part in parts):
        raise BlunixError("refused archive path")
    return value


def _dest(value):
    if not isinstance(value, str) or not _DEST.fullmatch(value):
        raise BlunixError("refused dest")
    return value


def artifact_url(repo, version, asset):
    repo = _repo(repo)
    version = _version(version)
    asset = _asset(asset)
    return (
        "https://github.com/"
        + ORG
        + "/"
        + repo
        + "/releases/download/"
        + version
        + "/"
        + asset
    )


def _check_url(url):
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or host not in REDIRECT_HOSTS:
        raise BlunixError("refused tool url")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise BlunixError("refused tool url")
    prefix = "/" + ORG + "/"
    if not parts.path.startswith(prefix) or "/releases/latest" in parts.path:
        raise BlunixError("refused tool url")
    return host


class _Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlsplit(newurl)
        host = (parts.hostname or "").lower()
        if parts.scheme != "https" or host not in REDIRECT_HOSTS:
            raise BlunixError("refused redirect")
        if parts.username or parts.password:
            raise BlunixError("refused redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


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
    host = _check_url(url)
    context = ssl.create_default_context()
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise BlunixError("tls verify disabled")
    opener = urllib.request.build_opener(
        _Redirect(), urllib.request.HTTPSHandler(context=context)
    )
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "blunix-tools"})
    if host != urllib.parse.urlsplit(url).hostname:
        raise BlunixError("refused tool url")
    if not isinstance(name, str) or not name:
        raise BlunixError("refused tool")
    try:
        with opener.open(req, timeout=timeout) as resp:
            return _read_limited(resp, MAX_ARTIFACT)
    except BlunixError:
        raise
    except Exception:
        raise BlunixError("tool fetch failed")


def _gunzip(data):
    if not isinstance(data, (bytes, bytearray)) or data[:2] != b"\x1f\x8b":
        raise BlunixError("refused archive")
    chunks = []
    total = 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(bytes(data))) as handle:
            while True:
                block = handle.read(65536)
                if not block:
                    break
                total += len(block)
                if total > MAX_UNCOMPRESSED:
                    raise BlunixError("response too large")
                chunks.append(block)
    except BlunixError:
        raise
    except Exception:
        raise BlunixError("refused archive")
    return b"".join(chunks)


def extract_named(data, wanted):
    """Return the named regular files. A symlink or a path escape refuses the
    whole archive, including entries that were not requested.
    """
    if not isinstance(wanted, (list, tuple)) or not wanted:
        raise BlunixError("refused archive")
    plain = _gunzip(data)
    try:
        tar = tarfile.open(fileobj=io.BytesIO(plain), mode="r:")
    except tarfile.TarError:
        raise BlunixError("refused archive")
    members = tar.getmembers()
    if len(members) > MAX_MEMBERS:
        raise BlunixError("refused archive")
    total = 0
    for member in members:
        name = member.name
        if (
            not isinstance(name, str)
            or name.startswith("/")
            or "\\" in name
            or "\x00" in name
        ):
            raise BlunixError("refused archive")
        parts = name.split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise BlunixError("refused archive")
        if member.issym() or member.islnk() or member.isdev() or member.isfifo():
            raise BlunixError("refused archive")
        total += member.size
        if total > MAX_UNCOMPRESSED:
            raise BlunixError("response too large")
    found = {}
    for name in wanted:
        member = tar.getmember(name) if name in tar.getnames() else None
        if member is None or not member.isfile():
            raise BlunixError("refused archive")
        handle = tar.extractfile(member)
        if handle is None:
            raise BlunixError("refused archive")
        blob = handle.read(member.size + 1)
        if len(blob) != member.size or len(blob) > MAX_UNCOMPRESSED:
            raise BlunixError("refused archive")
        found[name] = blob
    return found


def parse_tools(doc):
    if not isinstance(doc, dict):
        raise BlunixError("rejected plaintext")
    require_keys(doc, _DOC_KEYS)
    require_header(doc, "GithubTools")
    name = require_name(doc.get("name"), "name")
    tools = doc.get("tools")
    if not isinstance(tools, list) or len(tools) > MAX_TOOLS:
        raise BlunixError("refused tools")
    parsed = []
    seen = set()
    dests = set()
    for raw in tools:
        if not isinstance(raw, dict):
            raise BlunixError("refused tool")
        require_keys(raw, _TOOL_KEYS if "digest" in raw else _TOOL_KEYS - {"digest"})
        tool_name = raw.get("name")
        if not isinstance(tool_name, str) or not _DEST.fullmatch(tool_name) or tool_name in seen:
            raise BlunixError("refused tool")
        seen.add(tool_name)
        files = raw.get("files")
        if not isinstance(files, list) or not files or len(files) > 8:
            raise BlunixError("refused files")
        parsed_files = []
        archives = set()
        for item in files:
            if not isinstance(item, dict):
                raise BlunixError("refused files")
            require_keys(item, _FILE_KEYS)
            archive = _archive_path(item.get("archive"))
            dest = _dest(item.get("dest"))
            if archive in archives or dest in dests:
                raise BlunixError("refused files")
            archives.add(archive)
            dests.add(dest)
            parsed_files.append({"archive": archive, "dest": dest})
        entry = {
            "name": tool_name,
            "repo": _repo(raw.get("repo")),
            "version": _version(raw.get("version")),
            "asset": _asset(raw.get("asset")),
            "default": require_bool(raw.get("default"), "default"),
            "files": parsed_files,
        }
        if "digest" in raw:
            digest = raw.get("digest")
            if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
                raise BlunixError("refused digest")
            entry["digest"] = digest
        entry["url"] = artifact_url(entry["repo"], entry["version"], entry["asset"])
        _check_url(entry["url"])
        parsed.append(entry)
    return {"name": name, "tools": parsed}


def load_tools(models, name):
    parsed = parse_tools(load_path(model_path(models, "tools", name)))
    if parsed["name"] != name:
        raise BlunixError("refused name")
    return parsed


def select_tools(model, names):
    by_name = {tool["name"]: tool for tool in model["tools"]}
    if names:
        chosen = []
        seen = set()
        for name in names:
            if name not in by_name or name in seen:
                raise BlunixError("refused tool")
            seen.add(name)
            chosen.append(by_name[name])
        return chosen
    return [tool for tool in model["tools"] if tool["default"]]


def _final_path(root, tool, dest):
    return os.path.join(
        root, "var", "lib", "blunix", "tools", tool["name"], tool["version"], dest
    )


def install_tools(model, root, names=None, fetch=None):
    """Link the selected tools after every digest matches.

    names selects those tools. No names means the tools marked default.
    A selected tool with no digest fails the run and writes nothing.
    """
    chosen = select_tools(model, names)
    for tool in chosen:
        if "digest" not in tool:
            raise BlunixError("refused digest")
    if not chosen:
        return []
    if fetch is None:
        fetch = default_fetch
    stage_root = os.path.join(root, "var", "lib", "blunix", "tools", "stage")
    staged = []
    try:
        for tool in chosen:
            data = fetch(tool["name"], tool["url"])
            if not digest_matches(tool["digest"], data):
                raise BlunixError("refused digest")
            members = extract_named(data, [item["archive"] for item in tool["files"]])
            for item in tool["files"]:
                path = os.path.join(stage_root, tool["name"], tool["version"], item["dest"])
                write_bytes(path, members[item["archive"]], 0o755)
                staged.append((path, _final_path(root, tool, item["dest"]), item["dest"]))
        link_dir = os.path.join(root, "var", "lib", "blunix", "tools", "bin")
        os.makedirs(link_dir, exist_ok=True)
        linked = []
        for stage, final, dest in staged:
            os.makedirs(os.path.dirname(final), exist_ok=True)
            os.replace(stage, final)
            os.chmod(final, 0o755)
            link = os.path.join(link_dir, dest)
            if os.path.lexists(link):
                os.remove(link)
            os.symlink(os.path.relpath(final, link_dir), link)
            linked.append(dest)
        return linked
    except Exception:
        for stage, _, _ in staged:
            if os.path.exists(stage):
                os.remove(stage)
        raise
    finally:
        if os.path.isdir(stage_root):
            shutil.rmtree(stage_root, ignore_errors=True)

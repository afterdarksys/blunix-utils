"""Build official Blunix release images from signed tags and stage them in R2.

    blunix-builder run [--config PATH]
    blunix-builder check-config [--config PATH]

One run: list the public repository's tags with `git ls-remote`, pick the
oldest release tag that has not been built, fetch it into a local bare
mirror, accept it only when its tag signature verifies against the pinned
signer allowlist, check it out into a fresh worktree, run the image build in
a throwaway privileged container started from a digest-pinned image, write
SOURCES.md, build-provenance.json and SHA256SUMS, and upload the release
directory to `{bucket}/{tag}/` with an S3 SigV4 PUT. build-provenance.json is
uploaded last and is the "this tag is staged" marker.

Threats: a forged, unsigned, lightweight, renamed (replayed) or re-pointed tag
building as a release; a hostile tag name escaping the work or object paths;
a floating base image; a stale package cache; the R2 credential reaching the
build container, the logs or the provenance; a half-uploaded release looking
complete; two runs racing. It does NOT protect against a compromised builder
host (the privileged container makes the host the trust boundary), a
compromised Debian mirror (no snapshot pinning yet), or a malicious commit
that was signed with a trusted key. It does not sign anything; signing is a
separate offline step over SHA256SUMS.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import errno
import fcntl
import hashlib
import hmac
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

__version__ = "0.1.0"

DEFAULT_CONFIG = "/etc/blunix-builder/config.yaml"
SHARE_DIR = Path(__file__).resolve().parent
INSIDE_SCRIPT = "inside-release.sh"
CREDENTIAL_NAME = "blunix-r2"
PROVENANCE = "build-provenance.json"
SUMS = "SHA256SUMS"
SCHEMA = "blunix-build-provenance/1"
REQUIRED_ARTIFACTS = ("blunix-installer.iso", "blunix.raw.zst", "SOURCES.md")

# vMAJOR.MINOR.PATCH with an optional -rc.N/-beta.N/-alpha.N. Nothing else:
# no slashes, no dots-only names, no shell or path metacharacters.
TAG_RE = re.compile(
    r"v(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})"
    r"(?:-(alpha|beta|rc)\.(0|[1-9][0-9]{0,3}))?\Z")
OID_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
FPR_RE = re.compile(r"[0-9A-F]{40}\Z")
SSH_FPR_RE = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
IMAGE_RE = re.compile(
    r"([a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?/)?"
    r"[a-z0-9]+(?:[._/-][a-z0-9]+)*(?::[A-Za-z0-9._-]{1,128})?"
    r"@sha256:([0-9a-f]{64})\Z")
NETWORK_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,62}\Z")
BUCKET_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]\Z")
ARTIFACT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
ACCESS_KEY_RE = re.compile(r"[A-Za-z0-9]{16,128}\Z")
SECRET_KEY_RE = re.compile(r"[A-Za-z0-9/+=_-]{16,256}\Z")

GIT_TIMEOUT = 600
GPG_TIMEOUT = 120
HTTP_TIMEOUT = 300
MAX_REMOTE_REFS = 5000
_BAD_GPG = ("BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG",
            "NO_PUBKEY", "NODATA", "FAILURE")


MAX_BUILD_TIMEOUT = 4 * 3600
# Every build container carries this label, so the unit's ExecStopPost can
# remove one that a systemd stop orphaned. Rehearsals do not carry it.
CONTAINER_LABEL = "blunix-builder=release"


class BuilderError(Exception):
    """A fail-closed stop. The message must never contain a secret."""


# --------------------------------------------------------------------- logging

def log(event, level="info", **fields):
    """One JSON line on stdout; journald adds time and unit.

    Callers pass only non-secret fields. Credential values never reach here.
    """
    record = {"level": level, "event": event}
    record.update(fields)
    sys.stdout.write(json.dumps(record, sort_keys=True, default=str) + "\n")
    sys.stdout.flush()


def _short(text, limit=96):
    """Bound and neutralise untrusted text before it is logged."""
    text = str(text)
    return repr(text[:limit]) + ("..." if len(text) > limit else "")


def utcnow():
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)


def iso(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------- config

_CONFIG_KEYS = {
    "repo_url", "poll_interval", "container_image", "container_network",
    "build_timeout", "state_dir", "work_dir", "keep_builds", "max_attempts",
    "trusted_keys", "trusted_fingerprints", "allowed_signers",
    "trusted_ssh_fingerprints", "r2",
}
_R2_KEYS = {"endpoint", "bucket", "region", "credentials_file", "check_existing"}


def _require(cond, message):
    if not cond:
        raise BuilderError("config: " + message)


def _abs_path(value, name):
    _require(isinstance(value, str) and value.startswith("/")
             and "\x00" not in value and ".." not in Path(value).parts,
             f"{name} must be an absolute path")
    return Path(value)


def _int(value, name, low, high):
    _require(isinstance(value, int) and not isinstance(value, bool)
             and low <= value <= high, f"{name} must be an integer {low}..{high}")
    return value


def validate_config(raw):
    """Return a normalised config dict, or raise BuilderError. No defaults for
    anything that decides trust: repo, image digest, keys, bucket, endpoint."""
    _require(isinstance(raw, dict), "top level must be a mapping")
    unknown = set(raw) - _CONFIG_KEYS
    _require(not unknown, f"unknown keys {sorted(unknown)}")
    cfg = {}

    repo = raw.get("repo_url")
    _require(isinstance(repo, str), "repo_url is required")
    parsed = urllib.parse.urlsplit(repo)
    _require(parsed.scheme == "https" and bool(parsed.hostname)
             and not parsed.username and not parsed.password
             and not parsed.query and not parsed.fragment
             and re.fullmatch(r"/[A-Za-z0-9_-][A-Za-z0-9._-]*/[A-Za-z0-9_-][A-Za-z0-9._-]*",
                              parsed.path or "") is not None
             and ".." not in parsed.path,
             "repo_url must be a credential-free https URL")
    cfg["repo_url"] = repo

    cfg["poll_interval"] = _int(raw.get("poll_interval", 600), "poll_interval", 60, 86400)
    # At most 4h: blunix-builder.service stops the run at TimeoutStartSec=5h, and
    # git, the image pull and the upload need the rest. A build systemd kills
    # instead of this timeout leaves its container to ExecStopPost.
    cfg["build_timeout"] = _int(raw.get("build_timeout", 14400), "build_timeout", 600, MAX_BUILD_TIMEOUT)
    cfg["keep_builds"] = _int(raw.get("keep_builds", 2), "keep_builds", 1, 20)
    cfg["max_attempts"] = _int(raw.get("max_attempts", 3), "max_attempts", 1, 20)

    image = raw.get("container_image")
    _require(isinstance(image, str) and IMAGE_RE.fullmatch(image),
             "container_image must be pinned as name@sha256:<64 hex>")
    _require(set(IMAGE_RE.fullmatch(image).group(2)) != {"0"},
             "container_image digest is the placeholder; pin a real digest")
    cfg["container_image"] = image
    cfg["container_digest"] = "sha256:" + IMAGE_RE.fullmatch(image).group(2)

    network = raw.get("container_network", "bridge")
    _require(isinstance(network, str) and NETWORK_RE.fullmatch(network)
             and network != "host", "container_network must be a named network, not host")
    cfg["container_network"] = network

    cfg["state_dir"] = _abs_path(raw.get("state_dir", "/var/lib/blunix-builder"), "state_dir")
    cfg["work_dir"] = _abs_path(raw.get("work_dir", "/srv/blunix-builds"), "work_dir")

    cfg["trusted_keys"] = _abs_path(raw.get("trusted_keys"), "trusted_keys")
    fprs = raw.get("trusted_fingerprints")
    _require(isinstance(fprs, list) and fprs
             and all(isinstance(f, str) and FPR_RE.fullmatch(f) for f in fprs),
             "trusted_fingerprints must list 40-hex uppercase OpenPGP fingerprints")
    cfg["trusted_fingerprints"] = frozenset(fprs)

    signers = raw.get("allowed_signers")
    ssh_fprs = raw.get("trusted_ssh_fingerprints", [])
    if signers is None:
        _require(not ssh_fprs, "trusted_ssh_fingerprints needs allowed_signers")
        cfg["allowed_signers"] = None
    else:
        cfg["allowed_signers"] = _abs_path(signers, "allowed_signers")
        _require(isinstance(ssh_fprs, list) and ssh_fprs
                 and all(isinstance(f, str) and SSH_FPR_RE.fullmatch(f) for f in ssh_fprs),
                 "trusted_ssh_fingerprints must list SHA256:<base64> fingerprints")
    cfg["trusted_ssh_fingerprints"] = frozenset(ssh_fprs)

    r2 = raw.get("r2")
    _require(isinstance(r2, dict), "r2 section is required")
    unknown = set(r2) - _R2_KEYS
    _require(not unknown, f"unknown r2 keys {sorted(unknown)}")
    endpoint = r2.get("endpoint")
    _require(isinstance(endpoint, str), "r2.endpoint is required")
    ep = urllib.parse.urlsplit(endpoint)
    _require(ep.scheme == "https" and ep.hostname and ep.path in ("", "/")
             and not ep.username and not ep.query and not ep.fragment,
             "r2.endpoint must be a bare https origin")
    bucket = r2.get("bucket")
    _require(isinstance(bucket, str) and BUCKET_RE.fullmatch(bucket), "r2.bucket is invalid")
    region = r2.get("region", "auto")
    _require(isinstance(region, str) and re.fullmatch(r"[a-z0-9-]{2,32}", region),
             "r2.region is invalid")
    check = r2.get("check_existing", True)
    _require(isinstance(check, bool), "r2.check_existing must be true or false")
    cfg["r2"] = {
        "host": ep.hostname,
        "port": ep.port or 443,
        "bucket": bucket,
        "region": region,
        "credentials_file": _abs_path(r2.get("credentials_file"), "r2.credentials_file"),
        "check_existing": check,
    }
    return cfg


def check_trust_files(cfg):
    """The trust root must exist, be a regular non-empty file, and not be
    writable by anyone but its owner. Missing trust root = no builds."""
    paths = [cfg["trusted_keys"]]
    if cfg["allowed_signers"] is not None:
        paths.append(cfg["allowed_signers"])
    for path in paths:
        try:
            info = path.lstat()
        except OSError:
            raise BuilderError(f"trust root missing: {path}") from None
        if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
            raise BuilderError(f"trust root is not a non-empty regular file: {path}")
        if info.st_mode & 0o022:
            raise BuilderError(f"trust root is group/world writable: {path}")


def load_config(path):
    import yaml  # PyYAML; already a repo dependency.

    try:
        with open(path, "rb") as handle:
            data = handle.read(65536 + 1)
    except OSError as exc:
        raise BuilderError(f"config: cannot read {path}: {exc.strerror}") from None
    if len(data) > 65536:
        raise BuilderError("config: file too large")
    try:
        raw = yaml.safe_load(data)
    except yaml.YAMLError:
        raise BuilderError("config: not valid YAML") from None
    cfg = validate_config(raw)
    cfg["config_sha256"] = hashlib.sha256(data).hexdigest()
    return cfg


# ----------------------------------------------------------------- credentials

def load_credentials(cfg, environ=None):
    """Read the R2 key pair. Prefer the systemd LoadCredential copy.

    File format, one per line: access_key_id=...  secret_access_key=...
    The file must be a regular file owned by us or root with no group/other
    permission bits. Errors never include the file contents.
    """
    environ = os.environ if environ is None else environ
    path = cfg["r2"]["credentials_file"]
    cred_dir = environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir:
        candidate = Path(cred_dir) / CREDENTIAL_NAME
        if candidate.exists():
            path = candidate
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise BuilderError("credentials: cannot open credential file") from None
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise BuilderError("credentials: not a regular file")
        if info.st_mode & 0o077:
            raise BuilderError("credentials: file must be mode 0600 or 0400")
        if info.st_uid not in (os.getuid(), 0):
            raise BuilderError("credentials: unexpected file owner")
        data = handle.read(4097)
    if len(data) > 4096:
        raise BuilderError("credentials: file too large")
    values = {}
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise BuilderError("credentials: file is not ASCII") from None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or key.strip() not in ("access_key_id", "secret_access_key"):
            raise BuilderError("credentials: unexpected line")
        values[key.strip()] = value.strip()
    access = values.get("access_key_id", "")
    secret = values.get("secret_access_key", "")
    if not ACCESS_KEY_RE.fullmatch(access) or not SECRET_KEY_RE.fullmatch(secret):
        raise BuilderError("credentials: access_key_id/secret_access_key missing or malformed")
    return access, secret


def fingerprint(secret):
    """Loggable stand-in for a credential (rule 6)."""
    return hashlib.sha256(secret.encode()).hexdigest()[:16]


# ----------------------------------------------------------------------- SigV4

_UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def uri_encode(text, keep_slash):
    safe = _UNRESERVED + ("/" if keep_slash else "")
    return urllib.parse.quote(text, safe=safe)


def _hmac(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def signing_key(secret, date, region, service):
    k = _hmac(("AWS4" + secret).encode("utf-8"), date)
    k = _hmac(k, region)
    k = _hmac(k, service)
    return _hmac(k, "aws4_request")


def sigv4_headers(method, host, path, query, headers, payload_sha256,
                  access_key, secret_key, region, service, amz_date):
    """Return headers including Authorization for an AWS SigV4 request.

    `path` is the raw (unencoded) object path; S3 encodes each segment once.
    `headers` must not already contain Authorization. Values are trimmed and
    names lower-cased, per the SigV4 canonical form.
    """
    date = amz_date[:8]
    all_headers = {k.lower(): " ".join(str(v).strip().split()) for k, v in headers.items()}
    all_headers["host"] = host
    all_headers["x-amz-date"] = amz_date
    if service == "s3":
        all_headers.setdefault("x-amz-content-sha256", payload_sha256)
    names = sorted(all_headers)
    canonical_headers = "".join(f"{n}:{all_headers[n]}\n" for n in names)
    signed = ";".join(names)
    canonical_query = "&".join(
        f"{uri_encode(k, False)}={uri_encode(v, False)}"
        for k, v in sorted(query.items()))
    canonical = "\n".join([
        method,
        uri_encode(path, True),
        canonical_query,
        canonical_headers,
        signed,
        payload_sha256,
    ])
    scope = f"{date}/{region}/{service}/aws4_request"
    to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope,
        hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    ])
    signature = hmac.new(signing_key(secret_key, date, region, service),
                         to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    out = dict(all_headers)
    out["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders={signed}, Signature={signature}")
    return out


class R2Client:
    """Minimal S3 client: HEAD and single-part PUT, path-style, TLS >= 1.3."""

    def __init__(self, r2cfg, access_key, secret_key, connect=None, clock=None):
        self.cfg = r2cfg
        self._access = access_key
        self._secret = secret_key
        self._connect = connect or self._tls_connection
        self._clock = clock or utcnow

    def __repr__(self):  # never expose the key pair through repr/logging
        return f"R2Client(bucket={self.cfg['bucket']!r}, key_fp={fingerprint(self._access)})"

    def _tls_connection(self):
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        return http.client.HTTPSConnection(
            self.cfg["host"], self.cfg["port"], timeout=HTTP_TIMEOUT, context=context)

    def _host_header(self):
        port = self.cfg["port"]
        return self.cfg["host"] if port == 443 else f"{self.cfg['host']}:{port}"

    def _path(self, key):
        return f"/{self.cfg['bucket']}/{key}"

    def _request(self, method, key, body=None, length=0, payload_sha256=EMPTY_SHA256,
                 extra=None):
        path = self._path(key)
        headers = dict(extra or {})
        if method == "PUT":
            headers["content-length"] = str(length)
        signed = sigv4_headers(method, self._host_header(), path, {}, headers,
                               payload_sha256, self._access, self._secret,
                               self.cfg["region"], "s3", self._clock().strftime("%Y%m%dT%H%M%SZ"))
        conn = self._connect()
        try:
            conn.putrequest(method, uri_encode(path, True), skip_host=True,
                            skip_accept_encoding=True)
            for name, value in signed.items():
                conn.putheader(name, value)
            conn.endheaders()
            if body is not None:
                while True:
                    chunk = body.read(1024 * 1024)
                    if not chunk:
                        break
                    conn.send(chunk)
            response = conn.getresponse()
            status = response.status
            response.read(65536)  # drain a bounded amount; never logged
            return status
        except (OSError, http.client.HTTPException) as exc:
            raise BuilderError(f"r2: {method} {key} failed: {type(exc).__name__}") from None
        finally:
            conn.close()

    def exists(self, key):
        status = self._request("HEAD", key)
        if status == 200:
            return True
        if status == 404:
            return False
        raise BuilderError(f"r2: HEAD {key} returned {status}; refusing to guess")

    def put_file(self, key, path, sha256_hex):
        length = path.stat().st_size
        with open(path, "rb") as handle:
            status = self._request(
                "PUT", key, body=handle, length=length, payload_sha256=sha256_hex,
                extra={"content-type": "application/octet-stream"})
        if status != 200:
            raise BuilderError(f"r2: PUT {key} returned {status}")


# ---------------------------------------------------------------- subprocesses

def base_env(home):
    """Minimal environment for children. Never inherits the R2 key pair."""
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }


def run_cmd(argv, env, timeout, cwd=None, stdout=None):
    """subprocess.run with a hard timeout; returns CompletedProcess."""
    try:
        return subprocess.run(
            argv, env=env, cwd=cwd, timeout=timeout, check=False,
            stdin=subprocess.DEVNULL,
            stdout=stdout if stdout is not None else subprocess.PIPE,
            stderr=subprocess.STDOUT if stdout is not None else subprocess.PIPE)
    except subprocess.TimeoutExpired:
        raise BuilderError(f"{Path(argv[0]).name} timed out") from None
    except OSError as exc:
        raise BuilderError(f"{Path(argv[0]).name} could not start: {exc.strerror}") from None


_GIT_HARDEN = [
    "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
    "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
    "-c", "transfer.fsckObjects=true", "-c", "credential.helper=",
]


# ------------------------------------------------------------------ tag logic

def valid_tag(name):
    return isinstance(name, str) and len(name) <= 32 and TAG_RE.fullmatch(name) is not None


def tag_sort_key(name):
    m = TAG_RE.fullmatch(name)
    major, minor, patch, pre, pre_n = m.groups()
    # A final release sorts after its pre-releases.
    rank = {"alpha": 0, "beta": 1, "rc": 2, None: 3}[pre]
    return (int(major), int(minor), int(patch), rank, int(pre_n or 0))


def parse_ls_remote(text):
    """Return {tag: (tag_object, commit)} for annotated, well-formed tags only.

    Lightweight tags (no peeled ^{} line) and invalid names are dropped and
    reported in the second return value.
    """
    objects, peeled, rejected = {}, {}, []
    lines = text.splitlines()
    if len(lines) > MAX_REMOTE_REFS:
        raise BuilderError("ls-remote: too many refs")
    for line in lines:
        oid, sep, ref = line.partition("\t")
        if not sep or not OID_RE.fullmatch(oid) or not ref.startswith("refs/tags/"):
            continue
        name = ref[len("refs/tags/"):]
        is_peeled = name.endswith("^{}")
        if is_peeled:
            name = name[:-3]
        if not valid_tag(name):
            rejected.append((name, "invalid tag name"))
            continue
        (peeled if is_peeled else objects)[name] = oid
    tags = {}
    for name, oid in objects.items():
        if name not in peeled:
            rejected.append((name, "lightweight tag (unsigned)"))
            continue
        tags[name] = (oid, peeled[name])
    return tags, rejected


def parse_gpg_status(status, allowlist):
    """Return the trusted primary fingerprint, or raise BuilderError."""
    tokens = []
    for line in status.splitlines():
        if line.startswith("[GNUPG:] "):
            tokens.append(line[9:].split())
    kinds = {t[0] for t in tokens if t}
    bad = kinds.intersection(_BAD_GPG)
    if bad:
        raise BuilderError(f"tag signature rejected ({sorted(bad)[0]})")
    if "GOODSIG" not in kinds:
        raise BuilderError("tag signature rejected (no good signature)")
    valid = [t for t in tokens if t and t[0] == "VALIDSIG"]
    if len(valid) != 1:
        raise BuilderError("tag signature rejected (expected exactly one signature)")
    fields = valid[0]
    primary = fields[10] if len(fields) > 10 else fields[1]
    if primary.upper() not in allowlist:
        raise BuilderError("tag signature rejected (signer not in allowlist)")
    return primary.upper()


_SSH_GOOD = re.compile(r'Good "git" signature for \S+ with \S+ key (SHA256:[A-Za-z0-9+/]{43})')


def parse_ssh_status(output, allowlist):
    found = _SSH_GOOD.findall(output)
    if len(found) != 1 or found[0] not in allowlist:
        raise BuilderError("tag signature rejected (ssh signer not in allowlist)")
    return found[0]


class Git:
    def __init__(self, cfg, runner=run_cmd):
        self.cfg = cfg
        self.run = runner
        self.mirror = cfg["state_dir"] / "mirror.git"
        self.env = base_env(cfg["state_dir"])

    def _git(self, *args, env=None, timeout=GIT_TIMEOUT, git_dir=True):
        argv = ["git"] + _GIT_HARDEN
        if git_dir:
            argv += ["--git-dir", str(self.mirror)]
        argv += list(args)
        return self.run(argv, env or self.env, timeout)

    def ls_remote(self):
        result = self._git("ls-remote", "--tags", "--", self.cfg["repo_url"], git_dir=False)
        if result.returncode != 0:
            raise BuilderError("git ls-remote failed")
        return result.stdout.decode("utf-8", "replace")

    def ensure_mirror(self):
        if not (self.mirror / "HEAD").is_file():
            result = self._git("init", "--bare", "-q", str(self.mirror), git_dir=False)
            if result.returncode != 0:
                raise BuilderError("git init failed")

    def fetch_tag(self, tag):
        ref = f"refs/tags/{tag}"
        result = self._git("fetch", "--no-tags", "--force", "-q", "--",
                           self.cfg["repo_url"], f"+{ref}:{ref}")
        if result.returncode != 0:
            raise BuilderError("git fetch failed")

    def rev(self, spec):
        result = self._git("rev-parse", "--verify", "-q", spec)
        out = result.stdout.decode().strip()
        if result.returncode != 0 or not OID_RE.fullmatch(out):
            raise BuilderError("git rev-parse failed")
        return out

    def object_type(self, oid):
        result = self._git("cat-file", "-t", oid)
        return result.stdout.decode().strip() if result.returncode == 0 else ""

    def tag_header_name(self, oid):
        result = self._git("cat-file", "tag", oid)
        if result.returncode != 0:
            raise BuilderError("git cat-file tag failed")
        for line in result.stdout.decode("utf-8", "replace").split("\n"):
            if not line:
                break
            if line.startswith("tag "):
                return line[4:]
        return None

    def tag_body(self, oid):
        result = self._git("cat-file", "tag", oid)
        return result.stdout.decode("utf-8", "replace") if result.returncode == 0 else ""

    def verify_signature(self, tag, oid):
        """Verify against a throwaway keyring holding only the pinned keys."""
        body = self.tag_body(oid)
        if "-----BEGIN SSH SIGNATURE-----" in body:
            if self.cfg["allowed_signers"] is None:
                raise BuilderError("tag signature rejected (ssh signatures not enabled)")
            result = self._git("-c", f"gpg.ssh.allowedSignersFile={self.cfg['allowed_signers']}",
                               "verify-tag", "--raw", oid)
            output = (result.stdout + result.stderr).decode("utf-8", "replace")
            if result.returncode != 0:
                raise BuilderError("tag signature rejected (ssh verify failed)")
            return "ssh:" + parse_ssh_status(output, self.cfg["trusted_ssh_fingerprints"])
        if "-----BEGIN PGP SIGNATURE-----" not in body:
            raise BuilderError("tag signature rejected (unsigned tag)")
        with tempfile.TemporaryDirectory(prefix="blunix-gnupg-") as home:
            os.chmod(home, 0o700)
            env = dict(self.env, GNUPGHOME=home)
            imported = self.run(["gpg", "--batch", "--no-tty", "--quiet", "--import",
                                 str(self.cfg["trusted_keys"])], env, GPG_TIMEOUT)
            if imported.returncode != 0:
                raise BuilderError("trust root could not be imported")
            result = self._git("-c", "gpg.program=gpg", "verify-tag", "--raw", oid, env=env)
            status = (result.stdout + result.stderr).decode("utf-8", "replace")
            if result.returncode != 0:
                parse_gpg_status(status, self.cfg["trusted_fingerprints"])  # names the reason
                raise BuilderError("tag signature rejected (verify-tag failed)")
            return "openpgp:" + parse_gpg_status(status, self.cfg["trusted_fingerprints"])

    def add_worktree(self, path, commit):
        result = self._git("worktree", "add", "--detach", "-f", str(path), commit)
        if result.returncode != 0:
            raise BuilderError("git worktree add failed")

    def remove_worktree(self, path):
        self._git("worktree", "remove", "--force", str(path))
        self._git("worktree", "prune")


def verify_tag(git, tag, tag_object, commit):
    """Fetch and verify one tag. Returns (signer, commit). Fail closed."""
    git.ensure_mirror()
    git.fetch_tag(tag)
    local_obj = git.rev(f"refs/tags/{tag}")
    if not hmac.compare_digest(local_obj, tag_object):
        raise BuilderError("tag object changed between ls-remote and fetch")
    if git.object_type(local_obj) != "tag":
        raise BuilderError("tag signature rejected (lightweight tag)")
    # A signed tag carries its own name. Re-publishing an old signed tag under
    # a new ref name (a replay) must not build as the new version.
    if git.tag_header_name(local_obj) != tag:
        raise BuilderError("tag signature rejected (tag name does not match signed name)")
    signer = git.verify_signature(tag, local_obj)
    local_commit = git.rev(f"{local_obj}^{{commit}}")
    if not hmac.compare_digest(local_commit, commit):
        raise BuilderError("tag commit does not match ls-remote")
    return signer, local_commit


# ---------------------------------------------------------------------- state

class State:
    def __init__(self, state_dir):
        self.root = state_dir
        self.built = state_dir / "built"
        self.rejected = state_dir / "rejected"
        self.attempts = state_dir / "attempts"

    def setup(self):
        for path in (self.root, self.built, self.rejected, self.attempts):
            path.mkdir(mode=0o750, parents=True, exist_ok=True)

    @staticmethod
    def _name(tag):
        if not valid_tag(tag):
            raise BuilderError("refusing state path for invalid tag")
        return tag + ".json"

    def _read(self, folder, tag):
        try:
            return json.loads((folder / self._name(tag)).read_text())
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            raise BuilderError("state file unreadable") from None

    def _write(self, folder, tag, data):
        target = folder / self._name(tag)
        fd, tmp = tempfile.mkstemp(dir=str(folder), prefix=".tmp-")
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump(data, handle, sort_keys=True, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, target)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def is_built(self, tag):
        return self._read(self.built, tag) is not None

    def mark_built(self, tag, data):
        self._write(self.built, tag, data)

    def rejected_object(self, tag):
        data = self._read(self.rejected, tag)
        return data.get("tag_object") if data else None

    def mark_rejected(self, tag, tag_object, reason):
        self._write(self.rejected, tag, {"tag_object": tag_object, "reason": reason,
                                         "at": iso(utcnow())})

    def attempts_for(self, tag, tag_object):
        data = self._read(self.attempts, tag)
        if not data or data.get("tag_object") != tag_object:
            return 0
        return int(data.get("count", 0))

    def bump_attempts(self, tag, tag_object):
        count = self.attempts_for(tag, tag_object) + 1
        self._write(self.attempts, tag, {"tag_object": tag_object, "count": count,
                                         "at": iso(utcnow())})
        return count

    def last_poll(self):
        try:
            return float((self.root / "last-poll").read_text().strip())
        except (OSError, ValueError):
            return 0.0

    def set_last_poll(self, when):
        (self.root / "last-poll").write_text(f"{when:.0f}\n")


@contextlib.contextmanager
def exclusive_lock(path):
    """Non-blocking flock. Yields True when held, False when another run is."""
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o640)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
                yield False
                return
            raise
        try:
            yield True
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


# ---------------------------------------------------------------------- build

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_dir_for(cfg, tag, commit):
    if not valid_tag(tag) or not OID_RE.fullmatch(commit):
        raise BuilderError("refusing build path")
    path = cfg["work_dir"] / f"{tag}-{commit[:12]}"
    if path.resolve().parent != cfg["work_dir"].resolve():
        raise BuilderError("build path escapes work_dir")
    return path


def container_name(tag, commit):
    return f"blunix-build-{tag.replace('.', '_')}-{commit[:12]}"


def docker_argv(cfg, tag, commit, worktree, share_dir, uid, gid):
    """The one privileged container. No credentials, no host network."""
    return [
        "docker", "run", "--rm", "--pull=never",
        "--name", container_name(tag, commit),
        "--label", CONTAINER_LABEL,
        "--privileged",
        "--network", cfg["container_network"],
        "-e", f"BLUNIX_RELEASE_VERSION={tag}",
        "-e", f"BUILDER_UID={uid}",
        "-e", f"BUILDER_GID={gid}",
        "-v", f"{worktree}:/src",
        "-v", f"{share_dir / INSIDE_SCRIPT}:/builder/{INSIDE_SCRIPT}:ro",
        "-w", "/src",
        cfg["container_image"],
        "bash", f"/builder/{INSIDE_SCRIPT}",
    ]


def run_container(cfg, tag, commit, worktree, runner=run_cmd, share_dir=SHARE_DIR):
    env = base_env(cfg["state_dir"])
    pulled = runner(["docker", "pull", "-q", cfg["container_image"]], env, GIT_TIMEOUT)
    if pulled.returncode != 0:
        raise BuilderError("docker pull of pinned image failed")
    # A container left by a run that systemd killed would make `--name` collide
    # and burn this attempt too. The lock means no other run owns it.
    runner(["docker", "rm", "-f", container_name(tag, commit)], env, 120)
    argv = docker_argv(cfg, tag, commit, worktree, share_dir, os.getuid(), os.getgid())
    log_path = worktree.parent / (worktree.name + ".log")
    with open(log_path, "wb") as build_log:
        try:
            result = runner(argv, env, cfg["build_timeout"], stdout=build_log)
        except BuilderError:
            runner(["docker", "rm", "-f", container_name(tag, commit)], env, 120)
            raise
    if result.returncode != 0:
        raise BuilderError(f"image build failed (exit {result.returncode}); see {log_path}")


def collect_artifacts(release_dir):
    """Flat regular files only. Verify the build's own SHA256SUMS first."""
    if not release_dir.is_dir() or release_dir.is_symlink():
        raise BuilderError("build/release is missing")
    names = []
    for entry in sorted(os.listdir(release_dir)):
        path = release_dir / entry
        if path.is_symlink() or not path.is_file():
            raise BuilderError(f"unexpected non-file in release dir: {_short(entry)}")
        if not ARTIFACT_RE.fullmatch(entry):
            raise BuilderError(f"unexpected release file name: {_short(entry)}")
        names.append(entry)
    for required in REQUIRED_ARTIFACTS + (SUMS,):
        if required not in names:
            raise BuilderError(f"release artifact missing: {required}")
    if PROVENANCE in names or SUMS + ".asc" in names:
        raise BuilderError("release dir already holds provenance or a signature")
    digests = {n: sha256_file(release_dir / n) for n in names if n != SUMS}
    for line in (release_dir / SUMS).read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (\S+)", line)
        if not match or match.group(2) not in digests:
            raise BuilderError("build SHA256SUMS has an unknown or malformed entry")
        if not hmac.compare_digest(digests[match.group(2)], match.group(1)):
            raise BuilderError(f"build SHA256SUMS mismatch: {match.group(2)}")
    return digests


def input_hashes(worktree, cfg, share_dir=SHARE_DIR):
    files = {
        "image/packages.txt": worktree / "image" / "packages.txt",
        "image/build-test-disk.sh": worktree / "image" / "build-test-disk.sh",
        "image/build-installer.sh": worktree / "image" / "build-installer.sh",
        "image/gpl-sources.py": worktree / "image" / "gpl-sources.py",
        "builder/" + INSIDE_SCRIPT: share_dir / INSIDE_SCRIPT,
        "builder/blunix_builder.py": Path(__file__).resolve(),
        "trusted_keys": cfg["trusted_keys"],
    }
    out = {}
    for name, path in files.items():
        if not path.is_file():
            raise BuilderError(f"input missing: {name}")
        out[name] = sha256_file(path)
    out["config"] = cfg["config_sha256"]
    return out


def make_provenance(cfg, tag, tag_object, commit, signer, started, finished,
                    inputs, artifacts, hostname):
    return {
        "schema": SCHEMA,
        "tag": tag,
        "tag_object": tag_object,
        "commit": commit,
        "repo_url": cfg["repo_url"],
        "signer": signer,
        "builder": {"name": "blunix-builder", "version": __version__,
                    "hostname": hostname},
        "container": {"image": cfg["container_image"],
                      "digest": cfg["container_digest"],
                      "network": cfg["container_network"], "privileged": True},
        "started_at": iso(started),
        "finished_at": iso(finished),
        "inputs": dict(sorted(inputs.items())),
        "artifacts": dict(sorted(artifacts.items())),
    }


def write_manifest(release_dir, digests):
    """SHA256SUMS in the `<hex>  <name>` form release-sign.py verifies."""
    lines = "".join(f"{digests[n]}  {n}\n" for n in sorted(digests))
    (release_dir / SUMS).write_text(lines)


def finalize_release(cfg, release_dir, tag, tag_object, commit, signer, started,
                     inputs, hostname=None, clock=utcnow):
    artifacts = collect_artifacts(release_dir)
    provenance = make_provenance(cfg, tag, tag_object, commit, signer, started, clock(),
                                 inputs, artifacts, hostname or socket.gethostname())
    (release_dir / PROVENANCE).write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    digests = dict(artifacts)
    digests[PROVENANCE] = sha256_file(release_dir / PROVENANCE)
    write_manifest(release_dir, digests)
    return provenance, digests


def upload_release(client, release_dir, tag, digests):
    """Everything else first, then SHA256SUMS, then the provenance marker."""
    order = [n for n in sorted(digests) if n != PROVENANCE] + [SUMS, PROVENANCE]
    sums_hash = sha256_file(release_dir / SUMS)
    for name in order:
        path = release_dir / name
        expected = sums_hash if name == SUMS else digests[name]
        if sha256_file(path) != expected:
            raise BuilderError(f"artifact changed before upload: {name}")
        client.put_file(f"{tag}/{name}", path, expected)
        log("uploaded", tag=tag, artifact=name, sha256=expected)


def clear_build_dir(cfg, worktree, runner=run_cmd):
    """Remove <worktree>/build that a killed build left owned by root.

    The container chowns build/ back to the builder on exit, but a timeout or a
    systemd kill SIGKILLs it first, and the builder user cannot delete root's
    files. A throwaway root container from the same pinned image, with no
    network and only that worktree mounted, removes build/ instead.
    """
    if not (worktree / "build").exists():
        return
    if worktree.resolve().parent != cfg["work_dir"].resolve():
        raise BuilderError("refusing to clear a build dir outside work_dir")
    runner(["docker", "run", "--rm", "--pull=never", "--network", "none",
            "-v", f"{worktree}:/w", cfg["container_image"], "rm", "-rf", "--", "/w/build"],
           base_env(cfg["state_dir"]), 600)
    if (worktree / "build").exists():
        raise BuilderError(f"could not clear a root-owned build dir: {worktree.name}")


def remove_build(cfg, git, path, runner=run_cmd):
    clear_build_dir(cfg, path, runner)
    git.remove_worktree(path)
    if path.exists():
        shutil.rmtree(path)


def prune_builds(cfg, git, keep, runner=run_cmd):
    pattern = re.compile(r"(v[0-9][0-9A-Za-z.-]*)-[0-9a-f]{12}\Z")
    entries = []
    for entry in os.listdir(cfg["work_dir"]):
        path = cfg["work_dir"] / entry
        if pattern.fullmatch(entry) and path.is_dir() and not path.is_symlink():
            entries.append((path.stat().st_mtime, path))
    for _, path in sorted(entries, reverse=True)[keep:]:
        remove_build(cfg, git, path, runner)
        log_file = path.parent / (path.name + ".log")
        if log_file.exists():
            log_file.unlink()
        log("pruned", path=str(path))


# ------------------------------------------------------------------------ run

class Deps:
    """Seams for tests: subprocess runner, R2 client factory, clock."""

    def __init__(self, runner=run_cmd, client_factory=None, clock=utcnow,
                 wallclock=time.time, environ=None, share_dir=SHARE_DIR, hostname=None):
        self.runner = runner
        self.client_factory = client_factory or (
            lambda cfg, environ: R2Client(cfg["r2"], *load_credentials(cfg, environ)))
        self.clock = clock
        self.wallclock = wallclock
        self.environ = os.environ if environ is None else environ
        self.share_dir = share_dir
        self.hostname = hostname


def build_one(cfg, deps, state, git, client, tag, tag_object, commit):
    started = deps.clock()
    signer, commit = verify_tag(git, tag, tag_object, commit)
    log("tag_verified", tag=tag, commit=commit, signer=signer)
    worktree = build_dir_for(cfg, tag, commit)
    if worktree.exists():
        remove_build(cfg, git, worktree, deps.runner)
    git.add_worktree(worktree, commit)
    if (worktree / "build").exists():
        raise BuilderError("fresh worktree already has build/; refusing stale cache")
    inputs = input_hashes(worktree, cfg, deps.share_dir)
    log("build_start", tag=tag, commit=commit, image=cfg["container_image"])
    run_container(cfg, tag, commit, worktree, deps.runner, deps.share_dir)
    release_dir = worktree / "build" / "release"
    provenance, digests = finalize_release(cfg, release_dir, tag, tag_object, commit, signer,
                                           started, inputs, deps.hostname, deps.clock)
    upload_release(client, release_dir, tag, digests)
    state.mark_built(tag, {"tag_object": tag_object, "commit": commit,
                           "finished_at": provenance["finished_at"],
                           "provenance_sha256": digests[PROVENANCE]})
    log("build_staged", tag=tag, commit=commit, bucket=cfg["r2"]["bucket"],
        provenance_sha256=digests[PROVENANCE])


def run_once(cfg, deps=None, force_poll=False):
    """Return a process exit code: 0 idle/success, 1 failure, 2 rejected tag."""
    deps = deps or Deps()
    check_trust_files(cfg)
    state = State(cfg["state_dir"])
    state.setup()
    cfg["work_dir"].mkdir(mode=0o750, parents=True, exist_ok=True)
    with exclusive_lock(cfg["state_dir"] / "lock") as held:
        if not held:
            log("busy", detail="another run holds the lock")
            return 0
        now = deps.wallclock()
        # 10% slack so a timer firing exactly every poll_interval never skips.
        if not force_poll and now - state.last_poll() < cfg["poll_interval"] * 0.9:
            log("idle", detail="poll interval not reached")
            return 0
        git = Git(cfg, deps.runner)
        listing = git.ls_remote()
        state.set_last_poll(now)
        tags, ignored = parse_ls_remote(listing)
        for name, reason in ignored:
            log("tag_ignored", level="warning", tag=_short(name), reason=reason)
        pending = [t for t in sorted(tags, key=tag_sort_key) if not state.is_built(t)]
        if not pending:
            log("idle", detail="no new release tags")
            return 0
        client = None
        for tag in pending:
            tag_object, commit = tags[tag]
            if state.rejected_object(tag) == tag_object:
                log("tag_skipped", level="warning", tag=tag, reason="previously rejected")
                continue
            if state.attempts_for(tag, tag_object) >= cfg["max_attempts"]:
                log("tag_skipped", level="error", tag=tag, reason="max attempts reached")
                continue
            if client is None:
                client = deps.client_factory(cfg, deps.environ)
            if cfg["r2"]["check_existing"] and client.exists(f"{tag}/{PROVENANCE}"):
                state.mark_built(tag, {"tag_object": tag_object, "commit": commit,
                                       "note": "already staged in R2"})
                log("tag_skipped", tag=tag, reason="already staged in R2")
                continue
            state.bump_attempts(tag, tag_object)
            try:
                build_one(cfg, deps, state, git, client, tag, tag_object, commit)
            except OSError as exc:
                # A filesystem error (a leftover the cleanup could not remove, a
                # full disk) is a failed attempt, logged, not a traceback.
                log("build_failed", level="error", tag=tag,
                    reason=f"{type(exc).__name__}: {exc.strerror or exc}")
                return 1
            except BuilderError as exc:
                message = str(exc)
                if message.startswith("tag signature rejected"):
                    state.mark_rejected(tag, tag_object, message)
                    log("tag_rejected", level="error", tag=tag, reason=message)
                    return 2
                log("build_failed", level="error", tag=tag, reason=message)
                return 1
            try:
                prune_builds(cfg, git, cfg["keep_builds"], deps.runner)
            except (BuilderError, OSError) as exc:
                log("prune_failed", level="warning", reason=str(exc))
            return 0  # one build per run; the timer brings the next
        return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="blunix-builder", description=__doc__.split("\n")[0])
    parser.add_argument("command", choices=("run", "check-config", "version"))
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument("--force-poll", action="store_true",
                        help="ignore poll_interval for this run")
    args = parser.parse_args(argv)
    if args.command == "version":
        print(__version__)
        return 0
    try:
        cfg = load_config(args.config)
        check_trust_files(cfg)
        if args.command == "check-config":
            log("config_ok", repo=cfg["repo_url"], image=cfg["container_image"],
                bucket=cfg["r2"]["bucket"], signers=sorted(cfg["trusted_fingerprints"]))
            return 0
        return run_once(cfg, force_poll=args.force_poll)
    except BuilderError as exc:
        log("error", level="error", reason=str(exc))
        return 1
    except OSError as exc:
        log("error", level="error", reason=f"{type(exc).__name__}: {exc.strerror or exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

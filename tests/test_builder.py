"""blunix-builder: tag trust, config, SigV4, idempotency and provenance.

Everything external is faked: no git network, no gpg keyring, no docker, no R2.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "blunix_builder", ROOT / "builder" / "blunix_builder.py")
bb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bb)

TRUSTED = "62F736BEA2AB2E1FA16D5138BCB3426C090ADF92"
OTHER = "0123456789ABCDEF0123456789ABCDEF01234567"
TAG_OBJ = "a" * 40
COMMIT = "c" * 40
SECRET = "SuperSecretR2KeyValue0123456789abcdef"
ACCESS = "AKIDBUILDERTEST0001"
DIGEST = "1" * 64


def validsig(primary):
    return ("[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG BCB3426C090ADF92 Blunix\n"
            f"[GNUPG:] VALIDSIG {primary} 2026-10-03 1790000000 0 4 0 22 10 00 {primary}\n")


def base_raw(tmp):
    keys = Path(tmp) / "tag-signers.asc"
    keys.write_text("-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n")
    os.chmod(keys, 0o644)
    creds = Path(tmp) / "r2-credentials"
    creds.write_text(f"access_key_id={ACCESS}\nsecret_access_key={SECRET}\n")
    os.chmod(creds, 0o600)
    return {
        "repo_url": "https://github.com/afterdarksys/blunix.git",
        "poll_interval": 600,
        "container_image": f"debian:trixie-slim@sha256:{DIGEST}",
        "container_network": "blunix-build",
        "state_dir": str(Path(tmp) / "state"),
        "work_dir": str(Path(tmp) / "work"),
        "trusted_keys": str(keys),
        "trusted_fingerprints": [TRUSTED],
        "r2": {"endpoint": "https://acct.r2.cloudflarestorage.com",
               "bucket": "blunix-release-staging",
               "credentials_file": str(creds)},
    }


def make_cfg(tmp, **overrides):
    raw = base_raw(tmp)
    raw.update(overrides)
    cfg = bb.validate_config(raw)
    cfg["config_sha256"] = "f" * 64
    return cfg


def done(code=0, out=b"", err=b""):
    return subprocess.CompletedProcess([], code, out, err)


class FakeHost:
    """Plays git, gpg and docker. Records every call with its environment."""

    def __init__(self, tags=None, tag_name=None, obj_type="tag", signature="pgp",
                 gpg_status=None, verify_code=0, fetched_obj=TAG_OBJ, commit=COMMIT,
                 build_ok=True, release_files=None, cleanup_ok=True):
        self.calls = []
        self.cleanup_ok = cleanup_ok
        self.tags = tags if tags is not None else {"v0.2.0": (TAG_OBJ, COMMIT)}
        self.tag_name = tag_name
        self.obj_type = obj_type
        self.signature = signature
        self.gpg_status = validsig(TRUSTED) if gpg_status is None else gpg_status
        self.verify_code = verify_code
        self.fetched_obj = fetched_obj
        self.commit = commit
        self.build_ok = build_ok
        self.release_files = release_files

    def _sub(self, argv):
        args = argv[1:]
        i = 0
        while i < len(args):
            if args[i] in ("-c", "--git-dir"):
                i += 2
                continue
            return args[i], args[i + 1:]
        return None, []

    def __call__(self, argv, env, timeout, cwd=None, stdout=None):
        self.calls.append((list(argv), dict(env)))
        tool = argv[0]
        if tool == "gpg":
            return done()
        if tool == "docker":
            return self._docker(argv, stdout)
        sub, rest = self._sub(argv)
        if sub == "ls-remote":
            lines = []
            for name, (obj, commit) in self.tags.items():
                lines.append(f"{obj}\trefs/tags/{name}")
                if obj != commit:
                    lines.append(f"{commit}\trefs/tags/{name}^{{}}")
            return done(out=("\n".join(lines) + "\n").encode())
        if sub in ("init", "fetch", "prune"):
            return done()
        if sub == "rev-parse":
            spec = rest[-1]
            return done(out=((self.commit if spec.endswith("^{commit}")
                              else self.fetched_obj) + "\n").encode())
        if sub == "cat-file":
            if rest[0] == "-t":
                return done(out=(self.obj_type + "\n").encode())
            name = self.tag_name or self._current_tag
            sig = {"pgp": "-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----\n",
                   "ssh": "-----BEGIN SSH SIGNATURE-----\nabc\n-----END SSH SIGNATURE-----\n",
                   "none": ""}[self.signature]
            body = (f"object {COMMIT}\ntype commit\ntag {name}\n"
                    f"tagger R <r@example.test> 1 +0000\n\nrelease\n{sig}")
            return done(out=body.encode())
        if sub == "verify-tag":
            return done(code=self.verify_code, err=self.gpg_status.encode())
        if sub == "worktree":
            if rest[0] == "add":
                path = Path(rest[-2])
                (path / "image").mkdir(parents=True)
                for name in ("packages.txt", "build-test-disk.sh", "build-installer.sh",
                             "gpl-sources.py"):
                    (path / "image" / name).write_text(name)
            return done()
        raise AssertionError(f"unexpected command {argv}")

    _current_tag = "v0.2.0"

    def _docker(self, argv, stdout):
        if argv[1] in ("pull", "rm"):
            return done()
        assert argv[1] == "run"
        if "none" in argv and argv[-3:-1] == ["-rf", "--"]:
            # The root cleanup container: removes <worktree>/build, unless the
            # test plays a cleanup that failed.
            mount = next(a for a in argv if a.endswith(":/w")).rsplit(":/w", 1)[0]
            if self.cleanup_ok:
                shutil.rmtree(Path(mount) / "build")
            return done()
        if not self.build_ok:
            return done(code=3)
        src = next(a for a in argv if a.endswith(":/src")).rsplit(":/src", 1)[0]
        release = Path(src) / "build" / "release"
        release.mkdir(parents=True)
        files = self.release_files or {
            "blunix-installer.iso": b"iso", "blunix.raw.zst": b"raw",
            "SOURCES.md": b"sources", "RELEASE-NOTES.md": b"notes"}
        for name, data in files.items():
            (release / name).write_bytes(data)
        sums = "".join(f"{hashlib.sha256(d).hexdigest()}  {n}\n"
                       for n, d in sorted(files.items()) if n != "SOURCES.md")
        (release / "SHA256SUMS").write_text(sums)
        return done()

    def ran(self, tool, sub=None):
        out = []
        for argv, _ in self.calls:
            if argv[0] != tool:
                continue
            if sub is None or (tool == "docker" and argv[1] == sub) or (
                    tool == "git" and self._sub(argv)[0] == sub):
                out.append(argv)
        return out


class FakeClient:
    def __init__(self, existing=()):
        self.existing = set(existing)
        self.puts = []

    def exists(self, key):
        return key in self.existing

    def put_file(self, key, path, sha):
        assert bb.sha256_file(path) == sha
        self.puts.append(key)


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = self._tmp.name
        share = Path(self.tmp) / "share"
        share.mkdir()
        (share / bb.INSIDE_SCRIPT).write_text("#!/bin/bash\n")
        self.share = share

    def deps(self, host, client=None):
        client = client or FakeClient()
        self.client = client
        return bb.Deps(runner=host, client_factory=lambda cfg, env: client,
                       wallclock=lambda: 10_000_000.0, environ={},
                       share_dir=self.share, hostname="builder1")

    def run_quiet(self, cfg, deps, **kw):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = bb.run_once(cfg, deps, **kw)
        return code, out.getvalue()


class TagNameTests(unittest.TestCase):
    def test_accepts_release_and_prerelease(self):
        for tag in ("v0.1.0", "v1.20.3", "v2.0.0-rc.1", "v0.2.0-beta.0"):
            self.assertTrue(bb.valid_tag(tag), tag)

    def test_rejects_traversal_and_junk(self):
        for tag in ("", "v1.2", "1.2.3", "v01.2.3", "v1.2.3/../../etc", "../v1.2.3",
                    "v1.2.3\n", "v1.2.3 ", "latest", "v1.2.3-rc1", "v1.2.3+x",
                    "v1.2.3-rc.1/x", "v1.2.3;rm", "v1.2.3\x00", "v99999.0.0", None):
            self.assertFalse(bb.valid_tag(tag), repr(tag))

    def test_state_and_build_paths_refuse_bad_tags(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = bb.State(Path(tmp))
            state.setup()
            with self.assertRaises(bb.BuilderError):
                state.mark_built("../../evil", {})
            cfg = make_cfg(tmp)
            with self.assertRaises(bb.BuilderError):
                bb.build_dir_for(cfg, "v1.0.0/../../x", COMMIT)
            self.assertEqual(bb.build_dir_for(cfg, "v1.0.0", COMMIT).name,
                             "v1.0.0-cccccccccccc")

    def test_ls_remote_drops_lightweight_and_invalid(self):
        text = (f"{TAG_OBJ}\trefs/tags/v0.2.0\n{COMMIT}\trefs/tags/v0.2.0^{{}}\n"
                f"{COMMIT}\trefs/tags/v0.1.0\n"
                f"{TAG_OBJ}\trefs/tags/../../x\n{COMMIT}\trefs/tags/../../x^{{}}\n"
                f"zzz\trefs/tags/v9.9.9\n")
        tags, rejected = bb.parse_ls_remote(text)
        self.assertEqual(tags, {"v0.2.0": (TAG_OBJ, COMMIT)})
        reasons = dict(rejected)
        self.assertIn("lightweight", reasons["v0.1.0"])
        self.assertIn("invalid", reasons["../../x"])

    def test_versions_sort_numerically(self):
        tags = ["v0.10.0", "v0.2.0", "v0.2.0-rc.1", "v0.9.1"]
        self.assertEqual(sorted(tags, key=bb.tag_sort_key),
                         ["v0.2.0-rc.1", "v0.2.0", "v0.9.1", "v0.10.0"])


class SignatureTests(Base):
    def verify(self, **kw):
        cfg = make_cfg(self.tmp)
        host = FakeHost(**kw)
        return bb.verify_tag(bb.Git(cfg, host), "v0.2.0", TAG_OBJ, COMMIT), host

    def test_trusted_signature_accepted(self):
        (signer, commit), host = self.verify()
        self.assertEqual(signer, "openpgp:" + TRUSTED)
        self.assertEqual(commit, COMMIT)
        # gpg ran against a throwaway GNUPGHOME, never the user's keyring.
        gpg_env = [env for argv, env in host.calls if argv[0] == "gpg"][0]
        self.assertIn("blunix-gnupg-", gpg_env["GNUPGHOME"])

    def test_unsigned_annotated_tag_rejected(self):
        with self.assertRaisesRegex(bb.BuilderError, "unsigned"):
            self.verify(signature="none")

    def test_wrong_key_rejected(self):
        with self.assertRaisesRegex(bb.BuilderError, "allowlist"):
            self.verify(gpg_status=validsig(OTHER))

    def test_bad_signature_rejected(self):
        status = "[GNUPG:] BADSIG BCB3426C090ADF92 Blunix\n"
        with self.assertRaisesRegex(bb.BuilderError, "BADSIG"):
            self.verify(gpg_status=status, verify_code=1)

    def test_unknown_key_rejected(self):
        status = "[GNUPG:] ERRSIG 1111 22 10 00 1 9\n[GNUPG:] NO_PUBKEY 1111\n"
        with self.assertRaisesRegex(bb.BuilderError, "rejected"):
            self.verify(gpg_status=status, verify_code=1)

    def test_good_status_but_failed_exit_rejected(self):
        with self.assertRaisesRegex(bb.BuilderError, "verify-tag failed"):
            self.verify(verify_code=1)

    def test_lightweight_tag_rejected(self):
        with self.assertRaisesRegex(bb.BuilderError, "lightweight"):
            self.verify(obj_type="commit")

    def test_replayed_tag_under_new_name_rejected(self):
        with self.assertRaisesRegex(bb.BuilderError, "signed name"):
            self.verify(tag_name="v0.1.0")

    def test_tag_object_swapped_after_listing_rejected(self):
        with self.assertRaisesRegex(bb.BuilderError, "changed"):
            self.verify(fetched_obj="b" * 40)

    def test_commit_mismatch_rejected(self):
        with self.assertRaisesRegex(bb.BuilderError, "commit"):
            self.verify(commit="d" * 40)

    def test_ssh_signature_rejected_unless_enabled(self):
        with self.assertRaisesRegex(bb.BuilderError, "ssh signatures not enabled"):
            self.verify(signature="ssh")

    def test_two_signatures_rejected(self):
        with self.assertRaisesRegex(bb.BuilderError, "exactly one"):
            bb.parse_gpg_status(validsig(TRUSTED) + validsig(TRUSTED), {TRUSTED})

    def test_ssh_status_allowlist(self):
        fp = "SHA256:" + "A" * 43
        line = f'Good "git" signature for ryan with ED25519 key {fp}\n'
        self.assertEqual(bb.parse_ssh_status(line, {fp}), fp)
        with self.assertRaises(bb.BuilderError):
            bb.parse_ssh_status(line, {"SHA256:" + "B" * 43})


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = self._tmp.name

    def bad(self, mutate, pattern):
        raw = base_raw(self.tmp)
        mutate(raw)
        with self.assertRaisesRegex(bb.BuilderError, pattern):
            bb.validate_config(raw)

    def test_valid(self):
        cfg = make_cfg(self.tmp)
        self.assertEqual(cfg["container_digest"], "sha256:" + DIGEST)
        self.assertEqual(cfg["r2"]["host"], "acct.r2.cloudflarestorage.com")

    def test_rejects_unsafe_values(self):
        cases = [
            (lambda r: r.pop("repo_url"), "repo_url"),
            (lambda r: r.update(repo_url="http://github.com/a/b.git"), "repo_url"),
            (lambda r: r.update(repo_url="https://tok@github.com/a/b.git"), "repo_url"),
            (lambda r: r.update(repo_url="https://github.com/a/../b"), "repo_url"),
            (lambda r: r.update(container_image="debian:trixie-slim"), "pinned"),
            (lambda r: r.update(container_image="debian@sha256:" + "0" * 64), "placeholder"),
            (lambda r: r.update(container_network="host"), "network"),
            (lambda r: r.update(trusted_fingerprints=[]), "fingerprints"),
            (lambda r: r.update(trusted_fingerprints=[TRUSTED.lower()]), "fingerprints"),
            (lambda r: r.pop("trusted_keys"), "trusted_keys"),
            (lambda r: r.update(state_dir="relative/state"), "state_dir"),
            (lambda r: r.update(work_dir="/srv/../etc"), "work_dir"),
            (lambda r: r.update(surprise=1), "unknown"),
            (lambda r: r.update(poll_interval=True), "poll_interval"),
            (lambda r: r["r2"].update(endpoint="http://acct.r2.example"), "endpoint"),
            (lambda r: r["r2"].update(endpoint="https://x.example/bucket"), "endpoint"),
            (lambda r: r["r2"].update(bucket="Bad_Bucket"), "bucket"),
            (lambda r: r["r2"].pop("credentials_file"), "credentials_file"),
            (lambda r: r.update(allowed_signers="/x"), "trusted_ssh_fingerprints"),
            (lambda r: r.pop("r2"), "r2"),
            # Must end before blunix-builder.service's TimeoutStartSec=5h.
            (lambda r: r.update(build_timeout=bb.MAX_BUILD_TIMEOUT + 1), "build_timeout"),
        ]
        for mutate, pattern in cases:
            with self.subTest(pattern=pattern):
                self.bad(mutate, pattern)

    def test_non_mapping_rejected(self):
        for raw in (None, [], "x"):
            with self.assertRaises(bb.BuilderError):
                bb.validate_config(raw)

    def test_load_config_rejects_bad_yaml(self):
        path = Path(self.tmp) / "c.yaml"
        path.write_text("repo_url: [unclosed\n")
        with self.assertRaisesRegex(bb.BuilderError, "YAML"):
            bb.load_config(str(path))
        with self.assertRaisesRegex(bb.BuilderError, "cannot read"):
            bb.load_config(str(Path(self.tmp) / "missing.yaml"))

    def test_example_config_refused_until_pinned(self):
        with self.assertRaisesRegex(bb.BuilderError, "placeholder"):
            bb.load_config(str(ROOT / "builder" / "config.example.yaml"))

    def test_missing_trust_root_fails_closed(self):
        cfg = make_cfg(self.tmp)
        cfg["trusted_keys"].unlink()
        with self.assertRaisesRegex(bb.BuilderError, "trust root missing"):
            bb.check_trust_files(cfg)

    def test_writable_or_empty_trust_root_fails_closed(self):
        cfg = make_cfg(self.tmp)
        os.chmod(cfg["trusted_keys"], 0o666)
        with self.assertRaisesRegex(bb.BuilderError, "writable"):
            bb.check_trust_files(cfg)
        cfg["trusted_keys"].write_text("")
        with self.assertRaisesRegex(bb.BuilderError, "non-empty"):
            bb.check_trust_files(cfg)

    def test_credentials_mode_and_format(self):
        cfg = make_cfg(self.tmp)
        self.assertEqual(bb.load_credentials(cfg, {}), (ACCESS, SECRET))
        path = cfg["r2"]["credentials_file"]
        os.chmod(path, 0o644)
        with self.assertRaisesRegex(bb.BuilderError, "0600") as ctx:
            bb.load_credentials(cfg, {})
        self.assertNotIn(SECRET, str(ctx.exception))
        os.chmod(path, 0o600)
        path.write_text(f"secret_access_key={SECRET}\n")
        with self.assertRaises(bb.BuilderError) as ctx:
            bb.load_credentials(cfg, {})
        self.assertNotIn(SECRET, str(ctx.exception))
        path.write_text(f"password={SECRET}\n")
        with self.assertRaises(bb.BuilderError) as ctx:
            bb.load_credentials(cfg, {})
        self.assertNotIn(SECRET, str(ctx.exception))

    def test_systemd_credential_preferred(self):
        cfg = make_cfg(self.tmp)
        cred_dir = Path(self.tmp) / "creds"
        cred_dir.mkdir()
        other = cred_dir / bb.CREDENTIAL_NAME
        other.write_text("access_key_id=AKIDFROMSYSTEMD0001\n"
                         "secret_access_key=FromSystemdSecret0123456789\n")
        os.chmod(other, 0o400)
        access, _ = bb.load_credentials(cfg, {"CREDENTIALS_DIRECTORY": str(cred_dir)})
        self.assertEqual(access, "AKIDFROMSYSTEMD0001")


class SigV4Tests(unittest.TestCase):
    """AWS published vectors (SigV4 test suite and the S3 SigV4 examples)."""

    def test_signing_key_vector(self):
        key = bb.signing_key("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                             "20120215", "us-east-1", "iam")
        self.assertEqual(key.hex(),
                         "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d")

    def test_get_vanilla(self):
        headers = bb.sigv4_headers(
            "GET", "example.amazonaws.com", "/", {}, {}, bb.EMPTY_SHA256,
            "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1", "service", "20150830T123600Z")
        self.assertEqual(
            headers["authorization"],
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
            "SignedHeaders=host;x-amz-date, "
            "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")

    S3_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    def test_s3_get_object(self):
        headers = bb.sigv4_headers(
            "GET", "examplebucket.s3.amazonaws.com", "/test.txt", {},
            {"Range": "bytes=0-9"}, bb.EMPTY_SHA256, "AKIAIOSFODNN7EXAMPLE",
            self.S3_SECRET, "us-east-1", "s3", "20130524T000000Z")
        self.assertTrue(headers["authorization"].endswith(
            "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"))

    def test_s3_put_object(self):
        body = b"Welcome to Amazon S3."
        headers = bb.sigv4_headers(
            "PUT", "examplebucket.s3.amazonaws.com", "/test$file.text", {},
            {"Date": "Fri, 24 May 2013 00:00:00 GMT",
             "x-amz-storage-class": "REDUCED_REDUNDANCY"},
            hashlib.sha256(body).hexdigest(), "AKIAIOSFODNN7EXAMPLE",
            self.S3_SECRET, "us-east-1", "s3", "20130524T000000Z")
        self.assertTrue(headers["authorization"].endswith(
            "Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"))

    def test_client_put_never_sends_secret(self):
        sent = []

        class Conn:
            def putrequest(self, method, path, **kw):
                sent.append(("req", method, path))

            def putheader(self, name, value):
                sent.append(("hdr", name, value))

            def endheaders(self):
                pass

            def send(self, chunk):
                sent.append(("body", chunk))

            def getresponse(self):
                class R:
                    status = 200

                    def read(self, n):
                        return b""
                return R()

            def close(self):
                pass

        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_cfg(tmp)
            artifact = Path(tmp) / "blunix.raw.zst"
            artifact.write_bytes(b"payload")
            client = bb.R2Client(cfg["r2"], ACCESS, SECRET, connect=Conn)
            client.put_file("v0.2.0/blunix.raw.zst", artifact, bb.sha256_file(artifact))
        self.assertIn(("req", "PUT", "/blunix-release-staging/v0.2.0/blunix.raw.zst"), sent)
        self.assertNotIn(SECRET, repr(sent))
        self.assertNotIn(SECRET, repr(client))
        auth = [v for k, n, v in [s for s in sent if s[0] == "hdr"] if n == "authorization"]
        self.assertTrue(auth and auth[0].startswith(f"AWS4-HMAC-SHA256 Credential={ACCESS}/"))


class ProvenanceTests(Base):
    def release(self, files):
        rel = Path(self.tmp) / "release"
        rel.mkdir()
        for name, data in files.items():
            (rel / name).write_bytes(data)
        sums = "".join(f"{hashlib.sha256(d).hexdigest()}  {n}\n" for n, d in files.items())
        (rel / "SHA256SUMS").write_text(sums)
        return rel

    FILES = {"blunix-installer.iso": b"iso", "blunix.raw.zst": b"raw", "SOURCES.md": b"s"}

    def test_provenance_and_manifest(self):
        cfg = make_cfg(self.tmp)
        rel = self.release(self.FILES)
        started = bb.utcnow()
        prov, digests = bb.finalize_release(
            cfg, rel, "v0.2.0", TAG_OBJ, COMMIT, "openpgp:" + TRUSTED, started,
            {"image/packages.txt": "e" * 64}, hostname="builder1")
        stored = json.loads((rel / bb.PROVENANCE).read_text())
        self.assertEqual(stored, prov)
        self.assertEqual(stored["schema"], bb.SCHEMA)
        self.assertEqual(stored["tag"], "v0.2.0")
        self.assertEqual(stored["tag_object"], TAG_OBJ)
        self.assertEqual(stored["commit"], COMMIT)
        self.assertEqual(stored["builder"]["version"], bb.__version__)
        self.assertEqual(stored["container"]["digest"], "sha256:" + DIGEST)
        self.assertEqual(stored["inputs"], {"image/packages.txt": "e" * 64})
        self.assertRegex(stored["started_at"], r"\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z")
        self.assertEqual(stored["artifacts"]["blunix.raw.zst"],
                         hashlib.sha256(b"raw").hexdigest())
        lines = (rel / "SHA256SUMS").read_text().splitlines()
        names = [line.split("  ", 1)[1] for line in lines]
        self.assertEqual(names, sorted(names))
        self.assertIn(bb.PROVENANCE, names)
        self.assertNotIn("SHA256SUMS", names)
        for line in lines:
            digest, name = line.split("  ", 1)
            self.assertEqual(bb.sha256_file(rel / name), digest)
        self.assertEqual(set(digests), set(names))

    def test_tampered_build_manifest_rejected(self):
        rel = self.release(self.FILES)
        (rel / "blunix.raw.zst").write_bytes(b"swapped")
        with self.assertRaisesRegex(bb.BuilderError, "mismatch"):
            bb.collect_artifacts(rel)

    def test_missing_artifact_and_symlink_rejected(self):
        files = dict(self.FILES)
        files.pop("SOURCES.md")
        rel = self.release(files)
        with self.assertRaisesRegex(bb.BuilderError, "SOURCES.md"):
            bb.collect_artifacts(rel)
        (rel / "SOURCES.md").symlink_to("/etc/passwd")
        with self.assertRaisesRegex(bb.BuilderError, "non-file"):
            bb.collect_artifacts(rel)


class RunTests(Base):
    def test_full_build_stages_release_without_leaking_secret(self):
        cfg = make_cfg(self.tmp)
        host = FakeHost()
        client = FakeClient()
        deps = self.deps(host, client)
        # Real credential loading, fake transport: exercise the secret path.
        deps.client_factory = lambda c, env: (bb.load_credentials(c, env), client)[1]
        code, logs = self.run_quiet(cfg, deps)
        self.assertEqual(code, 0, logs)
        self.assertEqual(client.puts[-1], "v0.2.0/build-provenance.json")
        self.assertEqual(client.puts[-2], "v0.2.0/SHA256SUMS")
        self.assertIn("v0.2.0/blunix.raw.zst", client.puts)
        self.assertTrue((cfg["state_dir"] / "built" / "v0.2.0.json").exists())
        run = host.ran("docker", "run")[0]
        self.assertIn("--privileged", run)
        self.assertIn("debian:trixie-slim@sha256:" + DIGEST, run)
        self.assertNotIn("host", run[run.index("--network") + 1])
        # The secret never reaches logs, child processes, or the release dir.
        self.assertNotIn(SECRET, logs)
        self.assertNotIn(ACCESS, logs)
        for argv, env in host.calls:
            self.assertNotIn(SECRET, " ".join(argv) + json.dumps(env))
        for path in Path(cfg["work_dir"]).rglob("*"):
            if path.is_file():
                self.assertNotIn(SECRET.encode(), path.read_bytes())
        for line in logs.splitlines():
            json.loads(line)

    def test_built_tag_is_skipped(self):
        cfg = make_cfg(self.tmp)
        state = bb.State(cfg["state_dir"])
        state.setup()
        state.mark_built("v0.2.0", {"tag_object": TAG_OBJ})
        host = FakeHost()
        code, logs = self.run_quiet(cfg, self.deps(host))
        self.assertEqual(code, 0)
        self.assertEqual(host.ran("docker"), [])
        self.assertEqual(host.ran("git", "fetch"), [])
        self.assertIn("no new release tags", logs)

    def test_tag_already_in_r2_is_skipped_and_marked(self):
        cfg = make_cfg(self.tmp)
        host = FakeHost()
        client = FakeClient(existing={"v0.2.0/build-provenance.json"})
        code, _ = self.run_quiet(cfg, self.deps(host, client))
        self.assertEqual(code, 0)
        self.assertEqual(host.ran("docker"), [])
        self.assertTrue(bb.State(cfg["state_dir"]).is_built("v0.2.0"))

    def test_poll_interval_respected(self):
        cfg = make_cfg(self.tmp)
        host = FakeHost()
        self.run_quiet(cfg, self.deps(host))
        host2 = FakeHost(tags={"v0.3.0": ("b" * 40, "d" * 40)})
        code, logs = self.run_quiet(cfg, self.deps(host2))
        self.assertEqual(code, 0)
        self.assertEqual(host2.calls, [])
        self.assertIn("poll interval", logs)

    def test_lock_held_means_no_work(self):
        cfg = make_cfg(self.tmp)
        bb.State(cfg["state_dir"]).setup()
        host = FakeHost()
        with bb.exclusive_lock(cfg["state_dir"] / "lock") as held:
            self.assertTrue(held)
            code, logs = self.run_quiet(cfg, self.deps(host))
        self.assertEqual(code, 0)
        self.assertEqual(host.calls, [])
        self.assertIn("busy", logs)

    def test_rejected_tag_recorded_and_not_retried(self):
        cfg = make_cfg(self.tmp)
        host = FakeHost(gpg_status=validsig(OTHER))
        code, logs = self.run_quiet(cfg, self.deps(host))
        self.assertEqual(code, 2)
        self.assertEqual(host.ran("docker"), [])
        self.assertIn("tag_rejected", logs)
        host2 = FakeHost(gpg_status=validsig(OTHER))
        code, logs = self.run_quiet(cfg, self.deps(host2), force_poll=True)
        self.assertEqual(code, 0)
        self.assertEqual(host2.ran("git", "fetch"), [])
        self.assertIn("previously rejected", logs)

    def test_failed_build_counts_attempts_then_stops(self):
        cfg = make_cfg(self.tmp, max_attempts=2)
        for _ in range(2):
            host = FakeHost(build_ok=False)
            code, logs = self.run_quiet(cfg, self.deps(host), force_poll=True)
            self.assertEqual(code, 1)
            self.assertIn("build_failed", logs)
            self.assertEqual(self.client.puts, [])
        host = FakeHost(build_ok=False)
        code, logs = self.run_quiet(cfg, self.deps(host), force_poll=True)
        self.assertEqual(code, 0)
        self.assertEqual(host.ran("docker"), [])
        self.assertIn("max attempts", logs)

    def _leftover(self, cfg):
        # What a killed build leaves: the worktree with a build/ dir that, on the
        # host, is owned by root.
        worktree = bb.build_dir_for(cfg, "v0.2.0", COMMIT)
        (worktree / "build" / "release").mkdir(parents=True)
        (worktree / "build" / "root-password").write_text("x")
        return worktree

    def test_leftover_build_dir_is_cleared_by_a_root_container_first(self):
        cfg = make_cfg(self.tmp)
        worktree = self._leftover(cfg)
        host = FakeHost()
        code, logs = self.run_quiet(cfg, self.deps(host))
        self.assertEqual(code, 0, logs)
        runs = host.ran("docker", "run")
        cleanup, build = runs[0], runs[1]
        self.assertEqual(cleanup[-4:], ["rm", "-rf", "--", "/w/build"])
        self.assertEqual(cleanup[cleanup.index("--network") + 1], "none")
        self.assertIn(f"{worktree}:/w", cleanup)
        self.assertIn(cfg["container_image"], cleanup)
        self.assertNotIn("--privileged", cleanup)
        self.assertIn("--privileged", build)

    def test_uncleared_leftover_is_a_logged_failed_attempt(self):
        cfg = make_cfg(self.tmp)
        self._leftover(cfg)
        host = FakeHost(cleanup_ok=False)
        code, logs = self.run_quiet(cfg, self.deps(host))
        self.assertEqual(code, 1)
        self.assertIn("could not clear a root-owned build dir", logs)
        self.assertEqual(len(host.ran("docker", "run")), 1)
        for line in logs.splitlines():
            json.loads(line)

    def test_filesystem_error_is_logged_not_raised(self):
        cfg = make_cfg(self.tmp)
        self._leftover(cfg)
        host = FakeHost()
        real = bb.shutil.rmtree

        def denied(path, *a, **kw):
            raise PermissionError(13, "Permission denied", str(path))
        bb.shutil.rmtree = denied
        self.addCleanup(setattr, bb.shutil, "rmtree", real)
        code, logs = self.run_quiet(cfg, self.deps(host))
        self.assertEqual(code, 1)
        self.assertIn("build_failed", logs)
        self.assertIn("PermissionError", logs)
        for line in logs.splitlines():
            json.loads(line)

    def test_build_container_is_labelled_and_a_stale_one_removed_first(self):
        cfg = make_cfg(self.tmp)
        host = FakeHost()
        code, _ = self.run_quiet(cfg, self.deps(host))
        self.assertEqual(code, 0)
        docker = [a for a, _ in host.calls if a[0] == "docker"]
        name = bb.container_name("v0.2.0", COMMIT)
        rm_at = docker.index(["docker", "rm", "-f", name])
        run_at = next(i for i, a in enumerate(docker) if a[1] == "run")
        self.assertLess(rm_at, run_at)
        run = docker[run_at]
        self.assertEqual(run[run.index("--label") + 1], bb.CONTAINER_LABEL)

    def test_missing_trust_root_stops_before_network(self):
        cfg = make_cfg(self.tmp)
        cfg["trusted_keys"].unlink()
        host = FakeHost()
        with self.assertRaises(bb.BuilderError):
            self.run_quiet(cfg, self.deps(host))
        self.assertEqual(host.calls, [])


class PackageTests(unittest.TestCase):
    def test_manifest_matches_packaged_files(self):
        builder = ROOT / "builder"
        lines = (builder / "MANIFEST.sha256").read_text().splitlines()
        self.assertTrue(lines)
        for line in lines:
            digest, name = line.split("  ", 1)
            self.assertFalse(name.startswith("/") or ".." in name)
            self.assertEqual(bb.sha256_file(builder / name), digest, name)

    def test_shipped_trust_root_is_the_pinned_key(self):
        shipped = (ROOT / "builder" / "keys" / "tag-signers.asc").read_bytes()
        self.assertEqual(shipped, (ROOT / "keys" / "blunix-releases.asc").read_bytes())
        example = (ROOT / "builder" / "config.example.yaml").read_text()
        self.assertIn(TRUSTED, example)


class DoorTests(unittest.TestCase):
    """The door addresses stay out of this public repo; check-door.sh gates
    the host-local door.nft that nftables.conf includes verbatim."""

    def check(self, text, symlink=False):
        with tempfile.TemporaryDirectory() as d:
            real = Path(d) / "real.nft"
            real.write_text(text)
            path = real
            if symlink:
                path = Path(d) / "door.nft"
                path.symlink_to(real)
            return subprocess.run(
                ["bash", str(ROOT / "builder" / "check-door.sh"), str(path)],
                capture_output=True, text=True)

    def test_accepts_one_define_of_plain_addresses(self):
        r = self.check("# door\n\ndefine DOOR_V4 = { 203.0.113.7, 198.51.100.20 }\n")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_rejects_bad_door_files(self):
        cases = {
            "placeholder": "define DOOR_V4 = { 192.0.2.1 }\n",
            "prefix": "define DOOR_V4 = { 203.0.113.0/24 }\n",
            "octet": "define DOOR_V4 = { 203.0.113.256 }\n",
            "loopback": "define DOOR_V4 = { 127.0.0.1 }\n",
            "any": "define DOOR_V4 = { 0.0.0.0 }\n",
            "empty": "# nothing\n",
            "two defines": "define DOOR_V4 = { 203.0.113.7 }\ndefine DOOR_V4 = { 203.0.113.8 }\n",
            "extra rule": "define DOOR_V4 = { 203.0.113.7 }\ntable inet x { }\n",
            "trailing junk": "define DOOR_V4 = { 203.0.113.7 } ; flush ruleset\n",
        }
        for name, text in cases.items():
            with self.subTest(name):
                self.assertNotEqual(self.check(text).returncode, 0)

    def test_rejects_symlink(self):
        r = self.check("define DOOR_V4 = { 203.0.113.7 }\n", symlink=True)
        self.assertNotEqual(r.returncode, 0)

    def test_public_ruleset_carries_no_addresses(self):
        conf = (ROOT / "builder" / "nftables.conf").read_text()
        self.assertIn('include "/etc/blunix-builder/door.nft"', conf)
        self.assertIn("elements = $DOOR_V4", conf)
        rules = "\n".join(l for l in conf.splitlines() if not l.lstrip().startswith("#"))
        self.assertNotRegex(rules, r"\b\d{1,3}(\.\d{1,3}){3}\b")


class DataDiskTests(unittest.TestCase):
    def test_install_pins_docker_to_the_data_disk_before_installing_it(self):
        sh = (ROOT / "builder" / "install.sh").read_text()
        guard = sh.index("mountpoint -q /srv")
        daemon = sh.index('"data-root": "/srv/docker"')
        packages = sh.index('echo "install: packages"')
        check = sh.index("{{.DockerRootDir}}")
        self.assertLess(guard, daemon)
        self.assertLess(daemon, packages)
        self.assertLess(packages, check)
        self.assertIn('/srv is on the root disk', sh)


    def test_release_container_starts_from_a_fresh_build_dir_with_secrets(self):
        sh = (ROOT / "builder" / "inside-release.sh").read_text()
        refuse = sh.index('if [ -e /src/build ]; then')
        made = sh.index("mkdir /src/build\n")
        secrets = sh.index("python3 /src/image/prepare-secrets.py")
        self.assertLess(sh.index("apt-get install -y -qq python3"), secrets)
        disk = sh.index("bash /src/image/build-test-disk.sh --inside --release")
        self.assertLess(refuse, made)
        self.assertLess(made, secrets)
        self.assertLess(secrets, disk)

    def test_docker_waits_for_the_data_disk(self):
        sh = (ROOT / "builder" / "install.sh").read_text()
        dropin = sh.index("/etc/systemd/system/docker.service.d/blunix-wait-for-srv.conf")
        self.assertLess(dropin, sh.index('echo "install: packages"'))
        conf = (ROOT / "builder" / "systemd" / "docker-wait-for-srv.conf").read_text()
        self.assertIn("RequiresMountsFor=/srv/docker", conf)
        self.assertIn("systemd/docker-wait-for-srv.conf", (ROOT / "builder" / "MANIFEST.sha256").read_text())

    def test_unit_removes_orphaned_build_containers(self):
        unit = (ROOT / "builder" / "systemd" / "blunix-builder.service").read_text()
        stop = next(l for l in unit.splitlines() if l.startswith("ExecStopPost="))
        self.assertIn(f"label={bb.CONTAINER_LABEL}", stop)
        self.assertIn("docker rm -f", stop)
        start = next(l for l in unit.splitlines() if l.startswith("TimeoutStartSec="))
        self.assertEqual(start, "TimeoutStartSec=5h")
        self.assertLess(bb.MAX_BUILD_TIMEOUT, 5 * 3600)

    def test_firewall_is_reloaded_at_boot(self):
        sh = (ROOT / "builder" / "install.sh").read_text()
        fw = sh[sh.index('if [ "$APPLY_FW" -eq 1 ]'):]
        fw = fw[:fw.index("\nfi\n")]
        self.assertIn("systemctl enable blunix-firewall.service", fw)
        unit = (ROOT / "builder" / "systemd" / "blunix-firewall.service").read_text()
        self.assertIn("ExecStartPre=/opt/blunix-builder/bin/check-door.sh /etc/blunix-builder/door.nft", unit)
        self.assertIn("Before=network-pre.target docker.service", unit)
        self.assertIn("WantedBy=sysinit.target", unit)
        manifest = (ROOT / "builder" / "MANIFEST.sha256").read_text()
        self.assertIn("systemd/blunix-firewall.service", manifest)


if __name__ == "__main__":
    unittest.main()

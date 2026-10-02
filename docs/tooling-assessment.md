# Blunix tooling assessment

Assessment of the local checkout, 2026-10-02. This is a code and workflow review,
not a claim about live deployments or a completed enterprise qualification.

## Delivered in this change

- Gitbuild: allowlisted repository checkout, recorded source commit, six language
  adapters and custom recipes, staged bundles, file hashes, owned relative links,
  upgrade/configuration handling, uninstall, and exception rollback.
- `gitbuild doctor`: build executable and pip availability checks.
- `gitbuild verify`: installed file and export-link drift checks.
- HTTPS fixes in tool downloads, AI downloads, bootstrap configuration retrieval,
  and installer release retrieval. Regression tests exercise real urllib openers
  while replacing only the HTTPS transport.
- Host-test CI on Debian, with offline real-toolchain fixture builds for all six
  languages. The existing local Docker test runner now prepares its test secrets
  and installs Git and Node for gitbuild tests. CI execution itself must still be
  confirmed after pushing the workflow.

## Remaining priorities

| Priority | Area | Existing evidence | Missing work and a useful acceptance check |
| --- | --- | --- | --- |
| P0 | Release authenticity | `image/scan-root.py`, `image/scan-raw.py`, checksums and pinned image URLs | Offline image/package signing and verifier key rotation. A changed image, bad signature, or withdrawn key must fail before a disk write. |
| P0 | Build isolation | Gitbuild refuses root source builds but executes trusted build scripts as the calling user | Disposable Debian builders, controlled network/dependency mirrors, resource limits, and no release credentials. A recipe must not read operator credentials or write the host. |
| P0 | Package dependencies | Gitbuild owns product files and links | Declare runtime libraries, interpreter/toolchain ABI, supported Debian release, conflicts and dependencies. Refuse an incompatible or incomplete runtime before activation. |
| P0 | VM installation regression | Manual QEMU/VMware launch scripts and Python installer tests exist | CI boots produced media and performs an actual install, reboot, network setup and encrypted-document handoff; cover UEFI, installer BIOS, blank/occupied disks, wrong keys and network failure. |
| P1 | Troubleshooting | Existing console messages, proxy health endpoint, and new gitbuild verification | `blunix doctor` and a consented `blunix support collect` command: bounded, redacted boot/network/storage/service diagnostics, useful offline. Tests must prove keys, passwords and configuration plaintext never enter the report. |
| P1 | Durable updates | Gitbuild restores an old package after handled publication errors | Persisted transaction recovery after power loss, retained versions, explicit rollback and disk-space checks; OS A/B updates remain a separate project. Kill the installer at each publication step and recover on the next run. |
| P1 | Packaging and distribution | Prepared directories with hashes and receipts | Portable signed bundle format or `.deb` export, package index, source/build provenance, SBOM and license inventory. Rebuild a pinned source revision and explain any artifact differences. |
| P1 | Service lifecycle | OS bootstrap/access systemd units exist | Product service declarations, users/groups, state directories, migration ordering, health checks and controlled restarts. A failed service upgrade must retain recoverable application state. |
| P1 | Web installation integration | Portal and node document parser exist | A declarative product selection model carrying reviewed package pins; fetch/install prepared packages during provisioning. Do not execute arbitrary source recipes from an untrusted node document. |
| P1 | Fleet automation | `docs/designs/blunix-service.md` and platform design describe future enrollment | Enrolled machine identity, signed desired state, maintenance windows, drift reporting and Terraform/Ansible interfaces. Exercise enrollment/revocation and interrupted application in integration tests. |
| P1 | API operations | Worker source, migrations and deployment scripts exist | Production configuration validation, D1/R2 backup and restore rehearsal, API availability checks and operational runbooks. The checked-in config still has placeholder D1/OIDC settings. |
| P2 | Builder profiles | Base package list is a small host image; language toolchains are external prerequisites | Versioned developer profiles for Python/Go/Rust/Node/PHP, native headers, lockfile policy, cache strategy and private-repository credentials. A clean builder should prepare representative real products without manual repair. |
| P2 | Desktop qualification | `lib/blunix/gui.py` activates a theme only when a graphical session exists | Desktop package profiles, display/audio/GPU integration, accessibility regression, suspend/resume, peripheral and application tests. Define a hardware support matrix and test it. |
| P2 | Debian source pipeline | Image script assembles binary packages with `mmdebstrap`; source notices are generated | If rebuilding Debian source is required: source snapshots, patch series, Debian build-dependency resolution, sbuild/buildd workers, signed APT repository and source artifact publication. Gitbuild does not implement that pipeline. |

## Suggested order

1. Run the new Debian CI and build several representative real repositories with
   checked-in recipes. Pin source commits and language lockfiles.
2. Add isolated builders and runtime dependency declarations before treating
   arbitrary product bundles as production packages.
3. Add signatures and real VM install/reboot tests before unattended distribution.
4. Implement offline diagnostics, durable rollback, service lifecycle and web
   product selection, then expand to fleet and desktop qualification.

The API typecheck/unit suite and static site tests already exist; the gaps are
primarily end-to-end system behavior, operations, and release/package guarantees.

## Validation and unresolved host issue

Local checks passed: 32 focused host/gitbuild tests (one additional test skipped
because the sandbox strips setuid bits), six real offline language build/install/
execution tests, the API typecheck and 102 API tests, and 13 site/portal tests.
The revised compression fixture also passed ten repeated runs. New Python files
pass Ruff; changed shell scripts pass syntax checks.

The full native macOS host suite is not green. Without `age`, an unrestricted run
completed 253 tests with six missing-age errors and 36 skips. Building the cached
age 1.2.1 source into a temporary test directory enabled additional tests but
exposed repeated PTY/process timeout failures in the existing `lib/blunix/age.py`
wrapper, including failure to reap a killed child within five seconds. The full
run was stopped after repeated failures. The underlying macOS issue remains
unresolved; these results do not establish whether Debian is affected.

Docker's local daemon was unavailable, so the Debian suite and image/VM builds
were not run here. The new Debian CI workflow is ready but has not been executed
remotely. Resolve the age wrapper portability issue and confirm Debian CI before
calling the host tooling fully validated.

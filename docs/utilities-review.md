# Utility ownership and review

The extraction preserves the module/model layout so existing imports, launchers,
tests, and image assembly paths continue working. Utility code is authored in
`blunix-utils` and copied into `blunix`; those copies should not be edited directly.

| Area | Existing source copied | Added here | Remaining work |
| --- | --- | --- | --- |
| Build/package tooling | Gitbuild, image builders, GPL source notices | Distribution sync with source provenance and owned-file deletion | Signed packages, runtime dependency declarations, SBOM, isolated builders |
| Security utilities | Mounted-root/raw-image secret scans, root sealing, age wrapper, serial redaction | Read-only protected-file ownership/permission audit | Comprehensive policy evaluation and remediation; existing macOS age/PTTY issue still needs diagnosis |
| Administration | Node, network, accessibility, bootstrap and tool commands | Selected systemd service-state inspection | Service installation/lifecycle definitions and runtime management policies |
| Integrity | Gitbuild receipt and file/link verification, image checksums | Aggregate installed-product integrity command | Cryptographic signatures and trusted external baselines |
| Troubleshooting | Console error reporting, proxy helpers | Doctor and metadata-only support collection | Explicitly redacted journal/network collectors, boot diagnostics and guided repair |
| Disk helpers | Disk model validation/rendering, installer selection/writing, VM/image helpers | Read-only device inspection and filesystem capacity reporting | SMART/NVMe health, filesystem checks/repair, LUKS recovery helpers with explicit destructive-action controls |

The new utilities never launch a shell or accept arbitrary commands. Support
collection is explicit, capped at 1 MiB, creates a new file with mode 0600, and
omits raw sensitive sources. The permission checker does not parse SSH settings,
read password hashes, or claim compliance certification. Integrity checks cover
Gitbuild products, not the whole Debian installation.

The sync script was tested with real temporary Git repositories for idempotence,
conflicting local changes, preservation of unrelated staged work, owned deletion,
bootstrap adoption, dry runs, symlink/traversal refusal and commit-hook failure
rollback. Distribution commits contain only managed paths and a source receipt.

Current local website/build aliases point into the distribution (`site` and
`portal`). They remain outside the utility sync map; their future extraction is
independent of this utility split.

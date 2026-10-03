# builder1 host baseline

`builder1` is a new, single-purpose DartNode VPS (Debian 13, KVM, 4-8 vCPU,
8-16 GiB RAM, at least 100 GiB disk). It builds official Blunix release images
from signed tags of the public `afterdarksys/blunix` repo and stages them,
unsigned, in R2 `blunix-release-staging`. Signing happens later, off this
host (see `blunix-build-infra-design.md` section 4e).

## What it holds, and what it never holds

| Holds | Never holds |
| --- | --- |
| R2 key pair for the staging bucket only (`/etc/blunix-builder/r2-credentials`, root 0600) | release signing secret key |
| Pinned tag-signer public key (`/opt/blunix-builder/keys/tag-signers.asc`) | GitHub token (repo is read anonymously) |
| Its own SSH host keys; a fresh admin SSH key used for this host only | Cloudflare account token, Authentik secrets, user ciphertext |

Pull-only: no listener except sshd, which is reachable only from the
vpscfgfarm door addresses.

## Trust boundary (read this)

The image build needs a privileged container (loop devices, kpartx, mount).
Privileged containers and membership in group `docker` are both
root-equivalent. So **the host is the trust boundary**: it builds only tags
signed by a pinned key, and it holds nothing worth stealing. A "build my
custom image" feature would break this model and needs a new threat model.

## Packages

`install.sh` installs, if missing: `docker.io git gnupg python3 python3-yaml
nftables unattended-upgrades openssh-client ca-certificates`. Recommended
alongside (baseline runbook, not install.sh): `fail2ban auditd chrony`.

## Data disk

builder1 has a 300 GiB root disk and a separate 2.9 TiB data disk. Builds and
Docker's layers go on the data disk, mounted at `/srv`: a full root disk in
the middle of a build would take the OS with it.

Set it up once, by a human: `mkfs` is on the vpscfgfarm deny floor, so it
never goes through the door. The script is
`vpscfgfarm/deploy/builder1/setup-data-disk.sh`. It refuses unless the disk is
blank, creates GPT + one XFS partition labelled `blunix-data`, and mounts it
at `/srv` by UUID with `nofail`.

`install.sh` then refuses to run unless `/srv` is its own mount, writes
`/etc/docker/daemon.json` with `"data-root": "/srv/docker"` before Docker is
installed, and checks `docker info` reports that root afterwards.

## sshd

DartNode ships `/etc/ssh/sshd_config.d/01-dartnode.conf` with password and
root login enabled. Fix it on first boot:

```
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
AllowUsers root@<door-ip>
```

## Firewall (nftables)

`nftables.conf` (installed to `/etc/blunix-builder/nftables.conf`) defines one
table, `inet blunix_host`, and leaves Docker's own tables alone:

- input: policy drop; established/related, loopback, rate-limited ICMP, and
  22/tcp from the door set only.
- output: policy drop; DNS 53, NTP 123, HTTP 80 (Debian mirrors) and HTTPS 443
  (GitHub, Debian, R2).
- forward (bridge `br-blunix`, the `blunix-build` Docker network): DNS, 80 and
  443 only. Everything else from build containers is dropped.

The door addresses are admin IPs and this repo is public, so they are not
in `nftables.conf`. It includes `/etc/blunix-builder/door.nft`, which comes
from the private vpscfgfarm repo (pushed through the door, root 0644) and
holds exactly one line:

```
define DOOR_V4 = { a.b.c.d, e.f.g.h }
```

Then `bash install.sh --apply-firewall`. It refuses a door.nft that is missing,
not root-owned, group/world writable, or anything but that one define of plain
IPv4 addresses (`check-door.sh`), then runs `nft -c` before loading. Keep a
second, stable fleet address in the set as a jump host so a changed home IP
is not a lockout, and apply it the first time over a session you can recover
(DartNode console).

## Unattended upgrades

DECISION (Ryan): security updates only, **no automatic reboot**, so a kernel
update never kills a build. `/etc/apt/apt.conf.d/52blunix-builder`:

```
Unattended-Upgrade::Origins-Pattern { "origin=Debian,codename=${distro_codename}-security"; };
Unattended-Upgrade::Automatic-Reboot "false";
```

Reboot by runbook outside a build: `vpsexec builder1 'systemctl is-active blunix-builder.service'`
must say `inactive` first.

## Users, directories, permissions

| Path | Owner | Mode | Purpose |
| --- | --- | --- | --- |
| user `builder` | system, nologin, groups `builder`,`docker` | | runs the service |
| `/opt/blunix-builder/{bin,lib,keys}` | root:root | 0755 / files 0644 (launcher 0755) | code and trust root |
| `/etc/blunix-builder/config.yaml` | root:root | 0644 | no secrets |
| `/etc/blunix-builder/r2-credentials` | root:root | 0600 | `access_key_id=` / `secret_access_key=` lines |
| `/var/lib/blunix-builder` | builder:builder | 0750 | `mirror.git`, `built/`, `rejected/`, `attempts/`, `lock`, `last-poll` |
| `/srv/blunix-builds` | builder:builder | 0750 | one worktree + `.log` per build; last 2 kept |

The service gets the credential through systemd `LoadCredential=blunix-r2`,
so the `builder` user never reads `/etc/blunix-builder/r2-credentials`
directly, and the build container never sees it.

## systemd

- `blunix-builder.timer`: 5 min after boot, then 10 min after each run ends.
- `blunix-builder.service`: oneshot, `User=builder`, `SupplementaryGroups=docker`,
  `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
  `PrivateDevices`, empty capability set, `ReadWritePaths` only for the state
  dir, work dir and `/run/docker.sock`. The docker socket is the escape hatch:
  the hardening confines the runner (git, gpg, HTTP parsing), not the build.

Exit codes: 0 idle or staged, 1 build/upload/config failure, 2 tag rejected
(signature, lightweight, renamed). Non-zero shows in `vpsexec check failed builder1`.
Logs are JSON lines in the journal: `journalctl -u blunix-builder -o cat`.

## R2

Bucket `blunix-release-staging`, private, lifecycle rule 30 days. Token:
**Object Read & Write scoped to this one bucket** (R2 has no write-only
object token; read is used only for the `HEAD {tag}/build-provenance.json`
idempotency check, and `r2.check_existing: false` drops that need). Objects:
`{tag}/<artifact>`, then `{tag}/SHA256SUMS`, then `{tag}/build-provenance.json`
last; a tag without the provenance object is not complete.

## Install via vpscfgfarm

On the laptop, in `blunix-utils`:

```sh
bash builder/package.sh            # rewrites builder/MANIFEST.sha256, prints tarball sha256
git diff --exit-code builder/MANIFEST.sha256   # the committed manifest must match
```

Then through the door (content-addressed, hash-checked):

```sh
H=<tarball sha256>
vpsexec builder1 push build/blunix-builder-0.1.0.tar.gz --sha256 $H --run --reason "blunix-builder 0.1.0"
vpsexec builder1 "echo '$H  /var/tmp/vpscfg-push/$H/blunix-builder-0.1.0.tar.gz' | sha256sum --check --status \
  && rm -rf /var/tmp/blunix-builder-pkg && mkdir -m 0700 /var/tmp/blunix-builder-pkg \
  && tar -C /var/tmp/blunix-builder-pkg --no-same-owner -xzf /var/tmp/vpscfg-push/$H/blunix-builder-0.1.0.tar.gz \
  && bash /var/tmp/blunix-builder-pkg/install.sh" \
  --verify "/opt/blunix-builder/bin/blunix-builder version" --run --reason "install blunix-builder 0.1.0"
```

`install.sh` re-checks every file against `MANIFEST.sha256` before it touches
the host. Once builder1's posture is `lockdown`, commit a runbook
`policies/blunix-builder-<sha>.yaml` naming that exact push (pattern:
`secretserver-release-cc20ecb.yaml`). Posture lives only in
`vpscfg-control.json`; that edit is Ryan's.

Credential delivery: Ryan writes `/etc/blunix-builder/r2-credentials` once over
the door (or a `vpsexec push` of a file named `builder-r2.conf`, after checking
`policies/secrets.yaml` masks it), then re-runs `install.sh` to enable the
timer. Rotate the token whenever the host is rebuilt.

Rollback: the previous tarball stays in `/var/tmp/vpscfg-push/<oldsha>/`;
re-run the install command with the old hash.

## First run checklist

1. `container_image` in `/etc/blunix-builder/config.yaml` pinned to a real digest
   (the shipped all-zero digest is refused).
2. `r2.endpoint` set to `https://<account-id>.r2.cloudflarestorage.com`.
3. `runuser -u builder -- /opt/blunix-builder/bin/blunix-builder check-config`.
4. `systemctl start blunix-builder.service; journalctl -u blunix-builder -o cat`.
5. Compare the staged `SHA256SUMS` and SOURCES.md with a laptop build of the
   same tag (byte equality is not expected until snapshot pinning).

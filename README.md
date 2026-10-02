# blunix-utils

The development repository for Blunix's custom host utilities and image helpers.
Make utility changes here, test and commit them, then sync their distribution
copies into `blunix`.

| Project | Responsibility |
| --- | --- |
| `blunix.io` | Website (currently the local symlink to `blunix/site`) |
| `build.blunix.io` | Build infrastructure entry point (currently the local symlink to `blunix/portal`) |
| `blunix` | Distribution, assembled images, and distribution integration |
| `blunix-utils` | Custom utilities, Gitbuild, host administration, security/integrity checks and image helper source |

The website and portal/API implementation are not owned by this utility repo.
Image helper scripts and their configuration/templates are maintained here and
synced into the distribution's existing `image/` paths so image builds retain
their current layout. `build/` contains only local artifacts and test fixtures;
it is never copied by the sync script.

## Get started

Repository: [afterdarksys/blunix-utils](https://github.com/afterdarksys/blunix-utils).

```sh
git clone https://github.com/afterdarksys/blunix-utils.git
cd blunix-utils
# Requires Python 3.9+ and PyYAML.
./apply/blunix doctor
./apply/gitbuild --help
```

Keep the distribution checkout at `../blunix` for the default sync workflow,
or pass `--dist /path/to/blunix` to `sync-to-dist.py`.

## Tools

- `apply/blunix`: installer/bootstrap, accessibility, network, node and disk model helpers.
- `apply/gitbuild`: source builds, product installation/removal, ownership and integrity verification.
- `blunix doctor [--root ROOT]`: executable availability and filesystem capacity.
- `blunix security audit [--root ROOT]`: protected-path ownership/permission checks.
- `blunix integrity check [PRODUCT] [--root ROOT]`: Gitbuild file and link drift.
- `blunix admin status`: selected systemd service states on the live host.
- `blunix disk inspect`: read-only block-device/mount metadata through `lsblk`.
- `blunix support collect --output report.json [--root ROOT]`: exclusive-create,
  mode-0600 JSON report containing availability, permission and package-integrity
  metadata. It does not collect configuration bodies, journal logs, environment
  variables, process arguments, credentials, or network addresses.
- `image/scan-root.py`, `scan-raw.py`, `seal-root.py`, `redact-serial.py`,
  `gpl-sources.py`: existing image security, sealing, redaction and source-notice helpers.

These new read-only checks are intentionally narrow. They are not a complete
hardening audit, signature verification, hardware health test, disk repair tool,
or automatic remediation system. Missing Linux commands report unavailable.
Disk and service inspection always refer to the running host, so they do not
accept `--root`. Root-targeted checks refuse protected-path symlinks rather than
following them outside a mounted image.

## Standalone packaging

`gitbuild.yaml` stages runtime modules, models, theme assets and relocatable
launchers under the `blunix-utils` product prefix. Prepare `afterdarksys/blunix-utils` with Gitbuild at an explicit tag or commit.
The installed runtime requires Python 3.9+ and PyYAML; `age` and Linux system tools
are required by their respective commands. Image builders remain source-tree
utilities and are distributed through the sync map.

## Development and distribution sync

Use Python 3.9+ and PyYAML for host tools. The sync script uses only the standard
library and Git. Language builders and additional test prerequisites are listed
in [the Gitbuild guide](docs/gitbuild.md).

```sh
PYTHONPATH=lib python3 -m unittest discover -s tests -p 'test_ops.py' -v
python3 -m unittest discover -s tests -p 'test_sync.py' -v
# Debian full suite (requires Docker):
bash image/run-unit-tests.sh

git add <changed-files>
git commit -m 'Describe the utility change'
python3 sync-to-dist.py --dry-run
python3 sync-to-dist.py
```

`sync-to-dist.py` defaults to the sibling `../blunix` repository. Override with
`--dist /path/to/blunix`. Source must be committed and clean. `dist-map.json`
defines directory/file mappings; only Git-tracked files are copied. New files
under mapped directories are included automatically once committed. Tests for
the sync script itself stay in this repository.

The script checks destination hashes against `.blunix-utils-sync.json`, refuses
conflicting distribution edits, preserves unrelated files and staged changes,
and commits exactly the managed paths using `git commit --only`. Deleted source
files remove only files owned by the previous receipt. Failed commits restore
the managed working files and clear only the staging added by the sync. Git
hooks run normally. No remote push occurs.

The receipt records the exact source commit and file hashes. The initial
`--bootstrap` sync adopts the captured `dist-baseline.json` extraction inventory;
a later sync cannot use that option. It will not overwrite intervening edits.
Without bootstrap, existing files can be adopted only if they already match the
source. Always bring distribution-side utility edits back into this repo before
syncing; there is no force-overwrite option.

A cooperative lock serializes sync invocations. This is not power-loss recovery;
keep other writers away from managed paths while syncing. Commit source code
before syncing; commit or unstage managed destination paths first. Unrelated
distribution changes can remain staged or unstaged.

See [the utility review](docs/utilities-review.md) for ownership and remaining
work, and [the tooling assessment](docs/tooling-assessment.md) for platform gaps.

Blunix's existing license and notices are retained in this repository. Copying
code into a separate repository does not change its licensing.

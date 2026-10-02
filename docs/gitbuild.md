# Gitbuild

Gitbuild checks out repositories owned by `straticus1` or `afterdarksys`, builds
an explicitly selected Git ref, and creates an installable directory bundle.
Installation puts the product in `/usr/local/afterdarksys/<product>` and publishes
relative links in `/usr/local/bin`, `/usr/local/sbin`, `/usr/local/lib/<product>`
and `/usr/local/etc/<product>`.

## Commands

From this checkout, use `./apply/gitbuild` or `./apply/blunix gitbuild`. Both
launchers are included in newly built Blunix images.

```sh
# Build as an ordinary user. Tags and branches resolve to a recorded commit.
./apply/gitbuild doctor --system go
./apply/gitbuild prepare afterdarksys/example --ref v1.2.3 --output ./build/example
# A full commit SHA is preferable when repeatability matters.
./apply/gitbuild prepare straticus1/example --ref <commit> --output ./build/example \
  --manifest ./recipes/example.yaml

# Review bundle.json and payload/ before installation.
sudo ./apply/gitbuild install ./build/example
./apply/gitbuild list
./apply/gitbuild verify example
sudo ./apply/gitbuild remove example          # retain configuration
sudo ./apply/gitbuild remove example --purge  # also remove configuration

# Assemble a target filesystem without changing the running OS.
./apply/gitbuild install ./build/example --root ./build/rootfs
```

`build` is an alias for `prepare`. The output must not exist. Build failures leave
no output bundle. Installation executes no repository code or lifecycle hooks.
Commands emit JSON results; failures return a nonzero exit code. Build subprocess
output remains visible. `verify` reports changed, missing, and extra files and
changed export links, returning 1 if any differ from the installation receipt.
`doctor` checks executable availability and Python pip, not toolchain versions or
application-specific native dependencies.

## Repository recipe

Place `gitbuild.yaml` in the repository root, or pass a local `--manifest` override.
There is no universal way to infer how every repository should be installed;
ambiguous projects and script repositories require a recipe. These recipes let
any repository in either owner namespace participate without changing its source.

```yaml
version: 1
product: example
system: bash
files:
  - source: scripts/example
    dest: bin/example
  - source: scripts/exampled
    dest: sbin/exampled
  - source: runtime
    dest: lib/runtime
  - source: config/example.conf
    dest: etc/example.conf
```

Sources are explicit files or directories relative to the checkout; destinations
are under `bin`, `sbin`, `lib`, or `etc`. No globs or parent traversal are accepted.
Commands in `bin` and `sbin` are executable. Configuration preserves its source
permissions. Supply restrictive source permissions for private defaults; do not
put credentials in build recipes or bundles.

| System | Default build behavior |
| --- | --- |
| `go` | `go build -trimpath -o <stage>/bin/<product> ./<target>`; target defaults to `.` |
| `rust` | `cargo build --release --locked`; copy `target/release/<product>` unless `files` specifies artifacts |
| `python` | Install project and dependencies using pip into `lib/python`; generate relocatable console-script launchers |
| `node` | `npm ci`, optional build script, prune development dependencies; copy app and runtime dependencies into `lib/node`, export `package.json` bin entries |
| `bash` | Copy explicitly declared scripts, libraries, and configuration |
| `php` | Run Composer when `composer.json` exists, then copy explicitly declared artifacts including vendor dependencies |
| `custom` | Run explicit command arrays and collect declared files or staged output |

A single `go.mod`, `Cargo.toml`, Python project marker, `package.json`, or
`composer.json` selects its adapter automatically. Multiple detected systems
require an explicit `system`. For monorepos, multiple binaries, PHP web apps, and
mixed-language projects, use `commands` and `files`. Node bin entries need their
usual executable interpreter shebang. PHP CLI scripts likewise need a PHP
shebang; web applications should be installed under `lib` with a separately
managed web-server configuration. No web server or service is started by gitbuild.

Explicit `commands` replace the adapter's default commands. Each command is an
argument array, executed without implicit shell evaluation. Use a checked-in
script to perform complex builds:

```yaml
version: 1
product: example
system: custom
commands:
  - [bash, scripts/build.sh]
files:
  - source: dist/example
    dest: bin/example
  - source: config
    dest: etc/defaults
```

The four payload directories already exist, so copy configuration to a path such
as `etc/example.conf` or `etc/defaults`, rather than to `etc` itself. A script may
also populate `$GITBUILD_STAGE` directly, or use conventional
`make install DESTDIR="$DESTDIR" PREFIX="$PREFIX"` from inside the script:

- `PREFIX=/usr/local/afterdarksys/<product>` is the final runtime prefix.
- `DESTDIR` is an isolated staging directory. Gitbuild collects `$DESTDIR$PREFIX`.
- `GITBUILD_STAGE` is the staged product directory, already containing the four areas.
- `GITBUILD_SOURCE` is the checkout directory.

Python launchers locate `lib/python` relative to their resolved installed path,
including when invoked through `/usr/local/bin`. Native extension dependencies
still require compatible Python and system libraries on the target. Libraries
under `/usr/local/lib/<product>` do not automatically enter the dynamic loader's
search path: binaries should use a suitable relative rpath or a wrapper.

## Ownership and upgrades

A bundle contains `bundle.json` and `payload/`. Metadata records the owner/repo,
requested ref, resolved commit, build system, OS, architecture, and SHA-256/mode
inventory. Installation checks the inventory before target writes and again after
copying. Bundles must match the installer's OS and architecture; cross-compilation
and installing Linux bundles from a macOS host are not supported in this version.

The installed `.gitbuild.json` receipt owns the product tree and its links.
Unmanaged product directories, foreign commands, replaced links, symlinked target
ancestors, external/absolute payload links, special files, and special permission
bits are refused. Internal relative library links are allowed; configuration
symlinks are refused. A lock serializes cooperating installers.

Install the next bundle to upgrade. Unmodified default configuration updates to
the new version. Locally modified or added configuration survives. If a modified
file has a new default, that default is saved alongside it as `.gitbuild-new`.
Resolve or remove this candidate before another conflicting upgrade. Removed
products retain their configuration and `etc` link with status `config-only`;
`--purge` removes them too.

Errors during publication roll back the product and links. This is exception
recovery, **not** power-loss recovery or a persistent multi-version rollback
system. If rollback itself fails, gitbuild reports the retained transaction
directory; its `previous/` tree must be kept for administrator recovery.
Builds execute repository and dependency code with the invoking user's
permissions and network access. Use a disposable Debian build environment for
untrusted code. Bundles are integrity checked but not signed; metadata alone does
not authenticate the producer. Keep the target root writable only by trusted
administrators during installation.

Gitbuild does not yet resolve Debian runtime dependencies, generate `.deb` files,
manage systemd units, update the web installation schema, fetch submodules, build
Debian itself from source, or claim byte-for-byte reproducible builds. Git HTTPS
checkout disables prompts and ambient Git config, so private-repository credential
integration needs a separate design.

## Builder prerequisites

The base image includes Git and Python/YAML. Install language toolchains only on
builder machines. On Debian, the corresponding package names include
`build-essential`, `pkg-config`, `golang-go`, `cargo`, `rustc`, `python3-pip`,
`python3-venv`, `nodejs`, `npm`, `bash`, `php-cli`, and `composer`. Project manifests
may require newer toolchains or additional development libraries. Gitbuild never
runs a package-manager command with root privileges on the operator's behalf.

Run the host tests with:

```sh
PYTHONPATH=lib python3 -m unittest discover -s tests -p 'test_gitbuild*.py' -v
PYTHONPATH=lib python3 -m unittest discover -s tests -p 'test_https_openers.py' -v
# With all six toolchains installed, run real offline build/install fixtures.
BLUNIX_TOOLCHAIN_TESTS=1 PYTHONPATH=lib python3 -m unittest discover -s tests -p 'test_gitbuild_toolchains.py' -v
```

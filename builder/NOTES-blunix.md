# blunix (dist) changes the builder wants

The builder does not edit `afterdarksys/blunix`. It works with the release
scripts as they are today, through `inside-release.sh`. These are the changes
recommended in `blunix` itself, in priority order.

1. **Sign release tags.** `v0.1.0` is a lightweight, unsigned tag, so the
   builder will never build it. Future releases: `git tag -s vX.Y.Z -m vX.Y.Z`
   with a key in `builder/keys/tag-signers.asc` and `trusted_fingerprints`.
2. **Emit SOURCES.md in the release build** (design item 14). Today
   `inside-release.sh` extracts `var/lib/dpkg/status` from the release disk and
   the installer squashfs after the build and runs `image/gpl-sources.py`.
   Better: `build-test-disk.sh --release` copies the rootfs dpkg status to
   `build/gpl/disk-status`, `build-installer.sh --release` copies its own to
   `build/gpl/installer-status`, runs gpl-sources.py into `build/release/`,
   and lists SOURCES.md in its SHA256SUMS. The wrapper step then becomes a
   check.
3. **A Linux host path** (design item 13). On Linux both `build-*.sh` refuse
   without `--inside`, and `--inside` assumes the container at `/src`. Add a
   documented Linux branch (same `docker run` as the Darwin branch) or keep
   `--inside` as the only Linux entry and say so in `image/README.md`.
4. **Pin the base image by digest on the laptop path too.** The Darwin branch
   runs floating `debian:trixie-slim`. Accept `BLUNIX_BUILD_IMAGE` (must match
   `name@sha256:<64 hex>`) so laptop and builder use the same pinned image.
5. **No cache in release mode.** `build-test-disk.sh` reuses
   `build/rootfs.tar` when `mmdebstrap.done` matches the `packages.txt` hash,
   which can ship stale security updates. `--release` should ignore the cache.
   The builder already guarantees an empty `build/`.
6. **snapshot.debian.org pinning** so two builds of one tag are byte-identical
   and laptop vs builder output can be compared.
7. **`--release` without `prepare-secrets.py`.** The Darwin branch always
   creates the test secrets, even for `--release`. The release disk does not
   use them; skipping them in release mode keeps test secrets out of release
   build trees entirely.

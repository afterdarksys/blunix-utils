#!/bin/bash
# Release build inside the builder's throwaway privileged container.
#
#   docker run --rm --privileged -v <worktree>:/src -w /src \
#     -v <this file>:/builder/inside-release.sh:ro \
#     -e BLUNIX_RELEASE_VERSION=<tag> -e BUILDER_UID=<uid> -e BUILDER_GID=<gid> \
#     <image>@sha256:<digest> bash /builder/inside-release.sh
#
# This is the Linux path for image/build-*.sh: on Linux those scripts refuse to
# run unless given --inside, which means "already in the build container with
# the checkout at /src". It runs, in order:
#   1. image/build-test-disk.sh --inside --release   (seal-root.py, scan-root.py
#      --release and scan-raw.py run inside it)
#   2. image/build-installer.sh --inside --release   (release disk re-scan,
#      payload scan, writes build/release/ and its SHA256SUMS)
#   3. dpkg status from the release disk and the installer squashfs, then
#      image/gpl-sources.py -> build/release/SOURCES.md
# build/ must not exist on entry: no mmdebstrap cache is carried into a release.
# On exit build/ is handed back to the builder user so the host can read and
# remove it. No credential is passed into this container.
set -eu
set -o pipefail

case "${BLUNIX_RELEASE_VERSION:-}" in
  ""|latest|*[!A-Za-z0-9.+-]*)
    echo "blunix-builder: refused release version" >&2
    exit 1
    ;;
esac
case "${BUILDER_UID:-}:${BUILDER_GID:-}" in
  *[!0-9:]*|:*|*:)
    echo "blunix-builder: BUILDER_UID/BUILDER_GID required" >&2
    exit 1
    ;;
esac
if [ "$(pwd)" != /src ] || [ ! -f /src/image/build-test-disk.sh ]; then
  echo "blunix-builder: expected the checkout at /src" >&2
  exit 1
fi
if [ -e /src/build ]; then
  echo "blunix-builder: build/ exists; a release starts from an empty tree" >&2
  exit 1
fi

CHECK=/mnt/blunix-gpl
LOOP=""
handback() {
  code=$?
  umount "$CHECK" 2>/dev/null || true
  if [ -n "$LOOP" ]; then
    kpartx -d "$LOOP" 2>/dev/null || true
    losetup -d "$LOOP" 2>/dev/null || true
  fi
  if [ -d /src/build ]; then
    chown -R "$BUILDER_UID:$BUILDER_GID" /src/build || true
  fi
  exit "$code"
}
trap handback EXIT

# A fresh, empty build/ (never a carried cache), plus this build's own throwaway
# test secrets: scan-root.py and scan-raw.py search the image for them, so they
# must exist even though a release image locks root and never contains them.
# They stay 0600 in build/, outside build/release/, which is all that is staged.
mkdir /src/build
python3 /src/image/prepare-secrets.py

echo "blunix-builder: disk"
bash /src/image/build-test-disk.sh --inside --release
echo "blunix-builder: installer"
bash /src/image/build-installer.sh --inside --release

echo "blunix-builder: gpl sources"
mkdir -p /src/build/gpl
LOOP=$(losetup -r -f --show /src/build/blunix-release.raw)
kpartx -r -av "$LOOP" >/dev/null
part=""
for candidate in /dev/mapper/"$(basename "$LOOP")"p*; do
  if [ "$(blkid -o value -s LABEL "$candidate" 2>/dev/null)" = "blunix-root" ]; then
    part=$candidate
  fi
done
if [ -z "$part" ]; then
  echo "blunix-builder: release disk has no blunix-root" >&2
  exit 1
fi
mkdir -p "$CHECK"
mount -o ro,noload "$part" "$CHECK"
install -m 0644 "$CHECK/var/lib/dpkg/status" /src/build/gpl/disk-status
umount "$CHECK"
kpartx -d "$LOOP"
losetup -d "$LOOP"
LOOP=""
unsquashfs -cat /src/build/release/blunix.squashfs var/lib/dpkg/status \
  > /src/build/gpl/installer-status
for status in disk-status installer-status; do
  if [ ! -s "/src/build/gpl/$status" ]; then
    echo "blunix-builder: empty dpkg status $status" >&2
    exit 1
  fi
done
python3 /src/image/gpl-sources.py "$BLUNIX_RELEASE_VERSION" \
  /src/build/gpl/disk-status /src/build/gpl/installer-status \
  > /src/build/release/SOURCES.md
if [ ! -s /src/build/release/SOURCES.md ]; then
  echo "blunix-builder: SOURCES.md empty" >&2
  exit 1
fi
echo "blunix-builder: release tree ready"

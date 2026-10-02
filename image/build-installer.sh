#!/bin/bash
# Live installer ISO: hybrid UEFI + BIOS, USB or optical, plus netboot media.
# The image it installs is build/blunix-test.raw, zstd-compressed, when present.
# --release packs build/blunix-release.raw instead, needs BLUNIX_RELEASE_VERSION,
# and refuses a disk that fails the release scan (fixture, test secrets, an
# unlocked account) or the raw byte scan (a key in free space), and is the only
# build that writes build/release/. Without --release the assets go to
# build/test/ with TEST in every name. This is not the signed UKI image.
set -eu
set -o pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

if [ "$(uname -s)" = "Darwin" ]; then
  if [ "${1:-}" = "--inside" ]; then
    echo "blunix: installer build refused" >&2
    exit 1
  fi
  mode_flag=""
  case "${1:-}" in
    "") ;;
    --release) mode_flag=--release ;;
    *)
      echo "blunix: installer build refused" >&2
      exit 1
      ;;
  esac
  python3 "$ROOT/image/prepare-secrets.py"
  mkdir -p "$ROOT/build/installer"
  set +e
  # shellcheck disable=SC2086
  docker run --rm --privileged \
    -e BLUNIX_RELEASE_VERSION="${BLUNIX_RELEASE_VERSION:-}" \
    -v "$ROOT":/src -w /src \
    debian:trixie-slim \
    bash /src/image/build-installer.sh --inside $mode_flag
  code=$?
  set -e
  if [ "$code" -ne 0 ]; then
    printf '%s\n' FAILED > "$ROOT/build/installer/status.txt"
    exit "$code"
  fi
  exit 0
fi

if [ "${1:-}" != "--inside" ]; then
  echo "blunix: installer build refused" >&2
  exit 1
fi
RELEASE=0
case "${2:-}" in
  "") ;;
  --release) RELEASE=1 ;;
  *)
    echo "blunix: installer build refused" >&2
    exit 1
    ;;
esac

export DEBIAN_FRONTEND=noninteractive
export LANG=C
export LC_ALL=C

OUT=/src/build/installer
WORK=/var/tmp/blunix-installer
ROOTFS=$WORK/rootfs
ISO=$WORK/iso
CACHE=$OUT/rootfs.tar
RAW=/src/build/blunix-test.raw
KIND=test
DEST=/src/build/test
TAG=-TEST
if [ "$RELEASE" -eq 1 ]; then
  RAW=/src/build/blunix-release.raw
  KIND=release
  DEST=/src/build/release
  TAG=""
fi
# The ISO volume label. The installer refuses any disk that carries it.
LABEL=BLUNIX_INSTALL
VERSION=${BLUNIX_RELEASE_VERSION:-}
CHECK=/mnt/blunix-check
LOOP=""

cleanup() {
  code=$?
  umount "$CHECK" 2>/dev/null || true
  if [ -n "$LOOP" ]; then
    kpartx -d "$LOOP" 2>/dev/null || true
    losetup -d "$LOOP" 2>/dev/null || true
  fi
  rm -rf "$WORK"
  mkdir -p "$OUT"
  if [ "$code" -eq 0 ]; then
    printf '%s\n' DONE > "$OUT/status.txt"
  else
    printf '%s\n' FAILED > "$OUT/status.txt"
  fi
  exit "$code"
}
trap cleanup EXIT

case "$VERSION" in
  "") ;;
  latest|*[!A-Za-z0-9.+-]*)
    echo "blunix: refused release version" >&2
    exit 1
    ;;
esac
if [ "$RELEASE" -eq 1 ]; then
  if [ -z "$VERSION" ]; then
    echo "blunix: release needs BLUNIX_RELEASE_VERSION" >&2
    exit 1
  fi
  if [ ! -s "$RAW" ]; then
    echo "blunix: release disk missing; run build-test-disk.sh --release" >&2
    exit 1
  fi
fi

echo "blunix: builder packages"
apt-get update -qq
apt-get install -y -qq \
  mmdebstrap squashfs-tools xorriso mtools dosfstools zstd kpartx \
  grub-common grub-pc-bin grub-efi-amd64-bin \
  python3 python3-yaml ca-certificates >/dev/null

pkgs=""
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    ""|\#*) continue ;;
  esac
  case "$line" in
    *[!A-Za-z0-9.+-]*)
      echo "blunix: refused package" >&2
      exit 1
      ;;
  esac
  if [ -z "$pkgs" ]; then
    pkgs=$line
  else
    pkgs="$pkgs,$line"
  fi
done < /src/image/installer/packages.txt

mkdir -p "$OUT" "$WORK"
stamp=$(sha256sum /src/image/installer/packages.txt | awk 'NR==1 { print $1 }')
# The Mac share folds case, so the rootfs is unpacked on the container disk.
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS"
use_cache=0
if [ -f "$OUT/mmdebstrap.done" ] \
  && [ "$(cat "$OUT/mmdebstrap.done")" = "$stamp" ] \
  && [ -s "$CACHE" ]; then
  echo "blunix: mmdebstrap cache"
  if tar -C "$ROOTFS" -xf "$CACHE" && [ -x "$ROOTFS/usr/bin/python3" ]; then
    use_cache=1
  else
    echo "blunix: mmdebstrap cache refused"
    rm -rf "$ROOTFS"
    mkdir -p "$ROOTFS"
  fi
fi
if [ "$use_cache" -ne 1 ]; then
  echo "blunix: mmdebstrap"
  rm -f "$OUT/mmdebstrap.done" "$CACHE"
  mmdebstrap --variant=apt --architectures=amd64 \
    --aptopt='APT::Install-Recommends "false"' \
    --aptopt='APT::Install-Suggests "false"' \
    --include="$pkgs" \
    trixie "$ROOTFS" \
    "deb http://deb.debian.org/debian trixie main" \
    "deb http://deb.debian.org/debian trixie-updates main" \
    "deb http://deb.debian.org/debian-security trixie-security main"
  tar -C "$ROOTFS" -cf "$CACHE" .
  printf '%s\n' "$stamp" > "$OUT/mmdebstrap.done"
fi

for tool in lsblk findmnt blockdev sgdisk growpart e2fsck resize2fs zstd age networkctl udevadm chroot; do
  if ! chroot "$ROOTFS" /bin/sh -c 'command -v "$1" >/dev/null' sh "$tool"; then
    echo "blunix: live system is missing $tool" >&2
    exit 1
  fi
done
if [ ! -d "$ROOTFS/usr/lib/live/boot" ] && [ ! -d "$ROOTFS/lib/live/boot" ]; then
  echo "blunix: live-boot missing" >&2
  exit 1
fi

echo "blunix: overlay"
rm -rf "$ROOTFS/usr/lib/blunix-python"
mkdir -p "$ROOTFS/usr/lib/blunix-python/blunix"
cp -a /src/lib/blunix/*.py "$ROOTFS/usr/lib/blunix-python/blunix/"
rm -rf "$ROOTFS/usr/share/blunix/models"
mkdir -p "$ROOTFS/usr/share/blunix"
cp -a /src/models "$ROOTFS/usr/share/blunix/models"
for launcher in /src/apply/blunix /src/apply/blunix-* /src/apply/gitbuild; do
  install -m 0755 "$launcher" "$ROOTFS/usr/bin/$(basename "$launcher")"
done
mkdir -p "$ROOTFS/etc/systemd/system"
install -m 0644 /src/image/units/blunix-access.service "$ROOTFS/etc/systemd/system/"
install -m 0644 "/src/image/installer/blunix-install@.service" "$ROOTFS/etc/systemd/system/"

wants() {
  target=$1
  unit=$2
  link=$3
  mkdir -p "$ROOTFS/etc/systemd/system/$target.wants"
  ln -sfn "$link" "$ROOTFS/etc/systemd/system/$target.wants/$unit"
}
wants multi-user.target systemd-networkd.service /usr/lib/systemd/system/systemd-networkd.service
wants multi-user.target systemd-resolved.service /usr/lib/systemd/system/systemd-resolved.service
wants sysinit.target blunix-access.service ../blunix-access.service
wants multi-user.target blunix-install@tty1.service ../blunix-install@.service
wants multi-user.target blunix-install@ttyS0.service ../blunix-install@.service
# The installer owns tty1 and ttyS0. Other VTs keep their getty; root is locked.
for unit in getty@tty1.service serial-getty@ttyS0.service \
  espeakup.service speech-dispatcher.service brltty.service; do
  ln -sfn /dev/null "$ROOTFS/etc/systemd/system/$unit"
done

rootpw=$(awk -F: '$1 == "root" { print $2 }' "$ROOTFS/etc/shadow")
case "$rootpw" in
  "*"|"!"*) ;;
  *)
    chroot "$ROOTFS" passwd -l root >/dev/null
    ;;
esac
printf '%s\n' blunix-installer > "$ROOTFS/etc/hostname"
cat > "$ROOTFS/etc/hosts" <<'EOF'
127.0.0.1 localhost
127.0.1.1 blunix-installer
EOF
rm -f "$ROOTFS/etc/resolv.conf"
ln -s /run/systemd/resolve/stub-resolv.conf "$ROOTFS/etc/resolv.conf"
: > "$ROOTFS/etc/machine-id"
# live-boot's init writes a stub here; networkd owns the network.
mkdir -p "$ROOTFS/etc/network"

if [ "$RELEASE" -eq 1 ]; then
  echo "blunix: release disk scan"
  LOOP=$(losetup -r -f --show "$RAW")
  kpartx -r -av "$LOOP" >/dev/null
  part=""
  for candidate in /dev/mapper/"$(basename "$LOOP")"p*; do
    if [ "$(blkid -o value -s LABEL "$candidate" 2>/dev/null)" = "blunix-root" ]; then
      part=$candidate
    fi
  done
  if [ -z "$part" ]; then
    echo "blunix: release disk has no blunix-root" >&2
    exit 1
  fi
  mkdir -p "$CHECK"
  mount -o ro,noload "$part" "$CHECK"
  # A fixture disk, a test secret, or an unlocked account stops the release.
  python3 /src/image/scan-root.py --release "$CHECK"
  umount "$CHECK"
  kpartx -d "$LOOP"
  losetup -d "$LOOP"
  LOOP=""
  # Free blocks too: a deleted key is still in the disk's bytes.
  python3 /src/image/scan-raw.py "$RAW"
  echo "blunix: release disk scan clean"
fi

echo "blunix: payload"
IMAGE_DIR="$ROOTFS/usr/share/blunix/image"
rm -rf "$IMAGE_DIR"
mkdir -p "$IMAGE_DIR"
payload=0
ZST="$OUT/$KIND.raw.zst"
if [ -s "$RAW" ]; then
  raw_stamp="$RAW $(stat -c '%s %Y' "$RAW")"
  if [ -s "$ZST" ] && [ -f "$OUT/$KIND.payload.done" ] \
    && [ "$(cat "$OUT/$KIND.payload.done")" = "$raw_stamp" ]; then
    echo "blunix: payload cache"
  else
    rm -f "$OUT/$KIND.payload.done" "$ZST"
    # zstd records the content size of a file input in the frame header.
    zstd -q -T0 -10 --no-progress -o "$WORK/blunix.raw.zst" "$RAW"
    cp "$WORK/blunix.raw.zst" "$ZST"
    rm -f "$WORK/blunix.raw.zst"
    printf '%s\n' "$raw_stamp" > "$OUT/$KIND.payload.done"
  fi
  if [ "$RELEASE" -eq 1 ]; then
    python3 /src/image/scan-raw.py "$ZST"
    echo "blunix: release payload scan clean"
  fi
  install -m 0644 "$ZST" "$IMAGE_DIR/blunix.raw.zst"
  digest=$(sha256sum "$IMAGE_DIR/blunix.raw.zst" | awk '{ print $1 }')
  printf '%s  %s\n' "$digest" blunix.raw.zst > "$IMAGE_DIR/blunix.raw.zst.sha256"
  cp "$IMAGE_DIR/blunix.raw.zst.sha256" "$OUT/$KIND.raw.zst.sha256"
  if [ -n "$VERSION" ]; then
    size=$(stat -c '%s' "$RAW")
    printf 'version=%s\nsha256=%s\nsize=%s\n' "$VERSION" "$digest" "$size" \
      > "$IMAGE_DIR/blunix.release"
  fi
  payload=1
  echo "blunix: payload sha256 $digest"
else
  echo "blunix: no disk; the installer will say there is no image"
fi

echo "blunix: scan"
python3 /src/image/scan-root.py "$ROOTFS"

echo "blunix: kernel"
mkdir -p "$ISO/live" "$ISO/boot/grub"
kernel=$(find "$ROOTFS/boot" -maxdepth 1 -type f -name 'vmlinuz-*' | sort | tail -n 1)
initrd=$(find "$ROOTFS/boot" -maxdepth 1 -type f -name 'initrd.img-*' | sort | tail -n 1)
if [ -z "$kernel" ] || [ -z "$initrd" ]; then
  echo "blunix: kernel or initrd missing" >&2
  exit 1
fi
cp "$kernel" "$ISO/live/vmlinuz"
cp "$initrd" "$ISO/live/initrd.img"

echo "blunix: squashfs"
mksquashfs "$ROOTFS" "$ISO/live/filesystem.squashfs" \
  -comp zstd -noappend -quiet -no-progress -e boot
printf '%s\n' "blunix installer medium" > "$ISO/live/blunix-installer"
install -m 0644 /src/image/installer/grub.cfg "$ISO/boot/grub/grub.cfg"

echo "blunix: iso"
grub-mkrescue -o "$WORK/blunix-installer.iso" "$ISO" -- -volid "$LABEL" >/dev/null 2>&1 \
  || grub-mkrescue -o "$WORK/blunix-installer.iso" "$ISO" -- -volid "$LABEL"
if [ ! -s "$WORK/blunix-installer.iso" ]; then
  echo "blunix: iso missing" >&2
  exit 1
fi
cp "$WORK/blunix-installer.iso" /src/build/blunix-installer.iso

echo "blunix: netboot media"
rm -rf "$OUT/media"
mkdir -p "$OUT/media"
cp "$ISO/live/vmlinuz" "$OUT/media/vmlinuz"
cp "$ISO/live/initrd.img" "$OUT/media/initrd.img"
cp "$ISO/live/filesystem.squashfs" "$OUT/media/blunix.squashfs"
install -m 0644 /src/image/ipxe/blunix.ipxe "$OUT/media/blunix.ipxe"

echo "blunix: assets to $DEST"
if [ "$RELEASE" -ne 1 ] && [ "$DEST" != /src/build/test ]; then
  echo "blunix: only --release writes build/release" >&2
  exit 1
fi
rm -rf "$DEST"
mkdir -p "$DEST"
iso_name="blunix-installer$TAG.iso"
zst_name="blunix$TAG.raw.zst"
sums="SHA256SUMS$TAG"
cp /src/build/blunix-installer.iso "$DEST/$iso_name"
assets="$iso_name"
if [ "$payload" -eq 1 ]; then
  cp "$ZST" "$DEST/$zst_name"
  assets="$assets $zst_name"
fi
if [ "$RELEASE" -eq 1 ]; then
  # Netboot fetches these over plain http. SHA256SUMS is what a proxy checks.
  for name in vmlinuz initrd.img blunix.squashfs; do
    cp "$OUT/media/$name" "$DEST/$name"
  done
  assets="$assets vmlinuz initrd.img blunix.squashfs"
  sed "s/@VERSION@/$VERSION/g" /src/image/release/RELEASE-NOTES.md > "$DEST/RELEASE-NOTES.md"
fi
limit=$((2 * 1024 * 1024 * 1024))
for asset in $assets; do
  if [ "$(stat -c '%s' "$DEST/$asset")" -ge "$limit" ]; then
    echo "blunix: release asset over 2 GiB $asset" >&2
    exit 1
  fi
done
if [ "$payload" -eq 1 ] && [ "$RELEASE" -ne 1 ]; then
  # The payload is the fixture test disk: test root password, fixture marker.
  cat > "$DEST/TEST-PAYLOAD.txt" <<'EOF'
blunix-TEST.raw.zst here is build/blunix-test.raw, the fixture test disk. It
carries the test root password hash and the bootstrap fixture. Do not upload it
as a public release. Only a --release build writes build/release/.
EOF
fi
# shellcheck disable=SC2086
(cd "$DEST" && sha256sum -- $assets > "$sums")
cat "$DEST/$sums"
ls -l /src/build/blunix-installer.iso
echo "blunix: installer ready"

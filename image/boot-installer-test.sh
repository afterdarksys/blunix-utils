#!/bin/bash
# Headless boot of build/blunix-installer.iso in QEMU (inside docker on a Mac).
# The target is a blank qcow2, so nothing real is at risk.
# Usage: boot-installer-test.sh [uefi|bios] [quick|full]
#   quick: the ISO's menu; answer hostname and key; the fetch of the real
#          ada.blnx.io must stop with "Nothing applied."
#   full:  the ISO's kernel with blunix.proxy=10.0.2.2:8080, a local stand-in
#          proxy serving a throwaway-key document, and a real install.
# Apple's /bin/bash is 3.2. Re-run under bash 4 or newer when one is installed.
if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  for candidate in /usr/local/bin/bash /opt/homebrew/bin/bash /opt/local/bin/bash; do
    if [ -x "$candidate" ] && [ "$("$candidate" -c 'echo "${BASH_VERSINFO[0]}"')" -ge 4 ] 2>/dev/null; then
      exec "$candidate" "$0" "$@"
    fi
  done
  echo "blunix: this script needs bash 4 or newer, and /bin/bash on macOS is 3.2. Install one (brew install bash) and run it again." >&2
  exit 2
fi
set -eu
set -o pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
FIRMWARE=${1:-uefi}
MODE=${2:-quick}
case "$FIRMWARE" in
  uefi|bios) ;;
  *) echo "blunix: refused firmware" >&2; exit 1 ;;
esac
case "$MODE" in
  quick|full) ;;
  *) echo "blunix: refused mode" >&2; exit 1 ;;
esac
if [ ! -s "$ROOT/build/blunix-installer.iso" ]; then
  echo "blunix: build the iso first" >&2
  exit 1
fi
LOG=serial.log
if [ "$FIRMWARE" = "bios" ]; then
  LOG=serial-bios.log
fi
if [ "$MODE" = "full" ]; then
  LOG=serial-install-$FIRMWARE.log
fi
mkdir -p "$ROOT/build/installer"
docker run --rm -e BOOT_TIMEOUT="${BOOT_TIMEOUT:-1500}" -v "$ROOT":/src -w /src debian:trixie-slim bash -c '
  set -eu
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-system-x86 qemu-utils ovmf python3 python3-yaml age >/dev/null
  cp /usr/share/OVMF/OVMF_VARS_4M.fd /var/tmp/OVMF_VARS_4M.fd
  qemu-img create -q -f qcow2 /var/tmp/target.qcow2 16G
  python3 /src/image/installer/drive-serial.py /src/build/blunix-installer.iso \
    /var/tmp/target.qcow2 /src/build/installer/'"$LOG"' '"$FIRMWARE"' '"$MODE"'
'

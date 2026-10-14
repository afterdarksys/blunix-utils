#!/bin/bash
# End-to-end netboot test in QEMU, with no disk and no install: a VM boots from
# the network, gets only the iPXE loader over QEMU's built-in TFTP, then loads the
# boot script, kernel, initrd and the whole installer image over http from
# `blunix proxy serve`, into RAM. It passes when the installer asks its first
# question on the serial console. Nothing is written anywhere but a temp dir.
#
#   image/test-netboot-qemu.sh [MEDIA_DIR] [--prefill]
#
# With --prefill the proxy gets a site file that lists the VM's MAC as label
# "qemu-test" with full speech: the VM must chain its per-machine script and the
# installer must offer qemu-test.blnx.io and wait for yes. Exit 3 means the
# proxy side worked but the media's installer is older than the offer.
#
# BIOS only: undionly.kpxe. MEDIA_DIR defaults to build/installer/media (vmlinuz,
# initrd.img, blunix.squashfs). The loader comes from build/ipxe/
# (image/ipxe/build-ipxe.sh). Needs qemu-system-x86_64 and bash 4 or newer. Port
# 8750 must be free: the loader falls back to the next-server on that port.
# A UEFI run (ipxe.efi) is not here yet: OVMF under QEMU on macOS went to the EFI
# shell without trying the network, with both the QEMU and the Debian firmware.
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
set -euo pipefail
cd "$(dirname "$0")/.."
PREFILL=0
ARGS=()
for arg in "$@"; do
  if [ "$arg" = --prefill ]; then PREFILL=1; else ARGS+=("$arg"); fi
done
MEDIA="$(cd "${ARGS[0]:-build/installer/media}" && pwd)"
MAC=52:54:00:12:34:56
PORT=8750
TIMEOUT=300
LOADER=undionly.kpxe
for f in vmlinuz initrd.img blunix.squashfs; do
  [ -f "$MEDIA/$f" ] || { echo "blunix: $MEDIA/$f is missing; build the installer first"; exit 2; }
done
[ -f "build/ipxe/$LOADER" ] || { echo "blunix: build/ipxe/$LOADER is missing; run image/ipxe/build-ipxe.sh"; exit 2; }
if [ "$(uname -s)" = Darwin ]; then ACCEL=hvf; elif [ -w /dev/kvm ]; then ACCEL=kvm; else ACCEL=tcg; fi

WORK="$(mktemp -d)"
cleanup() {
  [ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null || true
  [ -n "${PROXY_PID:-}" ] && kill "$PROXY_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT
(cd "$MEDIA" && shasum -a 256 vmlinuz initrd.img blunix.squashfs 2>/dev/null || sha256sum vmlinuz initrd.img blunix.squashfs) > "$WORK/SHA256SUMS"
cp "build/ipxe/$LOADER" "$WORK/$LOADER"

SITE_ARGS=()
EXPECT="blunix: build hostname."
if [ "$PREFILL" = 1 ]; then
  cat > "$WORK/site.yaml" <<SITE
defaults: {disk: cloud-vm, access: full-speech}
machines:
  - mac: "$MAC"
    label: qemu-test
    hostname: qemu-test
    dhcp: true
SITE
  SITE_ARGS=(--site "$WORK/site.yaml")
  EXPECT="blunix: the build proxy offers qemu-test.blnx.io. Say yes to use it."
fi

# 10.0.2.2 is the host as QEMU's user network sees it.
PYTHONPATH=lib python3 -m blunix proxy serve --listen "127.0.0.1:$PORT" --advertise "10.0.2.2:$PORT" \
  --media "$MEDIA" --sums "$WORK/SHA256SUMS" ${SITE_ARGS[@]+"${SITE_ARGS[@]}"} > "$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 60); do
  curl -sf -o /dev/null "http://127.0.0.1:$PORT/v1/boot.ipxe" && break
  kill -0 "$PROXY_PID" 2>/dev/null || { cat "$WORK/proxy.log"; exit 1; }
  sleep 1
done

qemu-system-x86_64 -accel "$ACCEL" -m 3072 -machine pc -display none \
  -netdev "user,id=n0,tftp=$WORK,bootfile=$LOADER" -device e1000,netdev=n0,mac="$MAC" -boot n \
  -serial "file:$WORK/serial.log" &
QEMU_PID=$!

result=FAIL
for _ in $(seq 1 "$TIMEOUT"); do
  if grep -aqF "$EXPECT" "$WORK/serial.log" 2>/dev/null; then result=PASS; break; fi
  if [ "$PREFILL" = 1 ] && grep -aq "blunix: build hostname." "$WORK/serial.log" 2>/dev/null; then break; fi
  grep -aqE "netboot failed|Kernel panic" "$WORK/serial.log" 2>/dev/null && break
  kill -0 "$QEMU_PID" 2>/dev/null || break
  sleep 1
done
echo "--- proxy"
grep -E "GET /(media|v1)" "$WORK/proxy.log" || true
[ "$PREFILL" = 1 ] && { grep -aE "blunix.access=|blunix.build=" "$WORK/serial.log" | head -2 || true; }
echo "--- serial"
tr -d '\r' < "$WORK/serial.log" | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' \
  | grep -aE "^iPXE [0-9]|^blunix|blunix:|tftp://|http://[^ ]*\.\.\.|Trying wget" || true
if [ "$PREFILL" = 1 ] && [ "$result" = FAIL ] \
   && grep -aq "blunix.access=full-speech blunix.build=qemu-test.blnx.io" "$WORK/serial.log" \
   && grep -aq "blunix: build hostname." "$WORK/serial.log"; then
  # The proxy did its part; the installer inside this media is older than the offer.
  echo "blunix: netboot bios --prefill: PROXY-ONLY. The per-machine script reached the kernel, but this media's installer predates blunix.build; rebuild the installer media to test the offer."
  exit 3
fi
echo "blunix: netboot bios$([ "$PREFILL" = 1 ] && echo ' --prefill'): $result"
[ "$result" = PASS ]

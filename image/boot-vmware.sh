#!/bin/bash
# Boot the mutable test disk in VMware Fusion and keep the public serial lines.
set -eu
set -o pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
VMDIR="$ROOT/build/vmware"
RAW="$ROOT/build/blunix-test.raw"
VMX="$VMDIR/blunix-test.vmx"
VMRUN="/usr/local/bin/vmrun"
if [ ! -x "$VMRUN" ]; then
  VMRUN=$(command -v vmrun || true)
fi
if [ -z "$VMRUN" ]; then
  echo "blunix: vmrun missing" >&2
  exit 1
fi

mkdir -p "$VMDIR"
exec > "$VMDIR/boot.log" 2>&1
echo "blunix: vmware boot"

stopped=0
stop_vm() {
  if [ "$stopped" -eq 0 ] && [ -f "$VMX" ]; then
    "$VMRUN" -T fusion stop "$VMX" hard >/dev/null 2>&1 || true
    stopped=1
  fi
}

cleanup() {
  code=$?
  stop_vm
  if [ "$code" -eq 0 ]; then
    printf '%s\n' DONE > "$VMDIR/status.txt"
  else
    printf '%s\n' FAILED > "$VMDIR/status.txt"
  fi
  exit "$code"
}
trap cleanup EXIT

if "$VMRUN" -T fusion list | grep -F "$VMX" >/dev/null 2>&1; then
  "$VMRUN" -T fusion stop "$VMX" hard >/dev/null 2>&1 || true
fi
rm -f "$VMDIR/serial.log" "$VMDIR/summary.txt" "$VMDIR/status.txt"

python3 "$ROOT/image/write-vmx.py" "$RAW" "$VMDIR"

if ! "$VMRUN" -T fusion start "$VMX" nogui; then
  echo "blunix: nogui refused, trying gui"
  "$VMRUN" -T fusion start "$VMX" gui
fi

deadline=$((SECONDS + 360))
ok=0
while [ "$SECONDS" -lt "$deadline" ]; do
  if [ -f "$VMDIR/serial.log" ]; then
    if python3 "$ROOT/image/redact-serial.py" --check "$VMDIR"; then
      ok=1
      break
    fi
  fi
  sleep 5
done

stop_vm
sleep 1
python3 "$ROOT/image/redact-serial.py" "$VMDIR"
if [ "$ok" -ne 1 ]; then
  exit 1
fi
echo "blunix: vmware evidence ready"

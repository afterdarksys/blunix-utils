#!/usr/bin/env python3
"""Boot the installer ISO in QEMU and answer its prompts over serial.

quick: boot the ISO's own menu, answer hostname and key, expect the fetch of
the real ada.blnx.io to stop with "Nothing applied."
full: boot the ISO's kernel with blunix.proxy=10.0.2.2:8080, where a local
stand-in serves a document encrypted to a throwaway key, and install onto the
blank disk.

Threats: none for a machine; this is a test driver. The key it types is a
random throwaway, never a real build key, and the log is checked for it:
echo is off, so it must not appear on the serial line.
"""

import os
import secrets
import select
import subprocess
import sys
import time

ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"


def _serve(key):
    """A stand-in for `blunix proxy serve`: one ciphertext at /v1/build/ada.blnx.io."""
    sys.path.insert(0, "/src/lib")
    from blunix.age import encrypt_bytes

    with open("/src/models/node/vmware-test.yaml", "rb") as handle:
        blob = encrypt_bytes(handle.read(), key)
    root = "/var/tmp/proxy-root"
    os.makedirs(os.path.join(root, "v1", "build"), exist_ok=True)
    with open(os.path.join(root, "v1", "build", "ada.blnx.io"), "wb") as handle:
        handle.write(blob)
    return subprocess.Popen(
        [sys.executable, "-m", "http.server", "8080", "--bind", "127.0.0.1", "--directory", root],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def main():
    iso, disk, log_path, firmware = sys.argv[1:5]
    mode = sys.argv[5] if len(sys.argv) > 5 else "quick"
    key = "".join(secrets.choice(ALPHABET) for _ in range(20))
    typed = "-".join(key[i:i + 5] for i in range(0, 20, 5))
    server = _serve(key) if mode == "full" else None
    argv = [
        "qemu-system-x86_64",
        "-m", "2048",
        "-smp", "2",
        "-machine", "q35",
        "-cdrom", iso,
        "-drive", "file=" + disk + ",if=virtio,format=qcow2",
        "-boot", "d",
        "-display", "none",
        "-monitor", "none",
        "-chardev", "stdio,id=s0,signal=off",
        "-serial", "chardev:s0",
        "-nic", "user,model=virtio-net-pci",
    ]
    if firmware == "uefi":
        argv += [
            "-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
            "-drive", "if=pflash,format=raw,file=/var/tmp/OVMF_VARS_4M.fd",
        ]
    steps = [
        ("blunix: build hostname.", "ada\r"),
        ("Say yes to keep it.", "yes\r"),
        ("It will not be spoken.", typed + "\r"),
        ("Nothing applied.", None),
    ]
    stops = ("Nothing applied.", "not bootable.", "install failed.")
    if mode == "full":
        media = "/src/build/installer/media/"
        argv += [
            "-kernel", media + "vmlinuz",
            "-initrd", media + "initrd.img",
            "-append",
            "boot=live noeject blunix.access=regular blunix.proxy=10.0.2.2:8080 console=tty0 console=ttyS0,115200",
        ]
        steps = steps[:3] + [
            ("Say yes to erase.", "yes\r"),
            ("Say yes to reboot.", "no\r"),
            ("blunix: not rebooting.", None),
        ]
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    seen = b""
    mark = 0
    step = 0
    deadline = time.monotonic() + int(os.environ.get("BOOT_TIMEOUT", "1500"))
    with open(log_path, "wb") as log:
        while time.monotonic() < deadline and step < len(steps):
            ready, _, _ = select.select([proc.stdout], [], [], 1.0)
            if ready:
                chunk = os.read(proc.stdout.fileno(), 65536)
                if not chunk:
                    break
                log.write(chunk)
                log.flush()
                seen += chunk
            if mode == "full" and any(stop.encode("ascii") in seen[mark:] for stop in stops):
                break
            want, answer = steps[step]
            found = seen.find(want.encode("ascii"), mark)
            if found < 0:
                continue
            mark = found + len(want)
            step += 1
            if answer is not None:
                time.sleep(2)
                proc.stdin.write(answer.encode("ascii"))
                proc.stdin.flush()
        # Let the last sentence land, then stop the VM.
        end = time.monotonic() + 5
        while time.monotonic() < end:
            ready, _, _ = select.select([proc.stdout], [], [], 0.5)
            if ready:
                chunk = os.read(proc.stdout.fileno(), 65536)
                if not chunk:
                    break
                log.write(chunk)
                seen += chunk
    proc.kill()
    proc.wait()
    if server is not None:
        server.kill()
        server.wait()
    text = seen.decode("utf-8", "replace")
    leaked = key in text or typed in text
    print("boot-test: firmware " + firmware + ", mode " + mode)
    print("boot-test: reached step " + str(step) + " of " + str(len(steps)))
    print("boot-test: key on the serial line: " + ("YES" if leaked else "no"))
    for line in text.replace("\r", "\n").splitlines():
        if "blunix:" in line:
            print("  " + line.strip())
    return 0 if step == len(steps) and not leaked else 1


if __name__ == "__main__":
    raise SystemExit(main())

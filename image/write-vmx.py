#!/usr/bin/env python3
"""Convert the raw test disk and write a Fusion vmx.

Threats: the age passphrase is copied from build/ into the vmx guestinfo
value. That file is mode 0600. The passphrase is not printed and is not
passed to qemu-img or vmrun.
"""

import os
import re
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, ".."))
_CHAR = re.compile(r"[A-Za-z0-9_-]{8,128}\Z")
_HOST = "ada-1042.build.blunix.io"


def _fail():
    sys.stderr.write("blunix: vmdk failed\n")
    raise SystemExit(1)


def _passphrase():
    path = os.path.join(_REPO, "build", "bootstrap-passphrase")
    try:
        with open(path, "rb") as handle:
            raw = handle.read(512)
    except OSError:
        _fail()
    if b"\x00" in raw or len(raw) > 256:
        _fail()
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        _fail()
    if not _CHAR.fullmatch(text):
        _fail()
    return text


def _quote(value):
    if any(ch in value for ch in ('"', "\\", "\n", "\r")):
        _fail()
    return '"' + value + '"'


def main():
    if len(sys.argv) != 3:
        _fail()
    raw = sys.argv[1]
    vm_dir = sys.argv[2]
    if not os.path.isfile(raw):
        _fail()
    os.makedirs(vm_dir, exist_ok=True)
    passphrase = _passphrase()
    qemu = "/usr/local/bin/qemu-img"
    if not os.path.isfile(qemu):
        qemu = "qemu-img"
    vmdk = os.path.join(vm_dir, "blunix-test.vmdk")
    if os.path.lexists(vmdk):
        os.remove(vmdk)
    proc = subprocess.run(
        [
            qemu,
            "convert",
            "-f",
            "raw",
            "-O",
            "vmdk",
            "-o",
            "adapter_type=lsilogic,subformat=monolithicSparse",
            raw,
            vmdk,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
    )
    if proc.returncode != 0 or not os.path.isfile(vmdk):
        _fail()
    lines = [
        '.encoding = "UTF-8"',
        'config.version = "8"',
        'virtualHW.version = "19"',
        'virtualHW.productCompatibility = "hosted"',
        'firmware = "efi"',
        'guestOS = "debian11-64"',
        'displayName = "blunix-test"',
        'numvcpus = "2"',
        'cpuid.coresPerSocket = "2"',
        'memsize = "2048"',
        'pciBridge0.present = "TRUE"',
        'pciBridge4.present = "TRUE"',
        'pciBridge4.virtualDev = "pcieRootPort"',
        'pciBridge4.functions = "8"',
        'pciBridge5.present = "TRUE"',
        'pciBridge5.virtualDev = "pcieRootPort"',
        'pciBridge5.functions = "8"',
        'pciBridge6.present = "TRUE"',
        'pciBridge6.virtualDev = "pcieRootPort"',
        'pciBridge6.functions = "8"',
        'pciBridge7.present = "TRUE"',
        'pciBridge7.virtualDev = "pcieRootPort"',
        'pciBridge7.functions = "8"',
        'vmci0.present = "TRUE"',
        'hpet0.present = "TRUE"',
        'nvram = "blunix-test.nvram"',
        'usb.present = "TRUE"',
        'ehci.present = "TRUE"',
        'usb_xhci.present = "TRUE"',
        'sound.present = "FALSE"',
        'floppy0.present = "FALSE"',
        'sata0.present = "TRUE"',
        'sata0:0.present = "TRUE"',
        'sata0:0.fileName = "blunix-test.vmdk"',
        'sata0:0.deviceType = "disk"',
        'ethernet0.present = "TRUE"',
        'ethernet0.connectionType = "nat"',
        'ethernet0.virtualDev = "e1000"',
        'ethernet0.addressType = "generated"',
        'ethernet0.startConnected = "TRUE"',
        'serial0.present = "TRUE"',
        'serial0.fileType = "file"',
        'serial0.fileName = "serial.log"',
        'serial0.startConnected = "TRUE"',
        'uefi.secureBoot.enabled = "FALSE"',
        'tools.syncTime = "TRUE"',
        'msg.autoAnswer = "TRUE"',
        'uuid.action = "create"',
        "guestinfo.blunix.hostname = " + _quote(_HOST),
        "guestinfo.blunix.passphrase = " + _quote(passphrase),
        "",
    ]
    vmx = os.path.join(vm_dir, "blunix-test.vmx")
    blob = ("\n".join(lines)).encode("ascii")
    if passphrase.encode("ascii") not in blob:
        _fail()
    fd = os.open(vmx, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, blob)
    finally:
        os.close(fd)
    os.chmod(vmx, 0o600)
    sys.stdout.write("blunix: vmdk ready\n")


if __name__ == "__main__":
    main()

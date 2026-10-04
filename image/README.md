# image/

Build scripts for the Blunix spike. Each one runs itself inside `docker run --privileged debian:trixie-slim` when started on a Mac.

| Script | Makes |
|---|---|
| `build-test-disk.sh` | `build/blunix-test.raw`, the mutable Debian 13 test disk (fixture bootstrap). |
| `build-test-disk.sh --release` | `build/blunix-release.raw`: the same disk with root locked, no fixture, no root-login sshd drop-in, and the console first-boot bootstrap. The build fails if the release scan finds a test secret, the fixture, or an unlocked account. |
| `build-installer.sh` | `build/blunix-installer.iso`, the live installer. Also `build/installer/media/` for netboot and `build/release/` for a GitHub release. |
| `BLUNIX_RELEASE_VERSION=v0.1.0 build-installer.sh --release` | The same, packing `build/blunix-release.raw`. It mounts that disk read-only and runs the release scan first, so a fixture disk cannot become a release. |
| `boot-installer-test.sh [uefi\|bios]` | Boots the ISO headless in QEMU against a blank disk and answers the first prompts over serial. Log: `build/installer/serial.log`. |
| `run-unit-tests.sh` | The unit tests, in Debian 13 with `age` and `zstd`. |
| `scan-raw-explain.py locate IMAGE` / `blocks FILE [--member PATH]` | Explains a refused raw scan: each hit's offset, kind, and the file (or free space) that holds it; and every PEM private-key block in a file with its SHA-256 and allowlist state. Prints no key bytes. See "When the raw scan refuses". |
| `gpl-sources.py VERSION STATUS...` | `SOURCES.md` for a release: every Debian source package and exact version from the artifacts' dpkg status files, with snapshot.debian.org links and the written offer. Attach it to every release. |

## When the raw scan refuses

`scan-raw.py` prints one fixed line, by design. To find out why, on the build host:

1. `image/scan-raw-explain.py locate build/blunix-release.raw` (uncompressed; a `.zst` gives offsets only). Each line is `offset, kind, listed|REFUSED, partition: path (inode, block)` or `free space or metadata`.
2. A hit in **free space** is a deleted file's bytes: a real leak. Find the build step that wrote and removed it; never allowlist it.
3. A hit in a **packaged file** (a library, a test vector): `image/scan-raw-explain.py blocks build/rootfs.tar --member /usr/lib/...` lists each block's hash. Confirm upstream that the block is a public constant (as GnuTLS's self-test keys are), then add exactly the `matched unlisted` hashes to `_PUBLIC_KEYS` in `scan-raw.py`, with a comment naming the package and version, and add a case to `tests/test_scan_raw.py`.
4. Rehearse the release (vpscfgfarm `deploy/builder1/rehearse-release.sh`) before spending a tag.

Through vpsexec, write the tool's output to a file on the host and read the lines you need; vpsexec masks long hex and base64 runs in what it prints.

## Install media

One flow runs from every medium: `blunix install`. It says each step as one sentence on tty1 and on the first serial port. Keys 1 to 5 at the boot menu pick full speech, console speech, large print, regular, or advanced, the same as the disk. The menu beeps when it is ready.

The installer asks for the build hostname (`ada.blnx.io`, `v3.ada.blnx.io`, or just `ada`), reads it back, and waits for yes. It then asks for the key with echo off. It fetches the document, decrypts it on the machine, picks the disk, writes the image, checks the image's sha256, applies the document, and installs the bootloader. A wrong key, a refused document, or a digest mismatch applies nothing. A disk that already holds anything needs a typed yes. Silence is no.

### USB stick

The ISO is hybrid: it boots on UEFI and on BIOS, from a stick or from optical media.

```
sudo dd if=build/blunix-installer.iso of=/dev/sdX bs=4M conv=fsync status=none
```

On a Mac, find the stick with `diskutil list`, then `diskutil unmountDisk /dev/diskN` and write to `/dev/rdiskN`. The installer never offers the stick it booted from as a target.

### ISO in a VM

Attach `build/blunix-installer.iso` as the CD and a blank disk of at least the image size (8 GiB for the test image). UEFI or BIOS both work. For a serial console, add a serial port; the installer also runs there.

```
qemu-system-x86_64 -m 2048 -machine q35 -cdrom build/blunix-installer.iso \
  -drive file=target.qcow2,if=virtio -boot d -nographic
```

### iPXE netboot

`build/installer/media/` holds `vmlinuz`, `initrd.img`, `blunix.squashfs`, and `blunix.ipxe`. Serve that directory as `/media/` on any HTTP server, or let `blunix proxy serve` do it, and chain `image/ipxe/blunix.ipxe` with `${proxy}` set to that server's `HOST:PORT`. The kernel line carries `blunix.proxy=${proxy}`, so the document is fetched through the proxy at `http://{proxy}/v1/build/{host}`. That path is safe only because age is authenticated: a swapped body does not decrypt. The image to install is inside the squashfs, so netboot needs no stick. live-boot copies the squashfs into RAM, so give the machine 2 GiB or more.

### Raw image for VMware, QEMU, or a cloud

`build/blunix-test.raw` (or `blunix.raw.zst` from a release, decompressed with `zstd -d`) boots directly. It keeps the first-boot bootstrap: the console asks for the build hostname and the key, and the document is applied on first boot. `boot-vmware.sh` and `write-vmx.py` wrap it for VMware Fusion. For a cloud, upload the raw disk as the provider's image format.

### Where the image comes from

The installer takes the image from the medium first: `blunix.raw.zst` with `blunix.raw.zst.sha256` in `/run/live/medium/blunix/` or inside the live system at `/usr/share/blunix/image/`. When the medium carries only a release pin (`blunix.release`: `version=`, `sha256=`, `size=`), it streams `https://github.com/afterdarksys/blunix/releases/download/{version}/blunix.raw.zst` with verified TLS. Redirects may land only on `github.com`, `objects.githubusercontent.com`, or `release-assets.githubusercontent.com`. The stream's sha256 must match the pin. The machine trusts a digest, never a host.

`BLUNIX_RELEASE_VERSION=v0.1.0 image/build-installer.sh --release` writes that pin into the ISO. `build/release/` then holds the ISO, `blunix.raw.zst`, and `SHA256SUMS`, each under GitHub's 2 GiB asset limit, ready for `gh release upload`. The build does not upload. Without `--release` the payload is the fixture test disk, and `build/release/TEST-PAYLOAD.txt` says so: that disk carries a test root password and must not be published.

The release raw disk, booted directly, asks on tty1 for the build hostname and the key at first boot and waits for a person. A disk written by the installer already has the document applied and does not ask again.

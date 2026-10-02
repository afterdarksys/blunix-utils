# Blunix @VERSION@ (draft)

This is an unsigned test release. Nothing in it is signed yet. SHA256SUMS
proves a download matches what was built; it does not prove who built it.

Blunix @VERSION@ is based on Debian 13 (trixie).

## Assets

| File | What it is |
|---|---|
| `blunix-installer.iso` | The live installer. Write it to a USB stick or attach it as a CD. |
| `blunix.raw.zst` | The disk image the installer writes. Also bootable on its own after `zstd -d`. |
| `vmlinuz`, `initrd.img`, `blunix.squashfs` | Netboot media for iPXE (`image/ipxe/blunix.ipxe`). |
| `SHA256SUMS` | The sha256 of every file above. |

## Boot

- The installer ISO boots on UEFI and on BIOS, from a USB stick or optical media.
- An installed disk boots on UEFI only.
- Netboot is for trusted LANs only until images are signed. The kernel, initrd
  and squashfs come over plain http, and iPXE does not check their digest.
- `blunix.raw.zst`, decompressed and booted directly, asks on tty1 for the
  build hostname and the key at first boot, and waits for a person. A disk
  written by the installer already has its document and does not ask.
- Each machine makes its own ssh host keys at first boot. None ship in the image.

## Verify

Download the files and SHA256SUMS into one folder, then:

```
sha256sum -c --ignore-missing SHA256SUMS
```

On a Mac, use `shasum -a 256 -c SHA256SUMS`. Every line must say OK. Do not
boot or write a file that fails.

## Licenses and source

- **Debian packages** in these images keep their own licenses, many of them the GNU GPL. `SOURCES.md`, attached to this release, lists every source package at its exact version, with a snapshot.debian.org link and a written offer for the corresponding source.
- **Blunix's own code** is source-available under the PolyForm Noncommercial License 1.0.0. It is free for personal use and noncommercial organizations. Commercial use needs a commercial license (see COMMERCIAL.md in the repository).

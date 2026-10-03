# Blunix @VERSION@

SHA256SUMS lists the sha256 of every file. SHA256SUMS.asc, added when the
release is signed offline after the build, is a signature over that list by
the Blunix release key:

```
62F7 36BE A2AB 2E1F A16D  5138 BCB3 426C 090A DF92
Blunix Release Signing <sign-releases@blunix.io>
```

The key is `keys/blunix-releases.asc` in the repository. A release without
SHA256SUMS.asc is unsigned: its checksums prove the bytes match what was
built, not who built them.

Blunix @VERSION@ is based on Debian 13 (trixie).

## Assets

| File | What it is |
|---|---|
| `blunix-installer.iso` | The live installer. Write it to a USB stick or attach it as a CD. |
| `blunix.raw.zst` | The disk image the installer writes. Also bootable on its own after `zstd -d`. |
| `vmlinuz`, `initrd.img`, `blunix.squashfs` | Netboot media for iPXE (`image/ipxe/blunix.ipxe`). |
| `SHA256SUMS`, `SHA256SUMS.asc` | The sha256 of every file, and the signature over that list. |
| `build-provenance.json` | What was built, from which commit, with which inputs. |

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

Download the files, SHA256SUMS and SHA256SUMS.asc into one folder, then:

```
gpg --import blunix-releases.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

gpg must say `Good signature` from the fingerprint above. Every line from
sha256sum must say OK; on a Mac, use `shasum -a 256 -c SHA256SUMS`. Do not
boot or write a file that fails.

## Licenses and source

- **Debian packages** in these images keep their own licenses, many of them the GNU GPL. `SOURCES.md`, attached to this release, lists every source package at its exact version, with a snapshot.debian.org link and a written offer for the corresponding source.
- **Blunix's own code** is source-available under the PolyForm Noncommercial License 1.0.0. It is free for personal use and noncommercial organizations. Commercial use needs a commercial license (see COMMERCIAL.md in the repository).

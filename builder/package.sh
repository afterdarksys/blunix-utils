#!/bin/bash
# Regenerate MANIFEST.sha256 and pack build/blunix-builder-<version>.tar.gz
# (deterministic: sorted names, fixed mtime/owner). Prints the tarball sha256
# for `vpsexec builder1 push ... --sha256 <hex>`. Run from anywhere.
set -eu
set -o pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"
FILES="blunix-builder blunix_builder.py inside-release.sh install.sh config.example.yaml
nftables.conf HOST.md NOTES-blunix.md keys/tag-signers.asc
systemd/blunix-builder.service systemd/blunix-builder.timer"
# shellcheck disable=SC2086
if command -v sha256sum >/dev/null; then sha256sum $FILES > MANIFEST.sha256
else shasum -a 256 $FILES > MANIFEST.sha256; fi
[ "${1:-}" = "--manifest-only" ] && exit 0
version=$(python3 -c 'import blunix_builder; print(blunix_builder.__version__)')
out="$HERE/../build/blunix-builder-$version.tar.gz"
mkdir -p "$HERE/../build"
# shellcheck disable=SC2086
tar --sort=name --mtime='2026-01-01 00:00:00Z' --owner=0 --group=0 --numeric-owner \
  -cf - MANIFEST.sha256 $FILES | gzip -n > "$out"
if command -v sha256sum >/dev/null; then sha256sum "$out"; else shasum -a 256 "$out"; fi

#!/bin/bash
# Prove the library inside Debian 13, where age is the distro package.
# e2fsprogs builds the ext4 image the raw scan test deletes a key from.
set -eu
set -o pipefail
cd "$(dirname "$0")/.."
docker run --rm -v "$PWD":/src -w /src debian:trixie-slim \
  bash -lc 'apt-get update -qq && apt-get install -y -qq python3 python3-yaml git nodejs age zstd e2fsprogs >/dev/null && python3 image/prepare-secrets.py && PYTHONPATH=lib python3 -m unittest discover -s tests -v'

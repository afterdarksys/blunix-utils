#!/bin/bash
# Prove the library inside Debian 13, where age is the distro package.
# e2fsprogs builds the ext4 image the raw scan test deletes a key from.
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
cd "$(dirname "$0")/.."
docker run --rm -v "$PWD":/src -w /src debian:trixie-slim \
  bash -lc 'apt-get update -qq && apt-get install -y -qq python3 python3-yaml git nodejs age zstd e2fsprogs >/dev/null && python3 image/prepare-secrets.py && PYTHONPATH=lib python3 -m unittest discover -s tests -v'

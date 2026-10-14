#!/bin/bash
# Build blunix-ipxe from a pinned upstream iPXE release, in a throwaway Debian 13
# container: undionly.kpxe (BIOS PXE) and ipxe.efi (UEFI, also for UEFI HTTP Boot),
# both with image/ipxe/embed.ipxe built in, HTTPS enabled. Output: build/ipxe/.
# The commit is checked, not just the tag name.
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
cd "$(dirname "$0")/../.."
IPXE_TAG=v2.0.0
IPXE_COMMIT=12798ec29aa8a64d8675c4378b99f5fe28447afb
mkdir -p build/ipxe
docker run --rm -i -v "$PWD/image/ipxe":/in:ro -v "$PWD/build/ipxe":/out \
  -e IPXE_TAG="$IPXE_TAG" -e IPXE_COMMIT="$IPXE_COMMIT" debian:trixie-slim bash -s <<'INNER'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends git ca-certificates gcc libc6-dev make binutils perl liblzma-dev mtools xorriso >/dev/null
git clone -q --depth 1 --branch "$IPXE_TAG" https://github.com/ipxe/ipxe /src
cd /src
test "$(git rev-parse HEAD)" = "$IPXE_COMMIT" || { echo "blunix: iPXE $IPXE_TAG is not $IPXE_COMMIT; refusing"; exit 1; }
cat > src/config/local/general.h <<'EOF'
#define DOWNLOAD_PROTO_HTTPS
#define IMAGE_TRUST_CMD
EOF
cd src
make -s -j"$(nproc)" bin/undionly.kpxe EMBED=/in/embed.ipxe >/dev/null
make -s -j"$(nproc)" bin-x86_64-efi/ipxe.efi EMBED=/in/embed.ipxe >/dev/null
cp bin/undionly.kpxe bin-x86_64-efi/ipxe.efi /out/
cd /out
sha256sum undionly.kpxe ipxe.efi > SHA256SUMS.ipxe
echo "blunix: built iPXE $IPXE_TAG ($IPXE_COMMIT)"
cat SHA256SUMS.ipxe
INNER

#!/bin/bash
# Install or update blunix-builder on builder1. Idempotent. Run as root from
# the extracted package directory (the one holding MANIFEST.sha256):
#
#   bash install.sh                    # install/update files, user, dirs, units
#   bash install.sh --apply-firewall   # also load nftables.conf; needs
#                                      # /etc/blunix-builder/door.nft
#
# It verifies every packaged file against MANIFEST.sha256 before touching the
# host, refuses symlinks, never writes a secret, and never overwrites an
# existing /etc/blunix-builder/config.yaml or r2-credentials.
set -eu
set -o pipefail
umask 022

PKG=$(cd "$(dirname "$0")" && pwd)
APPLY_FW=0
case "${1:-}" in
  "") ;;
  --apply-firewall) APPLY_FW=1 ;;
  *) echo "usage: install.sh [--apply-firewall]" >&2; exit 2 ;;
esac

fail() { echo "install: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run as root"
[ -r /etc/debian_version ] || fail "Debian host expected"

echo "install: verify package"
cd "$PKG"
[ -f MANIFEST.sha256 ] && [ ! -L MANIFEST.sha256 ] || fail "MANIFEST.sha256 missing"
while read -r digest name; do
  case "$digest" in *[!0-9a-f]*|"") fail "bad manifest line" ;; esac
  [ "${#digest}" -eq 64 ] || fail "bad manifest digest"
  case "$name" in /*|*..*|"") fail "bad manifest path" ;; esac
  [ -f "$name" ] && [ ! -L "$name" ] || fail "missing or symlinked: $name"
done < MANIFEST.sha256
sha256sum --check --strict --quiet MANIFEST.sha256 || fail "package hash mismatch"
if find . -type l | grep -q .; then
  fail "package contains symlinks"
fi

echo "install: data disk"
# Builds and Docker's layers live on the data disk (/srv), never the root
# disk: a full root disk mid-build takes the OS with it. The disk is set up
# once by a human (mkfs is on the vpscfgfarm floor); this only checks it.
mountpoint -q /srv || fail "/srv is not a mount; set up the data disk first (HOST.md)"
[ "$(findmnt -n -o SOURCE /srv)" != "$(findmnt -n -o SOURCE /)" ] \
  || fail "/srv is on the root disk"
install -d -m 0710 -o root -g root /srv/docker
install -d -m 0755 -o root -g root /etc/docker
if [ ! -e /etc/docker/daemon.json ]; then
  printf '{\n  "data-root": "/srv/docker"\n}\n' > /etc/docker/daemon.json
elif ! grep -Eq '"data-root": *"/srv/docker"' /etc/docker/daemon.json; then
  fail "/etc/docker/daemon.json exists without data-root /srv/docker"
fi

echo "install: packages"
export DEBIAN_FRONTEND=noninteractive
need=""
for pkg in docker.io git gnupg python3 python3-yaml nftables unattended-upgrades \
           openssh-client ca-certificates; do
  dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed' \
    || need="$need $pkg"
done
if [ -n "$need" ]; then
  apt-get update -qq
  # shellcheck disable=SC2086
  apt-get install -y -qq --no-install-recommends $need
fi

root_dir=$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || true)
[ "$root_dir" = /srv/docker ] || fail "docker data root is '$root_dir', expected /srv/docker"

echo "install: user"
if ! getent group builder >/dev/null; then
  groupadd --system builder
fi
if ! getent passwd builder >/dev/null; then
  useradd --system --gid builder --home-dir /var/lib/blunix-builder \
    --no-create-home --shell /usr/sbin/nologin builder
fi
getent group docker >/dev/null || fail "docker group missing"
usermod -aG docker builder

echo "install: directories"
install -d -m 0755 -o root -g root /opt/blunix-builder /opt/blunix-builder/bin \
  /opt/blunix-builder/lib /opt/blunix-builder/keys /etc/blunix-builder
install -d -m 0750 -o builder -g builder /var/lib/blunix-builder /srv/blunix-builds

echo "install: files"
install -m 0755 -o root -g root blunix-builder /opt/blunix-builder/bin/blunix-builder
install -m 0644 -o root -g root blunix_builder.py /opt/blunix-builder/lib/blunix_builder.py
install -m 0644 -o root -g root inside-release.sh /opt/blunix-builder/lib/inside-release.sh
install -m 0644 -o root -g root keys/tag-signers.asc /opt/blunix-builder/keys/tag-signers.asc
install -m 0644 -o root -g root HOST.md /opt/blunix-builder/HOST.md
install -m 0755 -o root -g root check-door.sh /opt/blunix-builder/bin/check-door.sh
install -m 0644 -o root -g root MANIFEST.sha256 /opt/blunix-builder/MANIFEST.sha256
install -m 0644 -o root -g root config.example.yaml /etc/blunix-builder/config.example.yaml
install -m 0644 -o root -g root nftables.conf /etc/blunix-builder/nftables.conf
if [ ! -e /etc/blunix-builder/config.yaml ]; then
  install -m 0644 -o root -g root config.example.yaml /etc/blunix-builder/config.yaml
  echo "install: wrote config.yaml from the example; set container_image and r2.endpoint"
fi
install -m 0644 -o root -g root systemd/blunix-builder.service \
  /etc/systemd/system/blunix-builder.service
install -m 0644 -o root -g root systemd/blunix-builder.timer \
  /etc/systemd/system/blunix-builder.timer

echo "install: docker network"
if ! docker network inspect blunix-build >/dev/null 2>&1; then
  docker network create --driver bridge \
    -o com.docker.network.bridge.name=br-blunix blunix-build >/dev/null
fi

if [ "$APPLY_FW" -eq 1 ]; then
  echo "install: firewall"
  door=/etc/blunix-builder/door.nft
  [ "$(stat -c '%u' "$door" 2>/dev/null)" = 0 ] || fail "$door missing or not root-owned"
  case "$(stat -c '%a' "$door")" in ?[0-7][2367]|?[2367]?) fail "$door is group/world writable" ;; esac
  bash "$PKG/check-door.sh" "$door" || fail "door.nft rejected"
  nft -c -f /etc/blunix-builder/nftables.conf
  nft -f /etc/blunix-builder/nftables.conf
fi

systemctl daemon-reload
ready=1
if [ ! -f /etc/blunix-builder/r2-credentials ]; then
  echo "install: /etc/blunix-builder/r2-credentials missing (root:root 0600)"
  ready=0
else
  chown root:root /etc/blunix-builder/r2-credentials
  chmod 0600 /etc/blunix-builder/r2-credentials
fi
if [ "$ready" -eq 1 ] \
  && runuser -u builder -- /opt/blunix-builder/bin/blunix-builder check-config \
       --config /etc/blunix-builder/config.yaml; then
  systemctl enable --now blunix-builder.timer
  echo "install: timer enabled"
else
  systemctl disable --now blunix-builder.timer 2>/dev/null || true
  echo "install: config not ready; timer left disabled"
fi
echo "install: done ($(sha256sum MANIFEST.sha256 | awk '{ print $1 }'))"

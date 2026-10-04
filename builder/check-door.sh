#!/bin/bash
# Validate a door.nft file before nftables.conf includes it:
#
#   bash check-door.sh /etc/blunix-builder/door.nft
#
# The door addresses are admin IPs, so they live in the private vpscfgfarm
# repo and are pushed to the host; this public repo ships only the include.
# Because nft includes the file verbatim, it must hold exactly one line
#   define DOOR_V4 = { a.b.c.d, ... }
# (comments and blank lines aside) and nothing that could add rules. Plain
# host addresses only: no prefixes, no placeholder, loopback or 0.0.0.0.
set -eu
set -o pipefail

fail() { echo "check-door: $*" >&2; exit 1; }

[ $# -eq 1 ] || fail "usage: check-door.sh <door.nft>"
f=$1
[ -f "$f" ] && [ ! -L "$f" ] || fail "$f missing or not a regular file"

octet='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
ip="$octet\\.$octet\\.$octet\\.$octet"
line_re="^define DOOR_V4 = \\{ $ip(, $ip)* \\}\$"

defines=0
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in ""|"#"*) continue ;; esac
  printf '%s\n' "$line" | grep -Eq "$line_re" || fail "unexpected line: $line"
  defines=$((defines + 1))
done < "$f"
[ "$defines" -eq 1 ] || fail "need exactly one DOOR_V4 define, found $defines"

addrs=$(grep -E '^define DOOR_V4' "$f" | sed -e 's/.*{ //' -e 's/ }$//' | tr ',' '\n' | tr -d ' ')
for a in $addrs; do
  case "$a" in
    192.0.2.*) fail "placeholder documentation address $a" ;;
    0.*|127.*) fail "not a door address: $a" ;;
  esac
done
echo "check-door: ok ($(printf '%s' "$addrs" | tr '\n' ' '))"

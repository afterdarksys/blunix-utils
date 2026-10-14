#!/bin/bash
# Real chroot provisioning for personal builds, in a throwaway Debian 13
# container. It copies the container's own root to /tmp/target and provisions
# that copy, so it never touches a host disk. Needs network for apt.
set -euo pipefail
cd "$(dirname "$0")/.."
docker run --rm -i -v "$PWD":/src:ro -w /src debian:trixie-slim bash -s <<'INNER'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-yaml >/dev/null
mkdir -p /tmp/target/dev /tmp/target/proc /tmp/target/sys /tmp/target/run /tmp/target/tmp
cp -a /bin /sbin /lib /usr /etc /var /root /tmp/target/
if [ -e /lib64 ]; then cp -a /lib64 /tmp/target/; fi
chmod 1777 /tmp/target/tmp
touch /tmp/target/dev/null
chmod 666 /tmp/target/dev/null
PYTHONPATH=lib python3 - <<'PY'
import base64
import subprocess
from pathlib import Path

from blunix.personal import provision

root = Path("/tmp/target")
key = "ssh-ed25519 " + base64.b64encode(
    bytes.fromhex("0000000b7373682d6564323535313900000020") + b"x" * 32
).decode()
dns = (root / "etc/resolv.conf").read_bytes()
said = []
provision(str(root), ["git", "curl", "nginx"], {"name": "operator", "sshPublicKey": key}, log=said.append)
assert (root / "etc/resolv.conf").read_bytes() == dns, "resolv.conf not restored"
policy = root / "usr/sbin/policy-rc.d"
assert not policy.exists() or policy.read_text() != "#!/bin/sh\nexit 101\n", "policy-rc.d left behind"
keys = root / "home/operator/.ssh/authorized_keys"
assert keys.stat().st_uid >= 1000, "authorized_keys not owned by the administrator"
assert keys.stat().st_mode & 0o777 == 0o600
lock = (root / "var/lib/blunix/packages.lock").read_text()
assert "git=" in lock and "nginx=" in lock and "sudo=" in lock and "openssh-server=" in lock
subprocess.run(["chroot", str(root), "visudo", "-cf", "/etc/sudoers"], check=True, stdout=subprocess.DEVNULL)
(root / "run/sshd").mkdir(exist_ok=True)
subprocess.run(["chroot", str(root), "ssh-keygen", "-A"], check=True, stdout=subprocess.DEVNULL)
subprocess.run(["chroot", str(root), "/usr/sbin/sshd", "-t"], check=True)
config = subprocess.check_output(["chroot", str(root), "/usr/sbin/sshd", "-T"], text=True)
for line in ("passwordauthentication no", "permitrootlogin no", "pubkeyauthentication yes",
             "kbdinteractiveauthentication no"):
    assert line in config, line
assert (root / "etc/systemd/system/multi-user.target.wants/ssh.service").is_symlink()
assert any("not pinned" in line for line in said)
print("blunix: personal provisioning passed: apt, administrator, sudo, sshd, packages.lock, restore.")
PY
INNER

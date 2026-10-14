"""iPXE script and dnsmasq config for the install VLAN.

Threats: a config line smuggled through a site value, and a netboot that
catches machines the operator did not list. Every value written here was
already validated (MAC, label, address, interface, range, path), so no line
can carry a newline or a second directive. PXE boot is offered only to MACs
in the site file (dnsmasq's `known` tag), and DNS is off (`port=0`).

What it does not stop: a second DHCP server on the same VLAN, an operator
running this config on a production LAN, or a LAN attacker swapping the
unsigned media in flight. Netboot is for trusted LANs until images are signed. It renders text; it never starts
dnsmasq.
"""

from __future__ import annotations

import ipaddress
import re

from blunix.errors import BlunixError

MEDIA_FILES = ("vmlinuz", "initrd.img", "blunix.squashfs")
# iPXE loaders (image/ipxe/build-ipxe.sh). Served over http from --media when
# SHA256SUMS lists them, so UEFI HTTP Boot needs no TFTP.
LOADER_FILES = ("undionly.kpxe", "ipxe.efi")
_IFACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,14}")
_TFTP_ROOT = re.compile(r"/[A-Za-z0-9._/-]{0,200}")


def render_ipxe(advertise, boot=None, machine=None, per_machine=False):
    """advertise is a validated HOST:PORT the booting machine can reach.
    boot is a site file's parsed `boot:` section, or None for the built-ins.

    With per_machine (a site is loaded), the script first asks for
    /v1/boot/MAC.ipxe; a MAC the site lists gets that machine's script, any
    other gets 404 and falls through to the generic boot below. With machine,
    this is that per-machine script: it offers the machine's build address
    (blunix.build=, which the installer still reads back and confirms) and
    boots the installer in the machine's own access profile, so a speech
    machine speaks from the first prompt."""
    from blunix.proxy_site import BOOT_BUILTIN, latest_url

    boot = boot or BOOT_BUILTIN
    base = "http://" + advertise
    access = machine["access"] if machine is not None else boot["access"]
    args = [
        "boot=live", "noeject", "fetch=" + base + "/media/blunix.squashfs",
        "blunix.proxy=" + advertise, "blunix.access=" + access,
    ]
    if machine is not None:
        args.append("blunix.build=" + latest_url(machine["label"])[len("https://"):-1])
    args += ["console=" + c for c in boot["console"]]
    args += list(boot["args"])
    lines = ["#!ipxe"]
    if machine is not None:
        lines.append("echo blunix: netboot for " + machine["label"] + " from the build proxy at " + advertise)
    else:
        lines.append("echo blunix: netboot from the build proxy at " + advertise)
        if per_machine:
            lines += [
                "chain " + base + "/v1/boot/${netX/mac:hexhyp}.ipxe || goto generic",
                ":generic",
            ]
    lines += [
        "kernel " + base + "/media/vmlinuz initrd=initrd.img " + " ".join(args),
        "initrd " + base + "/media/initrd.img",
        "boot",
        "",
    ]
    return "\n".join(lines)


def _range(value):
    if not isinstance(value, str) or value.count(",") != 1:
        raise BlunixError("refused range; give START,END")
    start_text, end_text = value.split(",")
    try:
        start = ipaddress.IPv4Address(start_text)
        end = ipaddress.IPv4Address(end_text)
    except ValueError:
        raise BlunixError("refused range; give START,END") from None
    if int(end) < int(start):
        raise BlunixError("refused range; END is before START")
    return str(start), str(end)


def render_dnsmasq(site, advertise, interface=None, dhcp_range=None, tftp_root=None):
    if interface is not None and not _IFACE.fullmatch(interface):
        raise BlunixError("refused interface")
    boot = site.get("boot") or {}
    lease = boot.get("lease", "12h")
    tftp = boot.get("tftp", True)
    if tftp_root is None:
        tftp_root = boot.get("tftp_root", "/srv/tftp")
    if not _TFTP_ROOT.fullmatch(tftp_root) or ".." in tftp_root:
        raise BlunixError("refused tftp root")
    lines = [
        "# blunix proxy dnsmasq config. Rendered only; review it, then run dnsmasq yourself.",
        "# Netboot is for trusted LANs only until images are signed: media travels over plain http.",
        "# DNS is off. PXE is offered only to the MACs listed below.",
        "port=0",
    ]
    if interface:
        lines += ["interface=" + interface, "bind-interfaces"]
    if dhcp_range:
        start, end = _range(dhcp_range)
        lines.append("dhcp-range=" + start + "," + end + "," + lease)
    else:
        nets = []
        for machine in site["machines"]:
            if not machine["dhcp"]:
                net = ipaddress.ip_interface(machine["address"]).network
                if net.version == 4 and net not in nets:
                    nets.append(net)
        if not nets:
            raise BlunixError("every machine uses dhcp; give --range START,END")
        for net in nets:
            lines.append(
                "dhcp-range=" + str(net.network_address) + ",static," + str(net.netmask) + "," + lease
            )
    lines.append("")
    for machine in site["machines"]:
        tag = "blx-" + machine["label"]
        lines.append("# machine " + str(machine["index"]) + ": " + machine["label"])
        if machine["dhcp"]:
            lines.append("dhcp-host=" + machine["mac"] + ",set:" + tag + "," + machine["hostname"])
            continue
        addr = ipaddress.ip_interface(machine["address"])
        if addr.version != 4:
            lines.append("# IPv6 install address; dnsmasq DHCPv4 reservation skipped")
            lines.append("dhcp-host=" + machine["mac"] + ",set:" + tag + "," + machine["hostname"])
            continue
        lines.append(
            "dhcp-host=" + machine["mac"] + ",set:" + tag + "," + str(addr.ip)
            + "," + machine["hostname"] + "," + lease
        )
        lines.append("dhcp-option=tag:" + tag + ",option:router," + machine["gateway"])
        dns4 = [d for d in machine["dns"] if ipaddress.ip_address(d).version == 4]
        if dns4:
            lines.append("dhcp-option=tag:" + tag + ",option:dns-server," + ",".join(dns4))
    lines += [
        "",
        "# iPXE fetches its boot script, kernel, initrd and the whole image over http.",
        "dhcp-match=set:ipxe,175",
        "dhcp-boot=tag:known,tag:ipxe,http://" + advertise + "/v1/boot.ipxe",
        "# UEFI HTTP Boot (client arch 16) loads ipxe.efi over http: no TFTP at all.",
        "dhcp-match=set:efihttp,option:client-arch,16",
        "dhcp-option-force=tag:efihttp,60,HTTPClient",
        "dhcp-boot=tag:known,tag:!ipxe,tag:efihttp,http://" + advertise + "/media/ipxe.efi",
    ]
    if tftp:
        lines += [
            "# Classic PXE firmware can only fetch its first file over TFTP: the loader only.",
            "dhcp-match=set:efi64,option:client-arch,7",
            "dhcp-match=set:efi64,option:client-arch,9",
            "dhcp-boot=tag:known,tag:!ipxe,tag:!efihttp,tag:efi64,ipxe.efi",
            "dhcp-boot=tag:known,tag:!ipxe,tag:!efihttp,tag:!efi64,undionly.kpxe",
            "enable-tftp",
            "tftp-root=" + tftp_root,
            "tftp-secure",
        ]
    else:
        lines += [
            "# TFTP is off (boot.tftp: false). BIOS PXE and UEFI PXE firmware without",
            "# HTTP Boot cannot start here; machines that already run iPXE and UEFI",
            "# HTTP Boot machines can.",
        ]
    lines.append("")
    return "\n".join(lines)

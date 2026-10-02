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
_IFACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,14}")
_TFTP_ROOT = re.compile(r"/[A-Za-z0-9._/-]{0,200}")


def render_ipxe(advertise):
    """advertise is a validated HOST:PORT the booting machine can reach."""
    base = "http://" + advertise
    return "\n".join(
        [
            "#!ipxe",
            "echo blunix: netboot from the build proxy at " + advertise,
            "kernel " + base + "/media/vmlinuz initrd=initrd.img"
            + " boot=live noeject fetch=" + base + "/media/blunix.squashfs"
            + " blunix.proxy=" + advertise
            + " blunix.access=regular console=tty0 console=ttyS0,115200",
            "initrd " + base + "/media/initrd.img",
            "boot",
            "",
        ]
    )


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


def render_dnsmasq(site, advertise, interface=None, dhcp_range=None, tftp_root="/srv/tftp"):
    if interface is not None and not _IFACE.fullmatch(interface):
        raise BlunixError("refused interface")
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
        lines.append("dhcp-range=" + start + "," + end + ",12h")
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
                "dhcp-range=" + str(net.network_address) + ",static," + str(net.netmask) + ",12h"
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
            + "," + machine["hostname"] + ",12h"
        )
        lines.append("dhcp-option=tag:" + tag + ",option:router," + machine["gateway"])
        dns4 = [d for d in machine["dns"] if ipaddress.ip_address(d).version == 4]
        if dns4:
            lines.append("dhcp-option=tag:" + tag + ",option:dns-server," + ",".join(dns4))
    lines += [
        "",
        "dhcp-match=set:ipxe,175",
        "dhcp-match=set:efi64,option:client-arch,7",
        "dhcp-match=set:efi64,option:client-arch,9",
        "dhcp-boot=tag:known,tag:ipxe,http://" + advertise + "/v1/boot.ipxe",
        "dhcp-boot=tag:known,tag:!ipxe,tag:efi64,ipxe.efi",
        "dhcp-boot=tag:known,tag:!ipxe,tag:!efi64,undionly.kpxe",
        "enable-tftp",
        "tftp-root=" + tftp_root,
        "tftp-secure",
        "",
    ]
    return "\n".join(lines)

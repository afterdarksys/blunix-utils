#!/usr/bin/env python3
"""List the Debian source packages behind a release, for GPL source offers.

    image/gpl-sources.py VERSION disk-status installer-status > SOURCES.md

Each argument after VERSION is a dpkg status file (var/lib/dpkg/status) taken
from a release artifact. The output names every installed source package and
version, with a snapshot.debian.org link to the exact source, and the written
offer. It reads files only; it fetches nothing.

Threats: a release that ships GPL binaries without a route to the matching
source. It does not check that snapshot.debian.org still serves a version;
the written offer covers that.
"""

from __future__ import annotations

import re
import sys

_SOURCE = re.compile(r"^(\S+)(?:\s+\((\S+)\))?$")


def parse_status(text):
    """Yield (source, version) for each installed binary package."""
    for block in text.split("\n\n"):
        fields = {}
        for line in block.splitlines():
            if line[:1] in (" ", "\t") or ":" not in line:
                continue
            key, value = line.split(":", 1)
            fields[key] = value.strip()
        if "Package" not in fields or "Version" not in fields:
            continue
        if not fields.get("Status", "").endswith(" installed"):
            continue
        source, version = fields["Package"], fields["Version"]
        match = _SOURCE.match(fields.get("Source", ""))
        if match:
            source = match.group(1)
            if match.group(2):
                version = match.group(2)
        yield source, version


def render(release, found):
    lines = [
        "# Source for Blunix " + release,
        "",
        "The Blunix " + release + " installer ISO, disk image and netboot media contain "
        "binary packages from Debian 13 (trixie). Those packages keep their own licenses, "
        "many of them the GNU GPL. Blunix's own code is licensed separately; see LICENSE "
        "in the repository.",
        "",
        "## Where the source is",
        "",
        "Every source package below is in the Debian archive at the exact version shipped. "
        "The link opens that version on snapshot.debian.org. On a Debian system, "
        "`apt-get source NAME=VERSION` fetches the same thing.",
        "",
        "## Written offer",
        "",
        "For at least three years after this release, and for as long as we offer "
        "support for it, After Dark Systems will give anyone a complete copy of the "
        "corresponding source code for any GPL- or LGPL-licensed package in this release, on "
        "request, for no more than our cost of physically performing the distribution. Ask "
        "through https://github.com/afterdarksys/blunix/issues and name the release and "
        "the package.",
        "",
        "## Source packages (" + str(len(found)) + ")",
        "",
        "| Source package | Version | In |",
        "|---|---|---|",
    ]
    for (source, version), where in sorted(found.items()):
        url = "https://snapshot.debian.org/package/{0}/{1}/".format(source, version)
        lines.append("| [{0}]({1}) | `{2}` | {3} |".format(
            source, url, version, ", ".join(sorted(where))))
    lines.append("")
    return "\n".join(lines)


def main(argv):
    if len(argv) < 3:
        sys.stderr.write("usage: gpl-sources.py VERSION STATUS...\n")
        return 2
    release = argv[1]
    found = {}
    for path in argv[2:]:
        label = "installer" if "installer" in path else "disk"
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for pair in parse_status(handle.read()):
                found.setdefault(pair, set()).add(label)
    if not found:
        sys.stderr.write("gpl-sources: no installed packages found\n")
        return 1
    sys.stdout.write(render(release, found))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

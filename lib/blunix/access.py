"""Threats: the boot menu selects one of five profiles. An unknown cmdline
name resolves to regular, which masks speech and braille. A YAML profile that
does not match the built-in five is refused, so a document cannot invent a
sixth profile or turn speech on inside regular.

Orca and Emacspeak are sysexts. This module never starts them.
"""

from __future__ import annotations

import os
import re

from blunix.cmd import run_cmd
from blunix.errors import BlunixError
from blunix.schema import (
    load_path,
    model_path,
    require_bool,
    require_header,
    require_keys,
    require_name,
    write_text,
)

PROFILES = {
    "full-speech": {
        "speech": True,
        "braille": True,
        "large_print": False,
        "show_status": False,
        "orca": "if-installed",
    },
    "console-speech": {
        "speech": True,
        "braille": True,
        "large_print": False,
        "show_status": False,
        "orca": "never",
    },
    "large-print": {
        "speech": False,
        "braille": False,
        "large_print": True,
        "show_status": False,
        "orca": "never",
    },
    "regular": {
        "speech": False,
        "braille": False,
        "large_print": False,
        "show_status": False,
        "orca": "never",
    },
    "advanced": {
        "speech": False,
        "braille": False,
        "large_print": False,
        "show_status": True,
        "orca": "never",
    },
}

SPEECH_UNITS = (
    "espeakup.service",
    "speech-dispatcher.service",
    "brltty.service",
)
ENTRY_IDS = {
    "full-speech": "blunix-full-speech",
    "console-speech": "blunix-console-speech",
    "large-print": "blunix-large-print",
    "regular": "blunix-regular",
    "advanced": "blunix-advanced",
}
_KEYS = {
    "apiVersion",
    "kind",
    "name",
    "speech",
    "braille",
    "large_print",
    "show_status",
    "orca",
}
_CMDLINE = re.compile(r"(?:^|\s)blunix\.access=([^\s]+)")
_PREFERRED_FONT = "Lat15-Terminus32x16.psf.gz"


def parse_access(doc):
    if not isinstance(doc, dict):
        raise BlunixError("rejected plaintext")
    require_keys(doc, _KEYS)
    require_header(doc, "Access")
    name = require_name(doc.get("name"), "name")
    canon = PROFILES.get(name)
    if canon is None:
        raise BlunixError("refused access profile")
    got = {
        "speech": require_bool(doc.get("speech"), "speech"),
        "braille": require_bool(doc.get("braille"), "braille"),
        "large_print": require_bool(doc.get("large_print"), "large_print"),
        "show_status": require_bool(doc.get("show_status"), "show_status"),
        "orca": doc.get("orca"),
    }
    if got["orca"] not in ("if-installed", "never"):
        raise BlunixError("refused access profile")
    if got != canon:
        raise BlunixError("refused access profile")
    return {"name": name, **canon}


def load_access(models, name):
    if name not in PROFILES:
        raise BlunixError("refused access profile")
    parsed = parse_access(load_path(model_path(models, "access", name)))
    if parsed["name"] != name:
        raise BlunixError("refused name")
    return parsed


def profile_from_cmdline(cmdline):
    if not isinstance(cmdline, str):
        return "regular"
    found = _CMDLINE.search(cmdline)
    if not found:
        return "regular"
    name = found.group(1)
    if name not in PROFILES:
        return "regular"
    return name


def select_font(directory):
    preferred = os.path.join(directory, _PREFERRED_FONT)
    if os.path.isfile(preferred):
        return preferred
    try:
        names = os.listdir(directory)
    except OSError:
        return None
    found = [
        name
        for name in names
        if "32" in name and (name.endswith(".psf") or name.endswith(".psf.gz"))
    ]
    if not found:
        return None
    return os.path.join(directory, sorted(found)[0])


def plan_access(model, font_dir="/usr/share/consolefonts"):
    speech = bool(model["speech"])
    font = select_font(font_dir) if model["large_print"] else None
    return {
        "name": model["name"],
        "speech": speech,
        "braille": bool(model["braille"]),
        "large_print": bool(model["large_print"]),
        "show_status": bool(model["show_status"]),
        "mask": () if speech else SPEECH_UNITS,
        "start": SPEECH_UNITS if speech else (),
        "font": font,
        "entry": ENTRY_IDS[model["name"]],
    }


def _live(root):
    return os.path.abspath(root) == "/"


def _mask_files(root, units):
    unit_dir = os.path.join(root, "etc", "systemd", "system")
    os.makedirs(unit_dir, exist_ok=True)
    for unit in SPEECH_UNITS:
        link = os.path.join(unit_dir, unit)
        if unit in units:
            if os.path.islink(link) or os.path.exists(link):
                os.remove(link)
            os.symlink("/dev/null", link)
        elif os.path.islink(link) and os.readlink(link) == "/dev/null":
            os.remove(link)


def apply_access(model, root, cmdline=None, font_dir=None, log=None):
    if font_dir is None:
        font_dir = os.path.join(root, "usr", "share", "consolefonts")
        if _live(root):
            font_dir = "/usr/share/consolefonts"
    plan = plan_access(model, font_dir)
    os.makedirs(os.path.join(root, "etc", "blunix"), exist_ok=True)
    write_text(
        os.path.join(root, "etc", "blunix", "access.profile"),
        plan["name"] + "\n",
    )
    write_text(
        os.path.join(root, "etc", "blunix", "show-status"),
        "yes\n" if plan["show_status"] else "no\n",
    )
    write_text(
        os.path.join(root, "etc", "blunix", "next-boot-entry"),
        plan["entry"] + "\n",
    )
    _mask_files(root, plan["mask"])
    if plan["large_print"] and plan["font"]:
        # The basename is what vconsole setup looks up under consolefonts.
        font_name = os.path.basename(plan["font"])
        if font_name.endswith(".psf.gz"):
            font_key = font_name[: -len(".psf.gz")]
        elif font_name.endswith(".psf"):
            font_key = font_name[: -len(".psf")]
        else:
            font_key = font_name
        write_text(
            os.path.join(root, "etc", "vconsole.conf"),
            "FONT=" + font_key + "\n",
        )
    if not _live(root):
        return plan
    for unit in plan["mask"]:
        run_cmd(["systemctl", "mask", unit], check=False)
    for unit in plan["start"]:
        run_cmd(["systemctl", "unmask", unit], check=False)
    if plan["speech"]:
        mod = run_cmd(["modprobe", "speakup_soft"], check=False)
        failed = mod.returncode != 0
        for unit in plan["start"]:
            started = run_cmd(["systemctl", "start", unit], check=False)
            if started.returncode != 0:
                failed = True
        if failed and log is not None:
            log("blunix: speech did not start")
            try:
                fd = os.open("/dev/console", os.O_WRONLY | os.O_NOCTTY)
            except OSError:
                fd = -1
            if fd >= 0:
                try:
                    os.write(fd, b"\a\a\a")
                finally:
                    os.close(fd)
    if plan["large_print"] and plan["font"]:
        setfont = run_cmd(["setfont", plan["font"]], check=False)
        if setfont.returncode != 0 and log is not None:
            log("blunix: large print font was not applied")
    return plan


def boot_access(root="/", cmdline=None, log=None):
    if cmdline is None:
        try:
            with open("/proc/cmdline", "r", encoding="utf-8") as handle:
                cmdline = handle.read()
        except OSError:
            cmdline = ""
    name = profile_from_cmdline(cmdline)
    model = {"name": name, **PROFILES[name]}
    return apply_access(model, root, cmdline=cmdline, log=log)

"""Threats: the blue theme is a set of files. It is selected only when a
graphical session is already installed. This module does not install a
desktop, does not start Orca, and does not fetch anything.

What it does not stop: a package installed later that adds GTK without
another `blunix gui apply`. The theme stays unselected until that command
runs again.
"""

from __future__ import annotations

import os
import shutil

from blunix.errors import BlunixError
from blunix.schema import write_text

THEME_NAME = "Blunix"
_MARKER = "blunix-gui"

# A graphical session is one of these programs on disk. The cloud image has
# none of them. Orca's sysext is what adds the first one.
_GRAPHICAL = (
    "usr/bin/orca",
    "usr/bin/gnome-session",
    "usr/bin/sway",
    "usr/bin/labwc",
    "usr/bin/weston",
    "usr/bin/Xorg",
    "usr/bin/Xwayland",
    "usr/bin/startplasma-wayland",
)

_ACTIVATION = (
    "etc/gtk-3.0/settings.ini",
    "etc/gtk-4.0/settings.ini",
    "etc/profile.d/blunix-gui.sh",
    "etc/skel/.config/gtk-3.0/gtk.css",
    "etc/skel/.config/gtk-3.0/settings.ini",
    "etc/skel/.config/gtk-4.0/gtk.css",
    "etc/skel/.config/gtk-4.0/settings.ini",
    "root/.config/gtk-3.0/gtk.css",
    "root/.config/gtk-3.0/settings.ini",
    "root/.config/gtk-4.0/gtk.css",
    "root/.config/gtk-4.0/settings.ini",
)

_SETTINGS = """# blunix-gui
[Settings]
gtk-theme-name=Blunix
gtk-application-prefer-dark-theme=1
gtk-font-name=Sans 14
"""

_PROFILE = """# blunix-gui
export GTK_THEME=Blunix
"""


def graphical_installed(root):
    for rel in _GRAPHICAL:
        if os.path.isfile(os.path.join(root, rel)):
            return True
    return False


def theme_source(root):
    installed = os.path.join(root, "usr", "share", "themes", THEME_NAME, "index.theme")
    if os.path.isfile(installed):
        return os.path.dirname(installed)
    here = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "image", "gui", THEME_NAME)
    )
    if os.path.isfile(os.path.join(here, "index.theme")):
        return here
    raise BlunixError("theme missing")


def _ours(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            first = handle.readline()
    except OSError:
        return False
    return _MARKER in first


def _clear_activation(root):
    for rel in _ACTIVATION:
        path = os.path.join(root, rel)
        if os.path.isfile(path) and _ours(path):
            os.remove(path)


def _replace_tree(source, dest):
    parent = os.path.dirname(dest)
    os.makedirs(parent, exist_ok=True)
    tmp = dest + ".tmp"
    if os.path.isdir(tmp):
        shutil.rmtree(tmp)
    shutil.copytree(source, tmp)
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    os.rename(tmp, dest)


def _activate(root, theme):
    css_path = os.path.join(theme, "gtk-4.0", "gtk.css")
    try:
        with open(css_path, "r", encoding="utf-8") as handle:
            css = handle.read()
    except OSError:
        raise BlunixError("theme missing")
    if _MARKER not in css.splitlines()[0]:
        raise BlunixError("theme missing")
    for rel in (
        "etc/skel/.config/gtk-3.0/gtk.css",
        "etc/skel/.config/gtk-4.0/gtk.css",
        "root/.config/gtk-3.0/gtk.css",
        "root/.config/gtk-4.0/gtk.css",
    ):
        write_text(os.path.join(root, rel), css, 0o644)
    for rel in (
        "etc/gtk-3.0/settings.ini",
        "etc/gtk-4.0/settings.ini",
        "etc/skel/.config/gtk-3.0/settings.ini",
        "etc/skel/.config/gtk-4.0/settings.ini",
        "root/.config/gtk-3.0/settings.ini",
        "root/.config/gtk-4.0/settings.ini",
    ):
        write_text(os.path.join(root, rel), _SETTINGS, 0o644)
    write_text(os.path.join(root, "etc", "profile.d", "blunix-gui.sh"), _PROFILE, 0o644)


def apply_gui(root, source=None):
    """Stage the theme. Select it only when a graphical session is installed."""
    if source is None:
        source = theme_source(root)
    if not os.path.isfile(os.path.join(source, "index.theme")):
        raise BlunixError("theme missing")
    dest = os.path.join(root, "usr", "share", "themes", THEME_NAME)
    if os.path.realpath(source) != os.path.realpath(dest):
        _replace_tree(source, dest)
    if not graphical_installed(root):
        _clear_activation(root)
        return False
    _activate(root, dest)
    return True

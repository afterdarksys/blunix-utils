"""Console lines for the serial log. Never pass a passphrase or a key."""

import os
import re

from blunix.errors import BlunixError

_SAFE = re.compile(r"[\x20-\x7e]{1,240}")


def console_line(message):
    if not isinstance(message, str) or not _SAFE.fullmatch(message):
        raise BlunixError("refused log line")
    print(message, flush=True)
    try:
        fd = os.open("/dev/console", os.O_WRONLY | os.O_NOCTTY)
    except OSError:
        return
    try:
        os.write(fd, (message + "\n").encode("ascii"))
    finally:
        os.close(fd)

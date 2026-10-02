"""Threats: a wrong passphrase, truncated ciphertext, or substituted plaintext
must not yield a partial apply. This module shells out to Debian age. It does
not implement a cipher or a KDF, and it does not log the passphrase or age's
own diagnostics.

What it does not stop: age's own scrypt work factor. Lost passphrase means
the ciphertext stays ciphertext.
"""

from __future__ import annotations

import os
import select
import shutil
import subprocess
import termios
import threading
import time
import tty

from blunix.errors import BlunixError, DecryptError
from blunix.schema import MAX_DOCUMENT, write_bytes

# Ciphertext is larger than the document by the age header. Cap the read.
_MAX_CIPHER = 256 * 1024
_TIMEOUT = 50


def _fail(mode):
    if mode == "decrypt":
        raise DecryptError() from None
    raise BlunixError("age encrypt failed") from None


def _secret_bytes(mode, passphrase):
    if not isinstance(passphrase, str) or passphrase == "" or len(passphrase) > 256:
        _fail(mode)
    try:
        raw = passphrase.encode("utf-8")
    except UnicodeError:
        _fail(mode)
    if b"\n" in raw or b"\r" in raw or b"\x00" in raw:
        _fail(mode)
    return raw


def _run_age(mode, passphrase, payload, timeout=_TIMEOUT):
    if mode not in ("encrypt", "decrypt"):
        raise BlunixError("refused command")
    secret = _secret_bytes(mode, passphrase)
    if not isinstance(payload, (bytes, bytearray)):
        _fail(mode)
    payload = bytes(payload)
    # Encrypt takes a document; decrypt takes ciphertext, which carries the
    # age header on top of it. Each has its own cap.
    if mode == "decrypt" and len(payload) > _MAX_CIPHER:
        _fail(mode)
    if mode == "encrypt" and len(payload) > MAX_DOCUMENT:
        raise BlunixError("document too large")
    age_bin = shutil.which("age")
    if age_bin is None:
        _fail(mode)
    master, slave = os.openpty()
    proc = None
    try:
        tty.setraw(slave)
        def _preexec():
            # One setsid. A second setsid in the same child fails.
            os.setsid()
            import fcntl
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

        argv = [age_bin, "--passphrase", "--encrypt"] if mode == "encrypt" else [age_bin, "--decrypt"]
        # Minimal environment. The passphrase is written to the pty, never stored here.
        # LANG=C keeps age's prompt in English so the pty pump can see it.
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TERM": "dumb"}
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                preexec_fn=_preexec,
                pass_fds=(slave,),
                close_fds=True,
                bufsize=0,
            )
        except OSError:
            _fail(mode)
        os.close(slave)
        slave = -1
        out_box = []

        def _write_stdin():
            try:
                proc.stdin.write(payload)
                proc.stdin.close()
            except Exception:
                try:
                    proc.stdin.close()
                except Exception:
                    return

        def _read_stdout():
            chunks = []
            total = 0
            try:
                while True:
                    block = proc.stdout.read(65536)
                    if not block:
                        break
                    total += len(block)
                    if total > _MAX_CIPHER:
                        proc.kill()
                        break
                    chunks.append(block)
            except Exception:
                return
            out_box.append(b"".join(chunks))

        def _pump_tty():
            # age writes the prompt to stderr and reads the answer from /dev/tty.
            # Watch both. The buffer is never logged.
            want = 2 if mode == "encrypt" else 1
            answered = 0
            buf = b""
            err_fd = proc.stderr.fileno()
            watch = [master, err_fd]
            deadline = time.monotonic() + timeout
            while answered < want and watch and time.monotonic() < deadline:
                try:
                    ready, _, _ = select.select(watch, [], [], 0.2)
                except (OSError, ValueError):
                    return
                if not ready:
                    if proc.poll() is not None:
                        return
                    continue
                for fd in ready:
                    try:
                        chunk = os.read(fd, 1024)
                    except OSError:
                        if fd in watch:
                            watch.remove(fd)
                        continue
                    if not chunk:
                        if fd in watch:
                            watch.remove(fd)
                        continue
                    buf += chunk
                    lower = buf.lower()
                    while b"passphrase" in lower and answered < want:
                        try:
                            os.write(master, secret + b"\n")
                        except OSError:
                            return
                        answered += 1
                        idx = lower.find(b"passphrase")
                        buf = buf[idx + len(b"passphrase"):]
                        lower = buf.lower()
                if len(buf) > 4096:
                    buf = buf[-1024:]
                if proc.poll() is not None and b"passphrase" not in buf.lower():
                    return

        workers = (
            threading.Thread(target=_write_stdin),
            threading.Thread(target=_read_stdout),
            threading.Thread(target=_pump_tty),
        )
        for worker in workers:
            worker.daemon = True
            worker.start()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
            _fail(mode)
        for worker in workers:
            worker.join(timeout=5)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        code = proc.returncode
        out = out_box[0] if out_box else b""
        if code != 0 or not out or len(out) > _MAX_CIPHER:
            _fail(mode)
        return out
    finally:
        if slave >= 0:
            os.close(slave)
        if master >= 0:
            os.close(master)
        if proc is not None and proc.poll() is None:
            proc.kill()


def encrypt_bytes(plaintext, passphrase):
    return _run_age("encrypt", passphrase, plaintext)


def decrypt_bytes(ciphertext, passphrase):
    return _run_age("decrypt", passphrase, ciphertext)


def encrypt_file(src, dest, passphrase):
    with open(src, "rb") as handle:
        data = handle.read(MAX_DOCUMENT + 1)
    if len(data) > MAX_DOCUMENT:
        raise BlunixError("document too large")
    write_bytes(dest, encrypt_bytes(data, passphrase), 0o644)


def decrypt_to_file(ciphertext, passphrase, dest):
    data = decrypt_bytes(ciphertext, passphrase)
    tmp = dest + ".tmp"
    try:
        write_bytes(tmp, data, 0o600)
        os.replace(tmp, dest)
        os.chmod(dest, 0o600)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return dest

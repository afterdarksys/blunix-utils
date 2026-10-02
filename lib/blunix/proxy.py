"""`blunix proxy`: publish a site of machines and serve their installs on a LAN.

Threats: an account key on argv or in output, a build key sent to the API or
written anywhere but keys.txt, a label that belongs to someone else, a
partial publish that loses the key of a build it already uploaded. The
account key is read only from its 0600 file. Every document is rendered and
validated before the first network call. Each build key is written to
keys.txt (created O_EXCL, mode 0600) as a pending card before its upload,
so a lost upload answer never loses the key of a version the API recorded;
the card is then marked published, or not confirmed. state.json, stdout and
stderr never carry a key.

What it does not stop: a person who reads keys.txt. Treat it like the keys
it holds; print the cards and delete it.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import sys
import time

from blunix.age import encrypt_bytes
from blunix.errors import BlunixError
from blunix.keyfmt import display_key, generate_key
from blunix.proxy_boot import render_dnsmasq
from blunix.proxy_config import (
    DEFAULT_API,
    DEFAULT_LISTEN,
    Api,
    check_api_url,
    check_key,
    default_config_path,
    default_key_path,
    fingerprint,
    load_config,
    parse_hostport,
    read_key_file,
    save_config,
    write_private,
)
from blunix.proxy_site import latest_url, load_site, pinned_url, render_node, validate_node

_AGE_BINARY = b"age-encryption.org/v1\n"
_COMMANDS = {
    "init": ({"--api", "--key-file", "--listen", "--config"}, set(), 0),
    "plan": ({"--config"}, {"--check"}, 1),
    "publish": ({"--config", "--out"}, set(), 1),
    "serve": ({"--config", "--site", "--media", "--sums", "--listen", "--advertise"}, set(), 0),
    "dnsmasq": ({"--config", "--interface", "--range", "--proxy", "--tftp-root"}, set(), 1),
}
USAGE = """usage:
  blunix proxy init [--api URL] [--key-file PATH] [--listen HOST:PORT]
  blunix proxy plan SITE.yaml [--check]
  blunix proxy publish SITE.yaml [--out DIR]
  blunix proxy serve [--site SITE.yaml] [--media DIR [--sums PATH]] [--listen HOST:PORT] [--advertise HOST:PORT]
  blunix proxy dnsmasq SITE.yaml [--interface IF] [--range START,END] [--proxy HOST:PORT]
All commands take --config PATH (default ~/.config/blunix/proxy.yaml).
The account key is read from its key file, never from the command line."""


def _say(line):
    print("blunix proxy: " + line, flush=True)


def _parse(argv):
    for arg in argv:
        if "blx_" in arg or arg.startswith("--key=") or arg in ("--key", "--passphrase"):
            raise BlunixError("the account key is read from its key file, never from the command line")
    if not argv or argv[0] not in _COMMANDS:
        raise BlunixError("unknown command; run blunix proxy help")
    command = argv[0]
    valued, flags, npos = _COMMANDS[command]
    opts = {}
    positional = []
    index = 1
    while index < len(argv):
        item = argv[index]
        if item.startswith("--"):
            name, eq, value = item.partition("=")
            if name in flags and not eq:
                opts[name[2:]] = True
                index += 1
                continue
            if name not in valued:
                raise BlunixError("unknown option " + name.split("\n")[0][:40])
            if not eq:
                if index + 1 >= len(argv) or argv[index + 1].startswith("--"):
                    raise BlunixError("option " + name + " needs a value")
                value = argv[index + 1]
                index += 1
            opts[name[2:]] = value
            index += 1
            continue
        positional.append(item)
        index += 1
    if len(positional) != npos:
        raise BlunixError(command + " takes " + ("a site file" if npos else "no file argument"))
    return command, positional, opts


def _read_secret():
    if sys.stdin.isatty():
        return getpass.getpass("blunix proxy: account key (blx_...). It will not be shown: ")
    return sys.stdin.readline(300).strip()


def cmd_init(opts, read_secret=None):
    config = opts.get("config") or default_config_path()
    api = check_api_url(opts.get("api", DEFAULT_API))
    listen = opts.get("listen", DEFAULT_LISTEN)
    parse_hostport(listen, "listen address")
    key_file = os.path.abspath(os.path.expanduser(opts.get("key-file") or default_key_path()))
    if os.path.lexists(key_file):
        key = read_key_file(key_file)
    else:
        key = check_key((read_secret or _read_secret)())
        write_private(key_file, key.encode("ascii") + b"\n")
    save_config(config, api, key_file, listen)
    _say("saved " + config + ". Account key fingerprint " + fingerprint(key) + ".")
    _say("api " + api + ", key file " + key_file + ", listen " + listen + ".")
    return 0


def _api(opts, context_factory=None):
    config = load_config(opts.get("config"))
    return Api(config["api"], read_key_file(config["key_file"]), context_factory)


def _describe(machine):
    where = "by dhcp" if machine["dhcp"] else (
        "at " + machine["address"] + " via " + machine["gateway"]
    )
    return (
        "machine " + machine["mac"] + " gets label " + machine["label"]
        + " (" + latest_url(machine["label"]) + "), hostname " + machine["hostname"]
        + ", network " + where + ", disk " + machine["disk"]
        + ", access " + machine["access"] + "."
    )


def _rendered(site, models=None):
    docs = []
    for machine in site["machines"]:
        data = render_node(machine)
        validate_node(machine, data, models)
        docs.append(data)
    return docs


def cmd_plan(path, opts, api=None):
    site = load_site(path)
    _rendered(site)
    owned = None
    if opts.get("check"):
        owned = (api or _api(opts)).list_labels()
    for machine in site["machines"]:
        line = _describe(machine)
        if owned is not None:
            line += " The label is already yours." if machine["label"] in owned else (
                " The label would be reserved."
            )
        _say(line)
    _say(
        "publish would reserve each label, encrypt one document per machine with a new key,"
        " upload it as a new version, and write the keys to keys.txt."
        " Running publish again uploads new versions."
    )
    return 0


def _pending_card(machine, key, day):
    return (
        "Install card for " + machine["label"] + ". Pending: written before the upload.\n"
        "Machine hostname: " + machine["hostname"] + ". MAC: " + machine["mac"] + ".\n"
        "Latest URL: " + latest_url(machine["label"]) + "\n"
        "Key: " + display_key(key) + "\n"
        "Date: " + day + ".\n"
    )


def _published_card(machine, result):
    return (
        "Published: " + machine["label"] + " version " + str(result["version"]) + ".\n"
        "Pinned URL: " + pinned_url(machine["label"], result["version"]) + "\n"
        "SHA-256 of the ciphertext: " + result["sha256"] + "\n\n"
    )


def _unconfirmed_card(machine):
    return (
        "Not confirmed: the upload failed or its answer was lost, so this run did not publish "
        + machine["label"] + ". If " + latest_url(machine["label"])
        + " has a version newer than your last card, this key opens it.\n\n"
    )


def _append(fd, text):
    os.write(fd, text.encode("utf-8"))
    os.fsync(fd)


def _write_state(out_dir, records):
    body = json.dumps({"published": records}, indent=2, sort_keys=True) + "\n"
    write_private(os.path.join(out_dir, "state.json"), body.encode("utf-8"), exclusive=False)


def cmd_publish(path, opts, api=None, encrypt=encrypt_bytes, models=None):
    site = load_site(path)
    docs = _rendered(site, models)
    api = api or _api(opts)
    out_dir = opts.get("out") or ("blunix-publish-" + time.strftime("%Y%m%d-%H%M%S", time.gmtime()))
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    keys_path = os.path.join(out_dir, "keys.txt")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(keys_path, flags, 0o600)
    except FileExistsError:
        raise BlunixError(keys_path + " already exists; move it or pick another --out") from None
    except OSError:
        raise BlunixError("could not create " + keys_path) from None
    day = time.strftime("%Y-%m-%d", time.gmtime())
    records = []
    owned = None
    try:
        for machine, doc in zip(site["machines"], docs):
            label = machine["label"]
            if api.reserve(label) == "taken":
                if owned is None:
                    owned = api.list_labels()
                if label not in owned:
                    _write_state(out_dir, records)
                    _say(
                        "stopped: label " + label + " belongs to another account. "
                        + str(len(records)) + " earlier machines are published; their keys are in "
                        + keys_path + "."
                    )
                    return 1
            key = generate_key()
            ciphertext = encrypt(doc, key)
            if not isinstance(ciphertext, bytes) or not ciphertext.startswith(_AGE_BINARY):
                raise BlunixError("age did not produce a ciphertext")
            # The key is on disk before the upload: the API may commit a version and
            # the answer may still be lost.
            _append(fd, _pending_card(machine, key, day))
            del key
            try:
                result = api.upload(label, ciphertext)
            except BaseException:
                _append(fd, _unconfirmed_card(machine))
                raise
            _append(fd, _published_card(machine, result))
            records.append(
                {
                    "mac": machine["mac"],
                    "label": label,
                    "hostname": machine["hostname"],
                    "version": result["version"],
                    "sha256": result["sha256"],
                    "size": result["size"],
                    "url": latest_url(label),
                    "pinnedUrl": pinned_url(label, result["version"]),
                    "document_sha256": hashlib.sha256(doc).hexdigest(),
                    "date": day,
                }
            )
            _write_state(out_dir, records)
            _say(
                "published " + label + " version " + str(result["version"])
                + ", sha256 " + result["sha256"][:16] + "."
            )
    finally:
        os.close(fd)
    _say(
        "published " + str(len(records)) + " machines. Install cards are in " + keys_path
        + " (mode 0600). Running publish again uploads new versions."
    )
    return 0


def cmd_serve(opts, server_factory=None):
    from blunix.proxy_serve import ProxyServer

    listen = opts.get("listen") or load_config(opts.get("config"))["listen"]
    host, port = parse_hostport(listen, "listen address")
    site = load_site(opts["site"]) if opts.get("site") else None
    if opts.get("sums") and not opts.get("media"):
        raise BlunixError("--sums checks --media; give both")
    server = (server_factory or ProxyServer)(
        (host, port), site=site, media=opts.get("media"), sums=opts.get("sums"),
        advertise=opts.get("advertise"),
    )
    count = len(site["machines"]) if site else 0
    _say(
        "serving on " + listen + ": build relay, boot.ipxe, netconfig for "
        + str(count) + " machines. It never serves keys."
    )
    if opts.get("media"):
        _say("media matches SHA256SUMS. Netboot is for trusted LANs only until images are signed.")
    if getattr(server, "advertise", None) is None:
        _say("boot.ipxe answers 404: give --advertise HOST:PORT or a specific --listen address.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def cmd_dnsmasq(path, opts):
    site = load_site(path)
    proxy = opts.get("proxy")
    if not proxy:
        try:
            listen = load_config(opts.get("config"))["listen"]
        except BlunixError:
            listen = DEFAULT_LISTEN
        if listen.split(":")[0] in ("0.0.0.0", "localhost", "127.0.0.1"):
            raise BlunixError("give --proxy HOST:PORT, the proxy address the install LAN reaches")
        proxy = listen
    host, port = parse_hostport(proxy, "proxy address")
    sys.stdout.write(
        render_dnsmasq(
            site,
            host + ":" + str(port),
            interface=opts.get("interface"),
            dhcp_range=opts.get("range"),
            tftp_root=opts.get("tftp-root", "/srv/tftp"),
        )
    )
    sys.stdout.flush()
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "proxy":
        argv = argv[1:]
    if argv in ([], ["help"], ["-h"], ["--help"]):
        print(USAGE, file=sys.stdout if argv else sys.stderr)
        return 0 if argv else 1
    try:
        command, positional, opts = _parse(argv)
        if command == "init":
            return cmd_init(opts)
        if command == "plan":
            return cmd_plan(positional[0], opts)
        if command == "publish":
            return cmd_publish(positional[0], opts)
        if command == "serve":
            return cmd_serve(opts)
        return cmd_dnsmasq(positional[0], opts)
    except BlunixError as exc:
        print("blunix proxy: " + str(exc), file=sys.stderr, flush=True)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

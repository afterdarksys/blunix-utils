# Utility source ownership

This repo is the source of truth for custom Blunix host utilities and image helpers.
Keep website, portal and API development in their owning projects.

Maintain `dist-map.json` when changing distribution destinations. Commit and test
source changes here, then use `sync-to-dist.py --dry-run` followed by
`sync-to-dist.py` to update the sibling distribution. Never manually overwrite
conflicting distribution edits. Do not copy build artifacts, caches, private
keys, test credentials, or Git internals into the distribution.

Run focused tests under `PYTHONPATH=lib`. The full host suite targets Debian and
requires age, Git, Node, zstd and e2fsprogs; `image/run-unit-tests.sh` prepares it
in Docker. The existing age PTY wrapper has an unresolved macOS test issue.

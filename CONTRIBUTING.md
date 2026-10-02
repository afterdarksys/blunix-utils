# Contributing

Thank you for helping. Blunix is built so that a blind or low-vision operator can install and run a machine without seeing the screen. Please keep that true in anything you change.

## Before your first pull request

- **Sign the CLA.** Read [CLA.md](CLA.md). On your first pull request, a bot asks you to sign by commenting one sentence. You keep your copyright. The agreement lets After Dark Systems offer your work under both the noncommercial license and commercial licenses. Companies can email licensing@blunix.io for an entity agreement.
- **Do not include code you did not write** unless you name its source and license in the pull request.

## Rules the code already follows

- Security-domain code carries a `Threats:` note and negative tests: tampered, oversized, expired and wrong-key input must be refused. Everything fails closed.
- No `shell=True`, no `os.system`, no disabled TLS verification, no secrets in logs.
- Every prompt and result on the console is one sentence, starting with `blunix:`. There are no spinners and no colour-only states. A new prompt answers "what does a screen reader user hear?"
- Web pages have one `h1`, ordered headings, labels on every control, and text contrast of 7:1 or better.

## Tests

```
bash image/run-unit-tests.sh                  # Python suite, in Debian 13 with age
(cd platform/api && npm ci && npm test)       # API
node --test tests/site/releases.test.mjs tests/site/portal.test.mjs
```

## Licensing questions

Email licensing@blunix.io.

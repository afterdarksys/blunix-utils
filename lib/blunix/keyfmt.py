"""Threats: a weak or guessable build key, and a key typed with lookalike
characters that silently fails to decrypt. Keys come from the OS CSPRNG
(secrets) only. This module never logs or prints a key.

What it does not stop: a person who reads the key off the install card.
The ciphertext is public on a public label; the 100-bit key plus age's scrypt
work factor is the whole defence.
"""

from __future__ import annotations

import secrets

# Crockford base32, lowercase. No i, l, o, u.
ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"
KEY_LENGTH = 20  # 20 * 5 bits = 100 bits
GROUP = 5
_LOOKALIKE = {"i": "1", "l": "1", "o": "0"}


def generate_key():
    """Return a new canonical key: 20 lowercase Crockford base32 characters."""
    return "".join(secrets.choice(ALPHABET) for _ in range(KEY_LENGTH))


def display_key(canonical):
    """Group a canonical key as xxxxx-xxxxx-xxxxx-xxxxx for the install card."""
    if not is_canonical(canonical):
        raise ValueError("not a canonical key")
    return "-".join(
        canonical[i : i + GROUP] for i in range(0, KEY_LENGTH, GROUP)
    )


def is_canonical(value):
    return (
        isinstance(value, str)
        and len(value) == KEY_LENGTH
        and all(ch in ALPHABET for ch in value)
    )


def canonical_key(typed):
    """Map what a person typed to the canonical key, or None.

    Lowercase, drop spaces and hyphens, map i/l to 1 and o to 0. Returns the
    canonical string only if the result is exactly a key; otherwise None, and
    the caller tries the raw input as a hand-chosen passphrase.
    """
    if not isinstance(typed, str) or len(typed) > 64:
        return None
    out = []
    for ch in typed.strip().lower():
        if ch in " -\t":
            continue
        out.append(_LOOKALIKE.get(ch, ch))
    candidate = "".join(out)
    return candidate if is_canonical(candidate) else None


def passphrase_candidates(typed):
    """Passphrases to try, in order: the canonical key, then the raw input.

    At most two, never an empty string, no duplicates.
    """
    found = []
    canon = canonical_key(typed)
    if canon:
        found.append(canon)
    if isinstance(typed, str) and typed and typed not in found:
        found.append(typed)
    return found

"""Fail-closed errors. Messages are fixed phrases safe to print on a console."""


class BlunixError(Exception):
    """A document, argument, or local step was refused."""


class DecryptError(BlunixError):
    """Passphrase decrypt failed. The message is always the same phrase."""

    def __init__(self):
        super().__init__("could not decrypt")

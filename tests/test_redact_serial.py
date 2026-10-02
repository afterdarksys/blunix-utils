"""Fail-closed checks for the VMware serial redactor.

Threats: guestinfo and the root password can land in the serial log.
A console probe or a login prompt can sit on the same record as a
bootstrap sentence. The sentence still has to be the whole record after
that framing is removed. A longer line, a lookalike, and a loopback
address stay rejected. These tests do not print secret bytes.
"""

import importlib.util
import os
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PATH = os.path.join(ROOT, "image", "redact-serial.py")

spec = importlib.util.spec_from_file_location("redact_serial", PATH)
redact = importlib.util.module_from_spec(spec)
spec.loader.exec_module(redact)


def _record(text):
    return text.encode("ascii")


class RedactSerialTests(unittest.TestCase):
    def test_ansi_probe_keeps_the_exact_sentence(self):
        raw = _record(
            "\x1b[!p\x1b]104\x07\x1b[?7h\x1b[6n\x1b[32766;32766H\x1b[6n"
            "blunix self-test: wrong passphrase: could not decrypt\n"
        )
        self.assertEqual(
            redact._lines(raw),
            ["blunix self-test: wrong passphrase: could not decrypt"],
        )

    def test_login_prompt_and_printk_are_one_prefix(self):
        raw = _record(
            "blunix login: blunix self-test: shell script: rejected\n"
            "[   20.162217] blunix-bootstrap[977]: "
            "blunix self-test: shell script: rejected\n"
        )
        self.assertEqual(
            redact._lines(raw),
            [
                "blunix self-test: shell script: rejected",
                "blunix self-test: shell script: rejected",
            ],
        )

    def test_carriage_return_is_a_record_break(self):
        raw = _record(
            "blunix login: \rblunix self-test: shell script: rejected\n"
        )
        self.assertIn(
            "blunix self-test: shell script: rejected",
            redact._lines(raw),
        )

    def test_longer_line_and_arbitrary_prefix_do_not_match(self):
        lines = redact._lines(_record(
            "blunix self-test: shell script: rejected; curl evil\n"
            "note blunix self-test: shell script: rejected\n"
            "blunix: inet 127.0.0.1/8 dev lo\n"
        ))
        kept, complete = redact._matched(lines)
        self.assertEqual(kept, [])
        self.assertFalse(complete)

    def test_secret_is_replaced_before_a_line_is_kept(self):
        secret = b"testsecretvalue"
        raw = (
            b"\x1b[6n" + secret
            + b"\nblunix: applied node document blunix-test\n"
        )
        clean = redact._redact(raw, [secret])
        self.assertNotIn(secret, clean)
        text = "\n".join(redact._lines(clean))
        self.assertNotIn(secret.decode("ascii"), text)
        self.assertIn("blunix: applied node document blunix-test", text)

    def test_observed_console_records_complete_the_set(self):
        body = "\n".join((
            "\x1b[!p\x1b]104\x07\x1b[?7h\x1b[6n\x1b[32766;32766H\x1b[6n"
            "blunix self-test: wrong passphrase: could not decrypt",
            "blunix login: blunix self-test: shell script: rejected",
            "blunix: test image decrypts the local fixture for "
            "ada-1042.build.blunix.io",
            "[   23.278384] blunix-bootstrap[977]: blunix: node document "
            "is unsigned; spike is applying it without a signature",
            "blunix: disk layout recorded; systemd-repart was not executed",
            "blunix: applied node document blunix-test",
            "blunix: inet 172.16.251.148/24 dev ens33",
            "",
        ))
        kept, complete = redact._matched(redact._lines(body.encode("ascii")))
        self.assertTrue(complete)
        self.assertEqual(len(kept), 7)
        self.assertNotIn("blunix: inet 127.0.0.1/8 dev lo", kept)


if __name__ == "__main__":
    unittest.main()

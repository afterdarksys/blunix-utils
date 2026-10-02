"""Exercise real urllib openers, intercepting transport only (no network)."""

import io
import ssl
import unittest
import urllib.request
import urllib.response
from unittest.mock import patch

from blunix import ai, bootstrap, installer, tools


class HTTPSRegressionTests(unittest.TestCase):
    def test_default_download_paths_use_handler_context(self):
        cases = [
            lambda: tools.default_fetch(
                "demo", tools.artifact_url("demo", "v1", "demo.tar.gz")
            ),
            lambda: ai.default_fetch("grok", ai.artifact_url("grok", "1.0")),
            lambda: bootstrap.fetch_https("demo.blnx.io"),
            lambda: installer._open_release(
                "https://github.com/afterdarksys/blunix/releases/download/v1/blunix.raw.zst",
                None,
                None,
            ),
        ]
        for fetch in cases:
            contexts = []

            def transport(handler, request, contexts=contexts):
                contexts.append(handler._context)
                response = urllib.response.addinfourl(
                    io.BytesIO(b"payload"), {}, request.full_url, 200
                )
                response.msg = "OK"
                return response

            with (
                self.subTest(fetch=fetch),
                patch.object(urllib.request.HTTPSHandler, "https_open", transport),
            ):
                result = fetch()
                if not isinstance(result, bytes):
                    with result:
                        result = result.read()
                self.assertEqual(result, b"payload")
                self.assertEqual(len(contexts), 1)
                self.assertEqual(contexts[0].verify_mode, ssl.CERT_REQUIRED)
                self.assertTrue(contexts[0].check_hostname)


if __name__ == "__main__":
    unittest.main()

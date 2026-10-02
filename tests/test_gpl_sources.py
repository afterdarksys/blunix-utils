import importlib.util
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "gpl_sources", os.path.join(ROOT, "image", "gpl-sources.py"))
gpl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gpl)

STATUS = """Package: libc6
Status: install ok installed
Source: glibc
Version: 2.41-12+deb13u4

Package: bash
Status: install ok installed
Version: 5.2.37-2

Package: libfoo1
Status: install ok installed
Source: foo (1.2-3)
Version: 1.2-3+b1

Package: gone
Status: deinstall ok config-files
Version: 9.9
"""


class GplSourcesTests(unittest.TestCase):
    def test_source_names_and_versions(self):
        found = set(gpl.parse_status(STATUS))
        self.assertIn(("glibc", "2.41-12+deb13u4"), found)
        self.assertIn(("bash", "5.2.37-2"), found)
        # A binNMU keeps the source version, not the binary one.
        self.assertIn(("foo", "1.2-3"), found)

    def test_removed_packages_are_not_listed(self):
        self.assertNotIn("gone", {name for name, _ in gpl.parse_status(STATUS)})

    def test_render_links_exact_versions_and_offers_source(self):
        text = gpl.render("v9", {("glibc", "2.41-12+deb13u4"): {"disk"}})
        self.assertIn("https://snapshot.debian.org/package/glibc/2.41-12+deb13u4/", text)
        self.assertIn("## Written offer", text)
        self.assertIn("three years", text)

    def test_empty_status_fails(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix="-disk", delete=False) as handle:
            handle.write("")
        try:
            self.assertEqual(gpl.main(["x", "v9", handle.name]), 1)
        finally:
            os.unlink(handle.name)


if __name__ == "__main__":
    unittest.main()

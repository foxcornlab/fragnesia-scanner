"""Tests for fragnesia_scanner. Run: python3 -m unittest discover -s tests -v"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fragnesia_scanner import (  # noqa: E402
    FIXED,
    NOT_AFFECTED,
    UNKNOWN,
    VULNERABLE,
    grade_debian,
    grade_host,
    grade_ubuntu,
    grade_upstream,
    newest,
    parse_kernel,
)


class TestParse(unittest.TestCase):
    def test_upstream(self):
        self.assertEqual(parse_kernel("6.6.140")["base"], (6, 6, 140))
        self.assertEqual(parse_kernel("6.6.140")["abi"], None)

    def test_ubuntu_uname(self):
        p = parse_kernel("6.8.0-124-generic")
        self.assertEqual((p["base"], p["abi"], p["sub"]), ((6, 8, 0), 124, None))
        self.assertEqual(p["flavor"], "generic")

    def test_ubuntu_package(self):
        p = parse_kernel("6.8.0-124.124")
        self.assertEqual((p["base"], p["abi"], p["sub"]), ((6, 8, 0), 124, 124))

    def test_debian_package(self):
        p = parse_kernel("6.1.174-1")
        self.assertEqual((p["base"], p["abi"]), ((6, 1, 174), 1))

    def test_garbage(self):
        self.assertIsNone(parse_kernel("not-a-kernel"))
        self.assertIsNone(parse_kernel(""))
        self.assertIsNone(parse_kernel(None))


class TestUpstream(unittest.TestCase):
    def test_each_fixed_line_boundary(self):
        cases = [
            ("5.10.256", VULNERABLE), ("5.10.257", FIXED),
            ("5.15.207", VULNERABLE), ("5.15.208", FIXED),
            ("6.1.173", VULNERABLE), ("6.1.174", FIXED),
            ("6.6.140", VULNERABLE), ("6.6.141", FIXED),
            ("6.12.90", VULNERABLE), ("6.12.91", FIXED),
            ("6.18.32", VULNERABLE), ("6.18.33", FIXED),
            ("7.0.9", VULNERABLE), ("7.0.10", FIXED),
        ]
        for version, expected in cases:
            with self.subTest(version=version):
                self.assertEqual(grade_upstream(parse_kernel(version))[0], expected)

    def test_not_affected(self):
        self.assertEqual(grade_upstream(parse_kernel("3.8.13"))[0], NOT_AFFECTED)
        self.assertEqual(grade_upstream(parse_kernel("7.1.0"))[0], NOT_AFFECTED)
        self.assertEqual(grade_upstream(parse_kernel("7.2.1"))[0], NOT_AFFECTED)

    def test_line_with_no_fix_is_unknown(self):
        # 6.17 has no upstream stable fix in the table: never guess clean.
        self.assertEqual(grade_upstream(parse_kernel("6.17.5"))[0], UNKNOWN)
        self.assertEqual(grade_upstream(parse_kernel("6.5.3"))[0], UNKNOWN)


class TestUbuntu(unittest.TestCase):
    def test_package_version_definitive(self):
        self.assertEqual(
            grade_ubuntu("24.04", parse_kernel("6.8.0-124-generic"),
                         parse_kernel("6.8.0-124.100"))[0], VULNERABLE)
        self.assertEqual(
            grade_ubuntu("24.04", parse_kernel("6.8.0-124-generic"),
                         parse_kernel("6.8.0-124.124"))[0], FIXED)
        self.assertEqual(
            grade_ubuntu("24.04", parse_kernel("6.8.0-124-generic"),
                         parse_kernel("6.8.0-125.10"))[0], FIXED)

    def test_uname_abi_trap(self):
        # ABI below fixed -> vulnerable; ABI equal -> UNKNOWN (upload hidden);
        # ABI above -> fixed.
        self.assertEqual(
            grade_ubuntu("24.04", parse_kernel("6.8.0-123-generic"), None)[0], VULNERABLE)
        self.assertEqual(
            grade_ubuntu("24.04", parse_kernel("6.8.0-124-generic"), None)[0], UNKNOWN)
        self.assertEqual(
            grade_ubuntu("24.04", parse_kernel("6.8.0-125-generic"), None)[0], FIXED)

    def test_20_04_standard_kernel_not_affected(self):
        self.assertEqual(
            grade_ubuntu("20.04", parse_kernel("5.4.0-200-generic"), None)[0], NOT_AFFECTED)

    def test_20_04_hwe_unknown(self):
        self.assertEqual(
            grade_ubuntu("20.04", parse_kernel("5.15.0-100-generic"), None)[0], UNKNOWN)

    def test_other_releases(self):
        self.assertEqual(
            grade_ubuntu("22.04", parse_kernel("5.15.0-180-generic"),
                         parse_kernel("5.15.0-181.191"))[0], FIXED)
        self.assertEqual(
            grade_ubuntu("22.04", parse_kernel("5.15.0-181-generic"), None)[0], UNKNOWN)
        self.assertEqual(
            grade_ubuntu("25.10", parse_kernel("6.17.0-35-generic"),
                         parse_kernel("6.17.0-35.35"))[0], FIXED)
        self.assertEqual(
            grade_ubuntu("26.04", parse_kernel("7.0.0-22-generic"),
                         parse_kernel("7.0.0-22.22"))[0], FIXED)


class TestDebian(unittest.TestCase):
    def test_package_versions(self):
        self.assertEqual(
            grade_debian("bookworm", parse_kernel("6.1.174-1"))[0], FIXED)
        self.assertEqual(
            grade_debian("bookworm", parse_kernel("6.1.0-30"))[0], VULNERABLE)
        self.assertEqual(
            grade_debian("trixie", parse_kernel("6.12.90-1"))[0], FIXED)
        self.assertEqual(
            grade_debian("bullseye", parse_kernel("5.10.257-1"))[0], FIXED)

    def test_no_package_is_unknown(self):
        self.assertEqual(grade_debian("bookworm", None)[0], UNKNOWN)

    def test_unknown_release(self):
        self.assertEqual(grade_debian("sid", parse_kernel("6.12.90-1"))[0], UNKNOWN)


class TestHost(unittest.TestCase):
    def test_rhel_gets_upstream_plus_advisory_note(self):
        result = grade_host("rhel", "9.6", "", parse_kernel("6.6.140"), None)
        self.assertEqual(result["verdict"], VULNERABLE)
        self.assertTrue(any("RHSA" in n for n in result["notes"]))

    def test_unknown_distro_falls_back_to_upstream(self):
        result = grade_host("arch", "", "", parse_kernel("6.12.91"), None)
        self.assertEqual(result["verdict"], FIXED)

    def test_newest_package(self):
        pkgs = [parse_kernel("6.8.0-124.100"), parse_kernel("6.8.0-124.124")]
        self.assertEqual(newest(pkgs)["sub"], 124)


if __name__ == "__main__":
    unittest.main()

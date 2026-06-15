"""Hardening tests: error paths, bad input, edge cases.

These tests cover the new defensive code added to core.py and cli.py:
  - malformed / unreadable config and baseline files
  - bad --allow-regex from the CLI
  - scan_path on a missing root
  - write_baseline to an unwritable location
  - Allowlist.from_iterables with an invalid regex
  - CLI top-level guard for unexpected exceptions
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from secretsweep.core import (  # noqa: E402
    Allowlist,
    Engine,
    load_baseline,
    load_config,
    write_baseline,
)
from secretsweep.cli import main  # noqa: E402


# ---------------------------------------------------------------------------
# load_config edge cases
# ---------------------------------------------------------------------------
class TestLoadConfig(unittest.TestCase):
    def test_missing_path_returns_empty(self):
        """A path that does not exist silently returns {}."""
        self.assertEqual(load_config("/no/such/path/config.json"), {})

    def test_empty_string_path_returns_empty(self):
        self.assertEqual(load_config(""), {})

    def test_none_path_returns_empty(self):
        self.assertEqual(load_config(None), {})

    def test_malformed_json_raises_value_error(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                        delete=False) as fh:
            fh.write("{this is not valid json")
            name = fh.name
        try:
            with self.assertRaises(ValueError) as ctx:
                load_config(name)
            self.assertIn("invalid JSON", str(ctx.exception))
        finally:
            os.unlink(name)

    def test_non_object_json_raises_value_error(self):
        """Config must be a JSON object, not a list or scalar."""
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                        delete=False) as fh:
            fh.write('["rule1", "rule2"]')
            name = fh.name
        try:
            with self.assertRaises(ValueError) as ctx:
                load_config(name)
            self.assertIn("JSON object", str(ctx.exception))
        finally:
            os.unlink(name)

    def test_empty_file_returns_empty(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                        delete=False) as fh:
            fh.write("   \n")
            name = fh.name
        try:
            self.assertEqual(load_config(name), {})
        finally:
            os.unlink(name)


# ---------------------------------------------------------------------------
# load_baseline edge cases
# ---------------------------------------------------------------------------
class TestLoadBaseline(unittest.TestCase):
    def test_missing_path_returns_empty_set(self):
        self.assertEqual(load_baseline("/no/such/baseline.json"), set())

    def test_empty_file_returns_empty_set(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                        delete=False) as fh:
            fh.write("")
            name = fh.name
        try:
            self.assertEqual(load_baseline(name), set())
        finally:
            os.unlink(name)

    def test_bare_list_format(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                        delete=False) as fh:
            json.dump(["fp1", "fp2", "fp3"], fh)
            name = fh.name
        try:
            fps = load_baseline(name)
            self.assertEqual(fps, {"fp1", "fp2", "fp3"})
        finally:
            os.unlink(name)

    def test_object_format_with_fingerprints_key(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                        delete=False) as fh:
            json.dump({"tool": "secretsweep", "fingerprints": ["a", "b"]},
                      fh)
            name = fh.name
        try:
            fps = load_baseline(name)
            self.assertEqual(fps, {"a", "b"})
        finally:
            os.unlink(name)

    def test_newline_delimited_fallback(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                        delete=False) as fh:
            fh.write("fp_aaa\n# comment\nfp_bbb\n\n")
            name = fh.name
        try:
            fps = load_baseline(name)
            self.assertIn("fp_aaa", fps)
            self.assertIn("fp_bbb", fps)
            self.assertNotIn("# comment", fps)
        finally:
            os.unlink(name)


# ---------------------------------------------------------------------------
# write_baseline edge cases
# ---------------------------------------------------------------------------
class TestWriteBaseline(unittest.TestCase):
    def test_write_to_bad_path_raises_oserror(self):
        with self.assertRaises(OSError) as ctx:
            write_baseline("/no/such/dir/baseline.json", [])
        self.assertIn("Cannot write baseline", str(ctx.exception))

    def test_empty_findings_writes_empty_fingerprints(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                        delete=False) as fh:
            name = fh.name
        try:
            n = write_baseline(name, [])
            self.assertEqual(n, 0)
            with open(name) as fh:
                data = json.load(fh)
            self.assertEqual(data["fingerprints"], [])
        finally:
            os.unlink(name)


# ---------------------------------------------------------------------------
# Allowlist bad regex
# ---------------------------------------------------------------------------
class TestAllowlistBadRegex(unittest.TestCase):
    def test_invalid_regex_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            Allowlist.from_iterables(regexes=["[invalid("])
        self.assertIn("Invalid allowlist regex", str(ctx.exception))

    def test_valid_regex_works(self):
        al = Allowlist.from_iterables(regexes=[r"^test_.*"])
        self.assertEqual(len(al.regexes), 1)


# ---------------------------------------------------------------------------
# Engine.scan_path on missing root
# ---------------------------------------------------------------------------
class TestScanPathMissing(unittest.TestCase):
    def test_scan_path_nonexistent_raises(self):
        eng = Engine()
        with self.assertRaises(FileNotFoundError):
            eng.scan_path("/no/such/directory/at/all")


# ---------------------------------------------------------------------------
# CLI: bad --allow-regex returns exit 1, not a traceback
# ---------------------------------------------------------------------------
class TestCLIBadInput(unittest.TestCase):
    def _run(self, argv):
        out = io.StringIO()
        err = io.StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            code = main(argv)
        finally:
            sys.stdout, sys.stderr = old_out, old_err
        return code, out.getvalue(), err.getvalue()

    def test_bad_allow_regex_exits_1_with_message(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                        delete=False) as fh:
            fh.write("nothing sensitive here\n")
            name = fh.name
        try:
            code, _, stderr = self._run(
                ["scan", name, "--allow-regex", "[invalid("])
            self.assertEqual(code, 1)
            self.assertIn("error", stderr.lower())
            self.assertIn("allow-regex", stderr)
        finally:
            os.unlink(name)

    def test_malformed_config_exits_1_with_message(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                        delete=False) as fh:
            fh.write("{broken json")
            cfg_name = fh.name
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                        delete=False) as fh:
            fh.write("nothing here\n")
            scan_name = fh.name
        try:
            code, _, stderr = self._run(
                ["scan", scan_name, "--config", cfg_name])
            self.assertEqual(code, 1)
            self.assertIn("error", stderr.lower())
        finally:
            os.unlink(cfg_name)
            os.unlink(scan_name)

    def test_missing_scan_path_exits_1_with_message(self):
        code, _, stderr = self._run(["scan", "/no/such/path/file.txt"])
        self.assertEqual(code, 1)
        self.assertIn("error", stderr.lower())
        self.assertIn("not found", stderr.lower())

    def test_baseline_write_to_bad_path_exits_1(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                        delete=False) as fh:
            fh.write("nothing\n")
            scan_name = fh.name
        try:
            code, _, stderr = self._run(
                ["baseline", scan_name,
                 "-o", "/no/such/dir/baseline.json"])
            self.assertEqual(code, 1)
            self.assertIn("error", stderr.lower())
        finally:
            os.unlink(scan_name)


if __name__ == "__main__":
    unittest.main()

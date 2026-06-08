"""Smoke tests for SECRETSWEEP. Standard library only, no network."""
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from secretsweep import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    scan_text,
    redact,
    rotation_plan,
    shannon_entropy,
    DETECTORS,
)
from secretsweep.cli import main  # noqa: E402

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "config.env")


class TestCore(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "secretsweep")
        self.assertTrue(TOOL_VERSION)

    def test_entropy_monotonic(self):
        self.assertGreater(shannon_entropy("aB3xZ9qP1mK7vL2nR5tW"), shannon_entropy("aaaaaaaa"))
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_redact_masks_middle(self):
        r = redact("AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(r.startswith("AKI"))
        self.assertTrue(r.endswith("PLE"))
        self.assertIn("*", r)
        self.assertNotIn("IOSFODNN", r)

    def test_detects_aws_key(self):
        f = scan_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
        ids = {x.detector_id for x in f}
        self.assertIn("aws-access-key-id", ids)

    def test_detects_github_pat(self):
        f = scan_text("token=ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEE")
        self.assertTrue(any(x.detector_id == "github-pat" for x in f))

    def test_low_entropy_not_flagged(self):
        # repeated chars -> below the generic-assignment entropy floor
        f = scan_text('api_key = "aaaaaaaaaaaaaaaaaaaaaaaa"')
        self.assertFalse(any(x.detector_id == "generic-high-entropy-assignment" for x in f))

    def test_clean_text_no_findings(self):
        self.assertEqual(scan_text("APP_NAME=billing\nLOG_LEVEL=info\n"), [])

    def test_findings_are_redacted(self):
        f = scan_text("STRIPE_SECRET_KEY=sk_live_EXAMPLE0000000000000")
        self.assertTrue(f)
        self.assertNotIn("4eC39HqLyjWDarjtT1zdp7dc", f[0].match)

    def test_provider_filter(self):
        text = "AKIAIOSFODNN7EXAMPLE ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEE"
        only_gh = scan_text(text, providers=["github"])
        self.assertTrue(only_gh)
        self.assertTrue(all(x.provider == "github" for x in only_gh))

    def test_line_column(self):
        f = scan_text("line1\nline2\nGITHUB=ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEE")
        self.assertEqual(f[0].line, 3)

    def test_rotation_plan(self):
        f = scan_text("AKIAIOSFODNN7EXAMPLE")
        plan = rotation_plan(f)
        self.assertTrue(plan)
        self.assertEqual(plan[0]["provider"], "aws")
        self.assertTrue(plan[0]["rotation_steps"])

    def test_detector_ids_unique(self):
        ids = [d.id for d in DETECTORS]
        self.assertEqual(len(ids), len(set(ids)))


class TestCLI(unittest.TestCase):
    def _run(self, argv):
        out = io.StringIO()
        old = sys.stdout
        sys.stdout = out
        try:
            code = main(argv)
        finally:
            sys.stdout = old
        return code, out.getvalue()

    def test_scan_demo_json_nonzero_exit(self):
        code, output = self._run(["--format", "json", "scan", DEMO, "--rotate"])
        self.assertEqual(code, 1)  # secrets found -> non-zero
        data = json.loads(output)
        self.assertEqual(data["tool"], "secretsweep")
        self.assertGreater(data["count"], 0)
        self.assertIn("rotation_plan", data)

    def test_scan_clean_file_exit_zero(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as fh:
            fh.write("APP_NAME=demo\nLOG_LEVEL=info\n")
            name = fh.name
        try:
            code, _ = self._run(["--format", "json", "scan", name])
            self.assertEqual(code, 0)
        finally:
            os.unlink(name)

    def test_missing_path_exit_two(self):
        code, _ = self._run(["scan", os.path.join(os.path.dirname(__file__), "nope_xyz")])
        self.assertEqual(code, 2)

    def test_detectors_command(self):
        code, output = self._run(["--format", "json", "detectors"])
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertTrue(len(data["detectors"]) >= 8)


if __name__ == "__main__":
    unittest.main()

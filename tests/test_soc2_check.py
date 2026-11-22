"""Tests for the SOC 2 readiness checker. Standard library only.

Run with:  python3 -m unittest discover -s tests -v
"""

import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "skills" / "soc2-compliance-check" / "scripts" / "soc2_check.py"
EXAMPLES = ROOT / "examples"

spec = importlib.util.spec_from_file_location("soc2_check", SCRIPT)
soc2 = importlib.util.module_from_spec(spec)
sys.modules["soc2_check"] = soc2  # needed by dataclasses on Python 3.12+
spec.loader.exec_module(soc2)


def statuses(report):
    return {f["id"]: f["status"] for f in report["findings"]}


def write_tree(root, files):
    for rel, content in files.items():
        path = Path(root, rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


class ExampleAppTests(unittest.TestCase):
    def test_compliant_example_is_ready(self):
        report = soc2.run_checks(str(EXAMPLES / "compliant-app"))
        self.assertEqual(report["verdict"], "READY (automated checks)")
        self.assertEqual(report["score"], 100)
        self.assertEqual(report["counts"]["FAIL"], 0)

    def test_noncompliant_example_is_not_ready(self):
        report = soc2.run_checks(str(EXAMPLES / "noncompliant-app"))
        self.assertEqual(report["verdict"], "NOT READY")
        st = statuses(report)
        for check_id in ["SEC-001", "SEC-002", "NET-002", "DEP-002", "CHG-001", "CHG-002"]:
            self.assertEqual(st[check_id], "FAIL", check_id)
        for check_id in ["NET-001", "SEC-010", "SEC-011", "SEC-020", "SEC-021", "INF-001"]:
            self.assertIn(st[check_id], ("WARN", "FAIL"), check_id)

    def test_noncompliant_output_never_echoes_secret_values(self):
        report = soc2.run_checks(str(EXAMPLES / "noncompliant-app"))
        blob = repr(report)
        self.assertNotIn("hunter2hunter2", blob)


class DetectionTests(unittest.TestCase):
    def run_on(self, files):
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(tmp, files)
            return soc2.run_checks(tmp)

    def test_aws_key_is_detected(self):
        key = "AKIA" + "ABCDEFGHIJKLMNOP"  # assembled at runtime so this file has no literal key
        report = self.run_on({"app.py": f'KEY = "{key}"\n'})
        self.assertEqual(statuses(report)["SEC-001"], "FAIL")

    def test_private_key_block_is_detected(self):
        header = "-----BEGIN " + "RSA PRIVATE KEY-----"
        report = self.run_on({"deploy.sh": header + "\n"})
        self.assertEqual(statuses(report)["SEC-001"], "FAIL")

    def test_placeholders_are_not_flagged(self):
        report = self.run_on({"config.js": 'const apiKey = "your_api_key_here";\n'})
        self.assertEqual(statuses(report)["SEC-001"], "PASS")

    def test_soc2_ignore_marker_suppresses_a_line(self):
        key = "AKIA" + "ABCDEFGHIJKLMNOP"
        report = self.run_on({"fixture.py": f'KEY = "{key}"  # soc2-ignore test fixture\n'})
        self.assertEqual(statuses(report)["SEC-001"], "PASS")

    def test_env_example_is_not_treated_as_a_real_env_file(self):
        report = self.run_on({".env.example": "API_KEY=REPLACE_ME\n", ".gitignore": ".env\n"})
        self.assertEqual(statuses(report)["SEC-002"], "PASS")

    def test_real_env_file_is_a_failure(self):
        report = self.run_on({".env": "DATABASE_URL=postgres://u:p@db/app\n", ".gitignore": ".env\n"})
        self.assertEqual(statuses(report)["SEC-002"], "FAIL")

    def test_tls_verification_disabled_is_a_failure(self):
        report = self.run_on({"client.py": "import requests\nrequests.get(u, verify=False)\n"})
        self.assertEqual(statuses(report)["NET-002"], "FAIL")

    def test_sql_concatenation_is_warned(self):
        report = self.run_on({"db.js": 'db.query("SELECT * FROM t WHERE id = " + id);\n'})
        self.assertEqual(statuses(report)["SEC-021"], "WARN")

    def test_parameterized_sql_passes(self):
        report = self.run_on({"db.js": "db.query('SELECT * FROM t WHERE id = $1', [id]);\n"})
        self.assertEqual(statuses(report)["SEC-021"], "PASS")

    def test_ci_and_tests_are_detected(self):
        report = self.run_on({
            ".github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: npm test\n",
            "tests/app.test.js": "test('x', () => {});\n",
        })
        st = statuses(report)
        self.assertEqual(st["CHG-001"], "PASS")
        self.assertEqual(st["CHG-002"], "PASS")

    def test_empty_folder_is_not_ready(self):
        report = self.run_on({})
        self.assertEqual(report["verdict"], "NOT READY")
        self.assertEqual(report["files_scanned"], 0)

    def test_binary_files_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "image.bin").write_bytes(b"\x00\x01AKIAABCDEFGHIJKLMNOP")
            report = soc2.run_checks(tmp)
        self.assertEqual(statuses(report)["SEC-001"], "PASS")


class CliTests(unittest.TestCase):
    def test_missing_path_returns_usage_error(self):
        with redirect_stdout(io.StringIO()):
            code = soc2.main(["/definitely/not/a/real/path"])
        self.assertEqual(code, 2)

    def test_fail_findings_return_exit_code_1(self):
        with redirect_stdout(io.StringIO()):
            code = soc2.main([str(EXAMPLES / "noncompliant-app")])
        self.assertEqual(code, 1)

    def test_fail_on_never_always_returns_zero(self):
        with redirect_stdout(io.StringIO()):
            code = soc2.main([str(EXAMPLES / "noncompliant-app"), "--fail-on", "never"])
        self.assertEqual(code, 0)

    def test_json_and_markdown_outputs_render(self):
        report = soc2.run_checks(str(EXAMPLES / "compliant-app"))
        self.assertIn("## Details", soc2.render_markdown(report))
        self.assertIn("SOC 2 Readiness Check", soc2.render_text(report))


if __name__ == "__main__":
    unittest.main()

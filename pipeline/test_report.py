import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pipeline import scan
from pipeline.report import (NONE_FOUND, NOT_SAFE, PARTIAL, SAFE, VERDICT_DESCRIPTIONS, VERDICTS, build, exceeds,
                             summarize, to_markdown, verdict)

ROOT = Path(__file__).resolve().parents[1]


def component(source, line, algorithm, tier, context="source", asset="code-primitive", **extra):
    return {"type": "application-code", "source": source, "line": line, "codeSnippet": f"use({algorithm})",
            "cryptoProperties": {"detectedAlgorithm": algorithm, "context": context, "assetType": asset},
            "quantumRiskAssessment": {"tier": tier, **extra}}


REPORTS = {"code": {"components": [
    component("a.js", 3, "RSA-2048", "CRITICAL", suggestion="Migrate signatures to ML-DSA.", nistStandard="FIPS 204"),
    component("a.js", 9, "AES-256-GCM", "SAFE"),
    component("b.js", 1, "RSA-2048", "Critical"),
    component("test/x.test.js", 2, "MD5", "CRITICAL", context="test"),
    component("package.json", 4, "jsonwebtoken (crypto library)", "UNKNOWN", asset="dependency"),
]}}


class SummarizeTest(unittest.TestCase):
    def test_counts_algorithms_and_files(self):
        summary = summarize(REPORTS)
        self.assertEqual(summary["totalFindings"], 5)
        self.assertEqual(summary["riskCounts"], {"CRITICAL": 3, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 1, "UNKNOWN": 1})
        self.assertEqual(summary["byKind"], {"code": summary["riskCounts"]})
        self.assertEqual(summary["byAssetType"], {"code-primitive": 4, "dependency": 1})
        self.assertEqual(summary["byContext"], {"source": 4, "test": 1})
        self.assertEqual(summary["algorithms"][0], {"algorithm": "RSA-2048", "risk": "CRITICAL", "count": 2, "files": 2})
        self.assertEqual(summary["filesWithFindings"], 4)
        self.assertEqual(summary["testFindingsExcluded"], 0)

    def test_excluding_tests(self):
        summary = summarize(REPORTS, include_tests=False)
        self.assertEqual(summary["totalFindings"], 4)
        self.assertEqual(summary["riskCounts"]["CRITICAL"], 2)
        self.assertEqual(summary["testFindingsExcluded"], 1)
        self.assertNotIn("MD5", {row["algorithm"] for row in summary["algorithms"]})

    def test_empty_reports(self):
        summary = summarize({})
        self.assertEqual(summary["totalFindings"], 0)
        self.assertEqual(summary["algorithms"], [])
        self.assertEqual(set(summary["riskCounts"].values()), {0})


class VerdictTest(unittest.TestCase):
    def summary(self, **counts):
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0, "UNKNOWN": 0, **counts}
        return {"totalFindings": sum(risk_counts.values()), "riskCounts": risk_counts}

    def test_policy(self):
        for counts, expected in [
            ({}, NONE_FOUND),
            ({"CRITICAL": 1, "SAFE": 50}, NOT_SAFE),
            ({"HIGH": 1}, NOT_SAFE),
            ({"HIGH": 1, "MEDIUM": 3}, NOT_SAFE),
            ({"MEDIUM": 2, "SAFE": 3}, PARTIAL),
            ({"LOW": 1, "SAFE": 3}, PARTIAL),
            ({"UNKNOWN": 1, "SAFE": 9}, PARTIAL),
            ({"SAFE": 4}, SAFE),
        ]:
            with self.subTest(counts=counts):
                self.assertEqual(verdict(self.summary(**counts)), expected)

    def test_build_adds_verdict_and_description(self):
        summary = build(REPORTS)
        self.assertEqual(summary["verdict"], NOT_SAFE)
        self.assertEqual(summary["verdictDescription"], VERDICT_DESCRIPTIONS[NOT_SAFE])
        self.assertEqual(build({})["verdict"], NONE_FOUND)


class ThresholdTest(unittest.TestCase):
    def test_fail_on(self):
        critical = summarize(REPORTS)
        medium_only = summarize({"code": {"components": [component("a.py", 1, "AES-128", "MEDIUM")]}})
        self.assertTrue(exceeds(critical, "critical"))
        self.assertFalse(exceeds(critical, "none"))
        self.assertFalse(exceeds(medium_only, "critical"))
        self.assertFalse(exceeds(medium_only, "high"))
        self.assertTrue(exceeds(medium_only, "medium"))


class MarkdownTest(unittest.TestCase):
    def test_sections_findings_and_caveats(self):
        summary = {**summarize(REPORTS), "verdict": NOT_SAFE, "verdictDescription": "Explained."}
        markdown = to_markdown(summary, REPORTS, "team/repo")
        self.assertTrue(markdown.startswith("# Quantum-safety report: team/repo\n"))
        self.assertIn(f"**Verdict: {NOT_SAFE}**. Explained.", markdown)
        self.assertIn("| CRITICAL | 3 |", markdown)
        self.assertNotIn("| HIGH |", markdown)
        self.assertIn("| RSA-2048 | CRITICAL | 2 | 2 |", markdown)
        self.assertIn("### `a.js`", markdown)
        self.assertIn("- **CRITICAL** line 3: RSA-2048 `use(RSA-2048)`. Migrate signatures to ML-DSA. (FIPS 204)", markdown)
        # Within a file, the worst risk is listed first.
        self.assertLess(markdown.index("line 3: RSA-2048"), markdown.index("line 9: AES-256-GCM"))
        self.assertIn("## What this report does not cover", markdown)
        self.assertIn("not proof", markdown)

    def test_pipes_and_backticks_cannot_break_tables(self):
        reports = {"code": {"components": [component("a.js", 1, "weird|`name`", "UNKNOWN")]}}
        summary = {**summarize(reports), "verdict": NOT_SAFE, "verdictDescription": ""}
        markdown = to_markdown(summary, reports, "t")
        self.assertIn("| weird\\|'name' | UNKNOWN | 1 | 1 |", markdown)

    def test_excluded_tests_are_not_listed(self):
        summary = {**summarize(REPORTS, include_tests=False), "verdict": NOT_SAFE, "verdictDescription": ""}
        markdown = to_markdown(summary, REPORTS, "t", include_tests=False)
        self.assertNotIn("x.test.js", markdown)
        self.assertIn("1 test findings excluded", markdown)


class CliTest(unittest.TestCase):
    """End to end through verdict(); fails until verdict() is implemented."""

    def run_cli(self, *args):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()) as out:
            code = scan.main([*args, "-o", folder])
            report = json.loads((Path(folder) / "report.json").read_text()) if code != 2 else None
            markdown = (Path(folder) / "report.md").read_text() if code != 2 else None
        return code, report, markdown, out.getvalue()

    def test_local_repository_report_and_exit_code(self):
        code, report, markdown, out = self.run_cli(str(ROOT / "test_data/js_crypto"))
        self.assertEqual(code, 1)
        self.assertEqual(set(report), {"target", "summary", "reports"})
        self.assertEqual(report["target"], "js_crypto")
        self.assertIn(report["summary"]["verdict"], VERDICTS)
        self.assertEqual(report["summary"]["totalFindings"], 31)
        self.assertIsInstance(report["reports"]["code"]["components"], list)
        self.assertIn("src/keys.ts", markdown)
        self.assertIn(report["summary"]["verdict"], out)

    def test_threshold_none_passes(self):
        self.assertEqual(self.run_cli(str(ROOT / "test_data/js_crypto"), "--fail-on", "none")[0], 0)

    def test_safe_only_repository_passes_critical_gate(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "a.js").write_text("crypto.createCipheriv('aes-256-gcm', key, iv);\n")
            code, report, _, _ = self.run_cli(folder)
        self.assertEqual(code, 0)
        self.assertEqual(report["summary"]["riskCounts"]["SAFE"], 1)

    def test_repository_url_is_cloned_then_scanned(self):
        def fake_clone(url, target):
            self.assertEqual(url, "https://github.com/team/app.git")
            Path(target).mkdir()
            (Path(target) / "a.js").write_text("crypto.createHash('md5');\n")

        with patch("pipeline.scan.clone", side_effect=fake_clone):
            code, report, _, _ = self.run_cli("https://github.com/team/app")
        self.assertEqual(code, 1)
        self.assertEqual(report["target"], "team/app")

    def test_bad_targets_fail_cleanly(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(scan.main(["https://evil.test/a/b", "-o", "unused"]), 2)
            self.assertEqual(scan.main([str(ROOT / "does-not-exist"), "-o", "unused"]), 2)
        self.assertIn("Scan failed", err.getvalue())
        self.assertFalse((ROOT / "unused").exists())


if __name__ == "__main__":
    unittest.main()

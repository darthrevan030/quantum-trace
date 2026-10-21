import json
import tempfile
import unittest
from pathlib import Path

from pipeline import registry
from pipeline.analyze_source import analyze
from pipeline.walker import walk

ROOT = Path(__file__).resolve().parents[1]


class WalkerTest(unittest.TestCase):
    def test_limits_skip_instead_of_failing(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ["a.js", "b.js", "c.js"]:
                (root / name).write_text("x")
            (root / "big.js").write_text("x" * 50)
            (root / "node_modules").mkdir()
            (root / "node_modules/dep.js").write_text("x")
            files, skipped = walk(root, max_files=2, max_file_bytes=10)
            self.assertEqual([f.name for f in files], ["a.js", "b.js"])
            self.assertEqual(skipped, {"largeFiles": 1, "overFileLimit": 1, "symlinks": 0})


class AnalyzeTest(unittest.TestCase):
    def run_analysis(self, root):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "reports.json"
            analyze(Path(root), output)
            return json.loads(output.read_text())

    def test_repository_produces_code_report_with_relative_sources(self):
        reports = self.run_analysis(ROOT / "test_data/js_crypto")
        self.assertEqual(set(reports), {"code"})
        code = reports["code"]
        self.assertEqual(len(code["components"]), 31)
        self.assertIn("src/keys.ts", {c["source"] for c in code["components"]})
        self.assertEqual(code["metadata"]["inputFileCount"], 11)
        self.assertEqual(code["metadata"]["skippedFiles"], {"largeFiles": 0, "overFileLimit": 0, "symlinks": 0})

    def test_more_than_two_thousand_files_is_scanned_not_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for index in range(2100):
                (root / f"f{index}.js").write_text("")
            (root / "z.js").write_text("crypto.createHash('md5');\n")
            reports = self.run_analysis(root)
            self.assertEqual([c["source"] for c in reports["code"]["components"]], ["z.js"])
            self.assertEqual(reports["code"]["metadata"]["inputFileCount"], 2101)

    def test_existing_code_cbom_export_is_imported(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            component = {"type": "application-code", "name": "x.py:1",
                         "quantumRiskAssessment": {"tier": "CRITICAL"}, "cryptoProperties": {}}
            (root / "export.json").write_text(json.dumps({"metadata": {"sourceFile": "x.py"}, "components": [
                component, {"type": "unregistered-kind", "name": "ignored"}]}))
            reports = self.run_analysis(root)
            self.assertEqual(reports["code"]["components"], [{**component, "source": "x.py"}])

    def test_invalid_component_in_export_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "export.json").write_text(json.dumps({"components": ["not a component"]}))
            with self.assertRaises(TypeError):
                self.run_analysis(folder)

    def test_nothing_supported_is_an_error(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "notes.txt").write_text("hello")
            (Path(folder) / "data.json").write_text('{"not": "a cbom"}')
            with self.assertRaisesRegex(ValueError, "No supported inputs"):
                self.run_analysis(folder)

    def test_registered_extension_kind_runs(self):
        # The seam the network/cloud branches plug into.
        def fake(root, files):
            return {"components": [{"type": "fake-asset", "source": str(files[0])}]}

        registry.register("fake", fake)
        try:
            with tempfile.TemporaryDirectory() as folder:
                (Path(folder) / "a.txt").write_text("x")
                reports = self.run_analysis(folder)
            self.assertEqual(reports["fake"]["components"], [{"type": "fake-asset", "source": "a.txt"}])
        finally:
            registry.SCANNERS.pop("fake")


if __name__ == "__main__":
    unittest.main()

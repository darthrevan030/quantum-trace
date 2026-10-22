import json
import tempfile
import unittest
from pathlib import Path

from test_data.generators import code
from test_data.generators.common import verify


def tree(root):
    # Git may check fixtures out with CRLF (core.autocrlf); compare content, not the checkout's line endings.
    return {path.relative_to(root).as_posix(): path.read_bytes().replace(b"\r\n", b"\n")
            for path in sorted(Path(root).rglob("*")) if path.is_file()}


class CodeGeneratorTest(unittest.TestCase):
    def test_regenerating_reproduces_the_committed_fixtures_exactly(self):
        with tempfile.TemporaryDirectory() as folder:
            code.generate(Path(folder))
            self.assertEqual(tree(folder), tree(code.FIXTURE))

    def test_verify_records_expected_results(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest = verify("code", code.FIXTURE, code.EXPECTED_COUNTS, expected_dir=folder)
            saved = json.loads((Path(folder) / "code.json").read_text(encoding="utf-8"))
        self.assertEqual(saved, manifest)
        self.assertEqual(saved["fixture"], "code")
        self.assertEqual(saved["riskCounts"], {"CRITICAL": 6, "MEDIUM": 4, "SAFE": 3})
        self.assertEqual(saved["totalFindings"], 13)
        self.assertIn({"source": "python/legacy/main.py", "name": "main.py:7", "risk": "MEDIUM"}, saved["findings"])

    def test_changed_scanner_output_is_rejected_and_nothing_is_written(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(SystemExit, "scanner output changed"):
                verify("code", code.FIXTURE, {"CRITICAL": 7, "MEDIUM": 3, "SAFE": 3}, expected_dir=folder)
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_missing_report_kind_names_the_branch_to_use(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(SystemExit, "network scanner registered"):
                verify("network", code.FIXTURE, {}, expected_dir=folder)


class NetworkGeneratorTest(unittest.TestCase):
    def test_regenerating_reproduces_the_committed_captures_exactly(self):
        from test_data.generators import network

        with tempfile.TemporaryDirectory() as folder:
            network.generate(Path(folder))
            self.assertEqual(tree(folder), tree(network.FIXTURE))

    def test_expected_results_match_the_scanner(self):
        from test_data.generators import network

        with tempfile.TemporaryDirectory() as folder:
            manifest = verify("network", network.FIXTURE, network.EXPECTED_COUNTS, expected_dir=folder)
        committed = json.loads((network.FIXTURE.parent / "expected/network.json").read_text(encoding="utf-8"))
class CloudGeneratorTest(unittest.TestCase):
    def test_regenerating_reproduces_the_committed_inventories_exactly(self):
        from test_data.generators import cloud

        with tempfile.TemporaryDirectory() as folder:
            cloud.generate(Path(folder))
            self.assertEqual(tree(folder), tree(cloud.FIXTURE))

    def test_expected_results_match_the_scanner(self):
        from test_data.generators import cloud

        with tempfile.TemporaryDirectory() as folder:
            manifest = verify("cloud", cloud.FIXTURE, cloud.EXPECTED_COUNTS, expected_dir=folder)
        committed = json.loads((cloud.FIXTURE.parent / "expected/cloud.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest, committed)


if __name__ == "__main__":
    unittest.main()

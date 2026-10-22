import gc
import sqlite3
import tempfile
import unittest
import warnings
from contextlib import closing
from pathlib import Path

from pipeline.database import add_code_classification, create_source, init_db
from pipeline.source_store import STORAGE, SourceStore


def code_component(source="a.js", line=1, algorithm="RSA-2048", tier="CRITICAL"):
    return {"type": "application-code", "name": f"{source}:{line}", "source": source, "line": line,
            "codeSnippet": "generateKeyPairSync('rsa')",
            "cryptoProperties": {"language": "javascript", "detectedAlgorithm": algorithm, "keySizeBits": 2048},
            "quantumRiskAssessment": {"tier": tier, "reason": "Shor", "suggestion": "Use ML-DSA."}}


class DatabaseTest(unittest.TestCase):
    def test_helpers_close_their_connections(self):
        # An unclosed connection keeps the file locked on Windows and leaks a ResourceWarning everywhere.
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "q.db"
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                init_db(db)
                create_source("repo", "/tmp/repo", "git_repo", db)
                add_code_classification({"file_path": "a.py", "language": "python", "primitive": "RSA", "risk": "CRITICAL"}, db)
                gc.collect()
            leaks = [w for w in caught if issubclass(w.category, ResourceWarning)]
            self.assertEqual(leaks, [])
            db.unlink()  # Fails on Windows while a connection is still open.

    def test_main_schema_has_only_code_tables(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "q.db"
            init_db(db)
            with closing(sqlite3.connect(db)) as conn:
                tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertIn("code_classification", tables)
            self.assertNotIn("network_session", tables)


class SourceStoreTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.db = Path(self.folder.name) / "q.db"
        self.store = SourceStore(self.db)

    def tearDown(self):
        gc.collect()
        self.folder.cleanup()

    def test_code_report_round_trip_and_columns(self):
        report = {"metadata": {"scannedFiles": 1}, "components": [code_component()]}
        self.store.create({"id": "s1", "name": "team/app", "kind": "repository"})
        self.store.save_reports("s1", {"code": report})
        self.store.save_reports("s1", {"code": report})  # Saving twice replaces, never duplicates.
        self.assertEqual(self.store.get("s1")["reports"], {"code": report})
        with closing(sqlite3.connect(self.db)) as conn:
            row = conn.execute("SELECT file_path, language, primitive, risk, key_size, line_number, suggestion "
                               "FROM code_classification WHERE source_id='s1'").fetchall()
        self.assertEqual(row, [("a.js", "javascript", "RSA-2048", "CRITICAL", 2048, 1, "Use ML-DSA.")])

    def test_legacy_rows_are_migrated(self):
        add_code_classification({"file_path": "old.py", "language": "python", "primitive": "RSA", "risk": "Critical"}, self.db)
        legacy = SourceStore(self.db).get("legacy")["reports"]["code"]["components"]
        self.assertEqual(legacy[0]["cryptoProperties"]["detectedAlgorithm"], "RSA")
        self.assertEqual(legacy[0]["source"], "old.py")

    def test_unregistered_kind_is_rejected_on_save_and_skipped_on_load(self):
        self.store.create({"id": "s2", "name": "x", "kind": "files"})
        with self.assertRaisesRegex(ValueError, "network"):
            self.store.save_reports("s2", {"network": {"components": []}})
        # A database written by a build with the network extension still opens without it.
        self.store.save_reports("s2", {"code": {"components": []}})
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute("INSERT INTO source_report VALUES('s2', 'network', '{}')")
        self.assertEqual(set(self.store.get("s2")["reports"]), {"code"})

    def test_extension_kind_registers_its_own_table(self):
        STORAGE.pop("fake", None)
        from pipeline.source_store import register_storage
        register_storage("fake", "fake_asset", "CREATE TABLE IF NOT EXISTS fake_asset (id INTEGER PRIMARY KEY, name TEXT)",
                         lambda component: {"name": component["name"]},
                         lambda row: {"name": row["name"]})
        try:
            store = SourceStore(self.db)
            store.create({"id": "s3", "name": "x", "kind": "files"})
            store.save_reports("s3", {"fake": {"components": [{"name": "asset"}]}})
            self.assertEqual(store.get("s3")["reports"]["fake"]["components"], [{"name": "asset"}])
        finally:
            STORAGE.pop("fake")


if __name__ == "__main__":
    unittest.main()

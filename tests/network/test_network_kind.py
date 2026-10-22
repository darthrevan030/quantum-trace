import contextlib
import gc
import io
import json
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from pipeline.analyze_source import run_scanners
from pipeline.export_cbom import export_cbom
from pipeline.pcap_scanner import analyze_pcap_to_cbom
from pipeline.source_store import SourceStore

ROOT = Path(__file__).resolve().parents[2]
CAPTURES = ROOT / "test_data/network"


def risks(report):
    counts = {}
    for component in report["components"]:
        counts[component["risk"]] = counts.get(component["risk"], 0) + 1
    return counts


class AnalysisTest(unittest.TestCase):
    def test_captures_produce_classified_sessions(self):
        reports = run_scanners(CAPTURES)
        self.assertEqual(set(reports), {"network"})
        network = reports["network"]
        self.assertEqual(len(network["components"]), 6)
        self.assertEqual(risks(network), {"CRITICAL": 3, "MEDIUM": 1, "SAFE": 1, "UNKNOWN": 1})
        self.assertEqual({c["source"] for c in network["components"]},
                         {"legacy_tls.pcap", "hybrid_safe_tls.pcap", "hybrid_aes128_tls.pcap", "clienthello_only.pcap"})
        self.assertEqual(network["metadata"]["captures"], 5)
        hybrid = next(c for c in network["components"] if c["source"] == "hybrid_safe_tls.pcap")
        self.assertEqual(hybrid["risk"], "SAFE")
        self.assertEqual(hybrid["cryptoProperties"]["keyExchange"]["risk"], "SAFE")

    def test_code_and_captures_in_one_source(self):
        with tempfile.TemporaryDirectory() as folder:
            shutil.copy(CAPTURES / "hybrid_safe_tls.pcap", folder)
            (Path(folder) / "app.js").write_text("crypto.createHash('md5');\n")
            self.assertEqual(set(run_scanners(Path(folder))), {"code", "network"})

    def test_no_captures_means_no_network_report(self):
        self.assertNotIn("network", run_scanners(ROOT / "test_data/js_crypto"))

    def test_exported_network_cbom_is_reclassified_on_import(self):
        with tempfile.TemporaryDirectory() as folder:
            raw = analyze_pcap_to_cbom(str(CAPTURES / "hybrid_aes128_tls.pcap"))
            (Path(folder) / "raw-export.json").write_text(json.dumps(raw))
            imported = run_scanners(Path(folder))["network"]["components"]
        self.assertEqual([c["risk"] for c in imported], ["MEDIUM"])
        self.assertEqual(imported[0]["cryptoProperties"]["encryption"]["keySizeBits"], 128)


class StorageAndExportTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.db = Path(self.folder.name) / "q.db"
        self.reports = run_scanners(CAPTURES)

    def tearDown(self):
        gc.collect()
        self.folder.cleanup()

    def test_network_sessions_round_trip_through_their_own_table(self):
        store = SourceStore(self.db)
        store.create({"id": "net", "name": "captures", "kind": "files"})
        store.save_reports("net", self.reports)
        self.assertEqual(store.get("net")["reports"], json.loads(json.dumps(self.reports)))
        with closing(sqlite3.connect(self.db)) as conn:
            rows = conn.execute("SELECT server_endpoint, encryption_algorithm, key_exchange_risk, conclusion "
                                "FROM network_session WHERE source_id='net' ORDER BY id").fetchall()
        self.assertEqual(len(rows), 6)
        self.assertIn(("198.51.100.4:443", "AES", "SAFE", "SAFE"), rows)

    def test_legacy_rows_without_component_json_are_rebuilt(self):
        store = SourceStore(self.db)
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute("INSERT INTO network_session (client_endpoint, server_endpoint, encryption_algorithm, conclusion) "
                         "VALUES ('client', 'server', 'AES', 'MEDIUM')")
        legacy = SourceStore(self.db).get("legacy")["reports"]["network"]["components"][0]
        self.assertEqual((legacy["risk"], legacy["evidence"]["server"]), ("MEDIUM", "server"))
        self.assertEqual(legacy["cryptoProperties"]["encryption"]["algorithm"], "AES")
        del store

    def test_sessions_export_as_tls_protocols_with_linked_algorithms(self):
        source = {"id": "net", "name": "captures", "kind": "files", "status": "ready", "reports": self.reports}
        bom = export_cbom(source)
        components = {c["bom-ref"]: c for c in bom["components"]}
        refs = set(components) | {bom["metadata"]["component"]["bom-ref"]}
        for dependency in bom["dependencies"]:
            self.assertTrue({dependency["ref"], *dependency.get("dependsOn", [])}.issubset(refs))
        sessions = [components[f"network:{i}"] for i in range(6)]
        self.assertTrue(all(s["cryptoProperties"]["assetType"] == "protocol" for s in sessions))
        self.assertEqual({s["cryptoProperties"]["protocolProperties"]["type"] for s in sessions}, {"tls"})
        encryption = [c for ref, c in components.items() if ref.endswith(":encryption")]
        self.assertIn("128", {c["cryptoProperties"]["algorithmProperties"].get("parameterSetIdentifier") for c in encryption})
        # Authentication becomes an asset only where the handshake recorded it; nothing is invented.
        recorded = {i for i, s in enumerate(self.reports["network"]["components"])
                    if s["cryptoProperties"]["authentication"]["algorithm"] != "Not recorded"}
        self.assertEqual(len(recorded), 2)
        self.assertEqual({i for i in range(6) if f"network:{i}:authentication" in components}, recorded)
        self.assertTrue(any(d["ref"].endswith(":keyExchange") and d.get("dependsOn") for d in bom["dependencies"]))


class ServerTest(unittest.TestCase):
    def test_uploaded_capture_is_analysed_by_the_server(self):
        from server import Application
        with tempfile.TemporaryDirectory() as folder:
            app = Application(Path(folder) / "q.db", Path(folder) / "inputs")
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    source = app.create("client-net", files=[("hybrid_safe_tls.pcap", (CAPTURES / "hybrid_safe_tls.pcap").read_bytes())])
                    app.jobs.shutdown(wait=True)
                result = app.store.get(source["id"])
                self.assertEqual(result["status"], "ready", result.get("error"))
                self.assertEqual([c["risk"] for c in result["reports"]["network"]["components"]], ["SAFE"])
            finally:
                app.jobs.shutdown()
                gc.collect()


if __name__ == "__main__":
    unittest.main()

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from pipeline.pcap_scanner import analyze_pcap_to_cbom

FIXTURE = Path(__file__).resolve().parents[2] / "test_data/network"


class PcapScannerTest(unittest.TestCase):
    def scan(self, name, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            report = analyze_pcap_to_cbom(str(FIXTURE / name), **kwargs)
        self.assertEqual(out.getvalue(), "", "a library call must not print")
        return report

    def test_sessions_and_negotiated_parameters(self):
        report = self.scan("legacy_tls.pcap")
        sessions = report["components"]
        self.assertEqual(len(sessions), 3)
        self.assertEqual(report["metadata"]["totalSessions"], 3)
        self.assertEqual({s["evidence"]["server"] for s in sessions},
                         {"198.51.100.1:443", "198.51.100.2:443", "198.51.100.3:443"})
        # Cipher suites stay as IANA ids here; translate_network_cbom names them.
        self.assertEqual(sorted(s["cryptoProperties"]["cipherSuite"] for s in sessions), ["47", "4866", "49200"])
        self.assertTrue(all(s["type"] == "network-session" for s in sessions))

    def test_hybrid_group_and_client_hello_only(self):
        hybrid = self.scan("hybrid_safe_tls.pcap")["components"][0]["cryptoProperties"]
        self.assertEqual(hybrid["keyExchangeGroup"], "X25519MLKEM768")
        self.assertTrue(hybrid["serverNegotiatedPQC"])
        partial = self.scan("clienthello_only.pcap")["components"][0]["cryptoProperties"]
        self.assertEqual(partial["cipherSuite"], "ClientHello_Only")

    def test_non_tls_traffic_has_no_sessions(self):
        self.assertEqual(self.scan("non_tls.pcap")["components"], [])

    def test_file_is_written_only_when_asked(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "out.json"
            report = self.scan("hybrid_safe_tls.pcap", output_json=str(target))
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), report)
            self.scan("hybrid_safe_tls.pcap")
            self.assertEqual([p.name for p in Path(folder).iterdir()], ["out.json"])


if __name__ == "__main__":
    unittest.main()

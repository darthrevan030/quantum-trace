import gc
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from pipeline.analyze_source import run_scanners
from pipeline.cloud_posture_scanner import rate_certificate, rate_kms_key, rate_policy
from pipeline.export_cbom import export_cbom
from pipeline.source_store import SourceStore

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "test_data/cloud"


def tiers(report):
    counts = {}
    for component in report["components"]:
        tier = component["quantumRiskAssessment"]["tier"]
        counts[tier] = counts.get(tier, 0) + 1
    return counts


class RatingTest(unittest.TestCase):
    def test_kms_key_specs(self):
        for spec, usage, tier in [
            ("RSA_2048", "SIGN_VERIFY", "CRITICAL"),
            ("ECC_NIST_P256", "SIGN_VERIFY", "CRITICAL"),
            ("ECC_SECG_P256K1", "SIGN_VERIFY", "CRITICAL"),
            ("SYMMETRIC_DEFAULT", "ENCRYPT_DECRYPT", "SAFE"),
            ("HMAC_256", "GENERATE_VERIFY_MAC", "SAFE"),
            ("ML_DSA_65", "SIGN_VERIFY", "SAFE"),
            # Previously "Medium": an unknown or missing spec is not evidence of a medium risk.
            (None, "ENCRYPT_DECRYPT", "UNKNOWN"),
            ("SOMETHING_NEW", "SIGN_VERIFY", "UNKNOWN"),
        ]:
            with self.subTest(spec=spec):
                result = rate_kms_key(spec, usage)
                self.assertEqual(result["tier"], tier, result)
                self.assertTrue(result["reason"])
        self.assertIn("ML-DSA", rate_kms_key("RSA_2048", "SIGN_VERIFY")["suggestion"])
        self.assertIn("ML-KEM", rate_kms_key("RSA_2048", "ENCRYPT_DECRYPT")["suggestion"])

    def test_certificate_key_algorithms(self):
        for algorithm, tier in [("RSA_2048", "CRITICAL"), ("EC_prime256v1", "CRITICAL"), ("EC_secp384r1", "CRITICAL"),
                                ("ML_DSA_65", "SAFE"), ("UNKNOWN", "UNKNOWN")]:
            with self.subTest(algorithm=algorithm):
                self.assertEqual(rate_certificate(algorithm)["tier"], tier)

    def test_tls_policies(self):
        for policy, tier in [
            # A PQ policy offers hybrid ML-KEM but still accepts classical clients, so it is not Safe.
            ("ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09", "MEDIUM"),
            ("ELBSecurityPolicy-TLS13-1-3-PQ-2025-09", "MEDIUM"),
            ("ELBSecurityPolicy-TLS13-1-2-2021-06", "CRITICAL"),
            ("ELBSecurityPolicy-2016-08", "CRITICAL"),
            ("custom-policy", "UNKNOWN"),
            (None, "UNKNOWN"),
        ]:
            with self.subTest(policy=policy):
                result = rate_policy(policy)
                self.assertEqual(result["tier"], tier, result)
        self.assertIn("ELBSecurityPolicy-2016-08", rate_policy("ELBSecurityPolicy-2016-08")["reason"])
        self.assertIn("classical", rate_policy("ELBSecurityPolicy-TLS13-1-3-PQ-2025-09")["reason"])
        self.assertEqual(rate_policy("ELBSecurityPolicy-2016-08")["urgency"], "HNDL")
        self.assertEqual(rate_policy("ELBSecurityPolicy-TLS13-1-3-PQ-2025-09")["urgency"], "HNDL")
        self.assertEqual(rate_kms_key("RSA_2048", "SIGN_VERIFY")["urgency"], "Forgery")
        self.assertEqual(rate_certificate("RSA_2048")["urgency"], "Forgery")


class AnalysisTest(unittest.TestCase):
    def test_fixture_inventories(self):
        reports = run_scanners(FIXTURE)
        self.assertEqual(set(reports), {"cloud"})
        cloud = reports["cloud"]
        self.assertEqual(tiers(cloud), {"CRITICAL": 6, "MEDIUM": 1, "SAFE": 2, "UNKNOWN": 1})
        self.assertEqual({c["type"] for c in cloud["components"]}, {"cloud-kms-key", "x509-certificate", "load-balancer-listener"})
        self.assertEqual({c["source"] for c in cloud["components"]},
                         {"kms_key_inventory.json", "acm_certificates.json", "load_balancer_listeners.json"})
        # Plain HTTP listeners carry no TLS and are not reported.
        self.assertFalse(any(c["name"].endswith(":80") for c in cloud["components"]))

    def test_inventories_are_found_by_content_not_file_name(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "prod-keys-export.json").write_text(json.dumps({"Keys": [{"KeyId": "k1", "KeySpec": "RSA_3072"}]}))
            (Path(folder) / "package.json").write_text('{"dependencies": {}}')
            (Path(folder) / "settings.json").write_text('{"Keys": "not a list"}')
            cloud = run_scanners(Path(folder))["cloud"]
        self.assertEqual([(c["source"], c["name"], c["quantumRiskAssessment"]["tier"]) for c in cloud["components"]],
                         [("prod-keys-export.json", "k1", "CRITICAL")])

    def test_folders_without_inventories_have_no_cloud_report(self):
        self.assertNotIn("cloud", run_scanners(ROOT / "test_data/js_crypto"))


class StorageAndExportTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.db = Path(self.folder.name) / "q.db"
        self.reports = run_scanners(FIXTURE)

    def tearDown(self):
        gc.collect()
        self.folder.cleanup()

    def test_assets_round_trip_through_their_own_table(self):
        store = SourceStore(self.db)
        store.create({"id": "aws", "name": "aws", "kind": "files"})
        store.save_reports("aws", self.reports)
        self.assertEqual(store.get("aws")["reports"], json.loads(json.dumps(self.reports)))
        with closing(sqlite3.connect(self.db)) as conn:
            rows = conn.execute("SELECT asset_type, name, risk FROM cloud_classification WHERE source_id='aws'").fetchall()
        self.assertEqual(len(rows), 10)
        self.assertIn(("cloud-kms-key", "alias/demo-pq-signing", "SAFE"), rows)

    def test_assets_export_as_certificates_keys_and_protocols(self):
        bom = export_cbom({"id": "aws", "name": "aws", "kind": "files", "status": "ready", "reports": self.reports})
        components = {c["bom-ref"]: c for c in bom["components"]}
        refs = set(components) | {bom["metadata"]["component"]["bom-ref"]}
        for dependency in bom["dependencies"]:
            self.assertTrue({dependency["ref"], *dependency.get("dependsOn", [])}.issubset(refs))
        by_type = {}
        for index, finding in enumerate(self.reports["cloud"]["components"]):
            by_type.setdefault(finding["type"], []).append(components[f"cloud:{index}"])
        self.assertEqual({c["cryptoProperties"]["assetType"] for c in by_type["x509-certificate"]}, {"certificate"})
        self.assertEqual({c["cryptoProperties"]["assetType"] for c in by_type["cloud-kms-key"]}, {"related-crypto-material"})
        self.assertEqual({c["cryptoProperties"]["assetType"] for c in by_type["load-balancer-listener"]}, {"protocol"})
        certificate = by_type["x509-certificate"][0]["cryptoProperties"]["certificateProperties"]
        self.assertEqual({asset["type"] for asset in certificate["relatedCryptographicAssets"]}, {"signatureAlgorithm", "algorithm"})
        # A TLS policy name is not evidence of negotiated algorithms, so none are linked.
        self.assertNotIn("relatedCryptographicAssets", by_type["load-balancer-listener"][0]["cryptoProperties"]["protocolProperties"])


if __name__ == "__main__":
    unittest.main()

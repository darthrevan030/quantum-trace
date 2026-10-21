import json
import re
import tempfile
import unittest
from pathlib import Path

from pipeline.code_scanner import load_rules, scan_code, scan_repositories
from pipeline.crypto_catalog import RISKS

ROOT = Path(__file__).resolve().parents[1]


def findings(report):
    return {
        (c["source"], c["line"], c["cryptoProperties"]["detectedAlgorithm"], c["quantumRiskAssessment"]["tier"])
        for c in report["components"]
    }


class JavaScriptRulesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = scan_code(ROOT / "test_data/js_crypto")

    def test_exact_findings(self):
        self.assertEqual(findings(self.report), {
            ("src/cipher.js", 3, "AES-128-CBC", "MEDIUM"),
            ("src/cipher.js", 4, "AES-256-GCM", "SAFE"),
            ("src/cipher.js", 5, "3DES", "MEDIUM"),
            ("src/cipher.js", 6, "Cipher (runtime-selected)", "UNKNOWN"),
            ("src/cipher.js", 7, "SHA-1", "MEDIUM"),
            ("src/cipher.js", 8, "HMAC-SHA-256", "SAFE"),
            ("src/keys.ts", 4, "RSA-4096", "CRITICAL"),
            ("src/keys.ts", 8, "EC P-256", "CRITICAL"),
            ("src/keys.ts", 9, "Ed25519", "CRITICAL"),
            ("src/keys.ts", 10, "ECDH P-384", "CRITICAL"),
            ("src/keys.ts", 11, "RSA", "CRITICAL"),
            ("src/webcrypto.mjs", 1, "AES-128-GCM", "MEDIUM"),
            ("src/webcrypto.mjs", 6, "ECDSA P-384", "CRITICAL"),
            ("src/webcrypto.mjs", 7, "SHA-256", "SAFE"),
            ("src/jwt.js", 2, "JWT RS256", "CRITICAL"),
            ("src/jwt.js", 3, "JWT HS256", "SAFE"),
            ("src/jwt.js", 4, "JWT ES256", "CRITICAL"),
            ("src/jwt.js", 4, "JWT HS512", "SAFE"),
            ("src/libs.js", 5, "3DES", "MEDIUM"),
            ("src/libs.js", 6, "MD5", "CRITICAL"),
            ("src/libs.js", 7, "X25519", "CRITICAL"),
            ("src/libs.js", 8, "bcrypt", "SAFE"),
            ("src/libs.js", 9, "ML-KEM-768", "SAFE"),
            ("src/jws.js", 2, "Mojaloop JWS (RS256/ES256)", "CRITICAL"),
            ("src/jws.js", 3, "Mojaloop JWS (RS256/ES256)", "CRITICAL"),
            ("src/tls.js", 1, "TLSv1", "CRITICAL"),
            ("src/tls.js", 1, "X25519MLKEM768", "SAFE"),
            ("src/tls.js", 1, "X25519", "CRITICAL"),
            ("package.json", 4, "jsonwebtoken (crypto library)", "UNKNOWN"),
            ("package.json", 5, "RSA via node-rsa", "CRITICAL"),
            ("package.json", 6, "ML-KEM via @noble/post-quantum", "SAFE"),
        })

    def test_negative_controls_produce_nothing(self):
        sources = {c["source"] for c in self.report["components"]}
        self.assertNotIn("src/lib/bundle.min.js", sources)
        self.assertNotIn("src/types.d.ts", sources)
        self.assertNotIn(2, {c["line"] for c in self.report["components"] if c["source"] == "src/cipher.js"})
        self.assertNotIn(9, {c["line"] for c in self.report["components"] if c["source"] == "src/cipher.js"})

    def test_key_size_comes_from_the_match_not_any_number(self):
        by_line = {(c["source"], c["line"]): c for c in self.report["components"]}
        self.assertIsNone(by_line[("src/cipher.js", 7)]["cryptoProperties"]["keySizeBits"])
        self.assertEqual(by_line[("src/keys.ts", 4)]["cryptoProperties"]["keySizeBits"], 4096)

    def test_component_shape(self):
        component = next(c for c in self.report["components"] if c["line"] == 4 and c["source"] == "src/keys.ts")
        self.assertEqual(component["type"], "application-code")
        self.assertEqual(component["name"], "keys.ts:4")
        self.assertEqual(component["codeSnippet"], "const rsa = generateKeyPairSync('rsa', {")
        props = component["cryptoProperties"]
        self.assertEqual(props["language"], "typescript")
        self.assertEqual(props["assetType"], "code-primitive")
        self.assertIsInstance(props["ruleId"], str)
        assessment = component["quantumRiskAssessment"]
        self.assertEqual(assessment["threat"], "Shor")
        self.assertIn("ML-DSA", assessment["suggestion"])
        dependency = next(c for c in self.report["components"] if c["source"] == "package.json" and c["line"] == 5)
        self.assertEqual(dependency["cryptoProperties"]["assetType"], "dependency")
        self.assertEqual(dependency["cryptoProperties"]["language"], "npm")
        self.assertEqual(dependency["cryptoProperties"]["context"], "source")
        self.assertEqual(props["context"], "source")

    def test_test_files_are_tagged(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "test").mkdir()
            (Path(folder) / "test/keys.test.js").write_text("crypto.createHash('md5');\n")
            (Path(folder) / "app.js").write_text("crypto.createHash('md5');\n")
            contexts = {c["source"]: c["cryptoProperties"]["context"] for c in scan_code(Path(folder))["components"]}
            self.assertEqual(contexts, {"test/keys.test.js": "test", "app.js": "source"})

    def test_pinned_transitive_dependencies_are_reported(self):
        # Real-world case (Mojaloop account-lookup-service): jsonwebtoken only appears under "overrides".
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "package.json").write_text(
                '{\n  "dependencies": {"express": "^4"},\n  "overrides": {\n    "jsonwebtoken": "9.0.0",\n'
                '    "some-lib": {"node-forge": "1.3.1"}\n  },\n  "resolutions": {"elliptic": "6.6.1"}\n}\n')
            report = scan_code(Path(folder))
            self.assertEqual(findings(report), {
                ("package.json", 4, "jsonwebtoken (crypto library)", "UNKNOWN"),
                ("package.json", 5, "node-forge (crypto library)", "UNKNOWN"),
                ("package.json", 7, "EC via elliptic", "CRITICAL"),
            })
            self.assertEqual({c["cryptoProperties"]["dependencySection"] for c in report["components"]},
                             {"overrides", "resolutions"})

    def test_metadata_summary(self):
        summary = self.report["metadata"]["quantumRiskSummary"]
        self.assertEqual(summary["totalFindings"], 31)
        self.assertEqual(summary["riskCounts"], {"CRITICAL": 15, "HIGH": 0, "MEDIUM": 5, "LOW": 0, "SAFE": 9, "UNKNOWN": 2})
        self.assertIsInstance(summary["codeQuantumRiskScore"], str)
        self.assertTrue(summary["codeQuantumRiskScore"].endswith("%"))


class PortedRulesTest(unittest.TestCase):
    def test_demo_fixture_findings(self):
        report = scan_code(ROOT / "test_data/code")
        self.assertEqual(findings(report), {
            ("python/pqc_config.py", 2, "ML-KEM-768", "SAFE"),
            ("python/legacy/main.py", 6, "RSA-2048", "CRITICAL"),
            ("python/legacy/main.py", 7, "SHA-1", "MEDIUM"),
            ("python/symmetric/main.py", 5, "AES", "MEDIUM"),
            ("java/LegacyCrypto.java", 8, "RSA", "CRITICAL"),
            ("java/LegacyCrypto.java", 9, "EC", "CRITICAL"),
            ("java/LegacyCrypto.java", 10, "MD5", "CRITICAL"),
            ("java/SymmetricCrypto.java", 6, "AES-GCM", "MEDIUM"),
            ("java/MigrationConfig.java", 3, "ML-KEM", "SAFE"),
            ("go/legacy/main.go", 12, "RSA-2048", "CRITICAL"),
            ("go/legacy/main.go", 13, "ECDSA P-256", "CRITICAL"),
            ("go/pqc/main.go", 4, "ML-KEM-768", "SAFE"),
            ("go/symmetric/main.go", 8, "AES", "MEDIUM"),
        })

    def test_language_extras(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "a.py").write_text("import hashlib, ssl\nh = hashlib.new('md5')\nctx = ssl.PROTOCOL_TLSv1_2\n")
            (root / "B.java").write_text('class B { void f() throws Exception {\n'
                                         '  java.security.KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");\n'
                                         '  g.initialize(3072);\n'
                                         '  Signature.getInstance("SHA256withECDSA");\n'
                                         '  Cipher.getInstance("DESede/CBC/PKCS5Padding");\n} }\n')
            (root / "c.go").write_text('package c\nfunc f() { _ = des.NewTripleDESCipher(k); _ = sha256.Sum256(b); _ = tls.VersionTLS12 }\n')
            self.assertEqual(findings(scan_code(root)), {
                ("a.py", 2, "MD5", "CRITICAL"),
                ("a.py", 3, "TLSv1.2", "HIGH"),
                ("B.java", 2, "RSA-3072", "CRITICAL"),
                ("B.java", 4, "ECDSA", "CRITICAL"),
                ("B.java", 5, "3DES", "MEDIUM"),
                ("c.go", 2, "3DES", "MEDIUM"),
                ("c.go", 2, "SHA-256", "SAFE"),
                ("c.go", 2, "TLSv1.2", "HIGH"),
            })


class NegativeTest(unittest.TestCase):
    def test_no_crypto_and_non_crypto_package_json(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            # Library-style names only count when that library is imported in the file.
            (root / "app.js").write_text("// createHash('md5') in a comment\nconst total = add(128, 256);\n"
                                         "const d = sha256(data);\nconst c = new EC('p256');\n")
            (root / "plain.py").write_text("def add(a, b):\n    return a + b\n")
            (root / "package.json").write_text('{"dependencies": {"express": "^4.0.0", "lodash": "^4.0.0"}}')
            (root / "broken").mkdir()
            (root / "broken/package.json").write_text("{not json")
            report = scan_code(root)
            self.assertEqual(report["components"], [])
            self.assertEqual(report["metadata"]["quantumRiskSummary"]["totalFindings"], 0)

    def test_unsupported_files_are_ignored(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "notes.txt").write_text("createHash('md5')\n")
            self.assertEqual(scan_code(Path(folder))["components"], [])


class RuleFilesTest(unittest.TestCase):
    def test_every_rule_is_well_formed(self):
        rulesets = load_rules()
        languages = {language for r in rulesets for language in r["extensions"].values()}
        self.assertGreaterEqual(languages, {"javascript", "typescript", "python", "java", "go"})
        ids = []
        for ruleset in rulesets:
            self.assertTrue(ruleset["extensions"])
            for rule in ruleset["rules"]:
                ids.append(rule["id"])
                self.assertIsInstance(rule["regex"], re.Pattern)
                self.assertTrue("algorithm" in rule or "algorithmMap" in rule or "algorithmPattern" in rule, rule["id"])
        self.assertEqual(len(ids), len(set(ids)), "rule ids must be unique")


class LegacyEntryPointTest(unittest.TestCase):
    def test_scan_repositories_writes_report_file(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / "cbom_code.json"
            scan_repositories(str(ROOT / "test_data/code"), str(out))
            report = json.loads(out.read_text())
            self.assertEqual(len(report["components"]), 13)
            self.assertTrue(all(c["quantumRiskAssessment"]["tier"] in RISKS for c in report["components"]))


if __name__ == "__main__":
    unittest.main()

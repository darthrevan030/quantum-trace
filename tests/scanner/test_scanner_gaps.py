"""Regressions found by hand-checking the Mojaloop scans against the source (sdk-standard-components, auth-service)."""

import tempfile
import unittest
from pathlib import Path

from pipeline.code_scanner import scan_code


def scan(files):
    """Scan a {relative path: text} tree and return {(path, line, algorithm, tier)}."""
    with tempfile.TemporaryDirectory() as folder:
        for name, text in files.items():
            path = Path(folder) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return scan_code(Path(folder))


def found(report):
    return {(c["source"], c["line"], c["cryptoProperties"]["detectedAlgorithm"], c["quantumRiskAssessment"]["tier"])
            for c in report["components"]}


class JwsLibraryTest(unittest.TestCase):
    """sdk-standard-components jwsSigner.js / jwsValidator.js produced no findings at all."""

    def test_algorithm_chosen_by_ternary_assignment(self):
        report = scan({"jwsSigner.js": (
            "const jws = require('jws');\n"
            "class Signer {\n"
            "    constructor(config) {\n"
            "        this.alg = config.signingKey.includes('BEGIN EC ') ? 'ES256' : 'RS256';\n"
            "    }\n"
            "    sign(o) { return jws.sign({ header: { alg: this.alg }, privateKey: o.key }); }\n"
            "}\n")})
        self.assertEqual(found(report), {
            ("jwsSigner.js", 4, "JWT ES256", "CRITICAL"),
            ("jwsSigner.js", 4, "JWT RS256", "CRITICAL"),
        })

    def test_algorithms_passed_through_a_constant(self):
        report = scan({"jwsValidator.js": (
            "const jwt = require('jsonwebtoken');\n"
            "const SIGNATURE_ALGORITHMS = ['RS256', 'ES256'];\n"
            "function validate(token, key) {\n"
            "    return jwt.verify(token, key, {\n"
            "        algorithms: SIGNATURE_ALGORITHMS  // only allow these\n"
            "    });\n"
            "}\n")})
        self.assertEqual(found(report), {
            ("jwsValidator.js", 5, "JWT RS256", "CRITICAL"),
            ("jwsValidator.js", 5, "JWT ES256", "CRITICAL"),
        })

    def test_library_call_with_no_visible_algorithm_is_unknown(self):
        report = scan({"v.js": (
            "const jwt = require('jsonwebtoken');\n"
            "module.exports = (t, k, cfg) => jwt.verify(t, k, { algorithms: cfg.algs });\n")})
        self.assertEqual(found(report), {("v.js", 2, "JWT/JWS call (algorithm not visible)", "UNKNOWN")})

    def test_safe_symmetric_algorithm_stays_safe_with_no_unknown_noise(self):
        report = scan({"s.js": (
            "const jwt = require('jsonwebtoken');\n"
            "module.exports = (p, secret) => jwt.sign(p, secret, { algorithm: 'HS256' });\n")})
        self.assertEqual(found(report), {("s.js", 2, "JWT HS256", "SAFE")})

    def test_object_named_jws_without_the_library_is_ignored(self):
        report = scan({"n.js": "const jws = makeFake();\njws.sign(data);\njws.verify(data);\n"})
        self.assertEqual(found(report), set())

    def test_unresolvable_constant_is_not_invented(self):
        report = scan({"c.js": (
            "const jwt = require('jsonwebtoken');\n"
            "jwt.verify(t, k, { algorithms: IMPORTED_ALGS });\n")})
        self.assertEqual(found(report), {("c.js", 2, "JWT/JWS call (algorithm not visible)", "UNKNOWN")})


class ConstantAlgorithmTest(unittest.TestCase):
    """sdk-standard-components IlpBase.js calls createHash(HASH_ALGORITHM) with a module constant."""

    def test_hash_and_hmac_resolve_a_same_file_constant(self):
        report = scan({"IlpBase.js": (
            "const crypto = require('crypto');\n"
            "const HASH_ALGORITHM = 'sha256';\n"
            "const digest = (d) => crypto.createHash(HASH_ALGORITHM).update(d).digest();\n"
            "const mac = (d, s) => crypto.createHmac(HASH_ALGORITHM, Buffer.from(s, 'ascii')).update(d).digest();\n")})
        self.assertEqual(found(report), {
            ("IlpBase.js", 3, "SHA-256", "SAFE"),
            ("IlpBase.js", 4, "HMAC-SHA-256", "SAFE"),
        })

    def test_constant_is_really_resolved_not_assumed_safe(self):
        report = scan({"old.js": "const LEGACY = \"md5\";\nconst h = crypto.createHash(LEGACY);\n"})
        self.assertEqual(found(report), {("old.js", 2, "MD5", "CRITICAL")})

    def test_unresolvable_identifier_is_unknown(self):
        report = scan({"dyn.js": "function h(algo, d) {\n  return crypto.createHash(algo).update(d);\n}\n"})
        self.assertEqual(found(report), {("dyn.js", 2, "Hash (runtime-selected)", "UNKNOWN")})

    def test_literal_hash_is_not_reported_twice(self):
        report = scan({"lit.js": "const h = crypto.createHash('sha256');\n"})
        self.assertEqual(found(report), {("lit.js", 1, "SHA-256", "SAFE")})


class MojaloopJwsConfigTest(unittest.TestCase):
    """auth-service never constructs a signer; it hands jwsSigningKey to the SDK request classes."""

    def test_signing_key_handed_to_the_sdk_is_reported(self):
        report = scan({"state.ts": (
            "const options = {\n"
            "  jwsSign: config.SHARED.JWS_SIGN,\n"
            "  jwsSigningKey: config.SHARED.JWS_SIGNING_KEY\n"
            "}\n")})
        self.assertEqual(found(report), {("state.ts", 3, "Mojaloop JWS (RS256/ES256)", "CRITICAL")})

    def test_flag_alone_and_commented_key_are_ignored(self):
        report = scan({"off.ts": "const o = { jwsSign: false }\n// jwsSigningKey: 'x'\n"})
        self.assertEqual(found(report), set())


class DuplicateFindingTest(unittest.TestCase):
    """Each generateKeyPairSync('ec', { namedCurve }) was reported on two lines."""

    def test_curve_option_inside_a_keygen_call_is_not_a_second_finding(self):
        report = scan({"k.js": (
            "const kp = crypto.generateKeyPairSync('ec', {\n"
            "  namedCurve: 'secp256k1', // allowed\n"
            "});\n")})
        self.assertEqual(found(report), {("k.js", 1, "EC secp256k1", "CRITICAL")})

    def test_consecutive_keygen_calls_are_both_reported(self):
        report = scan({"k.js": (
            "const a = crypto.generateKeyPairSync('ec', {\n"
            "  namedCurve: 'secp256k1',\n"
            "});\n"
            "const b = crypto.generateKeyPairSync('ec', {\n"
            "  namedCurve: 'secp256k1',\n"
            "});\n")})
        self.assertEqual({line for _, line, _, _ in found(report)}, {1, 4})

    def test_standalone_curve_setting_is_still_reported(self):
        report = scan({"cfg.js": "const options = {\n  namedCurve: 'secp256k1',\n};\n"})
        self.assertEqual(found(report), {("cfg.js", 2, "EC secp256k1", "CRITICAL")})


class ScoreTest(unittest.TestCase):
    """codeQuantumRiskScore counted test fixtures, so auth-service scored 86% on one production signature check."""

    @staticmethod
    def score(files):
        return scan(files)["metadata"]["quantumRiskSummary"]["codeQuantumRiskScore"]

    def test_test_findings_do_not_move_the_score(self):
        files = {"app.js": "crypto.createHash('sha256');\n",
                 "test/a.test.js": "crypto.createHash('md5');\ncrypto.createHash('sha1');\n"}
        self.assertEqual(self.score(files), "0.0%")

    def test_score_is_the_weighted_share_of_production_findings(self):
        files = {"app.js": "crypto.createHash('sha256');\ncrypto.createHash('md5');\n",
                 "test/a.test.js": "crypto.createHash('sha256');\n"}
        self.assertEqual(self.score(files), "50.0%")

    def test_total_findings_still_counts_tests(self):
        files = {"app.js": "crypto.createHash('md5');\n", "test/a.test.js": "crypto.createHash('md5');\n"}
        self.assertEqual(scan(files)["metadata"]["quantumRiskSummary"]["totalFindings"], 2)

    def test_only_test_findings_score_zero_not_a_crash(self):
        self.assertEqual(self.score({"test/a.test.js": "crypto.createHash('md5');\n"}), "0.0%")


if __name__ == "__main__":
    unittest.main()

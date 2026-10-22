import unittest

from pipeline.crypto_catalog import RISKS, classify, classify_name, label, normalize


class NormalizeTest(unittest.TestCase):
    def test_aliases_resolve_to_one_canonical_form(self):
        for name, algorithm, bits in [
            ("aes-256-gcm", "AES", 256),
            ("AES_128_CBC", "AES", 128),
            ("aes192", "AES", 192),
            ("id-aes128-GCM", "AES", 128),
            ("AES-GCM", "AES", None),
            ("des-ede3-cbc", "3DES", None),
            ("DESede", "3DES", None),
            ("TripleDES", "3DES", None),
            ("des-cbc", "DES", None),
            ("rc4", "RC4", None),
            ("bf-cbc", "Blowfish", None),
            ("chacha20-poly1305", "ChaCha20", 256),
            ("sha1", "SHA-1", None),
            ("SHA-256", "SHA-256", None),
            ("sha3-512", "SHA3-512", None),
            ("md5", "MD5", None),
            ("prime256v1", "EC", 256),
            ("secp384r1", "EC", 384),
            ("P-521", "EC", 521),
            ("secp256k1", "EC", 256),
            ("rsa", "RSA", None),
            ("RSA-OAEP", "RSA", None),
            ("rsa2048", "RSA", 2048),
            ("ed25519", "Ed25519", None),
            ("X25519", "X25519", None),
            ("X25519MLKEM768", "X25519MLKEM768", None),
            ("ml-kem-768", "ML-KEM", None),
            ("Kyber1024", "ML-KEM", None),
            ("ML-DSA-65", "ML-DSA", None),
            ("Dilithium3", "ML-DSA", None),
            ("SLH-DSA-SHA2-128s", "SLH-DSA", None),
        ]:
            with self.subTest(name=name):
                info = normalize(name)
                self.assertEqual(info["algorithm"], algorithm)
                self.assertEqual(info["keySizeBits"], bits)

    def test_parameter_sets_are_captured(self):
        self.assertEqual(normalize("ml-kem-768")["parameterSet"], "768")
        self.assertEqual(normalize("Dilithium3")["parameterSet"], "65")
        self.assertEqual(normalize("aes-256-gcm")["mode"], "GCM")

    def test_jwt_algorithm_names(self):
        self.assertEqual(normalize("RS256")["algorithm"], "RSA")
        self.assertEqual(normalize("PS512")["algorithm"], "RSA")
        self.assertEqual(normalize("ES384")["algorithm"], "EC")
        self.assertEqual(normalize("ES384")["keySizeBits"], 384)
        self.assertEqual(normalize("HS256")["algorithm"], "HMAC-SHA-256")
        self.assertEqual(normalize("EdDSA")["algorithm"], "Ed25519")

    def test_unrecognised_names_are_not_guessed(self):
        for name in ["", None, "banana", "aes-999", "sha-7", "MLKEM999"]:
            with self.subTest(name=name):
                self.assertIsNone(normalize(name)["algorithm"])


class ClassifyTest(unittest.TestCase):
    def assertRisk(self, expected, *args, **kwargs):
        result = classify(*args, **kwargs)
        self.assertEqual(result["risk"], expected, result)
        self.assertIn(result["risk"], RISKS)
        self.assertIsInstance(result["reason"], str)
        self.assertTrue(result["reason"])
        self.assertIsInstance(result["threat"], str)
        return result

    def test_shor_vulnerable_asymmetric_is_critical_at_any_size(self):
        for algorithm in ["RSA", "DSA", "DH", "EC", "ECDSA", "ECDH", "X25519", "X448", "Ed25519", "Ed448"]:
            for bits in [None, 1024, 4096]:
                with self.subTest(algorithm=algorithm, bits=bits):
                    result = self.assertRisk("CRITICAL", algorithm, key_bits=bits)
                    self.assertEqual(result["threat"], "Shor")

    def test_signature_and_key_exchange_get_different_migrations(self):
        signing = classify("RSA", purpose="signature")
        exchange = classify("RSA", purpose="keyExchange")
        self.assertIn("ML-DSA", signing["suggestion"])
        self.assertEqual(signing["nistStandard"], "FIPS 204 / 205")
        self.assertIn("ML-KEM", exchange["suggestion"])
        self.assertEqual(exchange["nistStandard"], "FIPS 203")

    def test_aes_depends_on_key_size(self):
        self.assertRisk("SAFE", "AES", key_bits=256)
        self.assertRisk("MEDIUM", "AES", key_bits=192)
        self.assertRisk("MEDIUM", "AES", key_bits=128)
        self.assertRisk("UNKNOWN", "AES", key_bits=512)
        self.assertRisk("UNKNOWN", "AES", key_bits=True)

    def test_missing_parameters_strict_vs_call_site(self):
        # Structured evidence (network): a missing size is a data gap.
        self.assertRisk("UNKNOWN", "AES", require_parameters=True)
        self.assertRisk("UNKNOWN", "ML-DSA", require_parameters=True)
        self.assertRisk("SAFE", "ML-DSA", parameter_set="65", require_parameters=True)
        # Code call sites: rate the weakest variant the algorithm allows.
        result = self.assertRisk("MEDIUM", "AES")
        self.assertIn("not visible", result["reason"])
        self.assertRisk("SAFE", "ML-KEM")

    def test_classically_broken_primitives(self):
        for algorithm in ["DES", "RC4", "RC2", "MD5", "MD4", "NONE"]:
            with self.subTest(algorithm=algorithm):
                self.assertRisk("CRITICAL", algorithm)

    def test_policy_rated_legacy_primitives(self):
        for algorithm in ["SHA-1", "3DES", "Blowfish"]:
            with self.subTest(algorithm=algorithm):
                self.assertRisk("MEDIUM", algorithm)

    def test_hashes_and_kdfs(self):
        for algorithm in ["SHA-256", "SHA-384", "SHA-512", "SHA3-256", "BLAKE2b", "HMAC-SHA-256", "PBKDF2", "scrypt", "Argon2", "bcrypt", "HKDF"]:
            with self.subTest(algorithm=algorithm):
                self.assertRisk("SAFE", algorithm)
        self.assertRisk("MEDIUM", "HMAC-SHA-1")
        self.assertRisk("CRITICAL", "HMAC-MD5")

    def test_post_quantum_and_hybrids_are_safe(self):
        for algorithm in ["ML-KEM", "ML-DSA", "SLH-DSA", "FN-DSA", "XMSS", "LMS", "X25519MLKEM768", "SecP256r1MLKEM768"]:
            with self.subTest(algorithm=algorithm):
                self.assertEqual(self.assertRisk("SAFE", algorithm)["threat"], "None")

    def test_protocol_versions(self):
        for version in ["SSLv3", "TLSv1", "TLSv1.1"]:
            with self.subTest(version=version):
                self.assertRisk("CRITICAL", version)
        self.assertRisk("HIGH", "TLSv1.2")
        self.assertRisk("UNKNOWN", "TLSv1.3")

    def test_unknown_algorithm_is_unknown_not_guessed(self):
        self.assertRisk("UNKNOWN", "banana")
        self.assertRisk("UNKNOWN", None)

    def test_sha1_rating_is_identical_whatever_the_spelling(self):
        # One catalog means one answer: code and network can no longer disagree.
        risks = {classify_name(name)["risk"] for name in ["sha1", "SHA-1", "SHA1", "sha-1"]}
        self.assertEqual(risks, {"MEDIUM"})


class ClassifyNameTest(unittest.TestCase):
    def test_name_with_embedded_size_is_classified_by_that_size(self):
        self.assertEqual(classify_name("aes-256-gcm")["risk"], "SAFE")
        self.assertEqual(classify_name("aes-128-cbc")["risk"], "MEDIUM")
        self.assertEqual(classify_name("RS256")["risk"], "CRITICAL")
        self.assertEqual(classify_name("HS256")["risk"], "SAFE")

    def test_result_carries_canonical_label(self):
        self.assertEqual(classify_name("aes-256-gcm")["algorithm"], "AES-256-GCM")
        self.assertEqual(classify_name("prime256v1")["algorithm"], "EC P-256")
        self.assertEqual(classify_name("rsa", key_bits=2048)["algorithm"], "RSA-2048")
        self.assertEqual(classify_name("banana")["algorithm"], "banana")

    def test_label(self):
        self.assertEqual(label({"algorithm": "ML-KEM", "parameterSet": "768"}), "ML-KEM-768")
        self.assertEqual(label({"algorithm": "SHA-1"}), "SHA-1")


if __name__ == "__main__":
    unittest.main()

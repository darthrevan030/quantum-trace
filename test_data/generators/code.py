"""Generate the Python/Java/Go code fixtures in test_data/code/, then verify them against the scanner.

Run from the repository root: uv run python -m test_data.generators.code
"""

from test_data.generators.common import TEST_DATA, verify, write

FIXTURE = TEST_DATA / "code"
EXPECTED_COUNTS = {"CRITICAL": 6, "MEDIUM": 4, "SAFE": 3}

FILES = {
    'python/legacy/main.py': '''
        # Static analysis fixture only; deliberately includes legacy cryptography.
        from Crypto.PublicKey import RSA
        import hashlib

        def legacy_credentials():
            key = RSA.generate(2048)
            digest = hashlib.sha1()
            return key, digest
    ''',
    'python/symmetric/main.py': '''
        # Static fixture: the current regex scanner does not infer this key length.
        from cryptography.hazmat.primitives.ciphers import algorithms

        def symmetric_cipher(key: bytes):
            return algorithms.AES(key)
    ''',
    'python/pqc_config.py': '''
        # A declared migration target, not an implementation of cryptography.
        migration_target = {"key_exchange": "mlkem768"}
    ''',
    'python/no_crypto.py': '''
        # Negative control: should produce no cryptographic findings.
        def add(left, right):
            return left + right
    ''',
    'java/LegacyCrypto.java': '''
        // Static analysis fixture; do not use these choices as security guidance.
        import java.security.KeyPairGenerator;
        import java.security.MessageDigest;
        import java.security.GeneralSecurityException;

        public class LegacyCrypto {
            public void examples() throws GeneralSecurityException {
                KeyPairGenerator.getInstance("RSA");
                KeyPairGenerator.getInstance("EC");
                MessageDigest.getInstance("MD5");
            }
        }
    ''',
    'java/SymmetricCrypto.java': '''
        import javax.crypto.Cipher;
        import java.security.GeneralSecurityException;

        public class SymmetricCrypto {
            public Cipher example() throws GeneralSecurityException {
                return Cipher.getInstance("AES/GCM/NoPadding");
            }
        }
    ''',
    'java/MigrationConfig.java': '''
        // A declared migration target; no encryption takes place here.
        public class MigrationConfig {
            public static final String TARGET = "MLKEM";
        }
    ''',
    'go/legacy/main.go': '''
        // Static analysis fixture only.
        package main

        import (
            "crypto/ecdsa"
            "crypto/elliptic"
            "crypto/rand"
            "crypto/rsa"
        )

        func main() {
            _, _ = rsa.GenerateKey(rand.Reader, 2048)
            _, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
        }
    ''',
    'go/symmetric/main.go': '''
        // Static fixture with a dummy key; never a production configuration.
        package main

        import "crypto/aes"

        func main() {
            key := make([]byte, 16)
            _, _ = aes.NewCipher(key)
        }
    ''',
    'go/pqc/main.go': '''
        // A declared migration target; no cryptography is implemented here.
        package main

        const target = "mlkem768"

        func main() { println(target) }
    ''',
}


def generate(target=FIXTURE):
    for path, content in FILES.items():
        write(target, path, content)


if __name__ == "__main__":
    generate()
    verify("code", FIXTURE, EXPECTED_COUNTS)

"""Report cryptographic libraries declared in dependency manifests."""

import json
import re

from pipeline.crypto_catalog import classify

# Package -> the algorithm family it implies, or None when it depends on how it is called.
NPM_LIBRARIES = {
    "@noble/post-quantum": "ML-KEM",
    "crystals-kyber": "Kyber",
    "crystals-kyber-js": "Kyber",
    "mlkem": "ML-KEM",
    "node-rsa": "RSA",
    "selfsigned": "RSA",
    "elliptic": "EC",
    "@noble/curves": "EC",
    "secp256k1": "EC",
    "tweetnacl": "X25519",
    "bcrypt": "bcrypt",
    "bcryptjs": "bcrypt",
    "argon2": "Argon2",
    "crypto-js": None,
    "node-forge": None,
    "jsonwebtoken": None,
    "jose": None,
    "node-jose": None,
    "jsrsasign": None,
    "jwk-to-pem": None,
    "openpgp": None,
    "libsodium-wrappers": None,
    "sodium-native": None,
    "@noble/hashes": None,
    "@noble/ciphers": None,
    "@peculiar/webcrypto": None,
    "@peculiar/x509": None,
    "pem": None,
    "ssh2": None,
    "@mojaloop/sdk-standard-components": None,
}
SECTIONS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
# Pins for transitive dependencies: the library still ships, even if nothing imports it directly.
PIN_SECTIONS = ("overrides", "resolutions")


def _packages(value):
    """Package names in a pin section, including nested override scopes."""
    if not isinstance(value, dict):
        return
    for name, nested in value.items():
        yield name.rsplit("@", 1)[0] if name.startswith("@") and name.count("@") > 1 else name
        yield from _packages(nested)


def _component(path, relative, line, snippet, package, algorithm, section):
    if algorithm:
        assessment = classify(algorithm)
        label = f"{algorithm} via {package}"
    else:
        assessment = {
            "risk": "UNKNOWN",
            "threat": "Depends on usage",
            "reason": "Cryptographic library dependency; its quantum safety depends on the algorithms "
            "called, which appear as separate code findings.",
            "suggestion": "Review how this library is used.",
        }
        label = f"{package} (crypto library)"
    return {
        "type": "application-code",
        "name": f"{path.name}:{line}",
        "source": relative,
        "line": line,
        "codeSnippet": snippet[:160],
        "cryptoProperties": {
            "assetType": "dependency",
            "language": "npm",
            "detectedAlgorithm": label,
            # A declared library is not evidence of how it is used, so it never feeds the purpose charts.
            "primitive": None,
            "library": package,
            "dependencySection": section,
            "keySize": None,
            "keySizeBits": None,
        },
        "quantumRiskAssessment": {"tier": assessment["risk"], **{k: v for k, v in assessment.items() if k != "risk"}},
    }


def scan_package_json(path, relative):
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        manifest = json.loads(text)
    except ValueError:
        return []
    if not isinstance(manifest, dict):
        return []
    lines = text.splitlines()
    components, reported = [], set()
    for section in SECTIONS + PIN_SECTIONS:
        packages = manifest.get(section) if section in SECTIONS else list(_packages(manifest.get(section)))
        if not isinstance(packages, (dict, list)):
            continue
        heading = re.compile(r'"' + re.escape(section) + r'"\s*:')
        start = next((number for number, content in enumerate(lines) if heading.search(content)), 0)
        for package in packages:
            if package not in NPM_LIBRARIES or package in reported:
                continue
            reported.add(package)
            pattern = re.compile(r'"' + re.escape(package) + r'(?:@[^"]*)?"\s*:')
            line = next((number for number, content in enumerate(lines[start:], start + 1) if pattern.search(content)), 1)
            components.append(_component(path, relative, line, lines[line - 1].strip(), package,
                                         NPM_LIBRARIES[package], section))
    return components


MANIFESTS = {"package.json": scan_package_json}

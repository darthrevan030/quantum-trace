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


def _component(path, relative, line, snippet, package, algorithm, section, version=None, dependency_path=None):
    pinned = f"{package}@{version}" if version else package
    if algorithm:
        assessment = classify(algorithm)
        label = f"{algorithm} via {pinned}"
    else:
        assessment = {
            "risk": "UNKNOWN",
            "threat": "Depends on usage",
            "reason": "Cryptographic library dependency; its quantum safety depends on the algorithms "
            "called, which appear as separate code findings.",
            "suggestion": "Review how this library is used.",
        }
        label = f"{pinned} (crypto library)"
    extra = {key: value for key, value in (("version", version), ("dependencyPath", dependency_path)) if value}
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
            **extra,
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


LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json")
LOCK_DEPENDENCY_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")
KEY_LINE = re.compile(r'^\s*"([^"]+)"\s*:\s*\{')


def _lock_nodes(lock, sibling):
    """Return (nodes, roots) for a lockfile.

    nodes maps an install path ("node_modules/a/node_modules/b") to {name, version, dev, deps}.
    roots is the set of directly declared package names, or None when the lockfile cannot say.
    """
    nodes, roots = {}, None
    packages = lock.get("packages")
    if isinstance(packages, dict):
        roots = set()
        for key, entry in packages.items():
            if not isinstance(entry, dict) or entry.get("link"):
                continue
            declared = [name for field in LOCK_DEPENDENCY_FIELDS + ("devDependencies",)
                        for name in (entry.get(field) or {})]
            if "node_modules/" not in key:  # The root project ("") and workspace packages.
                roots.update(declared)
                continue
            nodes[key] = {"name": entry.get("name") or key.rsplit("node_modules/", 1)[1], "version": entry.get("version"),
                          "dev": bool(entry.get("dev")),
                          "deps": [name for field in LOCK_DEPENDENCY_FIELDS for name in (entry.get(field) or {})]}
    elif isinstance(lock.get("dependencies"), dict):
        def flatten(dependencies, prefix):
            for name, entry in dependencies.items():
                if not isinstance(entry, dict):
                    continue
                key = f"{prefix}node_modules/{name}"
                nodes[key] = {"name": name, "version": entry.get("version"), "dev": bool(entry.get("dev")),
                              "deps": list(entry.get("requires") or {})}
                if isinstance(entry.get("dependencies"), dict):
                    flatten(entry["dependencies"], key + "/")

        flatten(lock["dependencies"], "")
        if isinstance(sibling, dict):
            roots = {name for field in SECTIONS for name in (sibling.get(field) or {})}
    return nodes, roots


def _resolve(nodes, parent, name):
    """The install path Node would load `name` from when required by the package at `parent`."""
    while True:
        candidate = f"{parent}/node_modules/{name}" if parent else f"node_modules/{name}"
        if candidate in nodes:
            return candidate
        if not parent:
            return None
        cut = parent.rfind("/node_modules/")
        parent = parent[:cut] if cut != -1 else ""


def _reach(nodes, roots):
    """Breadth-first walk from the declared packages; returns {install path: parent path, None for direct}."""
    parents, queue = {}, []
    for name in sorted(roots):
        key = _resolve(nodes, "", name)
        if key and key not in parents:
            parents[key] = None
            queue.append(key)
    while queue:
        key = queue.pop(0)
        for name in nodes[key]["deps"]:
            child = _resolve(nodes, key, name)
            if child and child not in parents:
                parents[child] = key
                queue.append(child)
    return parents


def _chain(nodes, parents, key):
    names = []
    while key is not None:
        names.append(nodes[key]["name"])
        key = parents[key]
    return names[::-1]


def scan_package_lock(path, relative):
    """Crypto libraries a lockfile resolves, including ones only pulled in transitively.

    Direct dependencies are left to package.json when it sits beside the lockfile. A transitive library
    is rated UNKNOWN: the lockfile shows it ships, not that the application calls it.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        lock = json.loads(text)
    except ValueError:
        return []
    if not isinstance(lock, dict):
        return []
    sibling = None
    if path.with_name("package.json").is_file():
        try:
            sibling = json.loads(path.with_name("package.json").read_text(encoding="utf-8", errors="ignore"))
        except ValueError:
            pass
    nodes, roots = _lock_nodes(lock, sibling)
    parents = _reach(nodes, roots) if roots is not None else {}
    lines = text.splitlines()
    first_line = {}
    for number, content in enumerate(lines, 1):
        found = KEY_LINE.match(content)
        if found:
            first_line.setdefault(found[1], number)

    installs = {}
    for key in sorted(nodes, key=lambda item: (item.count("node_modules/"), item)):
        node = nodes[key]
        if node["name"] in NPM_LIBRARIES and node["version"]:
            installs.setdefault((node["name"], node["version"]), []).append(key)
    components = []
    for (package, version), keys in installs.items():
        direct = any(key in parents and parents[key] is None for key in keys)
        if direct and sibling is not None:
            continue
        key = next((item for item in keys if item in parents and parents[item] is None), keys[0])
        line = first_line.get(key) or first_line.get(package) or 1
        snippet = lines[line - 1].strip() if line <= len(lines) else ""
        if roots is None:
            section, algorithm, chain = "lockfile", None, None
        elif direct:
            section, algorithm, chain = "dependencies", NPM_LIBRARIES[package], None
        else:
            section, algorithm = "transitive", None
            chain = _chain(nodes, parents, key) if key in parents else None
        component = _component(path, relative, line, snippet, package, algorithm, section, version, chain)
        if section != "dependencies":
            component["cryptoProperties"]["devOnly"] = all(nodes[item]["dev"] for item in keys)
        if chain:
            component["quantumRiskAssessment"]["reason"] = (
                f"Transitive dependency ({' > '.join(chain)}): the lockfile shows the library ships, "
                "not that the application calls its cryptography.")
        components.append(component)
    return sorted(components, key=lambda item: item["line"])


MANIFESTS = {"package.json": scan_package_json, **{name: scan_package_lock for name in LOCKFILES}}

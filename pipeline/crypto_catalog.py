"""Single source of truth for whether a cryptographic algorithm is quantum safe.

Scanners only detect algorithms; they call normalize()/classify() here so the same
algorithm always receives the same rating, whichever scanner found it.
"""

import re

RISKS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE", "UNKNOWN")

POLICY = {
    "primary": "pdfs/inspiring_solutions.pdf",
    "keySizeReference": "pdfs/nist_standards.pdf",
    "sha1Resolution": "SHA-1 is Medium per the challenge brief; the reference matrix instead rates it Critical.",
    "missingParameters": "Structured evidence with a missing key size or parameter set is UNKNOWN; "
    "a code call site that hides it is rated as the weakest variant the algorithm allows.",
}

# Broken by Shor's algorithm whatever the key size.
SHOR = {"RSA", "DSA", "DH", "EC", "ECDSA", "ECDH", "X25519", "X448", "Ed25519", "Ed448", "ElGamal"}
SIGNATURE_ONLY = {"DSA", "ECDSA", "Ed25519", "Ed448"}
KEY_EXCHANGE_ONLY = {"DH", "ECDH", "X25519", "X448"}
# Broken by classical cryptanalysis; a quantum computer is not needed.
BROKEN = {
    "DES": "Migrate to AES-256 with an authenticated encryption mode.",
    "RC4": "Migrate to AES-256-GCM or ChaCha20-Poly1305.",
    "RC2": "Migrate to AES-256 with an authenticated encryption mode.",
    "MD5": "Migrate to a SHA-256 or stronger hash-based construction.",
    "MD4": "Migrate to a SHA-256 or stronger hash-based construction.",
    "NONE": "Sign tokens with ML-DSA, or at minimum HMAC-SHA-256.",
}
# Legacy 64-bit-block ciphers, rated Medium by the challenge brief.
LEGACY_SYMMETRIC = {"3DES", "Blowfish", "CAST5", "IDEA"}
SYMMETRIC_SIZES = {
    "AES": (128, 192, 256),
    "Camellia": (128, 192, 256),
    "ARIA": (128, 192, 256),
    "SEED": (128,),
    "SM4": (128,),
    "ChaCha20": (256,),
    "XSalsa20": (256,),
    "Salsa20": (256,),
}
HASHES = {
    "SHA-1": "MEDIUM",
    "RIPEMD-160": "MEDIUM",
    "SHA-224": "LOW",
    "SHA3-224": "LOW",
    "SHA-256": "SAFE",
    "SHA-384": "SAFE",
    "SHA-512": "SAFE",
    "SHA-512/256": "SAFE",
    "SHA3-256": "SAFE",
    "SHA3-384": "SAFE",
    "SHA3-512": "SAFE",
    "SHAKE128": "SAFE",
    "SHAKE256": "SAFE",
    "BLAKE2b": "SAFE",
    "BLAKE2s": "SAFE",
    "BLAKE3": "SAFE",
    "SM3": "SAFE",
}
KDFS = {"PBKDF2", "scrypt", "Argon2", "bcrypt", "HKDF"}
PQC = {
    "ML-KEM": "FIPS 203",
    "ML-DSA": "FIPS 204",
    "SLH-DSA": "FIPS 205",
    "FN-DSA": "FIPS 206 (draft)",
    "XMSS": "NIST SP 800-208",
    "LMS": "NIST SP 800-208",
    "FrodoKEM": None,
    "HQC": None,
    "Classic-McEliece": None,
}
PQC_PARAMETERS = {"ML-KEM": {"512", "768", "1024"}, "ML-DSA": {"44", "65", "87"}}
# Only recognized combined constructions get a hybrid assessment.
MLKEM_GROUPS = {
    "MLKEM512",
    "MLKEM768",
    "MLKEM1024",
    "SecP256r1MLKEM512",
    "MLKEM512X25519",
    "SecP256r1MLKEM768",
    "X25519MLKEM768",
    "SecP384r1MLKEM1024",
    "curveSM2MLKEM768",
}
PROTOCOLS = {
    "SSLv2": ("CRITICAL", "Classical", "Obsolete protocol broken by classical attacks."),
    "SSLv3": ("CRITICAL", "Classical", "Obsolete protocol broken by classical attacks (POODLE)."),
    "TLSv1": ("CRITICAL", "Classical", "Deprecated by RFC 8996; relies on obsolete constructions."),
    "TLSv1.1": ("CRITICAL", "Classical", "Deprecated by RFC 8996; relies on obsolete constructions."),
    "TLSv1.2": ("HIGH", "Shor", "TLS 1.2 has no standardized post-quantum key exchange; sessions rely on classical (EC)DHE or RSA."),
    "TLSv1.3": ("UNKNOWN", "Depends on group", "Quantum safety depends on the negotiated group; require X25519MLKEM768 or another ML-KEM hybrid."),
}
DIRECT = {"NONE"}

MODES = r"(ecb|cbc|cfb1|cfb8|cfb|ofb|ctr|gcm|ccm|ocb|xts|siv|wrap|kw)?"
CURVES = {"192": "P-192", "224": "P-224", "256": "P-256", "384": "P-384", "521": "P-521"}
DILITHIUM = {"2": "44", "3": "65", "5": "87"}
# Pure ML-KEM groups normalize to ML-KEM with a parameter set; only combinations are hybrids.
HYBRIDS = {group.lower(): group for group in MLKEM_GROUPS if not re.fullmatch(r"MLKEM\d+", group)}


def _sized(algorithm, sizes):
    def build(match):
        bits = match.group(1)
        if bits and int(bits) not in sizes:
            return None
        mode = match.group(2) if match.re.groups >= 2 else None
        return {"algorithm": algorithm, "keySizeBits": int(bits) if bits else None, "mode": mode.upper() if mode else None}

    return build


def _fixed(algorithm, bits=None):
    return lambda match: {"algorithm": algorithm, "keySizeBits": bits}


def _curve(match):
    bits, suffix = match.group(2), match.group(3) or ""
    curve = f"secp{bits}k1" if suffix == "k1" else CURVES[bits]
    return {"algorithm": "EC", "keySizeBits": int(bits), "curve": curve}


def _pqc(algorithm, valid, rename=None):
    def build(match):
        parameter = match.group(1)
        if rename and parameter:
            parameter = rename.get(parameter)
            if parameter is None:
                return None
        if parameter and parameter not in valid:
            return None
        return {"algorithm": algorithm, "parameterSet": parameter}

    return build


def _hmac(match):
    inner = normalize(match.group(1))["algorithm"]
    return {"algorithm": f"HMAC-{inner}"} if inner in HASHES or inner in BROKEN else None


# Patterns run against the lower-case name with every non-alphanumeric removed.
PATTERNS = [
    (r"aes(\d+)?" + MODES + r"(?:hmacsha\d+|pad)?", _sized("AES", (128, 192, 256))),
    (r"camellia(\d+)?" + MODES, _sized("Camellia", (128, 192, 256))),
    (r"aria(\d+)?" + MODES, _sized("ARIA", (128, 192, 256))),
    (r"sm4()" + MODES, lambda m: {"algorithm": "SM4", "keySizeBits": 128}),
    (r"seed()" + MODES, lambda m: {"algorithm": "SEED", "keySizeBits": 128}),
    (r"x?chacha20(?:poly1305)?", _fixed("ChaCha20", 256)),
    (r"xsalsa20(?:poly1305)?", _fixed("XSalsa20", 256)),
    (r"salsa20", _fixed("Salsa20", 256)),
    (r"(?:desede3?|des3|tripledes|3des)" + MODES, _fixed("3DES")),
    (r"desx?" + MODES, _fixed("DES")),
    (r"(?:a?rc4|arcfour)(?:\d+|hmacmd5)?", _fixed("RC4")),
    (r"a?rc2(?:\d+)?" + MODES, _fixed("RC2")),
    (r"(?:bf|blowfish)" + MODES, _fixed("Blowfish")),
    (r"cast5?(?:128)?" + MODES, _fixed("CAST5")),
    (r"idea" + MODES, _fixed("IDEA")),
    (r"sha1", _fixed("SHA-1")),
    (r"sha2?(224|256|384|512)", lambda m: {"algorithm": f"SHA-{m.group(1)}"}),
    (r"sha512256", _fixed("SHA-512/256")),
    (r"sha3(224|256|384|512)", lambda m: {"algorithm": f"SHA3-{m.group(1)}"}),
    (r"shake(128|256)", lambda m: {"algorithm": f"SHAKE{m.group(1)}"}),
    (r"md5", _fixed("MD5")),
    (r"md4", _fixed("MD4")),
    (r"ripemd160", _fixed("RIPEMD-160")),
    (r"blake2b(?:512)?", _fixed("BLAKE2b")),
    (r"blake2s(?:256)?", _fixed("BLAKE2s")),
    (r"blake3", _fixed("BLAKE3")),
    (r"sm3", _fixed("SM3")),
    (r"hmac(\w+)", _hmac),
    (r"hs(256|384|512)", lambda m: {"algorithm": f"HMAC-SHA-{m.group(1)}"}),
    (r"(?:rs|ps)(256|384|512)", _fixed("RSA")),
    (r"es(256|384|512)", lambda m: {"algorithm": "EC", "keySizeBits": {"512": 521}.get(m.group(1), int(m.group(1))),
                                    "curve": CURVES[{"512": "521"}.get(m.group(1), m.group(1))]}),
    (r"eddsa", _fixed("Ed25519")),
    (r"rsa(\d{3,5})?\w*", lambda m: {"algorithm": "RSA", "keySizeBits": int(m.group(1)) if m.group(1) else None}),
    (r"ecdsa\w*", _fixed("ECDSA")),
    (r"ecdhe?", _fixed("ECDH")),
    (r"dsa(\d{3,5})?", lambda m: {"algorithm": "DSA", "keySizeBits": int(m.group(1)) if m.group(1) else None}),
    (r"(?:dh|dhe|ffdhe|diffiehellman|modp)(\d{3,5})?", lambda m: {"algorithm": "DH", "keySizeBits": int(m.group(1)) if m.group(1) else None}),
    (r"(secp|prime|p|nistp)(192|224|256|384|521)(r1|v1|k1)?", _curve),
    (r"brainpoolp(256|384|512)[rt]1", lambda m: {"algorithm": "EC", "keySizeBits": int(m.group(1)), "curve": f"brainpoolP{m.group(1)}r1"}),
    (r"ec", _fixed("EC")),
    (r"(?:x25519|curve25519)", _fixed("X25519")),
    (r"elgamal", _fixed("ElGamal")),
    (r"(?:x448|curve448)", _fixed("X448")),
    (r"ed25519", _fixed("Ed25519")),
    (r"ed448", _fixed("Ed448")),
    (r"(?:mlkem|kyber)(\d+)?", _pqc("ML-KEM", PQC_PARAMETERS["ML-KEM"])),
    (r"mldsa(\d+)?", _pqc("ML-DSA", PQC_PARAMETERS["ML-DSA"])),
    (r"dilithium(\d)?", _pqc("ML-DSA", PQC_PARAMETERS["ML-DSA"], DILITHIUM)),
    (r"(?:slhdsa|sphincs)\w*", _fixed("SLH-DSA")),
    (r"(?:fndsa|falcon)(?:512|1024)?", _fixed("FN-DSA")),
    (r"xmss\w*", _fixed("XMSS")),
    (r"(?:hss)?lms\w*", _fixed("LMS")),
    (r"frodokem\w*", _fixed("FrodoKEM")),
    (r"hqc\w*", _fixed("HQC")),
    (r"(?:classic)?mceliece\w*", _fixed("Classic-McEliece")),
    (r"pbkdf2\w*", _fixed("PBKDF2")),
    (r"scrypt", _fixed("scrypt")),
    (r"argon2\w*", _fixed("Argon2")),
    (r"bcrypt", _fixed("bcrypt")),
    (r"hkdf\w*", _fixed("HKDF")),
    (r"sslv?([23])", lambda m: {"algorithm": f"SSLv{m.group(1)}"}),
    (r"tlsv?1([0-3])?", lambda m: {"algorithm": "TLSv1" if m.group(1) in (None, "0") else f"TLSv1.{m.group(1)}"}),
]
PATTERNS = [(re.compile(pattern), build) for pattern, build in PATTERNS]


def normalize(name):
    """Map any spelling of an algorithm to {algorithm, keySizeBits, mode, parameterSet}.

    The algorithm is None when the name is not recognized; it is never guessed.
    """
    info = {"algorithm": None, "keySizeBits": None, "mode": None, "parameterSet": None}
    if not isinstance(name, str):
        return info
    compact = re.sub(r"[^a-z0-9]", "", re.sub(r"^id-", "", name.strip().lower()))
    if compact in HYBRIDS:
        return {**info, "algorithm": HYBRIDS[compact]}
    for pattern, build in PATTERNS:
        match = pattern.fullmatch(compact)
        if match:
            found = build(match)
            if found:
                info.update(found)
            return info
    return info


def label(info):
    """Readable name for a normalized algorithm, e.g. AES-256-GCM, RSA-2048, EC P-256."""
    algorithm, bits = info.get("algorithm"), info.get("keySizeBits")
    if algorithm in ("EC", "ECDSA", "ECDH") and info.get("curve"):
        return f"{algorithm} {info['curve']}"
    if info.get("parameterSet"):
        return f"{algorithm}-{info['parameterSet']}"
    name = algorithm
    if bits and algorithm in {"AES", "Camellia", "ARIA", "RSA", "DSA", "DH"}:
        name = f"{algorithm}-{bits}"
    if info.get("mode"):
        name = f"{name}-{info['mode']}"
    return name


def finding(risk, threat, reason, suggestion=None, standard=None):
    result = {"risk": risk, "threat": threat, "reason": reason}
    if suggestion:
        result["suggestion"] = suggestion
    if standard:
        result["nistStandard"] = standard
    return result


def _shor(algorithm, purpose):
    signing = purpose in ("signature", "authentication") or (purpose is None and algorithm in SIGNATURE_ONLY)
    exchange = purpose in ("keyExchange", "encryption") or (purpose is None and algorithm in KEY_EXCHANGE_ONLY)
    if signing:
        return finding("CRITICAL", "Shor", "Vulnerable to Shor's algorithm regardless of key size.",
                       "Migrate signatures to ML-DSA or SLH-DSA.", "FIPS 204 / 205")
    if exchange:
        return finding("CRITICAL", "Shor", "Vulnerable to Shor's algorithm regardless of key size.",
                       "Migrate key exchange to ML-KEM or a supported ML-KEM hybrid.", "FIPS 203")
    return finding("CRITICAL", "Shor", "Vulnerable to Shor's algorithm regardless of key size.",
                   "Migrate signatures to ML-DSA or SLH-DSA, and key exchange or encryption to ML-KEM.",
                   "FIPS 203 / 204 / 205")


def _symmetric(algorithm, bits, require_parameters):
    sizes = SYMMETRIC_SIZES[algorithm]
    note = ""
    if bits is None:
        if require_parameters:
            return finding("UNKNOWN", "Grover", f"{algorithm} key size is missing or invalid.")
        bits = min(sizes)
        note = f"Key size not visible at the call site; rated as {algorithm}-{bits} until verified. "
    elif type(bits) is not int or bits not in sizes:
        return finding("UNKNOWN", "Grover", f"{algorithm} key size is missing or invalid.")
    if bits >= 256:
        return finding("SAFE", "Grover",
                       note + f"The matrix's generic quantum key-search model gives approximately {bits // 2}-bit security.",
                       f"Keep {algorithm} with 256-bit keys.")
    return finding("MEDIUM", "Grover",
                   note + f"The matrix's generic quantum key-search model gives approximately {bits // 2}-bit security.",
                   "Increase the encryption key size to 256 bits (e.g. AES-256).")


def _pqc_finding(algorithm, parameter, require_parameters):
    standard = PQC[algorithm]
    valid = PQC_PARAMETERS.get(algorithm)
    if valid and parameter is not None:
        if str(parameter) not in valid:
            return finding("UNKNOWN", "Unknown", f"Unrecognized {algorithm} parameter set {parameter}.")
        return finding("SAFE", "None", "Recognized NIST post-quantum parameter set.", standard=standard)
    if valid and require_parameters:
        return finding("UNKNOWN", "Unknown", f"{algorithm} parameter set is not recorded.")
    return finding("SAFE", "None",
                   "Post-quantum algorithm resistant to Shor's and Grover's algorithms"
                   + ("; parameter set not visible, every standardized set is quantum resistant." if valid else "."),
                   standard=standard)


def classify(algorithm, key_bits=None, purpose=None, parameter_set=None, require_parameters=False):
    """Rate one algorithm: {risk, threat, reason, suggestion?, nistStandard?}.

    purpose: "signature"/"authentication", "keyExchange"/"encryption", "hash", or None.
    require_parameters: True for structured evidence where a missing size is a data gap.
    """
    info = normalize(algorithm)
    name = info["algorithm"] or (algorithm.upper() if isinstance(algorithm, str) and algorithm.upper() in DIRECT else None)
    bits = key_bits if key_bits is not None else info["keySizeBits"]
    parameter = parameter_set if parameter_set is not None else info["parameterSet"]
    if name is None:
        return finding("UNKNOWN", "Unknown", "Algorithm, parameters, or classification rule are unavailable.")
    if name in SHOR:
        return _shor(name, purpose)
    if name in MLKEM_GROUPS:
        return finding("SAFE", "None", "Recognized ML-KEM group; a hybrid is assessed as a combined construction.",
                       standard="FIPS 203 (ML-KEM component)")
    if name in PQC:
        return _pqc_finding(name, parameter, require_parameters)
    if name in SYMMETRIC_SIZES:
        return _symmetric(name, bits, require_parameters)
    if name in BROKEN:
        return finding("CRITICAL", "Classical", "Broken by classical cryptanalysis; no quantum computer is needed.",
                       BROKEN[name])
    if name in LEGACY_SYMMETRIC:
        return finding("MEDIUM", "Grover / Classical", "Legacy 64-bit-block cipher rated Medium by the challenge brief.",
                       "Migrate to AES-256 with an authenticated encryption mode.")
    if name == "SHA-1":
        return finding("MEDIUM", "Grover / Classical",
                       "SHA-1 is Medium under the challenge brief's quantum risk tiers. "
                       "The reference matrix rates it Critical for classical collision weaknesses.",
                       "Migrate to a SHA-256 or stronger hash-based construction.")
    if name in HASHES:
        risk = HASHES[name]
        return finding(risk, "Grover",
                       "Hash output size keeps adequate security against Grover's algorithm."
                       if risk == "SAFE" else "Hash output is short or legacy; quantum search reduces its margin.",
                       None if risk == "SAFE" else "Migrate to SHA-256 or stronger.")
    if name.startswith("HMAC-"):
        inner = classify(name[5:])
        return {**inner, "reason": f"HMAC with {name[5:]}: {inner['reason']}"}
    if name in KDFS:
        return finding("SAFE", "Grover",
                       "Key derivation or password hashing; quantum search gives at most a quadratic speed-up on guessing.")
    if name in PROTOCOLS:
        risk, threat, reason = PROTOCOLS[name]
        return finding(risk, threat, reason, "Require TLS 1.3 with an ML-KEM hybrid group (e.g. X25519MLKEM768).")
    return finding("UNKNOWN", "Unknown", "Algorithm, parameters, or classification rule are unavailable.")


def classify_name(name, key_bits=None, purpose=None, require_parameters=False):
    """normalize() + classify() for a raw name, adding a readable "algorithm" label."""
    info = normalize(name)
    if key_bits is not None:
        info["keySizeBits"] = key_bits
    result = classify(info["algorithm"] or name, info["keySizeBits"], purpose, info["parameterSet"], require_parameters)
    result["algorithm"] = label(info) if info["algorithm"] else (name or "Unknown")
    return result

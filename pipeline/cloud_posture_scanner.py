"""Cloud report kind: AWS KMS keys, ACM certificates and load-balancer TLS policies.

Inventories are recognised by their content, not their file names, and rated through the shared
crypto catalog. Registers analysis, storage and CycloneDX export; listed in registry.SCANNER_MODULES.
"""

import json
import re
import sys
from pathlib import Path

from pipeline.crypto_catalog import classify, label, normalize
from pipeline.export_cbom import register_exporter
from pipeline.registry import register
from pipeline.source_store import register_storage

KMS_PURPOSES = {"SIGN_VERIFY": "signature", "ENCRYPT_DECRYPT": "encryption", "KEY_AGREEMENT": "keyExchange",
                "GENERATE_VERIFY_MAC": "hash"}
COMPONENT_TYPES = ("cloud-kms-key", "x509-certificate", "load-balancer-listener")


def _assessment(result, reason=None, suggestion=None):
    assessment = {"tier": result["risk"], "threat": result["threat"], "reason": reason or result["reason"]}
    if suggestion or result.get("suggestion"):
        assessment["suggestion"] = suggestion or result["suggestion"]
    if result.get("nistStandard"):
        assessment["nistStandard"] = result["nistStandard"]
    if result.get("urgency"):
        assessment["urgency"] = result["urgency"]
    return assessment


def _unknown(reason):
    return {"tier": "UNKNOWN", "threat": "Unknown", "reason": reason, "suggestion": "Review this asset's algorithm."}


def kms_algorithm(spec):
    """Catalog name and key size for an AWS KMS KeySpec, or None when the spec is not recognised."""
    if spec == "SYMMETRIC_DEFAULT":
        return "AES", 256
    for pattern, build in ((r"RSA_(\d+)", lambda m: ("RSA", int(m[1]))), (r"ECC_NIST_P(\d+)", lambda m: (f"P-{m[1]}", None)),
                           (r"ECC_SECG_P256K1", lambda m: ("secp256k1", None)), (r"HMAC_(\d+)", lambda m: (f"HMAC-SHA-{m[1]}", None)),
                           (r"ML_DSA_(\d+)", lambda m: (f"ML-DSA-{m[1]}", None))):
        match = re.fullmatch(pattern, spec or "")
        if match:
            return build(match)
    return None


def rate_kms_key(spec, usage=None):
    found = kms_algorithm(spec)
    if not found:
        return _unknown(f"Key spec {spec or 'not recorded'} is not recognised.")
    name, bits = found
    return _assessment(classify(name, bits, KMS_PURPOSES.get(usage)))


def rate_certificate(key_algorithm):
    # ACM writes curves as EC_prime256v1 / EC_secp384r1; certificate keys sign.
    name = re.sub(r"^EC_", "", key_algorithm or "")
    if normalize(name)["algorithm"] is None:
        return _unknown(f"Certificate key algorithm {key_algorithm or 'not recorded'} is not recognised.")
    return _assessment(classify(name, purpose="signature"))


def rate_policy(policy):
    """AWS TLS policies: the name says whether hybrid ML-KEM key exchange is offered."""
    if not isinstance(policy, str) or not policy.strip():
        return _unknown("No TLS policy recorded for this listener.")
    if re.search(r"(^|-)PQ(-|$)", policy, re.IGNORECASE):
        # Offering a hybrid group does not stop a client from negotiating a classical one.
        return _assessment({**classify("X25519MLKEM768", purpose="keyExchange"), "risk": "MEDIUM", "threat": "Shor", "urgency": "HNDL"},
                           f"{policy} offers hybrid ML-KEM key exchange, but it still accepts classical key exchange from clients "
                           "that do not support it, so recorded sessions may remain breakable.",
                           "Confirm clients negotiate X25519MLKEM768, then retire classical groups where the policy allows.")
    if policy.startswith("ELBSecurityPolicy"):
        return _assessment(classify("ECDH", purpose="keyExchange"),
                           f"{policy} negotiates only classical (EC)DHE key exchange, which Shor's algorithm breaks; "
                           "recorded traffic could be decrypted later.",
                           "Switch to an AWS post-quantum TLS policy (name containing PQ) that offers X25519MLKEM768.")
    return _unknown(f"Custom or unrecognised TLS policy {policy}; review its key-exchange groups.")


def kms_components(data, source):
    for key in data["Keys"]:
        spec = key.get("KeySpec", "UNKNOWN")
        found = kms_algorithm(spec)
        yield {"type": "cloud-kms-key", "name": key.get("AliasName", key.get("KeyId")), "source": source, "arn": key.get("KeyArn"),
               "cryptoProperties": {"assetType": "key", "keySpec": spec,
                                    "detectedAlgorithm": label(normalize(found[0]) | {"keySizeBits": found[1]}) if found else spec,
                                    "keyUsage": key.get("KeyUsage"),
                                    "keyRotationEnabled": key.get("KeyRotationStatus") == "ENABLED", "origin": key.get("Origin")},
               "quantumRiskAssessment": rate_kms_key(spec, key.get("KeyUsage"))}


def certificate_components(data, source):
    for cert in data["Certificates"]:
        algorithm = cert.get("KeyAlgorithm", "UNKNOWN")
        yield {"type": "x509-certificate", "name": cert.get("DomainName"), "source": source, "arn": cert.get("CertificateArn"),
               "cryptoProperties": {"assetType": "certificate", "keyAlgorithm": algorithm,
                                    "signatureAlgorithm": cert.get("SignatureAlgorithm"), "type": cert.get("Type"),
                                    "status": cert.get("Status")},
               "quantumRiskAssessment": rate_certificate(algorithm)}


def listener_components(data, source):
    for balancer in data["LoadBalancers"]:
        for listener in balancer.get("Listeners", []):
            if listener.get("Protocol") not in ("HTTPS", "TLS"):
                continue  # Plain HTTP carries no TLS to assess.
            policy = listener.get("SslPolicy")
            yield {"type": "load-balancer-listener", "name": f"{balancer.get('LoadBalancerName')}:{listener.get('Port')}",
                   "source": source, "arn": listener.get("ListenerArn"),
                   "cryptoProperties": {"assetType": "protocol-policy", "protocol": listener.get("Protocol"),
                                        "port": listener.get("Port"), "sslPolicy": policy or "NONE",
                                        "associatedCertificates": [c.get("CertificateArn") for c in listener.get("Certificates", [])]},
                   "quantumRiskAssessment": rate_policy(policy)}


INVENTORIES = {"Keys": kms_components, "Certificates": certificate_components, "LoadBalancers": listener_components}


def scan_cloud(root, files):
    components, inventories = [], 0
    for path in files:
        if path.suffix.lower() != ".json":
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError):
            continue
        if not isinstance(data, dict):
            continue
        for field, read in INVENTORIES.items():
            if isinstance(data.get(field), list):
                inventories += 1
                components.extend(read(data, str(path)))
    if not inventories:
        return None
    return {"metadata": {"source": "AWS cloud inventory", "inventories": inventories}, "components": components}


register("cloud", scan_cloud, component_types=COMPONENT_TYPES)


register_storage(
    "cloud", "cloud_classification",
    """CREATE TABLE IF NOT EXISTS cloud_classification (
        id INTEGER PRIMARY KEY, asset_type TEXT, name TEXT, risk TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""",
    lambda component: {"asset_type": component.get("type"), "name": component.get("name"),
                       "risk": component.get("quantumRiskAssessment", {}).get("tier")},
    lambda row: {"type": row["asset_type"], "name": row["name"], "quantumRiskAssessment": {"tier": row["risk"]}},
)


def export_cloud(bom, finding, ref, evidence):
    kind, props = finding.get("type"), finding.get("cryptoProperties", {})
    if kind not in COMPONENT_TYPES:
        return None
    component = bom.asset(ref, finding.get("name") or ref, evidence)
    related = []
    if kind == "load-balancer-listener":
        # A policy name is not evidence of negotiated algorithms, so none are linked.
        protocol = {"type": "tls" if re.match(r"^(TLS|HTTPS)\b", props.get("protocol") or "", re.I) else "unknown"}
        component["cryptoProperties"] = {"assetType": "protocol", "protocolProperties": protocol}
    elif kind == "x509-certificate":
        certificate = {"certificateFormat": "X.509"}
        component["cryptoProperties"] = {"assetType": "certificate", "certificateProperties": certificate}
        for field, purpose, relation in (("signatureAlgorithm", "certificate-signature", "signatureAlgorithm"),
                                         ("keyAlgorithm", "certificate-key-algorithm", "algorithm")):
            target = bom.algorithm({"algorithm": props.get(field)}, f"{ref}:{field}", evidence, purpose)
            if target:
                related.append({"type": relation, "ref": target["bom-ref"]})
        if related:
            certificate["relatedCryptographicAssets"] = related
    else:
        material = {"type": "key"}
        if finding.get("arn"):
            material["id"] = finding["arn"]
        component["cryptoProperties"] = {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": material}
        target = bom.algorithm({"algorithm": props.get("keySpec")}, f"{ref}:algorithm", evidence, "key-specification")
        if target:
            related.append({"type": "algorithm", "ref": target["bom-ref"]})
            material["relatedCryptographicAssets"] = related
    bom.link(ref, related)
    return component


register_exporter("cloud", export_cloud)


if __name__ == "__main__":
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    report = scan_cloud(root, sorted(root.rglob("*.json"))) or {"components": []}
    Path("cbom_cloud.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"{len(report['components'])} cloud assets exported to 'cbom_cloud.json'.")

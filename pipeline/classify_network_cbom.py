"""Classify a structured, readable network CBOM using the hackathon risk matrix."""

import argparse
import json
from collections import Counter
from copy import deepcopy
from pathlib import Path

from pipeline.crypto_catalog import MLKEM_GROUPS, POLICY, classify

# Ratings come from the shared catalog, so a network finding and a code finding always agree.
NOT_RECORDED = {"", "none", "not recorded", "not determined", "negotiated separately"}


def finding(risk, reason, suggestion=None, standard=None):
    result = {"risk": risk, "reason": reason}
    if suggestion:
        result["suggestion"] = suggestion
    if standard:
        result["nistStandard"] = standard
    return result


def primitive_risk(details, purpose):
    algorithm = details.get("algorithm")
    # "None" here means the capture recorded no algorithm, not the JWT "none" algorithm.
    if not isinstance(algorithm, str) or algorithm.strip().lower() in NOT_RECORDED:
        return finding("UNKNOWN", "Algorithm, parameters, or classification rule are unavailable.")
    # Structured evidence: a missing key size or parameter set is a gap, so it stays UNKNOWN.
    parts = [
        classify(part.strip(), details.get("keySizeBits"), purpose, details.get("parameterSet"), require_parameters=True)
        for part in algorithm.split(" + ")
    ]
    result = parts[0] if len(parts) == 1 else {**parts[0], "risk": combined_risk(parts)}
    return finding(result["risk"], result["reason"], result.get("suggestion"), result.get("nistStandard"))


def combined_risk(findings):
    risks = {item["risk"] for item in findings}
    # A known critical finding stands even when other evidence is missing.
    return next(
        (risk for risk in ("CRITICAL", "UNKNOWN", "MEDIUM", "SAFE") if risk in risks),
        "UNKNOWN",
    )


def classify_session(properties):
    suite = properties.get("cipherSuite", {})
    group = properties.get("keyExchangeGroup", {})
    if not isinstance(suite, dict) or not isinstance(group, dict):
        raise ValueError(
            "Expected structured readable CBOM; run translate_cbom.py first."
        )
    encryption = primitive_risk(suite.get("encryption", {}), "encryption")
    hashed = primitive_risk(suite.get("hash", {}), "hash")
    authentication_details = suite.get("authentication") or {}
    if isinstance(authentication_details, str):
        authentication_details = {"algorithm": authentication_details}
    authentication_available = (
        authentication_details.get("algorithm") or ""
    ).strip() not in (
        "",
        "Negotiated separately",
        "Not recorded",
        "Not determined",
    )
    authentication = primitive_risk(authentication_details, "authentication")
    exchange_details = suite.get("keyExchange", {})
    if isinstance(exchange_details, str):
        exchange_details = {"algorithm": exchange_details}
    exchange = primitive_risk(exchange_details, "keyExchange")
    parts = group.get("components", [])
    part_findings = [{**part, **primitive_risk(part, "keyExchange")} for part in parts]
    if exchange_details.get("algorithm") in (
        "Negotiated separately",
        group.get("name"),
    ):
        if (
            group.get("name") in MLKEM_GROUPS
            and any(
                part.get("algorithm") == "ML-KEM" and result["risk"] == "SAFE"
                for part, result in zip(parts, part_findings)
            )
            and all(part.get("algorithm") in ("ML-KEM", "ECDH") for part in parts)
        ):
            exchange = finding(
                "SAFE",
                "Recognized ML-KEM group; a hybrid is assessed as a combined construction.",
                standard="FIPS 203 (ML-KEM component)",
            )
        elif part_findings:
            exchange = finding(
                combined_risk(part_findings),
                "Assessment of the recorded negotiated group.",
            )
    exchange["components"] = part_findings
    if group.get("hybrid"):
        for part in part_findings:
            part["riskScope"] = (
                "Primitive considered alone; see the combined key-exchange rating."
            )
    findings = {
        "encryption": encryption,
        "hash": hashed,
        "keyExchange": exchange,
        "authentication": authentication,
    }
    # Missing authentication remains visible as evidence, but does not set session risk.
    overall_findings = [encryption, hashed, exchange]
    if authentication_available:
        overall_findings.append(authentication)
    return {
        "risk": combined_risk(overall_findings),
        "encryptionAndKeyExchangeRisk": combined_risk([encryption, exchange]),
        "findings": findings,
        "missingOrUnsupported": [
            name for name, item in findings.items() if item["risk"] == "UNKNOWN"
        ],
        "policy": POLICY,
        "scope": "Quantum risk of reported algorithms; authentication contributes only when recorded. "
        "Not a complete TLS configuration or certificate audit.",
    }


def compact_algorithm(details, assessment):
    fields = (
        "keySizeBits",
        "mode",
        "authenticationTagBits",
        "authenticator",
        "construction",
        "outputBits",
        "role",
        "curve",
        "curveBits",
        "modulusBits",
        "parameterSet",
        "nistSecurityLevel",
    )
    result = {
        "algorithm": details.get("algorithm", "Not recorded"),
        "risk": assessment["risk"],
    }
    result.update({key: details[key] for key in fields if details.get(key) is not None})
    return result


def classify_cbom(cbom):
    if not isinstance(cbom, dict) or not isinstance(cbom.get("components"), list):
        raise TypeError("Expected a CBOM object containing a components list.")
    cbom = deepcopy(cbom)
    session_counts = Counter()
    algorithm_counts = Counter()
    for component in cbom["components"]:
        if component.get("type") != "network-session":
            continue
        properties = component["cryptoProperties"]
        assessment = classify_session(properties)
        suite = properties["cipherSuite"]
        findings = assessment["findings"]
        clean = {"protocol": "TLS", "negotiatedVersion": None}
        for purpose in ("encryption", "hash"):
            clean[purpose] = compact_algorithm(
                suite.get(purpose, {}), findings[purpose]
            )
        for purpose in ("keyExchange", "authentication"):
            algorithm = suite.get(purpose) or "Not recorded"
            if isinstance(algorithm, dict):
                algorithm = algorithm.get("algorithm", "Not recorded")
            clean[purpose] = compact_algorithm(
                {"algorithm": algorithm}, findings[purpose]
            )
        if clean["authentication"]["algorithm"] == "Negotiated separately":
            clean["authentication"]["algorithm"] = "Not recorded"
        parts = findings["keyExchange"]["components"]
        if clean["keyExchange"]["algorithm"] == "Negotiated separately":
            if len(parts) == 1:
                clean["keyExchange"] = compact_algorithm(
                    parts[0], findings["keyExchange"]
                )
            elif len(parts) > 1:
                clean["keyExchange"] = {
                    "algorithm": "Hybrid key exchange",
                    "risk": findings["keyExchange"]["risk"],
                    "components": [compact_algorithm(part, part) for part in parts],
                }
            else:
                clean["keyExchange"]["algorithm"] = "Not recorded"
        # Offered groups are distinct evidence, but need no duplicate breakdown.
        if properties.get("supportedGroups"):
            clean["offeredGroups"] = [
                group["name"] for group in properties["supportedGroups"]
            ]
        component["cryptoProperties"] = clean
        component.pop("quantumAssessment", None)
        component["risk"] = assessment["risk"]
        if component.get("source") == cbom.get("metadata", {}).get("sourceFile"):
            component.pop("source", None)
        session_counts[assessment["risk"]] += 1
        algorithm_counts.update(item["risk"] for item in findings.values())
    cbom["classificationSummary"] = {
        "sessionRiskCounts": {
            risk: session_counts[risk]
            for risk in ("CRITICAL", "MEDIUM", "SAFE", "UNKNOWN")
        },
        "algorithmRiskCounts": {
            risk: algorithm_counts[risk]
            for risk in ("CRITICAL", "MEDIUM", "SAFE", "UNKNOWN")
        },
    }
    return cbom


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Structured human-readable CBOM JSON")
    parser.add_argument("output", type=Path, help="Classified CBOM JSON")
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        parser.error("Choose a separate output file to preserve the readable input.")
    try:
        with args.input.open(encoding="utf-8") as source:
            cbom = classify_cbom(json.load(source))
    except (ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    args.output.write_text(json.dumps(cbom, indent=2) + "\n", encoding="utf-8")
    print(f"Classified CBOM saved to {args.output}")
    print(json.dumps(cbom["classificationSummary"], indent=2))

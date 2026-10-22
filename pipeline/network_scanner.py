"""Network report kind: TLS sessions in packet captures.

Registers analysis, storage and CycloneDX export for the kind; listed in registry.SCANNER_MODULES.
"""

import re

from pipeline.classify_network_cbom import classify_cbom
from pipeline.export_cbom import recorded, register_exporter
from pipeline.registry import register
from pipeline.source_store import register_storage
from pipeline.translate_network_cbom import translate_cbom

CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".cap"}
PURPOSES = (("encryption", "encryption"), ("hash", "hash"), ("keyExchange", "key_exchange"), ("authentication", "authentication"))


def scan_network(root, files):
    captures = [path for path in files if path.suffix.lower() in CAPTURE_SUFFIXES]
    if not captures:
        return None
    # Scapy is slow to import, so only load it when there is a capture to read.
    from pipeline.pcap_scanner import analyze_pcap_to_cbom

    components = []
    for path in captures:
        report = classify_cbom(translate_cbom(analyze_pcap_to_cbom(str(path))))
        for component in report["components"]:
            component["source"] = str(path)
        components.extend(report["components"])
    return {"metadata": {"source": "TLS packet capture analysis", "captures": len(captures)}, "components": components}


def import_network(component, report):
    """Classify an exported session that has not been rated yet; rated sessions are kept as they are."""
    if "risk" in component:
        return component
    single = {"metadata": report.get("metadata", {}), "components": [component]}
    if not isinstance(component.get("cryptoProperties", {}).get("cipherSuite"), dict):
        translate_cbom(single)
    return classify_cbom(single)["components"][0]


register("network", scan_network, component_types=("network-session",), import_hook=import_network)


SCHEMA = """
    CREATE TABLE IF NOT EXISTS network_session (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_id INTEGER,
        client_endpoint TEXT NOT NULL,
        server_endpoint TEXT NOT NULL,
        protocol TEXT,
        encryption_algorithm TEXT,
        encryption_risk TEXT,
        hash_algorithm TEXT,
        hash_risk TEXT,
        key_exchange_algorithm TEXT,
        key_exchange_risk TEXT,
        authentication_algorithm TEXT,
        authentication_risk TEXT,
        conclusion TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
"""


def network_columns(component):
    props = component.get("cryptoProperties", {})
    evidence = component.get("evidence", {})
    values = {"client_endpoint": evidence.get("client") or "Not recorded", "server_endpoint": evidence.get("server") or "Not recorded",
              "protocol": props.get("protocol"), "conclusion": component.get("risk") or "UNKNOWN"}
    for field, column in PURPOSES:
        details = props.get(field, {})
        values[column + "_algorithm"] = details.get("algorithm")
        values[column + "_risk"] = details.get("risk")
    return values


def network_legacy_component(row):
    props = {"protocol": row["protocol"]}
    for field, column in PURPOSES:
        props[field] = {"algorithm": row[column + "_algorithm"], "risk": row[column + "_risk"]}
    return {"type": "network-session", "name": f"TLS session {row['id']}", "risk": row["conclusion"],
            "evidence": {"client": row["client_endpoint"], "server": row["server_endpoint"]}, "cryptoProperties": props}


register_storage("network", "network_session", SCHEMA, network_columns, network_legacy_component)


def export_network(bom, finding, ref, evidence):
    """A session is a TLS protocol asset linked to the algorithms it negotiated."""
    props = finding.get("cryptoProperties", {})
    component = bom.asset(ref, finding.get("name") or ref, evidence)
    protocol = {"type": "tls" if re.match(r"^(TLS|HTTPS)\b", props.get("protocol") or "", re.I) else "unknown"}
    if recorded(props.get("negotiatedVersion")):
        protocol["version"] = props["negotiatedVersion"]
    component["cryptoProperties"] = {"assetType": "protocol", "protocolProperties": protocol}
    related = []
    for purpose, _ in PURPOSES:
        target = bom.algorithm(props.get(purpose) or {}, f"{ref}:{purpose}", evidence, purpose)
        if target:
            related.append({"type": "algorithm", "ref": target["bom-ref"]})
    if related:
        protocol["relatedCryptographicAssets"] = related
    bom.link(ref, related)
    return component


register_exporter("network", export_network)

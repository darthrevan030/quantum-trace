"""Turn scanner reports into a quantum-safety summary, verdict and Markdown report."""

from collections import Counter, defaultdict
from datetime import datetime, timezone

from pipeline.crypto_catalog import RISKS

NOT_SAFE = "NOT QUANTUM SAFE"
PARTIAL = "PARTIALLY QUANTUM SAFE"
SAFE = "QUANTUM SAFE (for detected cryptography)"
NONE_FOUND = "NO CRYPTOGRAPHY DETECTED"
VERDICTS = (NOT_SAFE, PARTIAL, SAFE, NONE_FOUND)
VERDICT_DESCRIPTIONS = {
    NOT_SAFE: "Cryptography that a quantum computer (or classical cryptanalysis) can break is in use.",
    PARTIAL: "No algorithm is broken outright, but some need stronger parameters or a review.",
    SAFE: "Every detected algorithm is rated quantum safe. Undetected cryptography may still exist.",
    NONE_FOUND: "The scanners found no cryptographic usage. This is not proof that none exists.",
}
FAIL_THRESHOLDS = {"critical": ("CRITICAL",), "high": ("CRITICAL", "HIGH"), "medium": ("CRITICAL", "HIGH", "MEDIUM"), "none": ()}
CAVEATS = [
    "Detection is pattern based: it finds cryptographic API calls, settings and dependencies. "
    "No findings is not proof that no cryptography exists.",
    "Algorithms chosen at runtime (configuration, environment variables) appear as UNKNOWN; review them.",
    "Dependencies are reported by name; the algorithms they use internally appear only where the code calls them.",
    "Ratings follow `pipeline/crypto_catalog.py` (its POLICY records contested choices, e.g. SHA-1 is Medium).",
]


def risk_of(component):
    value = component.get("risk") or component.get("quantumRiskAssessment", {}).get("tier")
    value = value.upper() if isinstance(value, str) else "UNKNOWN"
    return value if value in RISKS else "UNKNOWN"


def algorithm_of(component):
    props = component.get("cryptoProperties", {})
    return (props.get("detectedAlgorithm") or props.get("keySpec") or props.get("keyAlgorithm")
            or props.get("sslPolicy") or component.get("name") or "Unknown")


def _included(reports, include_tests):
    for kind, report in reports.items():
        for component in report.get("components", []):
            if include_tests or component.get("cryptoProperties", {}).get("context") != "test":
                yield kind, component


def summarize(reports, include_tests=True):
    """Counts only; verdict() turns them into a judgement."""
    risks, kinds, asset_types, contexts = Counter(), defaultdict(Counter), Counter(), Counter()
    algorithms, files = defaultdict(lambda: {"count": 0, "files": set()}), set()
    for kind, component in _included(reports, include_tests):
        risk = risk_of(component)
        risks[risk] += 1
        kinds[kind][risk] += 1
        props = component.get("cryptoProperties", {})
        asset_types[props.get("assetType") or component.get("type") or "unknown"] += 1
        contexts[props.get("context") or "source"] += 1
        entry = algorithms[(algorithm_of(component), risk)]
        entry["count"] += 1
        if component.get("source"):
            entry["files"].add(component["source"])
            files.add(component["source"])
    total = sum(len(r.get("components", [])) for r in reports.values())
    included = sum(risks.values())
    return {
        "totalFindings": included,
        "riskCounts": {risk: risks[risk] for risk in RISKS},
        "byKind": {kind: {risk: counts[risk] for risk in RISKS} for kind, counts in sorted(kinds.items())},
        "byAssetType": dict(sorted(asset_types.items())),
        "byContext": dict(sorted(contexts.items())),
        "algorithms": sorted(
            ({"algorithm": name, "risk": risk, "count": entry["count"], "files": len(entry["files"])}
             for (name, risk), entry in algorithms.items()),
            key=lambda row: (RISKS.index(row["risk"]), -row["count"], row["algorithm"])),
        "filesWithFindings": len(files),
        "testFindingsExcluded": total - included,
    }


def verdict(summary):
    """Return one of VERDICTS for a summary from summarize().

    summary["riskCounts"] has every risk in RISKS; summary["byAssetType"] tells code findings
    ("code-primitive") apart from "dependency" findings.
    """
    counts = summary["riskCounts"]
    if summary["totalFindings"] == 0:
        return NONE_FOUND
    if counts["CRITICAL"] or counts["HIGH"]:
        return NOT_SAFE
    if counts["MEDIUM"] or counts["LOW"] or counts["UNKNOWN"]:
        return PARTIAL
    if counts["SAFE"] and not (counts["CRITICAL"] or counts["HIGH"] or counts["MEDIUM"] or counts["LOW"] or counts["UNKNOWN"]):
        return SAFE
    return NONE_FOUND



def build(reports, include_tests=True):
    summary = summarize(reports, include_tests)
    summary["verdict"] = verdict(summary)
    summary["verdictDescription"] = VERDICT_DESCRIPTIONS[summary["verdict"]]
    return summary


def exceeds(summary, threshold):
    """True when the summary has a finding at or above the --fail-on threshold."""
    return any(summary["riskCounts"][risk] for risk in FAIL_THRESHOLDS[threshold])


def _cell(text):
    return str(text).replace("|", "\\|").replace("`", "'").replace("\n", " ")


def to_markdown(summary, reports, title, include_tests=True):
    lines = [
        f"# Quantum-safety report: {_cell(title)}",
        "",
        f"**Verdict: {summary['verdict']}**. {summary['verdictDescription']}",
        "",
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · "
        f"{summary['totalFindings']} findings in {summary['filesWithFindings']} files"
        + (f" · {summary['testFindingsExcluded']} test findings excluded" if summary["testFindingsExcluded"] else ""),
        "",
        "## Risk summary",
        "",
        "| Risk | Findings |",
        "|---|---:|",
        *(f"| {risk} | {count} |" for risk, count in summary["riskCounts"].items() if count),
        "",
        "## Algorithms",
        "",
        "| Algorithm | Risk | Findings | Files |",
        "|---|---|---:|---:|",
        *(f"| {_cell(row['algorithm'])} | {row['risk']} | {row['count']} | {row['files']} |" for row in summary["algorithms"]),
        "",
        "## Findings by file",
    ]
    by_file = defaultdict(list)
    for _, component in _included(reports, include_tests):
        by_file[component.get("source") or "Unknown source"].append(component)
    for source in sorted(by_file):
        lines += ["", f"### `{_cell(source)}`", ""]
        for component in sorted(by_file[source], key=lambda c: (RISKS.index(risk_of(c)), c.get("line") or 0)):
            assessment = component.get("quantumRiskAssessment", {})
            where = f"line {component['line']}" if component.get("line") else component.get("name", "")
            detail = assessment.get("suggestion") or assessment.get("reason") or ""
            standard = f" ({assessment['nistStandard']})" if assessment.get("nistStandard") else ""
            snippet = f" `{_cell(component['codeSnippet'])}`" if component.get("codeSnippet") else ""
            lines.append(f"- **{risk_of(component)}** {where}: {_cell(algorithm_of(component))}{snippet}. {_cell(detail)}{standard}")
    if not by_file:
        lines += ["", "No findings."]
    lines += ["", "## What this report does not cover", "", *(f"- {caveat}" for caveat in CAVEATS), ""]
    return "\n".join(lines)

"""Find cryptography in source code with data-driven rules (pipeline/rules/*.json).

Rules only detect an algorithm and its parameters; pipeline.crypto_catalog decides the risk.
"""

import json
import re
from bisect import bisect_right
from collections import Counter
from pathlib import Path

from pipeline.crypto_catalog import RISKS, classify, default_purpose, label, normalize
from pipeline.manifest_scanner import MANIFESTS
from pipeline.registry import register
from pipeline.walker import walk

RULES_DIR = Path(__file__).with_name("rules")
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|specs|fixtures?|test_data)/|\.(test|spec)\.\w+$|_test\.(go|py)$|(^|/)test_[^/]*\.py$")
EC_FAMILY = {"EC", "ECDSA", "ECDH"}
GROUP = re.compile(r"\{(\d+|item)\}")


def load_rules(directory=RULES_DIR):
    """Load every rule file; adding a language means adding one JSON file."""
    rulesets = []
    for path in sorted(Path(directory).glob("*.json")):
        ruleset = json.loads(path.read_text(encoding="utf-8"))
        ruleset["skip"] = [re.compile(pattern) for pattern in ruleset.get("skip", [])]
        for rule in ruleset["rules"]:
            flags = re.IGNORECASE if "i" in rule.get("flags", "") else 0
            rule["regex"] = re.compile(rule["regex"], flags)
            for key in ("algorithmPattern", "keySizePattern", "curvePattern", "hashPattern", "fileRequires"):
                if key in rule:
                    rule[key] = re.compile(rule[key], re.IGNORECASE if key == "algorithmPattern" else 0)
        rulesets.append(ruleset)
    return rulesets


def _fill(template, match, item=None):
    return GROUP.sub(lambda g: item if g.group(1) == "item" else (match.group(int(g.group(1))) or ""), template)


def _group(match, index):
    return match.group(index) if index and index <= (match.re.groups or 0) else None


def _window(text, match, rule, line_ends, line_index):
    """Text after the match, up to `lookahead` more lines, cut at `windowEnd` if given."""
    end = line_ends[min(line_index + rule.get("lookahead", 0), len(line_ends) - 1)]
    window = text[match.end():end]
    if rule.get("windowEnd") and rule["windowEnd"] in window:
        window = window[: window.index(rule["windowEnd"])]
    return window


def _search(pattern, window):
    found = pattern.search(window) if pattern else None
    return next((group for group in found.groups() if group), None) if found else None


def _resolve(rule, match, window):
    """Yield (raw algorithm text, label template item) for one match."""
    if "algorithmMap" in rule:
        yield rule["algorithmMap"].get((match.group(1) or "").lower(), "?"), None
        return
    if "algorithmPattern" in rule:
        yield _search(rule["algorithmPattern"], match.group(0) + window) or "?", None
        return
    raw = _fill(rule["algorithm"], match)
    if "split" in rule:
        for item in re.split(rule["split"], raw):
            if item:
                yield item, item
    else:
        yield raw, None


def _finding(rule, match, window, raw, item, relative):
    """Return (dedup key, partial component) or None when the rule drops unknown names."""
    info = normalize(raw) if raw != "?" else normalize(None)
    if info["algorithm"] is None and rule.get("dropUnknown"):
        return None
    if info["algorithm"] is None and raw.lower() == "hmac":
        hash_name = _search(rule.get("hashPattern"), window)
        if hash_name:
            info = normalize(f"hmac-{hash_name}")
    curve = _group(match, rule.get("curveGroup")) or _search(rule.get("curvePattern"), window)
    if curve:
        curve_info = normalize(curve)
        if curve_info["algorithm"] == "EC":
            family = info["algorithm"] if info["algorithm"] in EC_FAMILY else "EC"
            info.update(curve_info, algorithm=family)
    bits = _group(match, rule.get("keySizeGroup")) or _search(rule.get("keySizePattern"), window)
    if bits:
        info["keySizeBits"] = int(bits)
    if info["algorithm"] is None and raw.lower() == "none":
        info["algorithm"] = "NONE"

    if info["algorithm"] is None:
        assessment = {"risk": "UNKNOWN", "threat": "Unknown",
                      "reason": rule.get("reason", "Algorithm could not be determined from the code."),
                      "suggestion": "Review the algorithm used here."}
        name = rule.get("label") or raw
        key = ("?", rule["id"])
    else:
        target = rule.get("classifyAs") or info["algorithm"]
        purpose = rule.get("purpose") or default_purpose(info["algorithm"])
        assessment = classify(target, info["keySizeBits"], purpose, info["parameterSet"])
        if rule.get("classifyAs") and rule.get("reason"):
            assessment["reason"] = rule["reason"]
        name = _fill(rule["label"], match, item) if rule.get("label") and "algorithm" in rule else label(info)
        family = "EC" if info["algorithm"] in EC_FAMILY else info["algorithm"]
        key = (family, info["keySizeBits"], info["parameterSet"])
    return key, {
        "cryptoProperties": {
            "detectedAlgorithm": name,
            "primitive": rule.get("purpose") if info["algorithm"] is None else purpose,
            "keySize": info["keySizeBits"],
            "keySizeBits": info["keySizeBits"],
            "ruleId": rule["id"],
        },
        "quantumRiskAssessment": {"tier": assessment["risk"], **{k: v for k, v in assessment.items() if k != "risk"}},
    }


def scan_file(path, relative, ruleset, language):
    text = path.read_text(encoding="utf-8", errors="ignore")
    if "\0" in text[:8192]:
        return []
    lines = text.split("\n")
    line_starts, offset = [], 0
    for content in lines:
        line_starts.append(offset)
        offset += len(content) + 1
    line_ends = [start + len(content) for start, content in zip(line_starts, lines)]
    comments = tuple(ruleset.get("commentPrefixes", ()))
    seen, components = set(), []
    for rule in ruleset["rules"]:
        if "fileRequires" in rule and not rule["fileRequires"].search(text):
            continue
        for match in rule["regex"].finditer(text):
            index = bisect_right(line_starts, match.start()) - 1
            content = lines[index].strip()
            if comments and content.startswith(comments):
                continue
            window = _window(text, match, rule, line_ends, index)
            for raw, item in _resolve(rule, match, window):
                result = _finding(rule, match, window, raw, item, relative)
                if result is None or (index, result[0]) in seen:
                    continue
                seen.add((index, result[0]))
                component = result[1]
                component["cryptoProperties"].update(assetType="code-primitive", language=language)
                components.append({
                    "type": "application-code",
                    "name": f"{path.name}:{index + 1}",
                    "source": relative,
                    "line": index + 1,
                    "codeSnippet": content[:160],
                    **component,
                })
    return components


def summarize(components, scanned_files, languages):
    counts = Counter(c["quantumRiskAssessment"]["tier"] for c in components)
    total = len(components)
    score = round((counts["CRITICAL"] + 0.7 * counts["HIGH"] + 0.4 * counts["MEDIUM"]) / max(total, 1) * 100, 2)
    return {
        "source": "Static Code Cryptographic Inventory (SAST)",
        "scannedFiles": scanned_files,
        "languages": dict(sorted(languages.items())),
        "quantumRiskSummary": {
            "totalFindings": total,
            "riskCounts": {risk: counts[risk] for risk in RISKS},
            "codeQuantumRiskScore": f"{score}%",
        },
    }


def scan_code(root, files=None, rulesets=None):
    """Scan every supported file under root (or the given files) and return a code CBOM report."""
    root = Path(root)
    if files is None:
        files, _ = walk(root)
    rulesets = rulesets if rulesets is not None else load_rules()
    by_extension = {ext: (ruleset, language) for ruleset in rulesets for ext, language in ruleset["extensions"].items()}
    components, languages, scanned = [], Counter(), 0
    for path in files:
        relative = Path(path).relative_to(root).as_posix()
        if path.name in MANIFESTS:
            found = MANIFESTS[path.name](path, relative)
        else:
            ruleset, language = by_extension.get(path.suffix.lower(), (None, None))
            if not ruleset or any(pattern.search(relative) for pattern in ruleset["skip"]):
                continue
            languages[language] += 1
            found = scan_file(path, relative, ruleset, language)
        scanned += 1
        context = "test" if TEST_PATH.search(relative) else "source"
        for component in found:
            component["cryptoProperties"]["context"] = context
        components.extend(found)
    components.sort(key=lambda c: (c["source"], c["line"]))
    return {
        "bomFormat": "CycloneDX-CBOM-Draft",
        "specVersion": "1.6",
        "metadata": summarize(components, scanned, languages),
        "components": components,
    }


def _code_report(root, files):
    report = scan_code(root, files)
    return report if report["metadata"]["scannedFiles"] else None


register("code", _code_report, component_types=("application-code",))


def scan_repositories(base_dir="input_files/sample-repos", output_file="cbom_code.json"):
    """Write the code report for base_dir to output_file (kept for existing callers)."""
    report = scan_code(Path(base_dir))
    Path(output_file).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    import sys

    scan_repositories(*sys.argv[1:3])

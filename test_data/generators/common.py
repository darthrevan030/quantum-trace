"""Shared helpers for the per-feature fixture generators. Generated code is never executed."""

import json
import textwrap
from collections import Counter
from pathlib import Path

from pipeline.analyze_source import run_scanners
from pipeline.report import risk_of

TEST_DATA = Path(__file__).resolve().parents[1]
EXPECTED = TEST_DATA / "expected"


def write(root, relative, content):
    """Write one fixture file with LF endings so regenerating is byte-identical on every OS."""
    path = Path(root) / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8", newline="\n")


def verify(kind, fixture, expected_counts, expected_dir=EXPECTED):
    """Scan one fixture folder on its own, check its risk counts, and record expected/<kind>.json."""
    reports = run_scanners(Path(fixture))
    if kind not in reports:
        raise SystemExit(f"No {kind} report for {fixture}: is the {kind} scanner registered on this branch?")
    components = reports[kind]["components"]
    counts = dict(sorted(Counter(risk_of(component) for component in components).items()))
    if counts != expected_counts:
        raise SystemExit(f"{kind} scanner output changed: {counts} (expected {expected_counts})")
    manifest = {
        "description": "Expected output of the current QuantumTrace scanners; not a security certification.",
        "kind": kind,
        "fixture": Path(fixture).relative_to(TEST_DATA).as_posix() if Path(fixture).is_relative_to(TEST_DATA) else str(fixture),
        "totalFindings": len(components),
        "riskCounts": counts,
        "findings": [{"source": c.get("source"), "name": c.get("name"), "risk": risk_of(c)} for c in components],
    }
    Path(expected_dir).mkdir(parents=True, exist_ok=True)
    Path(expected_dir, f"{kind}.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"kind": kind, "verifiedRiskCounts": counts}))
    return manifest

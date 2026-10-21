"""Run the registered scanners in an isolated source directory; never execute input code."""

import json
import sys
from pathlib import Path

from pipeline.registry import COMPONENT_KINDS, IMPORT_HOOKS, load_scanners
from pipeline.walker import walk


def import_exports(files, reports):
    """Accept existing scanner exports (CBOM JSON) for registered kinds without re-scanning them."""
    for path in files:
        if path.suffix.lower() != ".json":
            continue
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError):
            continue
        if not isinstance(report, dict) or not isinstance(report.get("components"), list):
            continue
        for component in report["components"]:
            if not isinstance(component, dict):
                raise TypeError(f"Invalid CBOM component in {path.name}.")
            kind = COMPONENT_KINDS.get(component.get("type"))
            if not kind:
                continue
            if kind in IMPORT_HOOKS:
                component = IMPORT_HOOKS[kind](component, report)
            component.setdefault("source", report.get("metadata", {}).get("sourceFile") or str(path))
            reports.setdefault(kind, {"components": []})["components"].append(component)


def analyze(root, output):
    output.write_text(json.dumps(run_scanners(root)), encoding="utf-8")


def run_scanners(root):
    """Return {kind: report} for every registered scanner that found applicable input."""
    files, skipped = walk(root)
    reports = {}
    for kind, scanner in load_scanners().items():
        report = scanner(root, files)
        if report is not None:
            reports[kind] = report
    import_exports(files, reports)
    if not reports:
        raise ValueError(
            "No supported inputs found. Add source code (JavaScript/TypeScript, Python, Java, Go), "
            "a package.json, or a CBOM report."
        )
    for report in reports.values():
        for component in report["components"]:
            source = component.get("source")
            if source and Path(source).is_absolute() and Path(source).is_relative_to(root):
                component["source"] = Path(source).relative_to(root).as_posix()
        metadata = report.setdefault("metadata", {})
        metadata["inputFileCount"] = len(files)
        metadata["skippedFiles"] = skipped
    return reports


if __name__ == "__main__":
    try:
        analyze(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
    except Exception as error:
        print(f"Analysis failed: {error}", file=sys.stderr)
        sys.exit(1)

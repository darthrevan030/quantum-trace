"""Scan a local folder or a public GitHub/GitLab repository and write a quantum-safety report.

    uv run python -m pipeline.scan <path | https://github.com/owner/repo> [-o out] [--fail-on critical]
"""

import argparse
import json
import sys
import tempfile
from pathlib import Path

from pipeline.analyze_source import run_scanners
from pipeline.report import FAIL_THRESHOLDS, build, exceeds, to_markdown
from pipeline.repo_fetch import clone, repository_url


def scan_target(target):
    """Return (title, reports) for a local path or a repository URL."""
    if target.startswith("https://"):
        url, name = repository_url(target)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "repo"
            clone(url, root)
            return name, run_scanners(root)
    root = Path(target).resolve()
    if not root.is_dir():
        raise ValueError(f"Not a directory: {target}")
    return root.name, run_scanners(root)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Report whether a repository's cryptography is quantum safe.")
    parser.add_argument("target", help="Local directory or https://github.com|gitlab.com repository URL")
    parser.add_argument("-o", "--output-dir", default="quantumtrace-report", help="Where report.md and report.json are written")
    parser.add_argument("--fail-on", choices=list(FAIL_THRESHOLDS), default="critical",
                        help="Exit with status 1 when a finding at or above this risk exists (default: critical)")
    parser.add_argument("--exclude-tests", action="store_true", help="Leave findings in test files out of the report")
    args = parser.parse_args(argv)
    try:
        title, reports = scan_target(args.target)
    except ValueError as error:
        print(f"Scan failed: {error}", file=sys.stderr)
        return 2
    include_tests = not args.exclude_tests
    summary = build(reports, include_tests)
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps({"target": title, "summary": summary, "reports": reports}, indent=2),
                                        encoding="utf-8")
    (output / "report.md").write_text(to_markdown(summary, reports, title, include_tests), encoding="utf-8")
    counts = ", ".join(f"{count} {risk}" for risk, count in summary["riskCounts"].items() if count) or "no findings"
    print(f"{title}: {summary['verdict']} ({counts})")
    print(f"Report: {output / 'report.md'}")
    return 1 if exceeds(summary, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())

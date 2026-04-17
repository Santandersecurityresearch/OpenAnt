#!/usr/bin/env python3
"""
apply_suppressions.py — Filter pipeline_output.json against .openant-suppress.yml.

Reads the suppression list and removes matching findings from the pipeline output
so that known/accepted issues don't block PR gates. Expired suppressions are
ignored (treated as if they don't exist) and reported as warnings.

Matching rules (checked in order; first match wins):
  1. fingerprint  — matches finding id OR "{file}:{function}"
  2. rule         — matches finding short_name or cwe-based rule id (e.g. "CWE-89")
  3. path_prefix  — matches if finding location.file starts with the prefix

Exit codes:
  0 — filtering succeeded (remaining findings may still be non-zero)
  1 — error reading inputs
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("Error: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


def _fingerprint(finding: dict) -> str:
    loc = finding.get("location", {})
    f, fn = loc.get("file", ""), loc.get("function", "")
    return f"{f}:{fn}" if fn else f


def _rule_id(finding: dict) -> str:
    cwe = finding.get("cwe_id")
    if cwe and int(cwe) > 0:
        return f"CWE-{cwe}"
    return f"openant/{finding.get('short_name', 'finding').lower().replace(' ', '-')}"


def _is_expired(entry: dict) -> bool:
    expires = entry.get("expires")
    if not expires:
        return False
    try:
        return date.today() > date.fromisoformat(str(expires))
    except ValueError:
        return False


def _matches(finding: dict, entry: dict) -> bool:
    if "fingerprint" in entry:
        target = entry["fingerprint"]
        if finding.get("id") == target or _fingerprint(finding) == target:
            return True
    if "rule" in entry:
        if _rule_id(finding) == entry["rule"]:
            return True
        if finding.get("short_name", "").lower() == entry["rule"].lower():
            return True
    if "path_prefix" in entry:
        loc_file = finding.get("location", {}).get("file", "")
        if loc_file.startswith(entry["path_prefix"]):
            return True
    return False


def apply_suppressions(
    pipeline: dict,
    suppressions: list[dict],
    report_lines: list[str],
) -> dict:
    today = date.today()
    active: list[dict] = []
    expired: list[dict] = []

    for entry in suppressions:
        if _is_expired(entry):
            expired.append(entry)
        else:
            active.append(entry)

    for e in expired:
        report_lines.append(
            f"EXPIRED suppression ignored: {e.get('fingerprint') or e.get('rule') or e.get('path_prefix')} "
            f"(expired {e.get('expires')})"
        )

    kept: list[dict] = []
    suppressed_count = 0

    for finding in pipeline.get("findings", []):
        matched_entry: dict | None = None
        for entry in active:
            if _matches(finding, entry):
                matched_entry = entry
                break

        if matched_entry:
            suppressed_count += 1
            loc = finding.get("location", {})
            report_lines.append(
                f"SUPPRESSED: {loc.get('file')}:{loc.get('function')} "
                f"[{finding.get('stage1_verdict')}] — {matched_entry.get('reason', 'no reason given')} "
                f"(added by {matched_entry.get('added_by', '?')} on {matched_entry.get('added_date', '?')})"
            )
        else:
            kept.append(finding)

    result = dict(pipeline)
    result["findings"] = kept

    # Patch metrics to reflect filtered counts
    metrics = dict(result.get("metrics") or {})
    for verdict in ("vulnerable", "bypassable", "inconclusive"):
        metrics[verdict] = sum(
            1 for f in kept if f.get("stage1_verdict", "").lower() == verdict
        )
    result["metrics"] = metrics
    result["_suppressions_applied"] = {
        "total_suppressed": suppressed_count,
        "expired_ignored": len(expired),
        "date": today.isoformat(),
    }

    if not report_lines:
        report_lines.append(f"No findings matched any suppression rule (checked {len(active)} active rules).")
    else:
        report_lines.insert(0, f"Suppressions applied: {suppressed_count} finding(s) removed, {len(kept)} remaining.")

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Filter OpenAnt findings against a suppression list")
    parser.add_argument("--input",        required=True, help="Path to pipeline_output.json")
    parser.add_argument("--suppressions", required=True, help="Path to .openant-suppress.yml")
    parser.add_argument("--output",       required=True, help="Path for filtered pipeline_output.json")
    parser.add_argument("--report",       help="Path for human-readable suppression report (optional)")
    args = parser.parse_args()

    input_path = Path(args.input)
    supp_path  = Path(args.suppressions)

    if not input_path.exists():
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        return 1
    if not supp_path.exists():
        print(f"Error: suppression file not found: {supp_path}", file=sys.stderr)
        return 1

    try:
        pipeline = json.loads(input_path.read_text())
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in {input_path}: {e}", file=sys.stderr)
        return 1

    try:
        supp_data = yaml.safe_load(supp_path.read_text()) or {}
    except yaml.YAMLError as e:
        print(f"Error: invalid YAML in {supp_path}: {e}", file=sys.stderr)
        return 1

    suppressions: list[dict] = supp_data.get("suppressions", [])
    report_lines: list[str] = []

    filtered = apply_suppressions(pipeline, suppressions, report_lines)

    Path(args.output).write_text(json.dumps(filtered, indent=2))

    report_text = "\n".join(report_lines)
    if args.report:
        Path(args.report).write_text(report_text)
    else:
        print(report_text)

    return 0


if __name__ == "__main__":
    sys.exit(main())

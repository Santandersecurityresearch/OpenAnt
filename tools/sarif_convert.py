#!/usr/bin/env python3
"""
sarif_convert.py — Convert OpenAnt output to SARIF 2.1.0.

Accepts either:
  pipeline_output.json  — Stage 2-confirmed findings only
  results_verified.json — Full Stage 1 + Stage 2 results (preferred)

When given results_verified.json, all Stage 1 flagged units are emitted so
they appear in the GitHub Security tab, with SARIF level reflecting how far
each finding got through the pipeline:

  Stage 2 confirmed (agreed)     → error   (Critical)
  Stage 2 disagreed              → warning (needs manual review)
  Stage 1 only / not verified    → warning
  Inconclusive                   → note

Usage:
    python tools/sarif_convert.py results_verified.json -o results.sarif
    python tools/sarif_convert.py pipeline_output.json  -o results.sarif
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

_LEVEL_ERROR   = "error"
_LEVEL_WARNING = "warning"
_LEVEL_NOTE    = "note"

_SECURITY_SEVERITY = {
    _LEVEL_ERROR:   "9.0",   # Critical
    _LEVEL_WARNING: "6.5",   # High
    _LEVEL_NOTE:    "4.0",   # Medium
}


# ---------------------------------------------------------------------------
# results_verified.json conversion
# ---------------------------------------------------------------------------

def _level_from_verified_result(result: dict) -> str | None:
    """
    Determine SARIF level for a result from results_verified.json.
    Returns None if the result should be omitted (safe, protected).
    """
    stage1 = result.get("finding", "").lower()
    verif  = result.get("verification") or {}
    agreed = verif.get("agree")

    if stage1 in ("safe", "protected", ""):
        return None
    if stage1 == "inconclusive":
        return _LEVEL_NOTE
    if stage1 in ("vulnerable", "bypassable"):
        if agreed is True:
            return _LEVEL_ERROR      # Stage 2 confirmed
        if agreed is False:
            return _LEVEL_WARNING    # Stage 2 disagrees — still flag for review
        return _LEVEL_WARNING        # Not yet verified — flag for review
    return None


def _unit_id_to_file_and_function(unit_id: str) -> tuple[str, str]:
    """
    Split a unit_id like 'bad/libuser.py:login' into (file, function).
    Handles bare module-level unit_ids like 'bad/libuser.py:__module__'.
    """
    if ":" in unit_id:
        parts = unit_id.rsplit(":", 1)
        return parts[0], parts[1]
    return unit_id, ""


def _stage2_label(result: dict) -> str:
    verif = result.get("verification") or {}
    agreed = verif.get("agree")
    if agreed is True:
        return "Stage 2 confirmed exploitable"
    if agreed is False:
        return "Stage 2 could not confirm exploit path — manual review recommended"
    return "Stage 2 verification not run"


def convert_verified(verified: dict) -> dict[str, Any]:
    """Convert results_verified.json to SARIF 2.1.0."""
    results_raw = verified.get("results", [])
    repo_url    = verified.get("repository", {}).get("url", "")
    commit_sha  = verified.get("repository", {}).get("commit_sha", "")

    sarif_results: list[dict] = []
    rules_seen: set[str] = set()
    rules: list[dict] = []

    for idx, r in enumerate(results_raw):
        level = _level_from_verified_result(r)
        if level is None:
            continue

        unit_id = r.get("unit_id", r.get("route_key", f"unit-{idx}"))
        file_path, function_name = _unit_id_to_file_and_function(unit_id)
        stage1 = r.get("finding", "inconclusive").lower()

        # Build rule id from unit (no CWE in this schema)
        rule_id = f"openant/{stage1}"
        rule_label = {
            "vulnerable":   "Vulnerable",
            "bypassable":   "Bypassable security control",
            "inconclusive": "Inconclusive",
        }.get(stage1, stage1.title())

        if rule_id not in rules_seen:
            rules.append({
                "id": rule_id,
                "name": rule_label,
                "shortDescription": {"text": rule_label},
                "fullDescription": {"text": f"OpenAnt Stage 1 verdict: {rule_label}"},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "security-severity": _SECURITY_SEVERITY[level],
                    "tags": ["security"],
                },
            })
            rules_seen.add(rule_id)

        # Build message
        reasoning = r.get("reasoning", "") or ""
        stage2_note = _stage2_label(r)
        verif = r.get("verification") or {}
        verif_explanation = verif.get("explanation", "") or ""

        msg_parts = []
        if reasoning:
            msg_parts.append(reasoning[:400])
        msg_parts.append(stage2_note)
        if verif_explanation:
            msg_parts.append(f"Stage 2 detail: {verif_explanation[:300]}")

        sarif_results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": "\n\n".join(msg_parts) or "Potential vulnerability detected"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": file_path,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"name": function_name, "kind": "function"}] if function_name else [],
            }],
            "partialFingerprints": {
                "primaryLocationLineHash": unit_id,
            },
            "properties": {
                "security-severity": _SECURITY_SEVERITY[level],
                "openant/stage1_verdict": stage1,
                "openant/stage2_agreed": str(verif.get("agree", "not_verified")),
            },
        })

    return _wrap_sarif(rules, sarif_results, repo_url, commit_sha)


# ---------------------------------------------------------------------------
# pipeline_output.json conversion (original path, kept as fallback)
# ---------------------------------------------------------------------------

_VERDICT_TO_LEVEL: dict[str, str] = {
    "vulnerable":   _LEVEL_ERROR,
    "bypassable":   _LEVEL_WARNING,
    "inconclusive": _LEVEL_NOTE,
}

_VERDICT_TO_SECURITY_SEVERITY: dict[str, str] = {
    "vulnerable":   "9.0",
    "bypassable":   "6.5",
    "inconclusive": "4.0",
}


def _rule_id_pipeline(finding: dict) -> str:
    cwe = finding.get("cwe_id")
    if cwe and int(cwe) > 0:
        return f"CWE-{cwe}"
    return f"openant/{finding.get('short_name', 'finding').lower().replace(' ', '-')}"


def convert_pipeline(pipeline_output: dict) -> dict[str, Any]:
    """Convert pipeline_output.json to SARIF 2.1.0."""
    repo       = pipeline_output.get("repository", {})
    repo_url   = repo.get("url", "")
    commit_sha = repo.get("commit_sha", "")

    actionable = set(_VERDICT_TO_LEVEL.keys())
    findings = [
        f for f in pipeline_output.get("findings", [])
        if f.get("stage1_verdict", "").lower() in actionable
    ]

    rules_seen: set[str] = set()
    rules: list[dict] = []
    sarif_results: list[dict] = []

    for f in findings:
        verdict  = f.get("stage1_verdict", "inconclusive").lower()
        level    = _VERDICT_TO_LEVEL.get(verdict, _LEVEL_NOTE)
        location = f.get("location", {})
        file_path     = location.get("file", "")
        function_name = location.get("function", "")
        rid = _rule_id_pipeline(f)

        if rid not in rules_seen:
            cwe_id   = f.get("cwe_id")
            cwe_name = f.get("cwe_name", "")
            rule: dict[str, Any] = {
                "id": rid,
                "name": f.get("short_name", "Vulnerability"),
                "shortDescription": {"text": f.get("name", cwe_name or "Vulnerability")},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "security-severity": _VERDICT_TO_SECURITY_SEVERITY.get(verdict, "4.0"),
                    "tags": ["security"],
                },
            }
            if cwe_id and int(cwe_id) > 0:
                rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
            rules.append(rule)
            rules_seen.add(rid)

        parts = [f.get("description") or f.get("name", "Vulnerability detected")]
        if function_name:
            parts.append(f"Function: `{function_name}`")
        if f.get("suggested_fix"):
            parts.append(f"Suggested fix: {f['suggested_fix']}")

        sarif_results.append({
            "ruleId": rid,
            "level": level,
            "message": {"text": "\n\n".join(parts)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"name": function_name, "kind": "function"}] if function_name else [],
            }],
            "partialFingerprints": {"primaryLocationLineHash": f["id"]},
            "properties": {
                "security-severity": _VERDICT_TO_SECURITY_SEVERITY.get(verdict, "4.0"),
                "openant/stage1_verdict": verdict,
                "openant/stage2_verdict": f.get("stage2_verdict", "").lower(),
            },
        })

    return _wrap_sarif(rules, sarif_results, repo_url, commit_sha)


# ---------------------------------------------------------------------------
# Shared SARIF wrapper
# ---------------------------------------------------------------------------

def _wrap_sarif(rules: list, results: list, repo_url: str, commit_sha: str) -> dict[str, Any]:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "OpenAnt",
                    "informationUri": "https://github.com/knostic/OpenAnt",
                    "version": "1.0.0",
                    "rules": rules,
                }
            },
            "results": results,
            "versionControlProvenance": [{
                "repositoryUri": repo_url,
                "revisionId": commit_sha,
            }] if repo_url else [],
            "columnKind": "utf16CodeUnits",
        }],
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert OpenAnt output to SARIF 2.1.0",
    )
    parser.add_argument("input", help="Path to results_verified.json or pipeline_output.json")
    parser.add_argument("-o", "--output", help="Output SARIF file path (default: stdout)")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        return 1

    try:
        data = json.loads(input_path.read_text())
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in {input_path}: {e}", file=sys.stderr)
        return 1

    # Auto-detect format by key presence
    if "results" in data and "verify" in data:
        sarif = convert_verified(data)
    else:
        sarif = convert_pipeline(data)

    sarif_text = json.dumps(sarif, indent=2)

    if args.output:
        Path(args.output).write_text(sarif_text)
        count = len(sarif["runs"][0]["results"])
        print(f"SARIF written to {args.output} ({count} findings)", file=sys.stderr)
    else:
        print(sarif_text)

    return 0


if __name__ == "__main__":
    sys.exit(main())

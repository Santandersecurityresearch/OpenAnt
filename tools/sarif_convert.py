#!/usr/bin/env python3
"""
sarif_convert.py — Convert OpenAnt pipeline_output.json to SARIF 2.1.0.

Usage:
    python tools/sarif_convert.py pipeline_output.json -o results.sarif
    python tools/sarif_convert.py pipeline_output.json  # writes to stdout

SARIF 2.1.0 spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
GitHub SARIF upload docs: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning

Only findings with stage1_verdict in {vulnerable, bypassable, inconclusive} are
emitted; protected/safe findings are omitted to keep the Security tab signal-rich.
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

# SARIF levels: error | warning | note
# GitHub maps: error → High, warning → Medium/Low, note → Note
_VERDICT_TO_LEVEL: dict[str, str] = {
    "vulnerable": "error",
    "bypassable": "warning",
    "inconclusive": "note",
}

# GitHub Code Scanning severity labels (shown in the UI filter)
# Injected as a property because SARIF level alone is coarse.
_VERDICT_TO_SECURITY_SEVERITY: dict[str, str] = {
    "vulnerable": "critical",
    "bypassable": "high",
    "inconclusive": "medium",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rule_id(finding: dict) -> str:
    """Stable rule ID from CWE number, e.g. 'CWE-78'."""
    cwe = finding.get("cwe_id")
    if cwe and int(cwe) > 0:
        return f"CWE-{cwe}"
    return f"openant/{finding['short_name'].lower().replace(' ', '-')}"


def _finding_to_result(finding: dict, repo_root: str) -> dict[str, Any]:
    """Map a single OpenAnt finding to a SARIF result object."""
    location = finding.get("location", {})
    file_path = location.get("file", "")
    function_name = location.get("function", "")
    verdict = finding.get("stage1_verdict", "inconclusive").lower()
    level = _VERDICT_TO_LEVEL.get(verdict, "note")

    # Build a helpful message that includes all useful context.
    parts = [finding.get("description") or finding.get("name", "Vulnerability detected")]
    if function_name:
        parts.append(f"Function: `{function_name}`")
    if finding.get("suggested_fix"):
        parts.append(f"Suggested fix: {finding['suggested_fix']}")
    message_text = "\n\n".join(parts)

    result: dict[str, Any] = {
        "ruleId": _rule_id(finding),
        "level": level,
        "message": {"text": message_text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": file_path,
                        "uriBaseId": "%SRCROOT%",
                    },
                    # Line number is not in the Finding schema; default to 1.
                    # The file+function context in the message compensates.
                    "region": {"startLine": 1},
                },
                "logicalLocations": [
                    {
                        "name": function_name,
                        "kind": "function",
                    }
                ] if function_name else [],
            }
        ],
        "partialFingerprints": {
            # Stable fingerprint so GitHub deduplicates across scans.
            "primaryLocationLineHash": finding["id"],
        },
        "properties": {
            "security-severity": _VERDICT_TO_SECURITY_SEVERITY.get(verdict, "medium"),
            "openant/stage1_verdict": verdict,
            "openant/stage2_verdict": finding.get("stage2_verdict", "").lower(),
            "openant/cwe_name": finding.get("cwe_name", ""),
        },
    }

    # Attach the vulnerable code snippet as a code flow if present.
    code = finding.get("vulnerable_code")
    if code:
        result["codeFlows"] = [
            {
                "message": {"text": "Vulnerable code snippet"},
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": file_path,
                                            "uriBaseId": "%SRCROOT%",
                                        },
                                        "region": {"startLine": 1},
                                    },
                                    "message": {"text": code[:500]},
                                }
                            }
                        ]
                    }
                ],
            }
        ]

    return result


def _finding_to_rule(finding: dict) -> dict[str, Any]:
    """Map a finding to the SARIF rules/reportingDescriptors entry."""
    cwe_id = finding.get("cwe_id")
    cwe_name = finding.get("cwe_name", "")
    verdict = finding.get("stage1_verdict", "inconclusive").lower()
    security_severity = _VERDICT_TO_SECURITY_SEVERITY.get(verdict, "medium")

    rule: dict[str, Any] = {
        "id": _rule_id(finding),
        "name": finding.get("short_name", "Vulnerability"),
        "shortDescription": {"text": finding.get("name", cwe_name or "Vulnerability")},
        "fullDescription": {
            "text": (
                f"{finding.get('name', '')}. "
                f"CWE-{cwe_id}: {cwe_name}." if cwe_id else finding.get("name", "")
            )
        },
        "defaultConfiguration": {
            "level": _VERDICT_TO_LEVEL.get(verdict, "note"),
        },
        "properties": {
            "security-severity": security_severity,
            "tags": ["security", f"CWE-{cwe_id}"] if cwe_id else ["security"],
        },
    }

    if cwe_id:
        rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
        rule["help"] = {
            "text": (
                f"CWE-{cwe_id}: {cwe_name}. "
                f"See https://cwe.mitre.org/data/definitions/{cwe_id}.html"
            )
        }

    return rule


# ---------------------------------------------------------------------------
# Main conversion
# ---------------------------------------------------------------------------

def convert(pipeline_output: dict) -> dict[str, Any]:
    """Convert a pipeline_output dict to a SARIF 2.1.0 document."""
    repo = pipeline_output.get("repository", {})
    repo_url = repo.get("url", "")
    commit_sha = repo.get("commit_sha", "")

    # Only emit actionable findings (drop protected/safe).
    # Normalise verdict to lowercase before comparing.
    actionable_verdicts = set(_VERDICT_TO_LEVEL.keys())
    findings = [
        f for f in pipeline_output.get("findings", [])
        if f.get("stage1_verdict", "").lower() in actionable_verdicts
    ]

    # Deduplicate rules by rule ID.
    rules_seen: set[str] = set()
    rules: list[dict] = []
    for f in findings:
        rid = _rule_id(f)
        if rid not in rules_seen:
            rules.append(_finding_to_rule(f))
            rules_seen.add(rid)

    results = [_finding_to_result(f, "") for f in findings]

    sarif: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OpenAnt",
                        "informationUri": "https://github.com/knostic/OpenAnt",
                        "version": "1.0.0",
                        "rules": rules,
                        "properties": {
                            "description": (
                                "Two-stage LLM-powered SAST: Stage 1 detects vulnerabilities, "
                                "Stage 2 simulates attacker exploitation to eliminate false positives."
                            )
                        },
                    }
                },
                "results": results,
                "versionControlProvenance": [
                    {
                        "repositoryUri": repo_url,
                        "revisionId": commit_sha,
                    }
                ] if repo_url else [],
                "columnKind": "utf16CodeUnits",
            }
        ],
    }

    return sarif


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert OpenAnt pipeline_output.json to SARIF 2.1.0",
    )
    parser.add_argument(
        "input",
        help="Path to pipeline_output.json",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output SARIF file path (default: stdout)",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        return 1

    try:
        pipeline_output = json.loads(input_path.read_text())
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in {input_path}: {e}", file=sys.stderr)
        return 1

    sarif = convert(pipeline_output)
    sarif_text = json.dumps(sarif, indent=2)

    if args.output:
        Path(args.output).write_text(sarif_text)
        finding_count = len(sarif["runs"][0]["results"])
        print(f"SARIF written to {args.output} ({finding_count} findings)", file=sys.stderr)
    else:
        print(sarif_text)

    return 0


if __name__ == "__main__":
    sys.exit(main())

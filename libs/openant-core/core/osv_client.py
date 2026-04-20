"""
osv_client.py — Query the OSV.dev vulnerability database.

Uses the OSV batch query API (https://api.osv.dev/v1/querybatch) to check
a list of packages against all known advisories in one round-trip per 1 000
packages. No API key required; OSV is a free public service.

Supports all OSV ecosystems: PyPI, npm, Go, crates.io, Maven, RubyGems,
Packagist, NuGet, Hex, and more.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from typing import Any

import requests

from core.manifest_parser import Dependency


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_BATCH_SIZE   = 1_000   # OSV hard limit per request
_TIMEOUT      = 30      # seconds per HTTP call
_MAX_RETRIES  = 3


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------

@dataclass
class Advisory:
    osv_id: str               # e.g. "GHSA-j8r2-6x86-q33q"
    aliases: list[str]        # CVE IDs etc.
    summary: str
    severity: str             # CRITICAL / HIGH / MODERATE / LOW / UNKNOWN
    cvss_score: float | None  # numeric score if available
    fixed_version: str | None # first version that fixes the vuln
    url: str | None           # primary reference URL

    def to_dict(self) -> dict:
        return {
            "osv_id": self.osv_id,
            "aliases": self.aliases,
            "summary": self.summary,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "fixed_version": self.fixed_version,
            "url": self.url,
        }


@dataclass
class PackageAdvisories:
    dependency: Dependency
    advisories: list[Advisory] = field(default_factory=list)

    @property
    def is_vulnerable(self) -> bool:
        return len(self.advisories) > 0

    def to_dict(self) -> dict:
        return {
            **self.dependency.to_dict(),
            "vulnerable": self.is_vulnerable,
            "advisory_count": len(self.advisories),
            "advisories": [a.to_dict() for a in self.advisories],
        }


@dataclass
class OsvQueryResult:
    results: list[PackageAdvisories] = field(default_factory=list)
    packages_checked: int = 0
    vulnerable_packages: int = 0
    total_advisories: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "packages_checked": self.packages_checked,
            "vulnerable_packages": self.vulnerable_packages,
            "total_advisories": self.total_advisories,
            "errors": self.errors,
            "findings": [r.to_dict() for r in self.results if r.is_vulnerable],
        }


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

def _extract_severity(vuln: dict) -> tuple[str, float | None]:
    """Return (severity_label, cvss_score) from an OSV vuln object."""
    # GitHub Advisory DB and others put severity in database_specific
    db_specific = vuln.get('database_specific') or {}
    label = (db_specific.get('severity') or '').upper()

    # Some ecosystems use ecosystem_specific
    if not label:
        eco_specific = vuln.get('ecosystem_specific') or {}
        label = (eco_specific.get('severity') or '').upper()

    # Normalise GitHub labels ("MODERATE" → keep as-is; others may differ)
    severity_map = {'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH',
                    'MODERATE': 'MODERATE', 'MEDIUM': 'MODERATE',
                    'LOW': 'LOW', 'NONE': 'LOW'}
    label = severity_map.get(label, label or 'UNKNOWN')

    # Numeric CVSS score
    score: float | None = None
    cvss_data = db_specific.get('cvss') or {}
    if isinstance(cvss_data, dict):
        raw_score = cvss_data.get('score') or cvss_data.get('baseScore')
        if raw_score is not None:
            try:
                score = float(raw_score)
            except (TypeError, ValueError):
                pass

    # If no label but we have a score, derive label from score
    if label == 'UNKNOWN' and score is not None:
        if score >= 9.0:
            label = 'CRITICAL'
        elif score >= 7.0:
            label = 'HIGH'
        elif score >= 4.0:
            label = 'MODERATE'
        else:
            label = 'LOW'

    return label, score


def _extract_fixed_version(vuln: dict, ecosystem: str) -> str | None:
    """Extract the first fixed version from OSV affected ranges."""
    for affected in (vuln.get('affected') or []):
        for rng in (affected.get('ranges') or []):
            for event in (rng.get('events') or []):
                fixed = event.get('fixed')
                if fixed:
                    return fixed
    return None


def _extract_url(vuln: dict) -> str | None:
    """Return the primary reference URL (prefer advisory, then CVE, then first ref)."""
    refs = vuln.get('references') or []
    for ref_type in ('ADVISORY', 'WEB'):
        for ref in refs:
            if ref.get('type') == ref_type:
                return ref.get('url')
    return refs[0].get('url') if refs else None


def _parse_advisory(vuln: dict, ecosystem: str) -> Advisory:
    osv_id  = vuln.get('id', 'UNKNOWN')
    aliases = [a for a in (vuln.get('aliases') or []) if a]
    summary = vuln.get('summary') or vuln.get('details') or 'No description available'
    # Truncate very long summaries
    if len(summary) > 300:
        summary = summary[:297] + '...'

    severity, score  = _extract_severity(vuln)
    fixed_version    = _extract_fixed_version(vuln, ecosystem)
    url              = _extract_url(vuln)

    return Advisory(
        osv_id=osv_id,
        aliases=aliases,
        summary=summary,
        severity=severity,
        cvss_score=score,
        fixed_version=fixed_version,
        url=url,
    )


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _post_with_retry(
    url: str,
    payload: dict,
    timeout: int = _TIMEOUT,
    max_retries: int = _MAX_RETRIES,
) -> dict:
    """POST *payload* to *url* with exponential backoff on 429/5xx."""
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.post(url, json=payload, timeout=timeout)
            if resp.status_code == 429:
                wait = 2 ** attempt
                print(f"[OSV] Rate limited; retrying in {wait}s…", file=sys.stderr)
                time.sleep(wait)
                continue
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            if attempt == max_retries:
                raise
            wait = 2 ** attempt
            print(f"[OSV] Request failed ({exc}); retry {attempt}/{max_retries} in {wait}s",
                  file=sys.stderr)
            time.sleep(wait)
    return {}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def query_packages(
    dependencies: list[Dependency],
    include_unpinned: bool = True,
) -> OsvQueryResult:
    """Query OSV for all *dependencies* and return advisory results.

    Args:
        dependencies:     List of Dependency objects from manifest_parser.
        include_unpinned: If True (default), also query packages whose version
                          is a range/constraint (best-effort with extracted
                          lower bound). Set False to only query exact versions.

    Returns:
        OsvQueryResult with per-package advisory lists.
    """
    to_query = [
        d for d in dependencies
        if d.version or include_unpinned
    ]

    if not to_query:
        return OsvQueryResult()

    # Skip packages with no version at all unless we have a name to query
    to_query = [d for d in to_query if d.name]

    result = OsvQueryResult(packages_checked=len(to_query))
    pkg_results: list[PackageAdvisories] = [
        PackageAdvisories(dependency=d) for d in to_query
    ]

    print(
        f"[OSV] Querying {len(to_query)} package(s) across "
        f"{len({d.ecosystem for d in to_query})} ecosystem(s)…",
        file=sys.stderr,
    )

    # Batch requests in chunks of _BATCH_SIZE
    for chunk_start in range(0, len(to_query), _BATCH_SIZE):
        chunk_deps  = to_query[chunk_start: chunk_start + _BATCH_SIZE]
        chunk_pkgs  = pkg_results[chunk_start: chunk_start + _BATCH_SIZE]

        queries = []
        for dep in chunk_deps:
            q: dict[str, Any] = {
                "package": {
                    "name":      dep.name,
                    "ecosystem": dep.ecosystem,
                }
            }
            if dep.version:
                q["version"] = dep.version
            queries.append(q)

        try:
            response = _post_with_retry(OSV_BATCH_URL, {"queries": queries})
        except requests.RequestException as exc:
            err = f"OSV batch query failed: {exc}"
            result.errors.append(err)
            print(f"[OSV] Error: {err}", file=sys.stderr)
            continue

        for pkg_result, osv_response in zip(chunk_pkgs, response.get('results', [])):
            for vuln in (osv_response.get('vulns') or []):
                advisory = _parse_advisory(vuln, pkg_result.dependency.ecosystem)
                pkg_result.advisories.append(advisory)

    result.results            = pkg_results
    result.vulnerable_packages = sum(1 for p in pkg_results if p.is_vulnerable)
    result.total_advisories   = sum(len(p.advisories) for p in pkg_results)

    print(
        f"[OSV] Done: {result.vulnerable_packages}/{len(to_query)} packages "
        f"have known advisories ({result.total_advisories} total).",
        file=sys.stderr,
    )
    return result

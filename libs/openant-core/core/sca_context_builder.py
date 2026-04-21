"""
sca_context_builder.py — Build per-file and repo-level SCA context for LLM prompts.

Resolves which source files import vulnerable packages and formats the data
for injection into Stage 1 and Stage 2 prompts. No LLM calls; cost is
negligible (one filesystem walk + import regex per file).

Produces two outputs:
  ScaContext.repo_summary  — short text for the app context block (Layer 1)
  ScaContext.file_index    — {relative_path: formatted_text} for per-unit injection (Layer 2)
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.osv_client import OsvQueryResult, PackageAdvisories


# ---------------------------------------------------------------------------
# Import alias table (import name → canonical normalised package name)
# Covers the most common cases where import name ≠ package name.
# ---------------------------------------------------------------------------

_PYTHON_ALIASES: dict[str, str] = {
    "yaml":        "pyyaml",
    "PIL":         "pillow",
    "pil":         "pillow",
    "cv2":         "opencv-python",
    "sklearn":     "scikit-learn",
    "bs4":         "beautifulsoup4",
    "jwt":         "pyjwt",
    "dateutil":    "python-dateutil",
    "dotenv":      "python-dotenv",
    "Crypto":      "pycryptodome",
    "crypto":      "pycryptodome",
    "OpenSSL":     "pyopenssl",
    "MySQLdb":     "mysql-connector-python",
    "google.cloud": "google-cloud",
    "usb":         "pyusb",
    "magic":       "python-magic",
    "serial":      "pyserial",
    "gi":          "pygobject",
    "wx":          "wxpython",
    "pkg_resources": "setuptools",
}

_SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__",
    ".tox", "dist", "build", "target", ".cargo",
}

_SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".go", ".rb", ".php",
}


# ---------------------------------------------------------------------------
# Import extractors
# ---------------------------------------------------------------------------

def _extract_python_imports(text: str) -> set[str]:
    names: set[str] = set()
    for m in re.finditer(r"^import\s+([\w, ]+)", text, re.MULTILINE):
        for part in m.group(1).split(","):
            pkg = part.strip().split(" as ")[0].strip().split(".")[0]
            if pkg:
                names.add(pkg)
    for m in re.finditer(r"^from\s+([A-Za-z0-9_\-]+)", text, re.MULTILINE):
        pkg = m.group(1).split(".")[0]
        if pkg and not pkg.startswith("."):
            names.add(pkg)
    return names


def _extract_js_imports(text: str) -> set[str]:
    names: set[str] = set()
    # require('pkg') / require("pkg")
    for m in re.finditer(r"""require\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)""", text):
        names.add(m.group(1).split("/")[0])
    # import ... from 'pkg'
    for m in re.finditer(r"""from\s+['"]([^'"./][^'"]*)['"]\s*""", text):
        names.add(m.group(1).split("/")[0])
    # import 'pkg'  (side-effect import)
    for m in re.finditer(r"""import\s+['"]([^'"./][^'"]*)['"]\s*""", text):
        names.add(m.group(1).split("/")[0])
    return names


def _extract_go_imports(text: str) -> set[str]:
    names: set[str] = set()
    # Single import: import "github.com/foo/bar"
    for m in re.finditer(r'^import\s+"([^"]+)"', text, re.MULTILINE):
        names.add(m.group(1))
    # Import block
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("import ("):
            in_block = True
            continue
        if in_block:
            if stripped == ")":
                in_block = False
                continue
            m = re.search(r'"([^"]+)"', stripped)
            if m:
                names.add(m.group(1))
    return names


def _extract_ruby_imports(text: str) -> set[str]:
    names: set[str] = set()
    for m in re.finditer(r"""require\s+['"]([^'"]+)['"]""", text):
        names.add(m.group(1))
    return names


def _extract_php_imports(text: str) -> set[str]:
    names: set[str] = set()
    # use Vendor\Package\Class
    for m in re.finditer(r"^use\s+([A-Za-z0-9_\\]+)", text, re.MULTILINE):
        parts = m.group(1).split("\\")
        if len(parts) >= 2:
            names.add(f"{parts[0]}/{parts[1]}".lower())
    return names


_EXTRACTOR_BY_EXT = {
    ".py":   _extract_python_imports,
    ".js":   _extract_js_imports,
    ".ts":   _extract_js_imports,
    ".jsx":  _extract_js_imports,
    ".tsx":  _extract_js_imports,
    ".mjs":  _extract_js_imports,
    ".cjs":  _extract_js_imports,
    ".go":   _extract_go_imports,
    ".rb":   _extract_ruby_imports,
    ".php":  _extract_php_imports,
}


# ---------------------------------------------------------------------------
# Package name normalisation and matching
# ---------------------------------------------------------------------------

def _normalise(name: str) -> str:
    return re.sub(r"[-_. ]", "", name.lower())


def _imports_match_package(import_names: set[str], pkg_name: str, ecosystem: str) -> bool:
    """Return True if any import name in *import_names* matches *pkg_name*."""
    norm_pkg = _normalise(pkg_name)

    for raw in import_names:
        # Apply alias table for Python
        canonical = _PYTHON_ALIASES.get(raw, raw)
        if _normalise(canonical) == norm_pkg:
            return True
        # Direct normalised match
        if _normalise(raw) == norm_pkg:
            return True
        # For Go: full module path match
        if ecosystem == "Go" and (raw == pkg_name or raw.startswith(pkg_name + "/")):
            return True

    return False


# ---------------------------------------------------------------------------
# Context formatting
# ---------------------------------------------------------------------------

_SEV_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "⚠️ ",
    "MODERATE": "🟡",
    "LOW":      "🔵",
    "UNKNOWN":  "❓",
}


def _format_advisories_for_file(pkg_list: list["PackageAdvisories"]) -> str:
    """Format a list of PackageAdvisories as a prompt-ready text block."""
    lines = [
        "## Vulnerable Dependencies in This File",
        "",
        "The following packages imported by this file have known security advisories.",
        "Factor these into your assessment — if this code calls into affected APIs,",
        "the risk is elevated.",
        "",
    ]
    for pkg in pkg_list:
        dep = pkg.dependency
        for adv in pkg.advisories:
            icon = _SEV_ICON.get(adv.severity, "❓")
            cve  = adv.aliases[0] if adv.aliases else adv.osv_id
            fix  = f"  → Fixed in: {adv.fixed_version}" if adv.fixed_version else ""
            lines += [
                f"  {icon} {dep.name} {dep.version}  [{adv.severity}]",
                f"     {cve}: {adv.summary[:120]}{'...' if len(adv.summary) > 120 else ''}",
            ]
            if fix:
                lines.append(f"     {fix}")
            lines.append("")

    lines += [
        "Note: a vulnerable dependency does not automatically mean this function is",
        "exploitable — assess whether the affected code path is reachable from",
        "user-controlled input through this specific function.",
        "",
    ]
    return "\n".join(lines)


def _format_repo_summary(vulnerable_pkgs: list["PackageAdvisories"]) -> str:
    """Short text for the app context block (Layer 1)."""
    if not vulnerable_pkgs:
        return ""

    total = len(vulnerable_pkgs)
    lines = [
        "## Dependency Security Posture",
        "",
        f"⚠️  {total} package{'s' if total != 1 else ''} in this repository "
        "{'have' if total != 1 else 'has'} known vulnerabilities:",
        "",
    ]
    for pkg in vulnerable_pkgs[:10]:  # cap display to 10
        dep = pkg.dependency
        top = pkg.advisories[0]
        icon = _SEV_ICON.get(top.severity, "❓")
        cve  = top.aliases[0] if top.aliases else top.osv_id
        lines.append(f"  {icon} {dep.name} {dep.version} → {top.severity} ({cve})")

    if total > 10:
        lines.append(f"  … and {total - 10} more.")

    lines += [
        "",
        "When analyzing code that imports these packages, pay extra attention to",
        "functions that interact with the affected APIs.",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main context object
# ---------------------------------------------------------------------------

@dataclass
class ScaContext:
    """SCA context ready for injection into LLM prompts."""
    repo_summary: str                    # Layer 1: injected alongside app context
    file_index: dict[str, str]           # Layer 2: rel_path → formatted advisory text
    vulnerable_package_count: int = 0
    total_advisory_count: int = 0

    def get_file_dep_context(self, file_path: str) -> str | None:
        """Return formatted dep context for *file_path*, or None if no vulns found.

        Tries exact match, then suffix match (handles absolute vs relative paths).
        """
        if not file_path:
            return None

        # Exact match
        if file_path in self.file_index:
            return self.file_index[file_path]

        # Strip leading slashes / normalise
        norm = file_path.lstrip("/")
        if norm in self.file_index:
            return self.file_index[norm]

        # Suffix match — unit_id may carry a full abs path; index stores relative
        for indexed_path, text in self.file_index.items():
            if norm.endswith(indexed_path) or indexed_path.endswith(norm):
                return text

        return None


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_sca_context(repo_path: str, osv_result: "OsvQueryResult") -> ScaContext | None:
    """Build a ScaContext from an OsvQueryResult by resolving imports in source files.

    Returns None if there are no vulnerable packages (nothing to inject).
    """
    vulnerable_pkgs = [p for p in osv_result.results if p.is_vulnerable]
    if not vulnerable_pkgs:
        return None

    repo_root = Path(repo_path).resolve()
    file_index: dict[str, str] = {}

    # Walk repository source files
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]

        for filename in filenames:
            ext = Path(filename).suffix.lower()
            extractor = _EXTRACTOR_BY_EXT.get(ext)
            if extractor is None:
                continue

            filepath = Path(dirpath) / filename
            try:
                text = filepath.read_text(errors="replace")
            except OSError:
                continue

            import_names = extractor(text)
            if not import_names:
                continue

            # Find which vulnerable packages are imported by this file
            matched: list["PackageAdvisories"] = []
            for pkg in vulnerable_pkgs:
                dep = pkg.dependency
                if _imports_match_package(import_names, dep.name, dep.ecosystem):
                    matched.append(pkg)

            if matched:
                rel = str(filepath.relative_to(repo_root))
                file_index[rel] = _format_advisories_for_file(matched)

    repo_summary = _format_repo_summary(vulnerable_pkgs)

    return ScaContext(
        repo_summary=repo_summary,
        file_index=file_index,
        vulnerable_package_count=len(vulnerable_pkgs),
        total_advisory_count=osv_result.total_advisories,
    )

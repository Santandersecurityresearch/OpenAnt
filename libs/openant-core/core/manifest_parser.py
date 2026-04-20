"""
manifest_parser.py — Discover and parse dependency manifests in a repository.

Supported formats and ecosystems:
  requirements.txt / requirements-*.txt / requirements/*.txt  → PyPI
  pyproject.toml ([project.dependencies] + [tool.poetry.dependencies])  → PyPI
  package.json (dependencies + devDependencies + peerDependencies)       → npm
  go.mod (require directives)                                             → Go
  Cargo.toml ([dependencies] + [dev-dependencies])                       → crates.io
  pom.xml (<dependencies>)                                               → Maven
  Gemfile.lock                                                           → RubyGems
  composer.json (require + require-dev)                                  → Packagist

Returns a list of Dependency objects. Version extraction is best-effort:
  - pinned=True  when the version is exact (==, bare in go.mod, lock file)
  - pinned=False when a range or constraint is present (>=, ^, ~, *)
  The `version` field always contains the lowest/best-effort version string so
  OSV lookups have something to work with even for unpinned deps.
"""

from __future__ import annotations

import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Dependency:
    name: str
    version: str          # exact or lower-bound; empty string if completely unpinned
    ecosystem: str        # OSV ecosystem identifier
    manifest_file: str    # path relative to repo root
    pinned: bool = True   # False = version is a range/constraint, not exact

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "manifest_file": self.manifest_file,
            "pinned": self.pinned,
        }


@dataclass
class ManifestParseResult:
    dependencies: list[Dependency] = field(default_factory=list)
    manifests_found: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.dependencies)

    @property
    def pinned_count(self) -> int:
        return sum(1 for d in self.dependencies if d.pinned)


# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------

_RANGE_OPS = re.compile(r'^[><=!~^*]+')
_EXTRAS    = re.compile(r'\[.*?\]')


def _clean_version(raw: str) -> tuple[str, bool]:
    """Return (version_string, is_pinned) from a raw version specifier.

    Examples:
      "==2.28.0"  → ("2.28.0", True)
      ">=2.28.0"  → ("2.28.0", False)
      "^4.18.0"   → ("4.18.0", False)
      "~1.0"      → ("1.0",    False)
      "4.18.0"    → ("4.18.0", True)   # bare version treated as exact
      "*"         → ("",       False)
      ""          → ("",       False)
    """
    raw = raw.strip().strip('"').strip("'")
    if not raw or raw in ('*', 'latest', 'x', 'X'):
        return '', False

    # Comma-separated constraints like ">=3.2,<4.0" — take the first
    first = raw.split(',')[0].strip()

    pinned = not bool(_RANGE_OPS.match(first))
    version = _RANGE_OPS.sub('', first).strip()
    # Strip pre-release/build metadata for cleaner OSV matching
    version = re.sub(r'[+].*$', '', version).strip()
    return version, pinned


def _strip_extras(name: str) -> str:
    """Remove PEP 508 extras from a package name: flask[async] → flask."""
    return _EXTRAS.sub('', name).strip()


# ---------------------------------------------------------------------------
# Per-format parsers
# ---------------------------------------------------------------------------

def _parse_requirements_txt(path: Path, repo_root: Path) -> list[Dependency]:
    """Parse a PEP 508 requirements file."""
    deps: list[Dependency] = []
    rel = str(path.relative_to(repo_root))

    for raw_line in path.read_text(errors='replace').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#') or line.startswith('-'):
            continue
        # Strip inline comments
        line = re.split(r'\s+#', line)[0].strip()
        # Skip VCS / URL deps
        if re.match(r'^(git\+|https?://|file://)', line, re.IGNORECASE):
            continue

        # Split name from version specifier: "requests>=2.28.0" or "requests==2.28.0"
        m = re.match(r'^([A-Za-z0-9_.\-]+(?:\[[^\]]*\])?)\s*(.*)', line)
        if not m:
            continue

        name    = _strip_extras(m.group(1))
        spec    = m.group(2).strip()
        version, pinned = _clean_version(spec)

        deps.append(Dependency(
            name=name,
            version=version,
            ecosystem='PyPI',
            manifest_file=rel,
            pinned=pinned,
        ))

    return deps


def _parse_pyproject_toml(path: Path, repo_root: Path) -> list[Dependency]:
    """Parse [project.dependencies] and [tool.poetry.dependencies] from pyproject.toml."""
    deps: list[Dependency] = []
    rel = str(path.relative_to(repo_root))
    text = path.read_text(errors='replace')

    # --- [project] PEP 621 style ---
    # dependencies = ["requests>=2.28", "flask==2.3.0"]
    pep621_match = re.search(
        r'\[project\].*?^dependencies\s*=\s*\[(.*?)\]',
        text, re.DOTALL | re.MULTILINE,
    )
    if pep621_match:
        for item in re.findall(r'"([^"]+)"', pep621_match.group(1)):
            m = re.match(r'^([A-Za-z0-9_.\-]+(?:\[[^\]]*\])?)\s*(.*)', item.strip())
            if m:
                name = _strip_extras(m.group(1))
                version, pinned = _clean_version(m.group(2))
                deps.append(Dependency(name=name, version=version,
                                       ecosystem='PyPI', manifest_file=rel, pinned=pinned))

    # --- [tool.poetry.dependencies] ---
    # requests = "^2.28.0"
    # flask = {version = "^2.3.0", ...}
    poetry_block = re.search(
        r'\[tool\.poetry\.dependencies\](.*?)(?=^\[|\Z)',
        text, re.DOTALL | re.MULTILINE,
    )
    if poetry_block:
        for line in poetry_block.group(1).splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('['):
                continue
            m = re.match(r'^([a-zA-Z0-9_.\-]+)\s*=\s*(.+)', line)
            if not m:
                continue
            name = m.group(1).strip()
            if name.lower() == 'python':
                continue
            spec = m.group(2).strip()
            # Inline table: { version = "^1.0" }
            version_m = re.search(r'version\s*=\s*"([^"]*)"', spec)
            if version_m:
                version, pinned = _clean_version(version_m.group(1))
            else:
                version, pinned = _clean_version(spec.strip('"').strip("'"))
            deps.append(Dependency(name=name, version=version,
                                   ecosystem='PyPI', manifest_file=rel, pinned=pinned))

    return deps


def _parse_package_json(path: Path, repo_root: Path) -> list[Dependency]:
    """Parse npm dependencies from package.json."""
    deps: list[Dependency] = []
    rel = str(path.relative_to(repo_root))

    try:
        data = json.loads(path.read_text(errors='replace'))
    except json.JSONDecodeError:
        return deps

    dep_keys = ('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies')
    for key in dep_keys:
        for name, spec in (data.get(key) or {}).items():
            if not isinstance(spec, str):
                continue
            # Skip VCS / file / workspace deps
            if re.match(r'^(git[+:]|https?://|file:|workspace:)', spec, re.IGNORECASE):
                continue
            version, pinned = _clean_version(spec)
            deps.append(Dependency(name=name, version=version,
                                   ecosystem='npm', manifest_file=rel, pinned=pinned))

    return deps


def _parse_go_mod(path: Path, repo_root: Path) -> list[Dependency]:
    """Parse go.mod require directives. All go.mod versions are exact."""
    deps: list[Dependency] = []
    rel = str(path.relative_to(repo_root))
    text = path.read_text(errors='replace')

    # require github.com/foo/bar v1.2.3
    for m in re.finditer(r'^\s*require\s+(\S+)\s+(v\S+)', text, re.MULTILINE):
        name, version = m.group(1), m.group(2).lstrip('v')
        deps.append(Dependency(name=name, version=version,
                               ecosystem='Go', manifest_file=rel, pinned=True))

    # require ( ... ) block
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('require ('):
            in_block = True
            continue
        if in_block:
            if stripped == ')':
                in_block = False
                continue
            if stripped.startswith('//'):
                continue
            m = re.match(r'(\S+)\s+(v\S+)', stripped)
            if m:
                name, version = m.group(1), m.group(2).lstrip('v')
                # Skip indirect markers in the version
                version = version.split(' ')[0]
                deps.append(Dependency(name=name, version=version,
                                       ecosystem='Go', manifest_file=rel, pinned=True))

    return deps


def _parse_cargo_toml(path: Path, repo_root: Path) -> list[Dependency]:
    """Parse Cargo.toml [dependencies] and [dev-dependencies]."""
    deps: list[Dependency] = []
    rel = str(path.relative_to(repo_root))
    text = path.read_text(errors='replace')

    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r'^\[(dev-)?dependencies\]', stripped, re.IGNORECASE):
            in_deps = True
            continue
        if stripped.startswith('[') and in_deps:
            in_deps = False
            continue
        if not in_deps or not stripped or stripped.startswith('#'):
            continue

        # serde = "1.0.193"
        m = re.match(r'^([a-zA-Z0-9_\-]+)\s*=\s*"([^"]*)"', stripped)
        if m:
            version, pinned = _clean_version(m.group(2))
            deps.append(Dependency(name=m.group(1), version=version,
                                   ecosystem='crates.io', manifest_file=rel, pinned=pinned))
            continue

        # serde = { version = "1.0", ... }
        m = re.match(r'^([a-zA-Z0-9_\-]+)\s*=\s*\{', stripped)
        if m:
            name = m.group(1)
            version_m = re.search(r'version\s*=\s*"([^"]*)"', stripped)
            if version_m:
                version, pinned = _clean_version(version_m.group(1))
                deps.append(Dependency(name=name, version=version,
                                       ecosystem='crates.io', manifest_file=rel, pinned=pinned))

    return deps


def _parse_pom_xml(path: Path, repo_root: Path) -> list[Dependency]:
    """Parse Maven pom.xml <dependencies>."""
    deps: list[Dependency] = []
    rel = str(path.relative_to(repo_root))

    try:
        tree = ET.parse(str(path))
    except ET.ParseError:
        return deps

    root = tree.getroot()
    # Handle namespace
    ns_m = re.match(r'(\{[^}]+\})', root.tag)
    ns = ns_m.group(1) if ns_m else ''

    for dep_el in root.iter(f'{ns}dependency'):
        group_id   = (dep_el.findtext(f'{ns}groupId')    or '').strip()
        artifact_id = (dep_el.findtext(f'{ns}artifactId') or '').strip()
        version_raw = (dep_el.findtext(f'{ns}version')    or '').strip()
        scope       = (dep_el.findtext(f'{ns}scope')      or 'compile').strip()

        # Skip test scope
        if scope == 'test':
            continue
        if not group_id or not artifact_id:
            continue

        name = f'{group_id}:{artifact_id}'
        # Maven versions are typically exact; property placeholders (${...}) are not
        pinned = bool(version_raw) and not version_raw.startswith('${')
        version = version_raw if pinned else ''

        deps.append(Dependency(name=name, version=version,
                               ecosystem='Maven', manifest_file=rel, pinned=pinned))

    return deps


def _parse_gemfile_lock(path: Path, repo_root: Path) -> list[Dependency]:
    """Parse Gemfile.lock GEM specs (exact versions)."""
    deps: list[Dependency] = []
    rel = str(path.relative_to(repo_root))
    text = path.read_text(errors='replace')

    in_specs = False
    for line in text.splitlines():
        if line.strip() == 'GEM':
            continue
        if '  specs:' in line:
            in_specs = True
            continue
        if in_specs:
            if line and not line.startswith(' '):
                in_specs = False
                continue
            # "    rails (7.0.4)" — 4-space indent = top-level gem
            m = re.match(r'^    ([a-zA-Z0-9_\-]+)\s+\(([^\)]+)\)\s*$', line)
            if m:
                deps.append(Dependency(
                    name=m.group(1),
                    version=m.group(2).split(',')[0].strip(),
                    ecosystem='RubyGems',
                    manifest_file=rel,
                    pinned=True,
                ))

    return deps


def _parse_composer_json(path: Path, repo_root: Path) -> list[Dependency]:
    """Parse PHP composer.json require and require-dev."""
    deps: list[Dependency] = []
    rel = str(path.relative_to(repo_root))

    try:
        data = json.loads(path.read_text(errors='replace'))
    except json.JSONDecodeError:
        return deps

    for key in ('require', 'require-dev'):
        for name, spec in (data.get(key) or {}).items():
            if name.lower() == 'php' or '/' not in name:
                continue
            version, pinned = _clean_version(str(spec))
            deps.append(Dependency(name=name, version=version,
                                   ecosystem='Packagist', manifest_file=rel, pinned=pinned))

    return deps


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

# Files to skip entirely
_SKIP_DIRS = {
    '.git', 'node_modules', 'vendor', '.venv', 'venv', '__pycache__',
    '.tox', 'dist', 'build', 'target', '.cargo',
}

# (filename_pattern, parser_function)
_MANIFEST_PARSERS: list[tuple[re.Pattern, object]] = [
    (re.compile(r'^requirements.*\.txt$', re.IGNORECASE), _parse_requirements_txt),
    (re.compile(r'^pyproject\.toml$',    re.IGNORECASE), _parse_pyproject_toml),
    (re.compile(r'^package\.json$',      re.IGNORECASE), _parse_package_json),
    (re.compile(r'^go\.mod$',            re.IGNORECASE), _parse_go_mod),
    (re.compile(r'^Cargo\.toml$',        re.IGNORECASE), _parse_cargo_toml),
    (re.compile(r'^pom\.xml$',           re.IGNORECASE), _parse_pom_xml),
    (re.compile(r'^Gemfile\.lock$',      re.IGNORECASE), _parse_gemfile_lock),
    (re.compile(r'^composer\.json$',     re.IGNORECASE), _parse_composer_json),
]


def parse_manifests(repo_path: str) -> ManifestParseResult:
    """Walk *repo_path* and parse all dependency manifests found.

    Returns a ManifestParseResult with all discovered dependencies,
    the list of manifest files found, and any parse errors encountered.
    """
    root = Path(repo_path).resolve()
    result = ManifestParseResult()

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune traversal into ignored directories
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]

        for filename in filenames:
            for pattern, parser in _MANIFEST_PARSERS:
                if pattern.match(filename):
                    filepath = Path(dirpath) / filename
                    try:
                        deps = parser(filepath, root)
                        if deps:
                            result.manifests_found.append(
                                str(filepath.relative_to(root))
                            )
                            result.dependencies.extend(deps)
                    except Exception as exc:
                        rel = str(filepath.relative_to(root))
                        result.errors.append(f"{rel}: {exc}")
                        print(f"[Manifest] Warning: failed to parse {rel}: {exc}",
                              file=sys.stderr)
                    break  # only one parser per file

    # Deduplicate: keep first occurrence of (name, ecosystem)
    seen: set[tuple[str, str]] = set()
    unique: list[Dependency] = []
    for dep in result.dependencies:
        key = (dep.name.lower(), dep.ecosystem)
        if key not in seen:
            seen.add(key)
            unique.append(dep)
    result.dependencies = unique

    print(
        f"[Manifest] Found {len(result.manifests_found)} manifest(s), "
        f"{result.total} unique dependencies "
        f"({result.pinned_count} pinned).",
        file=sys.stderr,
    )
    return result

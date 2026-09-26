import re
from dataclasses import dataclass

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from semantic_version import NpmSpec
from semantic_version import Version as SemVersion


@dataclass(frozen=True)
class VersionMatch:
    vulnerable: bool
    reason: str


def canonical_ecosystem(value: str) -> str:
    aliases = {
        "npm": "npm",
        "pypi": "pypi",
        "pip": "pypi",
        "python": "pypi",
        "maven": "maven",
        "nuget": "nuget",
        "golang": "go",
        "go": "go",
        "cargo": "cargo",
        "crates.io": "cargo",
    }
    return aliases.get(value.strip().lower(), value.strip().lower())


def normalize_package_name(ecosystem: str, name: str) -> str:
    normalized = name.strip()
    if canonical_ecosystem(ecosystem) == "pypi":
        return re.sub(r"[-_.]+", "-", normalized).lower()
    return normalized.lower()


def version_is_affected(ecosystem: str, version: str | None, affected_range: str) -> VersionMatch:
    if not version:
        return VersionMatch(False, "missing_resolved_version")
    ecosystem = canonical_ecosystem(ecosystem)
    try:
        if ecosystem == "npm":
            npm_range = re.sub(r"\s+", " ", affected_range.replace(",", " ")).strip()
            vulnerable = NpmSpec(npm_range).match(SemVersion.coerce(version))
        elif ecosystem == "pypi":
            vulnerable = Version(version) in SpecifierSet(affected_range)
        else:
            vulnerable = _comparator_range(version, affected_range)
    except (ValueError, InvalidVersion, InvalidSpecifier):
        return VersionMatch(False, "unsupported_or_invalid_range")
    return VersionMatch(
        vulnerable, "version_in_affected_range" if vulnerable else "version_not_affected"
    )


def _comparator_range(version: str, affected_range: str) -> bool:
    candidate = Version(version)
    clauses = [clause.strip() for clause in affected_range.split(",") if clause.strip()]
    if not clauses:
        return False
    comparisons = {
        "<": lambda left, right: left < right,
        "<=": lambda left, right: left <= right,
        ">": lambda left, right: left > right,
        ">=": lambda left, right: left >= right,
        "=": lambda left, right: left == right,
    }
    for clause in clauses:
        match = re.fullmatch(r"(<=|>=|<|>|=)?\s*v?(.+)", clause)
        if not match:
            return False
        operator, boundary = match.groups()
        if not comparisons[operator or "="](candidate, Version(boundary)):
            return False
    return True

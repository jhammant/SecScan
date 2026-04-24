"""Dependency manifest parsing + OSV.dev vulnerability lookup.

We read the *declared* manifest (not the lockfile) for a signal-rich view of
what the project intends to depend on. For Python we also read requirements.txt
and pyproject.toml. For Node we read package.json. Lockfiles remain skipped
by filters.py because their per-line LLM review is noisy; here we parse them
only to enrich versions when the manifest lacks them.
"""
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Any, Iterable

import httpx

from .models import DependencyAdvisory, DependencyFinding, Severity


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_TIMEOUT = 20.0


def scan_dependencies(repo_root: Path) -> list[DependencyFinding]:
    """Parse manifests and enrich with OSV advisories. Silent on network failure."""
    findings: list[DependencyFinding] = []
    for fn in _parsers:
        findings.extend(fn(repo_root))
    if not findings:
        return findings
    try:
        _enrich_with_osv(findings)
    except httpx.HTTPError:
        # Offline or rate-limited — return un-enriched list rather than fail the scan.
        pass
    return findings


# ---------------- manifest parsers ----------------

def _parse_npm(root: Root) -> list[DependencyFinding]:  # type: ignore[valid-type]
    out: list[DependencyFinding] = []
    for manifest in root.rglob("package.json"):
        if any(p in manifest.parts for p in ("node_modules",)):
            continue
        try:
            data = json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue
        rel = str(manifest.relative_to(root))
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            for name, version in (data.get(section) or {}).items():
                out.append(DependencyFinding(
                    ecosystem="npm", name=name, version=_clean_version(version), manifest=rel,
                ))
    return out


def _parse_python(root: Root) -> list[DependencyFinding]:  # type: ignore[valid-type]
    out: list[DependencyFinding] = []

    for req in list(root.rglob("requirements*.txt")) + list(root.rglob("requirements/*.txt")):
        rel = str(req.relative_to(root))
        try:
            for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.split("#", 1)[0].strip()
                if not line or line.startswith(("-", "git+", "http")):
                    continue
                name, version = _split_pep508(line)
                if name:
                    out.append(DependencyFinding(
                        ecosystem="PyPI", name=name, version=version, manifest=rel,
                    ))
        except OSError:
            continue

    for ppt in root.rglob("pyproject.toml"):
        rel = str(ppt.relative_to(root))
        try:
            import tomllib
        except ImportError:  # pragma: no cover — py<3.11
            break
        try:
            data = tomllib.loads(ppt.read_text(encoding="utf-8", errors="replace"))
        except (OSError, Exception):
            continue
        # PEP 621
        project = data.get("project") or {}
        for dep in project.get("dependencies", []) or []:
            name, version = _split_pep508(dep)
            if name:
                out.append(DependencyFinding(
                    ecosystem="PyPI", name=name, version=version, manifest=rel,
                ))
        # Poetry
        poetry_deps = (((data.get("tool") or {}).get("poetry") or {}).get("dependencies")) or {}
        for name, spec in poetry_deps.items():
            if name.lower() == "python":
                continue
            version = spec if isinstance(spec, str) else (spec or {}).get("version") if isinstance(spec, dict) else None
            out.append(DependencyFinding(
                ecosystem="PyPI", name=name, version=_clean_version(version), manifest=rel,
            ))
    return out


def _parse_go(root: Root) -> list[DependencyFinding]:  # type: ignore[valid-type]
    out: list[DependencyFinding] = []
    for gm in root.rglob("go.mod"):
        rel = str(gm.relative_to(root))
        try:
            text = gm.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Captures `require (` blocks and single-line `require` lines.
        block = False
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("require ("):
                block = True
                continue
            if block and s == ")":
                block = False
                continue
            if block or s.startswith("require "):
                parts = s.removeprefix("require ").split()
                if len(parts) >= 2:
                    out.append(DependencyFinding(
                        ecosystem="Go", name=parts[0], version=parts[1], manifest=rel,
                    ))
    return out


def _parse_rust(root: Root) -> list[DependencyFinding]:  # type: ignore[valid-type]
    out: list[DependencyFinding] = []
    try:
        import tomllib
    except ImportError:
        return out
    for cargo in root.rglob("Cargo.toml"):
        rel = str(cargo.relative_to(root))
        try:
            data = tomllib.loads(cargo.read_text(encoding="utf-8", errors="replace"))
        except (OSError, Exception):
            continue
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            deps = data.get(section) or {}
            for name, spec in deps.items():
                version = spec if isinstance(spec, str) else (spec or {}).get("version") if isinstance(spec, dict) else None
                out.append(DependencyFinding(
                    ecosystem="crates.io", name=name, version=_clean_version(version), manifest=rel,
                ))
    return out


def _parse_ruby(root: Root) -> list[DependencyFinding]:  # type: ignore[valid-type]
    out: list[DependencyFinding] = []
    for gf in root.rglob("Gemfile"):
        rel = str(gf.relative_to(root))
        try:
            text = gf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            m = re.match(r"\s*gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", line)
            if m:
                out.append(DependencyFinding(
                    ecosystem="RubyGems", name=m.group(1),
                    version=_clean_version(m.group(2)), manifest=rel,
                ))
    return out


Root = Path
_parsers = [_parse_npm, _parse_python, _parse_go, _parse_rust, _parse_ruby]


# ---------------- helpers ----------------

_PEP508_RE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]+\])?\s*(?:([<>=!~]=?|===)\s*([A-Za-z0-9_.\-*+]+))?"
)


def _split_pep508(spec: str) -> tuple[str | None, str | None]:
    m = _PEP508_RE.match(spec)
    if not m:
        return None, None
    name, _op, version = m.group(1), m.group(2), m.group(3)
    return name, version


def _clean_version(v: str | None) -> str | None:
    if not v:
        return None
    v = v.strip()
    # Strip leading specifiers like ^ ~ >= = v
    v = re.sub(r"^[~^>=<v\s]+", "", v)
    return v or None


# ---------------- OSV enrichment ----------------

def _enrich_with_osv(findings: Iterable[DependencyFinding]) -> None:
    findings = list(findings)
    if not findings:
        return

    queries: list[dict[str, Any]] = []
    for f in findings:
        q: dict[str, Any] = {"package": {"ecosystem": f.ecosystem, "name": f.name}}
        if f.version:
            q["version"] = f.version
        queries.append(q)

    # OSV batch caps at 1000 queries — chunk if needed.
    with httpx.Client(timeout=OSV_TIMEOUT) as client:
        for start in range(0, len(queries), 500):
            chunk = queries[start : start + 500]
            r = client.post(OSV_BATCH_URL, json={"queries": chunk})
            r.raise_for_status()
            results = r.json().get("results", [])
            for dep, res in zip(findings[start : start + 500], results):
                vulns = (res or {}).get("vulns") or []
                for v in vulns:
                    adv = _to_advisory(v)
                    if adv:
                        dep.advisories.append(adv)


def _to_advisory(v: dict[str, Any]) -> DependencyAdvisory | None:
    try:
        severity = _parse_severity(v)
        fixed = _fixed_versions(v)
        return DependencyAdvisory(
            id=str(v.get("id") or ""),
            summary=(v.get("summary") or v.get("details") or "")[:300],
            severity=severity,
            url=_first_url(v),
            fixed_in=fixed,
        )
    except Exception:
        return None


def _parse_severity(v: dict[str, Any]) -> Severity:
    # OSV severity is an array of {type, score}. We key off CVSS if present.
    for s in v.get("severity") or []:
        score_str = s.get("score") or ""
        m = re.search(r"/AV:[^ ]+", score_str)  # rough CVSS check
        if m:
            # Pull numeric score from "CVSS:3.1/AV:N/.../... 9.8"
            num = re.search(r"(\d+\.\d+)\s*$", score_str)
            if num:
                try:
                    val = float(num.group(1))
                    if val >= 9.0:
                        return Severity.CRITICAL
                    if val >= 7.0:
                        return Severity.HIGH
                    if val >= 4.0:
                        return Severity.MEDIUM
                    return Severity.LOW
                except ValueError:
                    pass
    # Fallback: database_specific.severity textual rating
    rating = ((v.get("database_specific") or {}).get("severity") or "").lower()
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "moderate": Severity.MEDIUM,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }.get(rating, Severity.MEDIUM)


def _fixed_versions(v: dict[str, Any]) -> list[str]:
    fixed: list[str] = []
    for affected in v.get("affected") or []:
        for r in affected.get("ranges") or []:
            for evt in r.get("events") or []:
                if "fixed" in evt:
                    fixed.append(str(evt["fixed"]))
    # dedupe while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for f in fixed:
        if f not in seen:
            seen.add(f); out.append(f)
    return out


def _first_url(v: dict[str, Any]) -> str | None:
    for ref in v.get("references") or []:
        if ref.get("type") in ("ADVISORY", "WEB", "FIX"):
            return ref.get("url")
    return None

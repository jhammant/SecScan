"""Synthesis + threat-modeling pass.

Inputs:
- Architecture document (from architecture.py)
- Per-file findings summary
- Dependency findings
- Repo-level hints

Outputs:
- Executive summary
- Systemic issues (patterns across files)
- Hotspots (files/components with the most risk)
- Per-lens grades
- NEW cross-cutting findings that the per-file scan couldn't see:
  trust-boundary bypasses, SSRF surfaces via integrations, auth gaps on
  specific routes, data exfiltration channels, privilege escalation paths.
"""
from __future__ import annotations
import json
from collections import Counter
from textwrap import dedent

from .lmstudio_client import LMStudioClient, LMStudioError
from .models import Finding, Grade, RepoScanResult, Severity, Synthesis


SYNTHESIS_SYSTEM = dedent("""
    You are a principal application security engineer producing a cross-cutting
    review of a codebase.

    You have already received per-file findings and an architecture document.
    Your job now is to identify issues that per-file review MISSED because they
    only make sense at the system level. Examples:

    - Auth middleware exists in component X but route Y is registered outside
      it and is therefore unauthenticated.
    - An HTTP client is constructed with a user-controlled URL (SSRF surface),
      reachable from an unauthenticated route.
    - Sensitive data flows from user input into logs, metrics, or third-party
      services without redaction.
    - Trust boundary between two components is weaker than assumed (shared
      secret in env, predictable tokens).
    - Dependency chain exposes the app to a known-vulnerable package in a
      code path that is actually reachable from user input.
    - Integration credentials are over-privileged or scoped wrongly.

    Also: produce a short executive summary, systemic issues list, hotspot
    list, and per-lens grades (A..F).

    Output STRICT JSON:
    {
      "executive_summary": "2-4 sentence overview",
      "systemic_issues": ["..."],
      "hotspots": ["src/auth/middleware.py — 7 findings, high severity"],
      "grades": [{"lens": "security", "grade": "C", "justification": "..."}],
      "cross_cutting_findings": [
        {
          "title": "Unauthenticated route bypasses auth middleware",
          "severity": "high",
          "confidence": "medium",
          "category": "Broken Access Control",
          "cwe": "CWE-862",
          "file": "src/routes/internal.py",
          "line_start": 12,
          "line_end": 28,
          "evidence": "short excerpt or structural description",
          "description": "why this is cross-cutting and how it's reached",
          "remediation": "concrete fix",
          "exploitable": true
        }
      ]
    }

    Keep total output concise. Prefer few, high-signal cross-cutting findings
    over a long noisy list.
""").strip()


def synthesize(client: LMStudioClient, result: RepoScanResult) -> Synthesis:
    # Guard against grading empty inputs. If architecture extraction did not
    # produce anything useful AND there are no per-file findings, the LLM has
    # nothing to reason over — calling it anyway tends to produce confident F
    # grades on non-existent evidence, which is worse than no report at all.
    if _inputs_are_empty(result):
        return Synthesis(
            executive_summary=(
                "Synthesis skipped: no architecture and no per-file findings were "
                "available. This usually means the architecture extraction pass "
                "failed (commonly: the loaded model's context window was smaller "
                "than the prompt). Re-run with a model loaded at a larger context "
                "length — see docs/CONFIGURATION.md — or check the scan log for an "
                "arch_error event. No grades are produced for empty input."
            ),
        )

    user_payload = _build_synthesis_input(result) + "\n\n/no_think"
    try:
        data = client.complete_json(
            SYNTHESIS_SYSTEM, user_payload, max_tokens=4096, temperature=0.15,
        )
    except LMStudioError as e:
        return Synthesis(executive_summary=f"(synthesis failed: {e})")

    return _coerce(data, result)


def _inputs_are_empty(result: RepoScanResult) -> bool:
    arch = result.architecture
    arch_empty = (
        arch is None
        or (
            not arch.components
            and not arch.integrations
            and not arch.trust_boundaries
            and not arch.data_flows
        )
    )
    findings_empty = not any(fr.findings for fr in result.files)
    deps_empty = not any(d.advisories for d in result.dependencies)
    return arch_empty and findings_empty and deps_empty


def _build_synthesis_input(result: RepoScanResult) -> str:
    findings = [f for fr in result.files for f in fr.findings]
    by_source = Counter(f.source for f in findings)
    top_files = Counter(f.file for f in findings).most_common(10)
    top_cats = Counter(f.category for f in findings).most_common(12)

    arch_json = result.architecture.model_dump() if result.architecture else {}
    # Keep per-finding payload compact — enough for triage, not full evidence.
    flat = [
        {
            "file": f.file,
            "line": f.line_start,
            "severity": f.severity.value,
            "confidence": f.confidence,
            "source": f.source,
            "category": f.category,
            "title": f.title,
        }
        for f in sorted(findings, key=lambda x: (-x.severity.weight, x.file))[:150]
    ]
    dep_summary = [
        {
            "ecosystem": d.ecosystem, "name": d.name, "version": d.version,
            "advisories": [a.id for a in d.advisories],
        }
        for d in result.dependencies if d.advisories
    ][:50]

    payload = {
        "architecture": arch_json,
        "counts_by_source": dict(by_source),
        "top_files_by_finding_count": top_files,
        "top_categories": top_cats,
        "findings": flat,
        "vulnerable_dependencies": dep_summary,
    }
    return "Review payload:\n\n" + json.dumps(payload, indent=2)


def _coerce(data: dict, result: RepoScanResult) -> Synthesis:
    def _as_list(v) -> list:
        return v if isinstance(v, list) else []

    grades = []
    for g in _as_list(data.get("grades")):
        if not isinstance(g, dict):
            continue
        grade = str(g.get("grade", "C")).upper()
        if grade not in ("A", "B", "C", "D", "F"):
            grade = "C"
        grades.append(Grade(
            lens=str(g.get("lens") or "overall"),
            grade=grade,  # type: ignore[arg-type]
            justification=str(g.get("justification") or ""),
        ))

    ccf: list[Finding] = []
    for f in _as_list(data.get("cross_cutting_findings")):
        if not isinstance(f, dict):
            continue
        try:
            finding = Finding(
                file=str(f.get("file") or "<architecture>"),
                line_start=int(f.get("line_start") or 0),
                line_end=int(f.get("line_end") or f.get("line_start") or 0),
                severity=Severity(str(f.get("severity", "medium")).lower()),
                category=str(f.get("category") or "Cross-cutting"),
                cwe=f.get("cwe"),
                title=str(f.get("title") or "Untitled cross-cutting issue"),
                description=str(f.get("description") or ""),
                evidence=str(f.get("evidence") or ""),
                remediation=str(f.get("remediation") or ""),
                confidence=str(f.get("confidence", "medium")).lower(),
                exploitable=bool(f.get("exploitable", False)),
                source="synthesis",
            )
            finding.ensure_id()
            ccf.append(finding)
        except Exception:
            continue

    return Synthesis(
        executive_summary=str(data.get("executive_summary") or ""),
        systemic_issues=[str(x) for x in _as_list(data.get("systemic_issues"))],
        hotspots=[str(x) for x in _as_list(data.get("hotspots"))],
        grades=grades,
        cross_cutting_findings=ccf,
    )

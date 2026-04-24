"""Verify LLM-generated findings by reading the actual cited source and
asking an adjudicator model to rule on whether the claim is supported.

Used to catch hallucinated findings, wrong line/file citations, and
false positives where downstream reasoning was built on a bad upstream signal.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from pathlib import Path
from textwrap import dedent
from typing import Literal

from .lmstudio_client import LMStudioClient, LMStudioError
from .models import Finding


VerdictT = Literal["verified", "wrong_line", "wrong_file", "false_positive", "needs_human"]


@dataclass
class Verdict:
    finding_id: str
    verdict: VerdictT
    confidence: str
    rationale: str
    attack_vector: str = ""
    preconditions: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "attack_vector": self.attack_vector,
            "preconditions": self.preconditions,
            "notes": self.notes,
        }


VERIFIER_SYSTEM = dedent("""
    You are a senior application security engineer performing adjudication of
    an automated finding. Another tool claimed a security issue exists at a
    specific file+line in a repo. You have been given:
      - the claim (title, description, severity, cited file, line range)
      - the actual source code surrounding that line

    Your job: rule on whether the claim is supported by the code AS SHOWN.

    Rules:
    - If the cited code clearly demonstrates the claimed issue, verdict = "verified".
    - If the code at the cited line is unrelated but similar code NEARBY would support
      the claim, verdict = "wrong_line".
    - If the file is entirely wrong (e.g. the claim is about network fetching but
      the file has no network code at all), verdict = "wrong_file".
    - If the cited code actively refutes the claim (e.g. claimed hardcoded key is
      a serialization function that constructs a PEM header), verdict = "false_positive".
    - If you cannot tell without more context, verdict = "needs_human".

    Do NOT be charitable — if the claim requires code outside what you can see,
    and what you can see doesn't contain it, say so.

    Output STRICT JSON, no markdown:
    {
      "verdict": "verified|wrong_line|wrong_file|false_positive|needs_human",
      "confidence": "low|medium|high",
      "rationale": "2-3 sentences explaining the verdict",
      "attack_vector": "If verified, describe the concrete attack in 2 sentences. Else empty.",
      "preconditions": ["list of things that must be true for exploitability"],
      "notes": "anything else worth flagging"
    }
    /no_think
""").strip()


def _read_context(repo_path: Path, rel_file: str, line_start: int, line_end: int,
                  pad: int = 15, max_lines: int = 220) -> tuple[str, int, int]:
    """Return (numbered source, shown_start, shown_end) — 1-indexed inclusive."""
    fp = repo_path / rel_file
    if not fp.exists():
        return f"<<file not found: {rel_file}>>", 0, 0
    try:
        lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        return f"<<read error: {e}>>", 0, 0

    if not lines:
        return "<<empty file>>", 0, 0

    # If the finding cited line 0/1 with no specific region, show the head of the file.
    if line_start <= 1 and line_end <= 1:
        start = 1
        end = min(len(lines), max_lines)
    else:
        start = max(1, line_start - pad)
        end = min(len(lines), line_end + pad)
        # Don't show more than max_lines
        if end - start + 1 > max_lines:
            end = start + max_lines - 1

    width = max(3, len(str(end)))
    rendered = "\n".join(
        f"{str(i).rjust(width)}  {lines[i - 1]}" for i in range(start, end + 1)
    )
    return rendered, start, end


def verify_finding(
    client: LMStudioClient,
    finding: Finding,
    repo_path: Path,
) -> Verdict:
    if not finding.file or finding.file.startswith("<"):
        return Verdict(
            finding_id=finding.id, verdict="needs_human", confidence="low",
            rationale="No concrete file cited — cannot verify from source.",
        )

    code, shown_start, shown_end = _read_context(
        repo_path, finding.file, finding.line_start, finding.line_end,
    )

    user = dedent(f"""
        Claim to verify:
        - title: {finding.title}
        - severity: {finding.severity.value}
        - source (what tool produced it): {finding.source}
        - file: {finding.file}
        - line range: {finding.line_start}-{finding.line_end}
        - category: {finding.category}{' (' + finding.cwe + ')' if finding.cwe else ''}
        - description: {finding.description[:1200]}

        Code shown (lines {shown_start}-{shown_end}):
        ```
        {code}
        ```

        Rule on the claim using the JSON schema in the system prompt.
        /no_think
    """).strip()

    try:
        data = client.complete_json(VERIFIER_SYSTEM, user, max_tokens=4096, temperature=0.1)
    except LMStudioError as e:
        return Verdict(
            finding_id=finding.id, verdict="needs_human", confidence="low",
            rationale=f"llm-error: {e}",
        )

    verdict_val = str(data.get("verdict", "needs_human")).lower()
    if verdict_val not in ("verified", "wrong_line", "wrong_file", "false_positive", "needs_human"):
        verdict_val = "needs_human"

    return Verdict(
        finding_id=finding.id,
        verdict=verdict_val,  # type: ignore[arg-type]
        confidence=str(data.get("confidence", "medium")).lower(),
        rationale=str(data.get("rationale", ""))[:800],
        attack_vector=str(data.get("attack_vector", ""))[:600],
        preconditions=[str(x) for x in (data.get("preconditions") or []) if isinstance(x, str)],
        notes=str(data.get("notes", ""))[:400],
    )


def verify_report(
    client: LMStudioClient,
    report_json_path: Path,
    clones_root: Path,
    severity_at_least: str = "high",
) -> dict:
    """Verify all findings in one report at or above a severity threshold.

    Returns a dict with verdicts keyed by finding id, plus a summary.
    """
    from .models import Severity  # local import to avoid cycle
    weight = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    floor = weight.get(severity_at_least, 3)

    data = json.loads(report_json_path.read_text())
    clone_path = Path(data.get("clone_path") or "")
    if not clone_path.exists():
        # Fall back to clones_root/<owner>/<name> if absolute path has moved
        repo = data["repo"]
        candidate = clones_root / repo
        if candidate.exists():
            clone_path = candidate

    all_findings: list[Finding] = []
    for fr in data.get("files", []) or []:
        for f in fr.get("findings") or []:
            try:
                all_findings.append(Finding(**f))
            except Exception:
                continue
    for f in (data.get("synthesis") or {}).get("cross_cutting_findings", []) or []:
        try:
            all_findings.append(Finding(**f))
        except Exception:
            continue

    verdicts: list[Verdict] = []
    for f in all_findings:
        if weight.get(f.severity.value, 0) < floor:
            continue
        v = verify_finding(client, f, clone_path)
        verdicts.append(v)

    summary = {"total": len(verdicts)}
    for v in verdicts:
        summary[v.verdict] = summary.get(v.verdict, 0) + 1
    return {"repo": data["repo"], "summary": summary, "verdicts": [v.to_dict() for v in verdicts]}

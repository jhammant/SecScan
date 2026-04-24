"""Markdown report + rich CLI summary."""
from __future__ import annotations
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .models import Architecture, RepoScanResult, Synthesis
from .scanner import sort_findings


SEVERITY_EMOJI = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


def write_markdown(result: RepoScanResult, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = result.repo.replace("/", "__")
    out = out_dir / f"{safe}.md"

    counts = result.counts
    src_counts = result.counts_by_source
    lines: list[str] = []
    lines.append(f"# Security Scan — {result.repo}")
    lines.append("")
    lines.append(f"- Commit: `{result.commit or 'unknown'}`")
    lines.append(f"- Model: `{result.model or 'unknown'}`")
    lines.append(f"- Lenses: `{', '.join(result.lenses_requested) or '(default)'}`")
    lines.append(f"- Started: {result.started_at.isoformat()}")
    if result.finished_at:
        lines.append(f"- Finished: {result.finished_at.isoformat()}")
    lines.append("")

    # --- Executive summary (if synthesis produced one) ---
    if result.synthesis and result.synthesis.executive_summary:
        lines.append("## Executive summary")
        lines.append("")
        lines.append(result.synthesis.executive_summary)
        lines.append("")

    # --- Counts ---
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {sev} | {counts[sev]} |")
    lines.append("")
    if src_counts:
        lines.append("| Source | Count |")
        lines.append("|---|---|")
        for k in sorted(src_counts):
            lines.append(f"| {k} | {src_counts[k]} |")
        lines.append("")

    # --- Grades + systemic issues + hotspots ---
    if result.synthesis:
        _render_synthesis(lines, result.synthesis)

    # --- Architecture ---
    if result.architecture:
        _render_architecture(lines, result.architecture)

    # --- Dependency advisories (standalone list too) ---
    vulnerable = [d for d in result.dependencies if d.advisories]
    if vulnerable:
        lines.append("## Vulnerable dependencies")
        lines.append("")
        lines.append("| Package | Version | Ecosystem | Advisories |")
        lines.append("|---|---|---|---|")
        for d in vulnerable:
            adv = ", ".join(a.id for a in d.advisories)
            lines.append(f"| `{d.name}` | `{d.version or '?'}` | {d.ecosystem} | {adv} |")
        lines.append("")

    # --- Findings ---
    findings = sort_findings(result.findings)
    if not findings:
        lines.append("_No findings._")
    else:
        lines.append("## Findings")
        lines.append("")
        for f in findings:
            lines.append(f"### [{f.severity.value.upper()}] [{f.source}] {f.title}")
            lines.append("")
            lines.append(f"- **ID:** `{f.id}`")
            lines.append(f"- **File:** `{f.file}:{f.line_start}-{f.line_end}`")
            lines.append(f"- **Category:** {f.category}" + (f" ({f.cwe})" if f.cwe else ""))
            lines.append(f"- **Confidence:** {f.confidence}")
            lines.append(f"- **Exploitable (model opinion):** {f.exploitable}")
            lines.append("")
            lines.append(f"**Description.** {f.description}")
            lines.append("")
            if f.evidence:
                lines.append("```")
                lines.append(f.evidence)
                lines.append("```")
                lines.append("")
            if f.remediation:
                lines.append(f"**Remediation.** {f.remediation}")
                lines.append("")

    # --- Skipped files ---
    skipped = [fr for fr in result.files if not fr.scanned]
    if skipped:
        lines.append("## Skipped files")
        lines.append("")
        lines.append("| File | Reason |")
        lines.append("|---|---|")
        for fr in skipped[:200]:
            lines.append(f"| `{fr.path}` | {fr.skipped_reason or fr.error or ''} |")
        if len(skipped) > 200:
            lines.append(f"| … | and {len(skipped) - 200} more |")
        lines.append("")

    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def _render_synthesis(lines: list[str], synth: Synthesis) -> None:
    if synth.grades:
        lines.append("## Grades")
        lines.append("")
        lines.append("| Lens | Grade | Justification |")
        lines.append("|---|---|---|")
        for g in synth.grades:
            lines.append(f"| {g.lens} | **{g.grade}** | {g.justification} |")
        lines.append("")
    if synth.systemic_issues:
        lines.append("## Systemic issues")
        lines.append("")
        for issue in synth.systemic_issues:
            lines.append(f"- {issue}")
        lines.append("")
    if synth.hotspots:
        lines.append("## Hotspots")
        lines.append("")
        for h in synth.hotspots:
            lines.append(f"- {h}")
        lines.append("")


def _render_architecture(lines: list[str], arch: Architecture) -> None:
    lines.append("## Architecture")
    lines.append("")
    if arch.summary:
        lines.append(arch.summary)
        lines.append("")
    if arch.auth_model:
        lines.append(f"**Auth model.** {arch.auth_model}")
        lines.append("")
    if arch.secrets_handling:
        lines.append(f"**Secrets handling.** {arch.secrets_handling}")
        lines.append("")

    if arch.components:
        lines.append("### Components")
        lines.append("")
        lines.append("| Name | Role | Entry points |")
        lines.append("|---|---|---|")
        for c in arch.components:
            ep = ", ".join(f"`{x}`" for x in c.entry_points[:4])
            lines.append(f"| {c.name} | {c.role} | {ep} |")
        lines.append("")

    if arch.integrations:
        lines.append("### External integrations")
        lines.append("")
        lines.append("| Name | Kind | Direction | Endpoint | Auth? | Notes |")
        lines.append("|---|---|---|---|---|---|")
        for i in arch.integrations:
            auth = "?" if i.authenticated is None else ("✓" if i.authenticated else "✗")
            lines.append(
                f"| {i.name} | {i.kind} | {i.direction} | "
                f"`{i.endpoint_hint or ''}` | {auth} | {i.notes} |"
            )
        lines.append("")

    if arch.trust_boundaries:
        lines.append("### Trust boundaries")
        lines.append("")
        for b in arch.trust_boundaries:
            lines.append(f"- **{b.description}**")
            if b.enforced_by:
                lines.append(f"  - enforced by: {', '.join(f'`{x}`' for x in b.enforced_by)}")
            for risk in b.bypass_risks:
                lines.append(f"  - risk: {risk}")
        lines.append("")

    if arch.data_flows:
        lines.append("### Data flows")
        lines.append("")
        for df in arch.data_flows:
            lines.append(f"- {df}")
        lines.append("")

    if arch.unknowns:
        lines.append("### Unresolved")
        lines.append("")
        for u in arch.unknowns:
            lines.append(f"- {u}")
        lines.append("")


def print_summary(console: Console, result: RepoScanResult) -> None:
    counts = result.counts
    table = Table(title=f"SecScan: {result.repo}")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev in ("critical", "high", "medium", "low", "info"):
        table.add_row(sev, str(counts[sev]))
    console.print(table)

    if result.synthesis and result.synthesis.grades:
        g = Table(title="Grades")
        g.add_column("Lens"); g.add_column("Grade"); g.add_column("Notes")
        for gr in result.synthesis.grades:
            g.add_row(gr.lens, gr.grade, gr.justification[:80])
        console.print(g)

    top = sort_findings(result.findings)[:10]
    if top:
        t2 = Table(title="Top findings")
        t2.add_column("Sev"); t2.add_column("Src"); t2.add_column("File"); t2.add_column("Line"); t2.add_column("Title")
        for f in top:
            t2.add_row(
                SEVERITY_EMOJI.get(f.severity.value, f.severity.value),
                f.source, f.file, str(f.line_start), f.title,
            )
        console.print(t2)

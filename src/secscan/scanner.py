"""Orchestrate a repo scan: clone → filter → per-file multi-lens LLM review
→ secrets + dependencies → architecture extraction → synthesis + threat model → aggregate.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable

from .config import settings
from .filters import FilterDecision, classify, detect_language, walk
from .github import GitHubClient, RepoRef, current_commit, parse_repo_url
from .lenses import Lens, SECURITY, QUALITY, resolve
from .lmstudio_client import LMStudioClient, LMStudioError
from .models import (
    FileScanResult,
    Finding,
    RepoScanResult,
    Severity,
    UserScanResult,
)
from .prompts import user_prompt


ProgressFn = Callable[[str, dict], None]


@dataclass
class ScanOptions:
    lenses: list[Lens] = field(default_factory=lambda: [SECURITY, QUALITY])
    enable_per_file: bool = True
    enable_secrets: bool = True
    enable_deps: bool = True
    enable_architecture: bool = True
    enable_synthesis: bool = True


class Scanner:
    def __init__(
        self,
        lmstudio: LMStudioClient,
        github: GitHubClient | None = None,
        progress: ProgressFn | None = None,
        options: ScanOptions | None = None,
    ):
        self.lm = lmstudio
        self.gh = github
        self.progress = progress or (lambda evt, data: None)
        self.opts = options or ScanOptions()

    # ---------- public entry points ----------

    def scan_repo_url(self, url_or_slug: str) -> RepoScanResult:
        owner, name = parse_repo_url(url_or_slug)
        if not self.gh:
            raise RuntimeError("GitHubClient required for URL scans")
        repo = self.gh.get_repo(owner, name)
        settings.ensure_dirs()
        path = self.gh.clone(repo, settings.clones_dir)
        return self.scan_local_repo(path, repo_label=repo.full_name)

    def scan_user(self, user: str, *, include_forks: bool = False) -> UserScanResult:
        if not self.gh:
            raise RuntimeError("GitHubClient required")
        settings.ensure_dirs()
        result = UserScanResult(user=user)
        repos = self.gh.list_user_repos(user, include_forks=include_forks)
        self.progress("user_repos_listed", {"user": user, "count": len(repos)})
        for repo in repos:
            path = self.gh.clone(repo, settings.clones_dir)
            rr = self.scan_local_repo(path, repo_label=repo.full_name)
            result.repos.append(rr)
        result.finished_at = datetime.utcnow()
        return result

    def scan_local_repo(self, path: Path, *, repo_label: str | None = None) -> RepoScanResult:
        path = path.resolve()
        label = repo_label or path.name
        result = RepoScanResult(
            repo=label,
            clone_path=str(path),
            commit=current_commit(path),
            model=self.lm.model,
            lenses_requested=[l.name for l in self.opts.lenses],
        )

        entries = walk(path)
        included = [(p, d) for p, d in entries if d.include]
        skipped = [(p, d) for p, d in entries if not d.include]
        self.progress("scan_start", {
            "repo": label,
            "included": len(included),
            "skipped": len(skipped),
            "lenses": [l.name for l in self.opts.lenses],
        })

        # --- per-file lens pass (skippable for fast triage runs) ---
        if not self.opts.enable_per_file:
            included = []
        for i, (fp, _decision) in enumerate(included):
            rel = str(fp.relative_to(path))
            self.progress("file_start", {"repo": label, "i": i + 1, "total": len(included), "file": rel})
            fr = self._scan_file(fp, path)
            result.files.append(fr)
            self.progress("file_done", {"repo": label, "file": fr.path, "findings": len(fr.findings)})

        for fp, decision in skipped:
            try:
                rel = str(fp.relative_to(path))
            except ValueError:
                continue
            result.files.append(FileScanResult(path=rel, scanned=False, skipped_reason=decision.reason))

        # --- non-LLM passes: secrets + deps ---
        if self.opts.enable_secrets:
            try:
                from .secrets_scan import scan_secrets
                self.progress("secrets_start", {"repo": label})
                secrets_findings = scan_secrets(path)
                self._attach_to_files(result, secrets_findings)
                self.progress("secrets_done", {"repo": label, "findings": len(secrets_findings)})
            except Exception as e:
                self.progress("secrets_error", {"repo": label, "err": str(e)})

        if self.opts.enable_deps:
            try:
                from .deps import scan_dependencies
                self.progress("deps_start", {"repo": label})
                dep_findings = scan_dependencies(path)
                result.dependencies = dep_findings
                # Emit advisories as Findings too so they appear in the main list.
                for df in dep_findings:
                    for adv in df.advisories:
                        f = Finding(
                            file=df.manifest,
                            line_start=0,
                            line_end=0,
                            severity=adv.severity,
                            category=f"Vulnerable dependency ({df.ecosystem})",
                            cwe=None,
                            title=f"{df.name}@{df.version or '?'} — {adv.summary[:80]}",
                            description=adv.summary + (f"\n\nAdvisory: {adv.url}" if adv.url else ""),
                            evidence=f"{df.name} {df.version or ''}".strip(),
                            remediation=(
                                f"Upgrade to: {', '.join(adv.fixed_in)}"
                                if adv.fixed_in else "Upgrade to a patched version."
                            ),
                            confidence="high",
                            exploitable=False,
                            source="dependency",
                        )
                        f.ensure_id()
                        self._attach_to_files(result, [f])
                self.progress("deps_done", {"repo": label, "packages": len(dep_findings)})
            except Exception as e:
                self.progress("deps_error", {"repo": label, "err": str(e)})

        # --- architecture pass (one LLM call for small repos, map-reduce for big) ---
        if self.opts.enable_architecture:
            try:
                from .architecture import extract_architecture
                from .architecture_hierarchical import (
                    extract_architecture_hierarchical,
                    flat_context_fits_budget,
                )
                self.progress("arch_start", {"repo": label})
                # If the flat repo-context prompt wouldn't fit ~12k tokens, go
                # hierarchical: one LLM call per subsystem, then one merge call.
                # Small/flat repos still use the fast single-call path.
                fits = flat_context_fits_budget(path)
                self.progress("arch_mode", {"repo": label,
                                              "mode": "flat" if fits else "hierarchical"})
                if fits:
                    result.architecture = extract_architecture(self.lm, path)
                else:
                    def _arch_progress(evt, data):
                        # Re-surface subsystem events under arch_* names for log clarity
                        self.progress(f"arch_{evt}", {**data, "repo": label})
                    result.architecture = extract_architecture_hierarchical(
                        self.lm, path, progress=_arch_progress,
                    )
                self.progress("arch_done", {"repo": label})
            except Exception as e:
                self.progress("arch_error", {"repo": label, "err": str(e)})

        # --- synthesis + threat modeling (uses architecture + findings) ---
        if self.opts.enable_synthesis:
            try:
                from .synthesis import synthesize
                self.progress("synth_start", {"repo": label})
                result.synthesis = synthesize(self.lm, result)
                self.progress("synth_done", {"repo": label})
            except Exception as e:
                self.progress("synth_error", {"repo": label, "err": str(e)})

        result.finished_at = datetime.utcnow()
        self.progress("scan_end", {"repo": label, "findings": len(result.findings)})
        return result

    # ---------- internals ----------

    def _scan_file(self, fp: Path, repo_root: Path) -> FileScanResult:
        rel = str(fp.relative_to(repo_root))
        rel_path = Path(rel)
        lang = detect_language(fp)
        try:
            code = fp.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return FileScanResult(path=rel, scanned=False, error=f"read:{e}")

        fr = FileScanResult(
            path=rel,
            language=lang,
            bytes=len(code.encode("utf-8", errors="replace")),
        )

        # One LLM call per lens that matches this file.
        lenses_for_file = [l for l in self.opts.lenses if l.matcher(rel_path)]
        fr.lenses_run = [l.name for l in lenses_for_file]

        for lens in lenses_for_file:
            try:
                data = self.lm.complete_json(lens.system_prompt, user_prompt(rel, lang, code))
            except LMStudioError as e:
                fr.error = (fr.error or "") + f" [{lens.name}] llm:{e};"
                continue
            except Exception as e:
                fr.error = (fr.error or "") + f" [{lens.name}] llm:{e.__class__.__name__};"
                continue

            for raw in data.get("findings", []) or []:
                try:
                    finding = Finding(
                        file=rel,
                        line_start=int(raw.get("line_start") or 0),
                        line_end=int(raw.get("line_end") or raw.get("line_start") or 0),
                        severity=Severity(str(raw.get("severity", "info")).lower()),
                        category=str(raw.get("category") or "Unclassified"),
                        cwe=raw.get("cwe"),
                        title=str(raw.get("title") or "Untitled issue"),
                        description=str(raw.get("description") or ""),
                        evidence=str(raw.get("evidence") or ""),
                        remediation=str(raw.get("remediation") or ""),
                        confidence=str(raw.get("confidence", "medium")).lower(),
                        exploitable=bool(raw.get("exploitable", False)),
                        source=lens.name,  # type: ignore[arg-type]
                    )
                    finding.ensure_id()
                    fr.findings.append(finding)
                except Exception as e:
                    fr.error = (fr.error or "") + f" [{lens.name}] bad-finding:{e};"
                    continue
        return fr

    # ---------- utilities ----------

    def _attach_to_files(self, result: RepoScanResult, findings: Iterable[Finding]) -> None:
        """Attach findings to the matching FileScanResult, or create a synthetic record."""
        by_path = {fr.path: fr for fr in result.files}
        for f in findings:
            fr = by_path.get(f.file)
            if fr is None:
                fr = FileScanResult(path=f.file, scanned=False, skipped_reason="auxiliary")
                result.files.append(fr)
                by_path[f.file] = fr
            fr.findings.append(f)


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity.weight, f.file, f.line_start))

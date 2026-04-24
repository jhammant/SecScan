"""Build a compact repo summary suitable for a single LLM prompt.

The LLM can't see the whole repo at once, so we give it:
- A pruned tree (source dirs + key config files)
- The content of known entrypoint/config files (capped)
- A deps manifest summary
- An endpoint hint derived from code grep (routes/handlers/urls)

This is shared input for the architecture extraction and synthesis passes.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from pathlib import Path

from .filters import SKIP_DIRS, classify


ENTRYPOINT_NAMES = {
    "package.json", "pyproject.toml", "requirements.txt", "Pipfile",
    "Gemfile", "go.mod", "Cargo.toml", "pom.xml", "build.gradle",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".env.example", "Procfile", "Makefile",
    "serverless.yml", "serverless.yaml",
}

ENTRYPOINT_EXTS = {
    "main.py", "app.py", "wsgi.py", "asgi.py", "manage.py",
    "index.js", "server.js", "main.js", "app.js",
    "index.ts", "server.ts", "main.ts", "app.ts",
    "main.go", "cmd/main.go",
    "main.rs", "src/main.rs",
}

_FILE_BUDGET = 6_000            # per-file char cap before truncation
_TREE_MAX_ENTRIES = 400         # cap on tree entries
_GREP_MAX = 40                  # cap per category


@dataclass
class RepoContext:
    tree: list[str] = field(default_factory=list)
    entrypoints: dict[str, str] = field(default_factory=dict)  # rel path -> (capped) content
    config_snippets: dict[str, str] = field(default_factory=dict)
    route_hints: list[str] = field(default_factory=list)        # grepped route decls
    http_client_hints: list[str] = field(default_factory=list)  # grepped outbound calls
    env_var_hints: list[str] = field(default_factory=list)      # grepped env var reads
    dep_summary: dict[str, list[str]] = field(default_factory=dict)  # ecosystem -> names

    def to_prompt_text(self) -> str:
        parts: list[str] = []
        parts.append("## Repo tree (pruned)")
        parts.append("\n".join(self.tree))
        if self.dep_summary:
            parts.append("\n## Declared dependencies")
            for eco, names in self.dep_summary.items():
                parts.append(f"- {eco}: {', '.join(names[:60])}" + ("…" if len(names) > 60 else ""))
        if self.route_hints:
            parts.append("\n## Route/handler hints")
            parts.extend(self.route_hints[:_GREP_MAX])
        if self.http_client_hints:
            parts.append("\n## Outbound HTTP / integration hints")
            parts.extend(self.http_client_hints[:_GREP_MAX])
        if self.env_var_hints:
            parts.append("\n## Env var reads")
            parts.extend(self.env_var_hints[:_GREP_MAX])
        if self.entrypoints:
            parts.append("\n## Entrypoint files")
            for rel, content in self.entrypoints.items():
                parts.append(f"\n### {rel}\n```\n{content}\n```")
        if self.config_snippets:
            parts.append("\n## Config snippets")
            for rel, content in self.config_snippets.items():
                parts.append(f"\n### {rel}\n```\n{content}\n```")
        return "\n".join(parts)


# ---------------- building ----------------

def build_context(repo_root: Path) -> RepoContext:
    ctx = RepoContext()
    _collect_tree(repo_root, ctx)
    _collect_entrypoints(repo_root, ctx)
    _collect_config(repo_root, ctx)
    _grep_hints(repo_root, ctx)
    _dep_summary(repo_root, ctx)
    return ctx


def _collect_tree(repo_root: Path, ctx: RepoContext) -> None:
    count = 0
    for p in sorted(repo_root.rglob("*")):
        try:
            rel = p.relative_to(repo_root)
        except ValueError:
            continue
        parts = rel.parts
        if any(s in SKIP_DIRS for s in parts):
            continue
        if p.is_dir():
            continue
        ctx.tree.append(str(rel))
        count += 1
        if count >= _TREE_MAX_ENTRIES:
            ctx.tree.append(f"... (+more, truncated at {_TREE_MAX_ENTRIES})")
            return


def _collect_entrypoints(repo_root: Path, ctx: RepoContext) -> None:
    wanted: list[Path] = []
    for p in repo_root.rglob("*"):
        if not p.is_file():
            continue
        if any(s in SKIP_DIRS for s in p.relative_to(repo_root).parts):
            continue
        if p.name in ENTRYPOINT_NAMES or p.name in ENTRYPOINT_EXTS:
            wanted.append(p)
    for p in wanted[:12]:
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(txt) > _FILE_BUDGET:
            txt = txt[:_FILE_BUDGET] + "\n... (truncated)"
        ctx.entrypoints[str(p.relative_to(repo_root))] = txt


def _collect_config(repo_root: Path, ctx: RepoContext) -> None:
    candidates = [
        "nginx.conf", "settings.py", "config.py", "config.yml", "config.yaml",
        "config.json", "application.yml", "application.yaml",
    ]
    for name in candidates:
        for p in repo_root.rglob(name):
            if any(s in SKIP_DIRS for s in p.relative_to(repo_root).parts):
                continue
            try:
                txt = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if len(txt) > _FILE_BUDGET:
                txt = txt[:_FILE_BUDGET] + "\n... (truncated)"
            ctx.config_snippets[str(p.relative_to(repo_root))] = txt
            if len(ctx.config_snippets) >= 6:
                return


_ROUTE_PATTERNS = [
    re.compile(r"@(app|router|api|blueprint|bp)\.(get|post|put|delete|patch|route|head|options)\(", re.I),
    re.compile(r"\b(router|app)\.(get|post|put|delete|patch|use|all)\s*\("),
    re.compile(r"\b(HandleFunc|Handle)\s*\("),                # net/http
    re.compile(r"\b(Get|Post|Put|Delete|Patch)Mapping\s*\("),  # Spring
    re.compile(r"^\s*resources\s+:"),                         # Rails
]

_HTTP_CLIENT_PATTERNS = [
    re.compile(r"\b(requests|httpx|urllib|axios|fetch|http\.Get|http\.Post|net\.http)\.[A-Za-z_]+\("),
    re.compile(r"boto3\.client\(|google\.cloud\.|stripe\.|anthropic\.|openai\."),
    re.compile(r"https?://[A-Za-z0-9.\-]+"),
]

_ENV_PATTERNS = [
    re.compile(r"os\.environ\[['\"]([A-Z_][A-Z0-9_]*)['\"]\]"),
    re.compile(r"os\.getenv\(['\"]([A-Z_][A-Z0-9_]*)['\"]"),
    re.compile(r"process\.env\.([A-Z_][A-Z0-9_]*)"),
    re.compile(r"ENV\[['\"]([A-Z_][A-Z0-9_]*)['\"]\]"),
]


def _grep_hints(repo_root: Path, ctx: RepoContext) -> None:
    routes: set[str] = set()
    clients: set[str] = set()
    env_vars: set[str] = set()
    for p in repo_root.rglob("*"):
        if not p.is_file():
            continue
        decision = classify(p, repo_root)
        if not decision.include:
            continue
        try:
            rel = str(p.relative_to(repo_root))
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            if len(routes) < _GREP_MAX:
                for pat in _ROUTE_PATTERNS:
                    if pat.search(line):
                        routes.add(f"{rel}:{i}: {line.strip()[:160]}")
                        break
            if len(clients) < _GREP_MAX:
                for pat in _HTTP_CLIENT_PATTERNS:
                    m = pat.search(line)
                    if m:
                        clients.add(f"{rel}:{i}: {line.strip()[:160]}")
                        break
            if len(env_vars) < _GREP_MAX:
                for pat in _ENV_PATTERNS:
                    m = pat.search(line)
                    if m:
                        env_vars.add(m.group(1))
                        break
    ctx.route_hints = sorted(routes)
    ctx.http_client_hints = sorted(clients)
    ctx.env_var_hints = sorted(env_vars)


def _dep_summary(repo_root: Path, ctx: RepoContext) -> None:
    try:
        from .deps import scan_dependencies
        deps = scan_dependencies(repo_root)
    except Exception:
        return
    by_eco: dict[str, list[str]] = {}
    for d in deps:
        by_eco.setdefault(d.ecosystem, []).append(d.name)
    ctx.dep_summary = by_eco

"""Hierarchical (map-reduce) architecture extraction for repos too big to fit
in a single prompt.

Strategy:
  1. Identify "subsystems" — the top-level directories beneath the repo root
     that contain source code (skipping tests, docs, ci, vendored libs, etc.).
     For monorepos these are usually obvious: `chia/`, `packages/web/`,
     `apps/api/`. For flat Python repos there may be only one subsystem.
  2. For each subsystem, build a scoped RepoContext (tree + entrypoints limited
     to that subsystem's file set) and run the existing `extract_architecture`
     prompt on it. Budget each per-subsystem prompt at ~8k tokens so even
     modest-context models succeed.
  3. Merge the subsystem Architectures into a single repo-level Architecture
     via one final LLM call. The merge prompt sees only the compact subsystem
     summaries (not their source), so it stays well inside budget.

Auto-trigger: scanner.py checks `flat_context_fits_budget()`; if not, uses this
module. Callers can also force it via `--hierarchical` once exposed in the CLI.
"""
from __future__ import annotations
import json
from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent
from typing import Callable

from .architecture import ARCHITECTURE_SYSTEM, _coerce as _coerce_architecture
from .filters import SKIP_DIRS
from .lmstudio_client import LMStudioClient, LMStudioError
from .models import Architecture, Component, ExternalIntegration, TrustBoundary
from .repo_context import (
    DEFAULT_PROMPT_BUDGET_TOKENS,
    RepoContext,
    _CHARS_PER_TOKEN,
    _collect_tree as _collect_tree_into,
    _dep_summary as _dep_summary_into,
    _grep_hints as _grep_hints_into,
    _collect_entrypoints as _collect_entrypoints_into,
    _collect_config as _collect_config_into,
)


_SUBSYSTEM_BUDGET_TOKENS = 8_000      # per-subsystem prompt budget
_MERGE_BUDGET_TOKENS = 10_000         # final merge prompt budget
# A subsystem with fewer files than this is rolled into a sibling's prompt
# rather than getting its own LLM call. Keeps us from burning a call on a
# two-file utility directory.
_MIN_FILES_PER_SUBSYSTEM = 5
# A subsystem with more files than this is recursively split into its
# immediate children. Critical for repos like chia-blockchain where a single
# top-level dir (`chia/`) holds 500+ files and a tree-only prompt loses all
# the useful context. Split into `chia/server/`, `chia/rpc/`, etc.
_MAX_FILES_PER_SUBSYSTEM = 180
# Cap on recursion depth during subsystem splitting. Prevents pathological
# repos with deeply nested single-file directories from producing thousands of
# micro-subsystems.
_MAX_SPLIT_DEPTH = 3

# Directories at the repo root that never stand on their own as a subsystem.
# Also catches underscore variants like `_tests`, `__tests__`, `testutils`.
_NON_SUBSYSTEM_DIRS = set(SKIP_DIRS) | {
    "tests", "test", "_tests", "_test", "__tests__", "__test__",
    "testutils", "test_utils", "testing", "testdata", "test_data",
    "docs", "doc", "_docs", "documentation",
    "examples", "example", "_examples", "samples", "sample", "demos", "demo",
    ".github", ".gitlab", "ci", "scripts", "script", "tools",
    "assets", "images", "fonts", "locale", "locales", "i18n",
    "benchmarks", "benchmark", "fixtures", "fixture",
    "mocks", "mock", "e2e", "integration_tests",
    "build_scripts",                 # packaging, not application logic
    "vendor", "third_party", "third-party", "deps",
}


def _is_subsystem_candidate_name(name: str) -> bool:
    """Return False if the dir name looks like test/docs/CI/scaffolding."""
    if name in _NON_SUBSYSTEM_DIRS or name.startswith("."):
        return False
    lo = name.lower()
    # Catch variants: anything containing 'test' as a whole word-ish token.
    if lo in {"tests", "test"} or lo.startswith(("_test", "test_", "tests_")):
        return False
    if lo.endswith(("_test", "_tests", "-test", "-tests")):
        return False
    return True


ProgressFn = Callable[[str, dict], None]


MERGE_SYSTEM = dedent("""
    You are a staff engineer producing a final repo-level architecture by
    merging per-subsystem analyses.

    You will receive:
      - The repo tree (pruned)
      - Declared dependencies
      - A list of subsystem architectures (each itself the output of an
        architecture extraction scoped to one top-level directory)

    Your job: synthesize these into a single Architecture document covering
    the whole repo. You do NOT need to re-derive components — the subsystem
    analyses already gave you that. You DO need to:
      - Consolidate duplicate components into the final list
      - Identify trust boundaries between subsystems
      - Identify data flows that cross subsystem edges
      - Pick the single auth model + secrets_handling statement that best
        describes the repo as a whole
      - List anything unknown at the repo level

    Output STRICT JSON with the same shape as a regular Architecture (summary,
    components, integrations, trust_boundaries, data_flows, auth_model,
    secrets_handling, unknowns). No markdown.
""").strip()


@dataclass
class Subsystem:
    name: str                      # top-level dir name, or "<root>" for root-level files
    root: Path                     # the directory to scope context to
    file_count: int                # for sizing decisions


# ---------------- subsystem discovery ----------------

def discover_subsystems(repo_root: Path) -> list[Subsystem]:
    """Find useful source directories, recursively splitting huge ones.

    Empty list means the repo is small/flat — caller should use flat extraction.

    Splitting rule: any directory with more than `_MAX_FILES_PER_SUBSYSTEM`
    files gets split into its immediate child directories. Without this a repo
    like chia-blockchain (500 files under one `chia/` dir) would collapse to
    a single tree-only subsystem where the LLM has nothing rich to reason over.
    """
    subs: list[Subsystem] = []
    for p in sorted(repo_root.iterdir()):
        if not p.is_dir():
            continue
        if not _is_subsystem_candidate_name(p.name):
            continue
        # Nested monorepo roots — drill one level deeper unconditionally.
        if p.name in {"packages", "apps", "services", "modules", "crates"}:
            for sub in sorted(p.iterdir()):
                if not sub.is_dir() or not _is_subsystem_candidate_name(sub.name):
                    continue
                n = _count_files(sub)
                if n >= _MIN_FILES_PER_SUBSYSTEM:
                    _split_or_add(
                        Subsystem(name=f"{p.name}/{sub.name}", root=sub, file_count=n),
                        subs, depth=1,
                    )
            continue
        n = _count_files(p)
        if n >= _MIN_FILES_PER_SUBSYSTEM:
            _split_or_add(Subsystem(name=p.name, root=p, file_count=n), subs, depth=1)
    # Include root-level scripts as a synthetic "<root>" subsystem if significant
    root_files = sum(1 for c in repo_root.iterdir() if c.is_file())
    if root_files >= 3:
        subs.append(Subsystem(name="<root>", root=repo_root, file_count=root_files))
    return subs


def _split_or_add(sub: Subsystem, out: list[Subsystem], *, depth: int) -> None:
    """Add `sub` to `out`. If it has more than `_MAX_FILES_PER_SUBSYSTEM` files
    and we haven't hit split-depth cap, recurse into its children instead."""
    if sub.file_count <= _MAX_FILES_PER_SUBSYSTEM or depth >= _MAX_SPLIT_DEPTH:
        out.append(sub)
        return

    child_subs_added = 0
    for child in sorted(sub.root.iterdir()):
        if not child.is_dir():
            continue
        if not _is_subsystem_candidate_name(child.name):
            continue
        n = _count_files(child)
        if n >= _MIN_FILES_PER_SUBSYSTEM:
            _split_or_add(
                Subsystem(name=f"{sub.name}/{child.name}", root=child, file_count=n),
                out, depth=depth + 1,
            )
            child_subs_added += 1

    # Also capture files sitting directly under `sub` (not in any subdir) as a
    # synthetic leaf — otherwise a top-level __init__.py with meaningful content
    # gets dropped.
    direct_files = sum(1 for c in sub.root.iterdir() if c.is_file())
    if direct_files >= _MIN_FILES_PER_SUBSYSTEM:
        # We don't want to rescan sub.root (that'd re-count child dirs).
        # A synthetic entry scoped to this dir's direct files would need a
        # different collector; for v1, fold into the parent name.
        out.append(Subsystem(name=f"{sub.name}/<root>", root=sub.root,
                              file_count=direct_files))

    # Fallback: if the dir had no splittable children at all (e.g. one flat
    # folder with 500 files), add it as-is so it doesn't vanish.
    if child_subs_added == 0 and direct_files < _MIN_FILES_PER_SUBSYSTEM:
        out.append(sub)


def _count_files(directory: Path) -> int:
    n = 0
    for p in directory.rglob("*"):
        if not p.is_file():
            continue
        if any(s in SKIP_DIRS for s in p.relative_to(directory).parts):
            continue
        n += 1
    return n


# ---------------- scoped context ----------------

def _scoped_context(sub: Subsystem, repo_root: Path) -> RepoContext:
    """RepoContext limited to one subsystem.

    Reuses the collector helpers from repo_context, but scoped. `repo_root` is
    still passed for dep scanning (deps are repo-level, not per-subsystem).
    """
    ctx = RepoContext()
    # Tree: files under sub.root only
    _collect_tree_into(sub.root, ctx)
    # Entrypoints + configs found under sub.root
    _collect_entrypoints_into(sub.root, ctx)
    _collect_config_into(sub.root, ctx)
    # Grep hints from files under sub.root
    _grep_hints_into(sub.root, ctx)
    # Deps are repo-level (manifest files usually live at repo root).
    _dep_summary_into(repo_root, ctx)
    return ctx


# ---------------- main entry ----------------

def flat_context_fits_budget(repo_root: Path, budget_tokens: int = DEFAULT_PROMPT_BUDGET_TOKENS) -> bool:
    """Fast pre-check — does the full flat context fit, before we burn an LLM call?"""
    from .repo_context import build_context
    ctx = build_context(repo_root)
    # Render at full fidelity and check size
    rendered = ctx.to_prompt_text(budget_tokens=10_000_000)  # effectively unbounded
    budget_chars = int(budget_tokens * _CHARS_PER_TOKEN)
    return len(rendered) <= budget_chars


def extract_architecture_hierarchical(
    client: LMStudioClient,
    repo_root: Path,
    *,
    progress: ProgressFn | None = None,
) -> Architecture:
    """Map-reduce architecture extraction. Returns an Architecture.

    Calls `progress(event, data)` for each phase so callers can surface timing.
    Events: `subsystems_discovered`, `subsystem_start`, `subsystem_done`,
    `subsystem_error`, `merge_start`, `merge_done`.
    """
    progress = progress or (lambda _e, _d: None)

    subs = discover_subsystems(repo_root)
    if not subs:
        # Nothing to map over — fall back to flat.
        from .architecture import extract_architecture
        return extract_architecture(client, repo_root)

    progress("subsystems_discovered", {"count": len(subs),
                                        "names": [s.name for s in subs]})

    sub_archs: list[tuple[str, Architecture]] = []
    for i, sub in enumerate(subs, start=1):
        progress("subsystem_start", {"i": i, "total": len(subs),
                                      "name": sub.name, "files": sub.file_count})
        try:
            ctx = _scoped_context(sub, repo_root)
            user = (
                f"Subsystem: {sub.name}\n\nRepo context (scoped to this subsystem):\n\n"
                + ctx.to_prompt_text(budget_tokens=_SUBSYSTEM_BUDGET_TOKENS)
                + "\n\n/no_think"
            )
            data = client.complete_json(
                ARCHITECTURE_SYSTEM, user, max_tokens=4096, temperature=0.1,
            )
            sub_archs.append((sub.name, _coerce_architecture(data)))
            progress("subsystem_done", {"i": i, "name": sub.name})
        except LMStudioError as e:
            progress("subsystem_error", {"i": i, "name": sub.name, "err": str(e)[:200]})

    if not sub_archs:
        return Architecture(summary="(hierarchical architecture extraction: every subsystem pass failed)")

    # Short-circuit for single-subsystem repos: the one arch IS the answer.
    if len(sub_archs) == 1:
        return sub_archs[0][1]

    # Merge phase
    progress("merge_start", {"subsystem_count": len(sub_archs)})
    try:
        merged = _merge_architectures(client, repo_root, sub_archs, progress=progress)
    except LMStudioError as e:
        # LLM merge errored — fall back to a mechanical concat of subsystems.
        merged = _mechanical_merge(sub_archs)
        merged.unknowns.append(f"LLM merge pass failed: {str(e)[:120]}")
        progress("merge_empty_fallback", {"reason": "lmstudio_error"})

    # Defense in depth: a successful call can still return an empty
    # Architecture if the model echoed `{}` or returned only whitespace
    # (we observed this on chia-blockchain — 25 valid subsystems, empty
    # merge). Without this branch we'd silently throw away every subsystem's
    # work. Mechanical merge is strictly better than nothing.
    if _arch_is_empty(merged):
        merged = _mechanical_merge(sub_archs)
        merged.unknowns.append(
            "LLM merge returned empty Architecture; mechanical concat used as fallback"
        )
        progress("merge_empty_fallback", {"reason": "empty_llm_result"})

    progress("merge_done", {"components": len(merged.components),
                            "integrations": len(merged.integrations)})
    return merged


def _arch_is_empty(arch: Architecture) -> bool:
    """An Architecture with no structural content. Used to detect an LLM merge
    that parse-succeeded but produced nothing useful, so we can fall back
    instead of returning a vacuous result downstream."""
    return not (
        arch.components
        or arch.integrations
        or arch.trust_boundaries
        or arch.data_flows
    )


# ---------------- merge ----------------

def _merge_architectures(
    client: LMStudioClient,
    repo_root: Path,
    sub_archs: list[tuple[str, Architecture]],
    *,
    progress: ProgressFn | None = None,
) -> Architecture:
    from .repo_context import build_context
    progress = progress or (lambda _e, _d: None)
    # For the merge, we give the model a pruned repo tree + per-subsystem summaries
    base = build_context(repo_root)
    tree_text = base.to_prompt_text(budget_tokens=_MERGE_BUDGET_TOKENS // 2)

    payload_budget_chars = int(_MERGE_BUDGET_TOKENS * _CHARS_PER_TOKEN * 0.6)
    subs_payload_text, shrink_level = _shrink_subs_payload(
        sub_archs, max_chars=payload_budget_chars,
    )
    if shrink_level > 0:
        progress("merge_payload_shrunk",
                 {"level": shrink_level, "chars": len(subs_payload_text),
                  "budget_chars": payload_budget_chars})
    user = dedent(f"""
        Merge these subsystem architectures into one repo-level architecture.

        Pruned repo tree for orientation:
        ```
        {tree_text}
        ```

        Subsystem analyses (one per top-level directory):
        ```json
        {subs_payload_text}
        ```

        Produce the final Architecture JSON.
        /no_think
    """).strip()
    data = client.complete_json(MERGE_SYSTEM, user, max_tokens=4096, temperature=0.1)
    return _coerce_architecture(data)


# ---------------- structural shrinking ----------------
#
# The previous implementation char-sliced `json.dumps(...)[:N]`, which chops a
# JSON object mid-key and produces unparseable text in the prompt. Models then
# returned `{}` or empty content — observed on chia-blockchain (25 valid
# subsystems → empty merge). Instead, build progressively-leaner views of each
# subsystem and pick the richest one that fits the budget. Every level emits
# valid JSON.

def _shrink_subs_payload(
    sub_archs: list[tuple[str, Architecture]],
    *,
    max_chars: int,
) -> tuple[str, int]:
    """Return `(json_text, shrink_level)` where the text fits `max_chars`.
    Levels:
      0 = full dump
      1 = drop high-volume fields (integration evidence_files/notes,
          component notable_files)
      2 = also drop entry_points, trust_boundaries.enforced_by, data_flows,
          unknowns (keep boundary descriptions and bypass risks)
      3 = skeleton: per-subsystem summary, component name+role,
          integration name+kind+direction, auth_model, secrets_handling
    Level 3 is always small enough for a sane merge budget. If even that
    overflows we hand back the level-3 text untruncated and let the upstream
    fallback handle it — never char-slice JSON.
    """
    builders = (_payload_full, _payload_light, _payload_lighter, _payload_skeleton)
    text = ""
    for level, build in enumerate(builders):
        text = json.dumps(build(sub_archs), indent=2)
        if len(text) <= max_chars:
            return text, level
    return text, len(builders) - 1


def _payload_full(sub_archs: list[tuple[str, Architecture]]) -> list[dict]:
    return [{"subsystem": name, **arch.model_dump()} for name, arch in sub_archs]


def _payload_light(sub_archs: list[tuple[str, Architecture]]) -> list[dict]:
    out: list[dict] = []
    for name, arch in sub_archs:
        d = arch.model_dump()
        for c in d.get("components", []):
            c.pop("notable_files", None)
        for ig in d.get("integrations", []):
            ig.pop("evidence_files", None)
            ig.pop("notes", None)
        out.append({"subsystem": name, **d})
    return out


def _payload_lighter(sub_archs: list[tuple[str, Architecture]]) -> list[dict]:
    out: list[dict] = []
    for name, arch in sub_archs:
        d = arch.model_dump()
        for c in d.get("components", []):
            c.pop("notable_files", None)
            c.pop("entry_points", None)
        for ig in d.get("integrations", []):
            ig.pop("evidence_files", None)
            ig.pop("notes", None)
        for tb in d.get("trust_boundaries", []):
            tb.pop("enforced_by", None)
        d.pop("data_flows", None)
        d.pop("unknowns", None)
        out.append({"subsystem": name, **d})
    return out


def _payload_skeleton(sub_archs: list[tuple[str, Architecture]]) -> list[dict]:
    out: list[dict] = []
    for name, arch in sub_archs:
        out.append({
            "subsystem": name,
            "summary": arch.summary,
            "components": [{"name": c.name, "role": c.role} for c in arch.components],
            "integrations": [
                {"name": i.name, "kind": i.kind, "direction": i.direction}
                for i in arch.integrations
            ],
            "auth_model": arch.auth_model,
            "secrets_handling": arch.secrets_handling,
        })
    return out


def _mechanical_merge(sub_archs: list[tuple[str, Architecture]]) -> Architecture:
    """LLM-free fallback merge — concatenate with de-dup by name/identifier."""
    summary_parts: list[str] = []
    components: list[Component] = []
    integrations: list[ExternalIntegration] = []
    trust_boundaries: list[TrustBoundary] = []
    data_flows: list[str] = []
    unknowns: list[str] = []
    auth_models: list[str] = []
    secrets_handling_notes: list[str] = []

    seen_component: set[str] = set()
    seen_integration: set[str] = set()

    for name, arch in sub_archs:
        if arch.summary:
            summary_parts.append(f"[{name}] {arch.summary}")
        for c in arch.components:
            key = c.name.lower()
            if key not in seen_component:
                seen_component.add(key)
                components.append(c)
        for i in arch.integrations:
            key = i.name.lower()
            if key not in seen_integration:
                seen_integration.add(key)
                integrations.append(i)
        trust_boundaries.extend(arch.trust_boundaries)
        data_flows.extend(arch.data_flows)
        unknowns.extend(arch.unknowns)
        if arch.auth_model:
            auth_models.append(f"[{name}] {arch.auth_model}")
        if arch.secrets_handling:
            secrets_handling_notes.append(f"[{name}] {arch.secrets_handling}")

    return Architecture(
        summary=" ".join(summary_parts)[:1200],
        components=components,
        integrations=integrations,
        trust_boundaries=trust_boundaries,
        data_flows=data_flows,
        auth_model="; ".join(auth_models)[:800],
        secrets_handling="; ".join(secrets_handling_notes)[:800],
        unknowns=unknowns,
    )

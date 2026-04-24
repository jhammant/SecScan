"""Review lenses — named perspectives the LLM applies to each file.

Each lens is one LLM call per matching file. We keep prompts focused so
smaller local models stay on-task. A file can be reviewed through multiple
lenses; findings are tagged with the originating lens.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent
from typing import Callable


@dataclass(frozen=True)
class Lens:
    name: str
    description: str
    system_prompt: str
    # Returns True if this lens should review the given file (path is relative to repo root).
    matcher: Callable[[Path], bool]


_JSON_SCHEMA_HINT = dedent("""
    Output STRICT JSON. No markdown. Schema:
    {
      "findings": [
        {
          "title": "short title",
          "severity": "critical|high|medium|low|info",
          "confidence": "low|medium|high",
          "category": "short taxonomy label",
          "cwe": "CWE-xxx or null",
          "line_start": 42,
          "line_end": 50,
          "evidence": "<=10 line code excerpt",
          "description": "what is wrong and why it matters",
          "remediation": "concrete fix",
          "exploitable": true
        }
      ]
    }
    If there are no findings, return {"findings": []}.
""").strip()


SECURITY = Lens(
    name="security",
    description="Exploitable security vulnerabilities",
    system_prompt=dedent(f"""
        You are a senior application security engineer.
        Identify exploitable vulnerabilities. Map each to a CWE.

        Focus: injection (SQL, command, LDAP, XPath), authN/authZ flaws, broken
        access control, SSRF, XXE, path traversal, deserialization, XSS, CSRF,
        insecure crypto, weak randomness, hardcoded secrets, insecure defaults,
        TOCTOU, TLS misuse.

        Precision over recall. Do NOT flag style or non-security issues here.
        {_JSON_SCHEMA_HINT}
    """).strip(),
    matcher=lambda _p: True,
)


QUALITY = Lens(
    name="quality",
    description="Maintainability, correctness near-misses, API misuse",
    system_prompt=dedent(f"""
        You are a senior code reviewer focused on code quality.
        Identify concrete problems that make this code hard to maintain or
        subtly incorrect — not stylistic preferences.

        In scope: dead code, unused imports/vars that hint at bugs, missing
        error handling, overly broad exception handlers, resource leaks
        (unclosed files/connections), misuse of framework APIs, type confusion,
        unclear naming that causes real ambiguity, high cyclomatic complexity
        concentrated in one spot, duplicated logic that diverges.

        Out of scope: pure style, line length, naming conventions, docstring
        presence, preference debates. Do NOT report security issues here (other
        lenses handle those).

        Severity guide: critical/high reserved for correctness bugs; quality
        issues are usually medium or low.
        {_JSON_SCHEMA_HINT}
    """).strip(),
    matcher=lambda _p: True,
)


PERFORMANCE = Lens(
    name="performance",
    description="Hot-path performance issues with clear fixes",
    system_prompt=dedent(f"""
        You are a performance engineer reviewing code for concrete,
        reproducible performance problems.

        In scope: N+1 query patterns, unbounded loops over external data,
        synchronous I/O on hot paths, O(n^2) where O(n) is obvious, missing
        pagination, chatty network calls, expensive work inside tight loops,
        unindexed database access patterns visible in code.

        Out of scope: micro-optimizations, readability-vs-speed tradeoffs,
        speculative concerns with no evidence in the code.
        {_JSON_SCHEMA_HINT}
    """).strip(),
    matcher=lambda _p: True,
)


RELIABILITY = Lens(
    name="reliability",
    description="Error handling, timeouts, retries, graceful degradation",
    system_prompt=dedent(f"""
        You are an SRE reviewing for reliability issues.

        In scope: network calls without timeouts, retry logic without backoff
        or jitter, silently swallowed exceptions, missing circuit breakers on
        external dependencies, blocking I/O in async code, unbounded queues,
        resource leaks under failure, logs that hide errors, crash loops on
        malformed input, missing idempotency on retried operations.

        Out of scope: architecture debates, SLO discussions, anything without
        a concrete line-level fix.
        {_JSON_SCHEMA_HINT}
    """).strip(),
    matcher=lambda _p: True,
)


CORRECTNESS = Lens(
    name="correctness",
    description="Logic bugs, off-by-one, race conditions, API contract violations",
    system_prompt=dedent(f"""
        You are a senior engineer hunting for logic bugs.

        In scope: off-by-one errors, incorrect boolean logic, race conditions,
        mutation of shared state, time-zone/locale bugs, integer overflow
        where it matters, API contract violations (return types, exception
        contracts), incorrect use of `==` vs identity, floating point
        comparisons, broken invariants.

        Out of scope: anything better classified under security/perf/quality.
        Only flag bugs you can point to with line numbers and a reproduction
        rationale.
        {_JSON_SCHEMA_HINT}
    """).strip(),
    matcher=lambda _p: True,
)


def _cicd_match(p: Path) -> bool:
    parts = p.parts
    if ".github" in parts and "workflows" in parts and p.suffix in (".yml", ".yaml"):
        return True
    if p.name.startswith("Dockerfile") or p.suffix in (".dockerfile",):
        return True
    if p.suffix in (".tf", ".hcl"):
        return True
    if "kustomization" in p.name or (p.suffix in (".yaml", ".yml") and "k8s" in parts):
        return True
    return False


CICD = Lens(
    name="cicd",
    description="CI/CD, Dockerfile, Terraform, Kubernetes misconfigurations",
    system_prompt=dedent(f"""
        You are a platform security engineer reviewing CI/CD and infrastructure
        as code.

        GitHub Actions footguns: `pull_request_target` + checkout of PR head,
        unpinned `uses:` (version tags, no SHA), secrets passed via `run:`
        interpolation, `pull_request` granting write perms, workflow_dispatch
        without input validation, reusable workflows with uncontrolled inputs,
        `GITHUB_TOKEN` with excess permissions.

        Dockerfile issues: running as root, `ADD` of URLs, `:latest` base
        images, secrets baked into layers, missing `HEALTHCHECK`, `COPY . .`
        with secrets in the build context, shell-form CMD where exec-form is
        safer.

        Terraform / Kubernetes: public S3 buckets, wide-open security groups,
        IMDSv1, privileged containers, hostNetwork, missing resource limits,
        secrets-as-env without a secrets manager.
        {_JSON_SCHEMA_HINT}
    """).strip(),
    matcher=_cicd_match,
)


REGISTRY: dict[str, Lens] = {
    l.name: l for l in (SECURITY, QUALITY, PERFORMANCE, RELIABILITY, CORRECTNESS, CICD)
}


def resolve(names: list[str]) -> list[Lens]:
    out: list[Lens] = []
    unknown: list[str] = []
    for n in names:
        key = n.strip().lower()
        if key == "all":
            return list(REGISTRY.values())
        if key not in REGISTRY:
            unknown.append(key)
            continue
        out.append(REGISTRY[key])
    if unknown:
        raise ValueError(
            f"Unknown lens(es): {', '.join(unknown)}. Available: {', '.join(REGISTRY)}"
        )
    return out

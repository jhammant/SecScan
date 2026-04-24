"""Regex-based secret detection.

Complements the LLM pass — deterministic, precise, fast. Rules are a curated
subset inspired by gitleaks/trufflehog. Adding new rules is a one-liner.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path

from .filters import classify
from .models import Finding, Severity


@dataclass(frozen=True)
class SecretRule:
    id: str
    name: str
    pattern: re.Pattern
    severity: Severity = Severity.HIGH


# Entropy-check helper so we don't flag every 40-char string.
def _shannon(s: str) -> float:
    from math import log2
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(s)
    return -sum((c / total) * log2(c / total) for c in counts.values())


_RULES: list[SecretRule] = [
    SecretRule("aws-access-key-id", "AWS Access Key ID",
               re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"), Severity.CRITICAL),
    SecretRule("aws-secret-access-key", "AWS Secret Access Key",
               re.compile(r"(?i)aws(.{0,20})?(secret|private)?.{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]"),
               Severity.CRITICAL),
    SecretRule("github-pat", "GitHub Personal Access Token",
               re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"), Severity.CRITICAL),
    SecretRule("github-oauth", "GitHub OAuth token",
               re.compile(r"\bgho_[A-Za-z0-9]{36,}\b"), Severity.CRITICAL),
    SecretRule("github-app", "GitHub App token",
               re.compile(r"\b(ghu|ghs)_[A-Za-z0-9]{36,}\b"), Severity.CRITICAL),
    SecretRule("github-fine-grained", "GitHub fine-grained PAT",
               re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"), Severity.CRITICAL),
    SecretRule("slack-bot-token", "Slack Bot token",
               re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), Severity.HIGH),
    SecretRule("slack-webhook", "Slack Webhook URL",
               re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
               Severity.HIGH),
    SecretRule("stripe-live", "Stripe live key",
               re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b"), Severity.CRITICAL),
    SecretRule("stripe-test", "Stripe test key",
               re.compile(r"\b(?:sk|rk)_test_[0-9a-zA-Z]{24,}\b"), Severity.LOW),
    SecretRule("google-api-key", "Google API Key",
               re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), Severity.HIGH),
    SecretRule("openai-key", "OpenAI API key",
               re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b"), Severity.HIGH),
    SecretRule("anthropic-key", "Anthropic API key",
               re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{32,}\b"), Severity.HIGH),
    SecretRule("pypi-token", "PyPI token",
               re.compile(r"\bpypi-AgEI[A-Za-z0-9_\-]{16,}\b"), Severity.HIGH),
    SecretRule("npm-token", "npm token",
               re.compile(r"\bnpm_[A-Za-z0-9]{36,}\b"), Severity.HIGH),
    SecretRule("private-key-pem", "Private key (PEM header)",
               re.compile(r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY(?: BLOCK)?-----"),
               Severity.CRITICAL),
    SecretRule("jwt", "JSON Web Token",
               re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
               Severity.MEDIUM),
    SecretRule("generic-password-assign", "Hardcoded password-like assignment",
               re.compile(
                   r"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*"
                   r"['\"]([^'\"\s]{8,})['\"]"
               ),
               Severity.MEDIUM),
]


# Never scan inside these by name/extension — common false-positive sources.
_SKIP_NAME = {"test_secrets", "secrets_test"}
_SKIP_EXT_FOR_GENERIC = {".md", ".txt", ".rst"}


def _extract_snippet(text: str, start: int, end: int, pad: int = 40) -> tuple[int, str]:
    """Return (line_number, snippet). Snippet is masked for the matched region."""
    line = text.count("\n", 0, start) + 1
    left = max(0, start - pad)
    right = min(len(text), end + pad)
    matched = text[start:end]
    mask = matched[:4] + "…" + matched[-4:] if len(matched) > 10 else "***"
    snippet = text[left:start] + mask + text[end:right]
    snippet = snippet.replace("\n", " ⏎ ")
    return line, snippet.strip()


def scan_file_for_secrets(path: Path, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    is_docs = path.suffix.lower() in _SKIP_EXT_FOR_GENERIC

    for rule in _RULES:
        # Generic rules skip docs to avoid FP; high-signal rules run everywhere.
        if rule.id.startswith("generic-") and is_docs:
            continue
        for m in rule.pattern.finditer(text):
            matched = m.group(0)
            # Entropy filter for generic rules — avoid flagging "password=hunter12!"
            if rule.id.startswith("generic-"):
                secret_val = m.group(1) if m.groups() else matched
                if _shannon(secret_val) < 3.0:
                    continue
            line_no, snippet = _extract_snippet(text, m.start(), m.end())
            f = Finding(
                file=rel,
                line_start=line_no,
                line_end=line_no,
                severity=rule.severity,
                category="Hardcoded Secret",
                cwe="CWE-798",
                title=f"{rule.name} detected",
                description=(
                    f"A string matching {rule.name} was found in source. Committed "
                    "secrets should be rotated and moved to a secret manager."
                ),
                evidence=snippet,
                remediation=(
                    "Rotate the credential at the provider, remove from VCS history "
                    "(git filter-repo / BFG), and load from env/secret manager."
                ),
                confidence="high",
                exploitable=True,
                source="secrets",
            )
            f.ensure_id()
            findings.append(f)
    return findings


def scan_secrets(repo_root: Path) -> list[Finding]:
    """Walk the repo, regex every includable file. Binary/lockfile/etc. skipped."""
    out: list[Finding] = []
    for p in repo_root.rglob("*"):
        if not p.is_file():
            continue
        decision = classify(p, repo_root)
        # For secrets, we also scan .env-style files even when "non-source".
        scan_anyway = p.name.lower() in {".env", ".env.local", ".env.production", "credentials"} \
            or p.suffix.lower() == ".env"
        if not decision.include and not scan_anyway:
            continue
        try:
            rel = str(p.relative_to(repo_root))
        except ValueError:
            continue
        if any(name in rel for name in _SKIP_NAME):
            continue
        out.extend(scan_file_for_secrets(p, rel))
    return out

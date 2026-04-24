"""Decide which files in a cloned repo are worth sending to the LLM."""
from __future__ import annotations
import os
import re
from pathlib import Path
from dataclasses import dataclass

# Risk-first mode (env-var gated): when on, we skip files that don't look
# security-relevant by either path or a peek at content. Cuts file count
# 4-8x on typical backend repos, trading breadth for time.
_RISK_FIRST = os.environ.get("SECSCAN_RISK_FIRST") == "1"

_RISK_PATH_RE = re.compile(
    r"(route|router|controller|handler|endpoint|api|resource|view|service|"
    r"auth|authn|authz|security|crypto|token|session|cookie|password|secret|"
    r"jwt|jws|jwe|oauth|oidc|sign|verify|encrypt|decrypt|cipher|key|credential|"
    r"middleware|filter|guard|permission|role|acl|login|logout|register|"
    r"csrf|cors|origin|upload|download|file|path|redirect|"
    r"sql|query|database|db|orm|serialize|deserialize|parse|render|template)",
    re.I,
)

# If a file's path doesn't match the above, we peek at the first ~16KB for
# any of these patterns. These are the structural hallmarks of "code that
# moves untrusted data around" — worth a security review.
_RISK_CONTENT_RE = re.compile(
    r"("
    # Route / controller decls (Java/Kotlin/JS/Python/Go)
    r"@(?:Get|Post|Put|Delete|Patch|Request|Exception)Mapping|"
    r"@(?:RestController|Controller|Path|Route|RequestBody|PathVariable|RequestParam)|"
    r"(?:app|router|api|blueprint|bp)\.(?:get|post|put|delete|patch|route|use|all)\s*\(|"
    r"HandleFunc\s*\(|"
    # Deserialization / parsing
    r"ObjectMapper|readValue|YAML\.load|pickle\.loads?|unmarshal|JSON\.parse|eval\s*\(|"
    # Shell / subprocess
    r"Runtime\.(?:getRuntime|exec)|ProcessBuilder|subprocess\.|os\.system|os\.popen|"
    # SQL / ORM
    r"(?:CREATE|SELECT|INSERT|UPDATE|DELETE)\s+[A-Z]|"
    r"(?:db|cursor|session|conn(?:ection)?|stmt)\.execute|prepareStatement|rawQuery|"
    # HTTP clients (outbound)
    r"(?:httpx|requests|urllib|axios|fetch|HttpClient)\.\s*(?:get|post|put|delete|patch|request)|"
    # Crypto primitives + key handling
    r"(?:hmac|hashlib|MessageDigest|Cipher|KeyFactory|Signature|KeyStore)\.|"
    r"(?:sign|verify|encrypt|decrypt)\s*\(|"
    r"-----BEGIN [A-Z ]*KEY|"
    # Secret / credential reads
    r"getenv\(['\"][A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CRED)|"
    # File / path handling
    r"(?:open|read|write)\s*\(\s*[^)]*(?:user|input|req|request|params|body)|"
    r"Path\.Combine|os\.path\.join\(|"
    # Redirects / SSRF surfaces
    r"redirect\s*\(|Location:\s*[+]|"
    r")",
    re.I,
)

# Extensions we consider source code worth scanning.
SOURCE_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".go", ".rs", ".rb", ".php", ".java", ".kt", ".kts", ".scala",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".m", ".mm", ".swift",
    ".sh", ".bash", ".zsh", ".ps1",
    ".sql", ".graphql", ".proto",
    ".yml", ".yaml", ".tf", ".hcl", ".dockerfile",
    ".html", ".vue", ".svelte",
}

CONFIG_FILENAMES = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "Makefile", ".env.example", "nginx.conf",
}

# Directories we always skip.
SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "out", "target",
    ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".next", ".nuxt", ".cache", "coverage", ".terraform",
    "bower_components", "third_party", "third-party",
    ".secscan",
}

# File patterns treated as lockfiles / generated — skipped unless force-included.
LOCK_PATTERNS = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb",
    "Pipfile.lock", "poetry.lock", "uv.lock",
    "Cargo.lock", "go.sum", "composer.lock", "Gemfile.lock",
}

MAX_FILE_BYTES = 200_000  # per-file cap; larger files are skipped or chunked


@dataclass
class FilterDecision:
    include: bool
    reason: str


def classify(path: Path, repo_root: Path) -> FilterDecision:
    rel = path.relative_to(repo_root)
    parts = set(rel.parts)

    if parts & SKIP_DIRS:
        return FilterDecision(False, f"skipped-dir:{(parts & SKIP_DIRS).pop()}")
    if path.name in LOCK_PATTERNS:
        return FilterDecision(False, "lockfile")
    if not path.is_file():
        return FilterDecision(False, "not-file")
    try:
        size = path.stat().st_size
    except OSError as e:
        return FilterDecision(False, f"stat-error:{e}")
    if size == 0:
        return FilterDecision(False, "empty")
    if size > MAX_FILE_BYTES:
        return FilterDecision(False, f"too-large:{size}")
    if _is_binary(path):
        return FilterDecision(False, "binary")

    ext = path.suffix.lower()
    base_included = ext in SOURCE_EXTS or path.name in CONFIG_FILENAMES
    if not base_included:
        return FilterDecision(False, "non-source")

    if _RISK_FIRST:
        # Skip test files in risk-first mode — they rarely host real vulns.
        rel_str = str(rel).lower()
        if any(seg in rel_str for seg in ("/test/", "/tests/", "__tests__", ".test.", ".spec.", "_test.", "_spec.")):
            return FilterDecision(False, "risk-first:test")
        if _RISK_PATH_RE.search(rel_str):
            return FilterDecision(True, "risk-first:path")
        # Peek at content for security-relevant patterns
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:16_000]
        except OSError as e:
            return FilterDecision(False, f"read-error:{e}")
        if _RISK_CONTENT_RE.search(head):
            return FilterDecision(True, "risk-first:content")
        return FilterDecision(False, "risk-first:no-risk-signal")

    if ext in SOURCE_EXTS:
        return FilterDecision(True, f"ext:{ext}")
    return FilterDecision(True, f"config:{path.name}")


def _is_binary(path: Path, sniff: int = 2048) -> bool:
    try:
        with path.open("rb") as fh:
            chunk = fh.read(sniff)
    except OSError:
        return True
    if b"\x00" in chunk:
        return True
    # Heuristic: ratio of non-text bytes
    text_chars = bytes(range(32, 127)) + b"\n\r\t\f\b"
    non_text = sum(1 for b in chunk if b not in text_chars)
    return len(chunk) > 0 and non_text / len(chunk) > 0.30


def walk(repo_root: Path) -> list[tuple[Path, FilterDecision]]:
    """Return every file under repo_root with its include/skip decision."""
    out: list[tuple[Path, FilterDecision]] = []
    for p in repo_root.rglob("*"):
        if p.is_dir():
            continue
        # cheap early exit: any parent dir matches skip
        if any(part in SKIP_DIRS for part in p.relative_to(repo_root).parts[:-1]):
            continue
        out.append((p, classify(p, repo_root)))
    return out


def detect_language(path: Path) -> str | None:
    ext = path.suffix.lower()
    mapping = {
        ".py": "python", ".js": "javascript", ".jsx": "javascript",
        ".ts": "typescript", ".tsx": "typescript", ".mjs": "javascript",
        ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php",
        ".java": "java", ".kt": "kotlin", ".scala": "scala",
        ".c": "c", ".cc": "cpp", ".cpp": "cpp", ".h": "c", ".hpp": "cpp",
        ".cs": "csharp", ".swift": "swift",
        ".sh": "bash", ".bash": "bash", ".zsh": "bash",
        ".sql": "sql", ".yml": "yaml", ".yaml": "yaml",
        ".tf": "terraform", ".hcl": "hcl",
        ".html": "html", ".vue": "vue", ".svelte": "svelte",
    }
    return mapping.get(ext)

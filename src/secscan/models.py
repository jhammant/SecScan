"""Pydantic data model for all SecScan outputs.

Stable schema across report JSON, report Markdown, and the TUI. Changes here
are breaking changes — version the JSON if you need to evolve.
"""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Literal
from pydantic import BaseModel, Field
import hashlib


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


# Where a finding originated — lens name (security/quality/…) or one of
# the non-LLM sources.
Source = Literal[
    "security", "quality", "performance", "reliability", "correctness", "cicd",
    "secrets", "dependency", "synthesis",
]


class Finding(BaseModel):
    id: str = ""  # stable hash, filled in post-init
    file: str
    line_start: int = 0
    line_end: int = 0
    severity: Severity
    category: str = Field(description="Short taxonomy label, e.g. 'SQL Injection'")
    cwe: str | None = None
    title: str
    description: str
    evidence: str = Field(default="", description="Relevant code snippet")
    remediation: str = ""
    confidence: Literal["low", "medium", "high"] = "medium"
    exploitable: bool = False
    source: Source = "security"

    def fingerprint(self) -> str:
        raw = f"{self.source}|{self.file}|{self.line_start}|{self.category}|{self.title}"
        return hashlib.sha1(raw.encode()).hexdigest()[:12]

    def ensure_id(self) -> None:
        if not self.id:
            self.id = self.fingerprint()


class FileScanResult(BaseModel):
    path: str
    language: str | None = None
    bytes: int = 0
    scanned: bool = True
    skipped_reason: str | None = None
    lenses_run: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None


# ---------------- architecture ----------------

class Component(BaseModel):
    name: str
    role: str                     # "web api", "worker", "cli", "frontend", ...
    entry_points: list[str] = Field(default_factory=list)
    notable_files: list[str] = Field(default_factory=list)


class ExternalIntegration(BaseModel):
    """Runtime dependency outside the repo: APIs, DBs, queues, cloud services."""
    name: str                     # human name, e.g. "Stripe API"
    kind: str                     # "http_api" | "database" | "queue" | "object_storage" | "auth_provider" | "cache" | "unknown"
    direction: Literal["outbound", "inbound", "bidirectional"] = "outbound"
    endpoint_hint: str | None = None  # URL/host if visible in code
    authenticated: bool | None = None
    evidence_files: list[str] = Field(default_factory=list)
    notes: str = ""


class TrustBoundary(BaseModel):
    description: str              # e.g. "public HTTP -> auth middleware -> internal handlers"
    enforced_by: list[str] = Field(default_factory=list)  # middleware/file refs
    bypass_risks: list[str] = Field(default_factory=list)


class Architecture(BaseModel):
    summary: str = ""
    components: list[Component] = Field(default_factory=list)
    integrations: list[ExternalIntegration] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    data_flows: list[str] = Field(default_factory=list)   # short prose bullets
    auth_model: str = ""
    secrets_handling: str = ""
    unknowns: list[str] = Field(default_factory=list)     # things the LLM couldn't infer


# ---------------- dependencies ----------------

class DependencyAdvisory(BaseModel):
    id: str                        # OSV id
    summary: str
    severity: Severity = Severity.MEDIUM
    url: str | None = None
    fixed_in: list[str] = Field(default_factory=list)


class DependencyFinding(BaseModel):
    ecosystem: str                 # npm, PyPI, Go, crates.io, ...
    name: str
    version: str | None = None
    manifest: str                  # relative path of file it came from
    advisories: list[DependencyAdvisory] = Field(default_factory=list)


# ---------------- synthesis ----------------

class Grade(BaseModel):
    lens: str
    grade: Literal["A", "B", "C", "D", "F"]
    justification: str


class Synthesis(BaseModel):
    executive_summary: str = ""
    systemic_issues: list[str] = Field(default_factory=list)
    hotspots: list[str] = Field(default_factory=list)     # "src/auth.py — 7 findings"
    grades: list[Grade] = Field(default_factory=list)
    # Cross-cutting findings the per-file pass couldn't see (e.g. SSRF surface,
    # auth bypass path, data exfil channel). Stored as normal Finding records
    # with source="synthesis" so they merge into the main list.
    cross_cutting_findings: list[Finding] = Field(default_factory=list)


# ---------------- repo result ----------------

class RepoScanResult(BaseModel):
    repo: str
    ref: str = "HEAD"
    commit: str | None = None
    clone_path: str | None = None
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: datetime | None = None
    model: str | None = None
    lenses_requested: list[str] = Field(default_factory=list)

    files: list[FileScanResult] = Field(default_factory=list)
    architecture: Architecture | None = None
    dependencies: list[DependencyFinding] = Field(default_factory=list)
    synthesis: Synthesis | None = None

    @property
    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        for f in self.files:
            out.extend(f.findings)
        if self.synthesis:
            out.extend(self.synthesis.cross_cutting_findings)
        return out

    @property
    def counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def counts_by_source(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.source] = out.get(f.source, 0) + 1
        return out


class UserScanResult(BaseModel):
    user: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: datetime | None = None
    repos: list[RepoScanResult] = Field(default_factory=list)

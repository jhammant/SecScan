"""Architecture extraction pass.

One LLM call per repo. Produces an Architecture document the user can read
*and* a machine-readable structure that the synthesis pass uses to hunt for
cross-cutting vulnerabilities (trust boundaries, integration misuse, auth
bypass paths, etc.).
"""
from __future__ import annotations
from pathlib import Path
from textwrap import dedent

from .lmstudio_client import LMStudioClient, LMStudioError
from .models import Architecture, Component, ExternalIntegration, TrustBoundary
from .repo_context import build_context


ARCHITECTURE_SYSTEM = dedent("""
    You are a staff engineer producing an architecture report for a code review.

    Your job: from the provided repo context (tree, entrypoints, config, route
    hints, integration hints, env vars, declared dependencies), infer what
    this application IS and how it is put together.

    Be precise and terse. Do NOT invent functionality not supported by evidence.
    When unsure, list it under "unknowns".

    Output STRICT JSON — no markdown:
    {
      "summary": "2-4 sentence plain-English description of the application",
      "components": [
        {
          "name": "web-api",
          "role": "HTTP API exposing /v1/*",
          "entry_points": ["src/app.py"],
          "notable_files": ["src/routes/user.py", "src/auth/middleware.py"]
        }
      ],
      "integrations": [
        {
          "name": "Stripe API",
          "kind": "http_api|database|queue|object_storage|auth_provider|cache|unknown",
          "direction": "outbound|inbound|bidirectional",
          "endpoint_hint": "api.stripe.com or null",
          "authenticated": true,
          "evidence_files": ["src/payments.py"],
          "notes": "short remark on how it is used"
        }
      ],
      "trust_boundaries": [
        {
          "description": "public HTTP → auth middleware → internal handlers",
          "enforced_by": ["src/auth/middleware.py"],
          "bypass_risks": ["routes declared outside the router blueprint may skip auth"]
        }
      ],
      "data_flows": [
        "User input in POST /upload flows to S3.put_object; filename is user-controlled"
      ],
      "auth_model": "JWT from Authorization header validated per-request in middleware.py",
      "secrets_handling": "read from env via os.getenv; no secret manager detected",
      "unknowns": ["how the worker talks to the main API"]
    }
""").strip()


def extract_architecture(client: LMStudioClient, repo_root: Path) -> Architecture:
    ctx = build_context(repo_root)
    user = "Repo context:\n\n" + ctx.to_prompt_text() + "\n\n/no_think"
    try:
        data = client.complete_json(
            ARCHITECTURE_SYSTEM, user, max_tokens=8192, temperature=0.1,
        )
    except LMStudioError:
        return Architecture(summary="(architecture extraction failed)")

    return _coerce(data)


def _coerce(data: dict) -> Architecture:
    def _as_list(v) -> list:
        return v if isinstance(v, list) else []

    return Architecture(
        summary=str(data.get("summary") or ""),
        components=[
            Component(
                name=str(c.get("name") or "component"),
                role=str(c.get("role") or ""),
                entry_points=[str(x) for x in _as_list(c.get("entry_points"))],
                notable_files=[str(x) for x in _as_list(c.get("notable_files"))],
            )
            for c in _as_list(data.get("components")) if isinstance(c, dict)
        ],
        integrations=[
            ExternalIntegration(
                name=str(i.get("name") or "integration"),
                kind=str(i.get("kind") or "unknown"),
                direction=_as_direction(i.get("direction")),
                endpoint_hint=(i.get("endpoint_hint") or None),
                authenticated=i.get("authenticated") if isinstance(i.get("authenticated"), bool) else None,
                evidence_files=[str(x) for x in _as_list(i.get("evidence_files"))],
                notes=str(i.get("notes") or ""),
            )
            for i in _as_list(data.get("integrations")) if isinstance(i, dict)
        ],
        trust_boundaries=[
            TrustBoundary(
                description=str(b.get("description") or ""),
                enforced_by=[str(x) for x in _as_list(b.get("enforced_by"))],
                bypass_risks=[str(x) for x in _as_list(b.get("bypass_risks"))],
            )
            for b in _as_list(data.get("trust_boundaries")) if isinstance(b, dict)
        ],
        data_flows=[str(x) for x in _as_list(data.get("data_flows"))],
        auth_model=str(data.get("auth_model") or ""),
        secrets_handling=str(data.get("secrets_handling") or ""),
        unknowns=[str(x) for x in _as_list(data.get("unknowns"))],
    )


def _as_direction(v) -> str:
    return v if v in ("outbound", "inbound", "bidirectional") else "outbound"

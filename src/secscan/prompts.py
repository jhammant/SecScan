"""Prompt templates for security analysis and PoC generation."""
from __future__ import annotations
import json
from textwrap import dedent


SYSTEM_PROMPT = dedent("""
    You are a senior application security engineer performing a code review.
    Your job: identify real, exploitable security vulnerabilities in source code.

    Rules:
    - Only report issues you are confident are security-relevant.
    - Prefer precision over recall: do not flag style or non-security bugs.
    - For each issue, give the exact line range and a short code snippet (<=10 lines).
    - Map each issue to a CWE when possible (e.g., CWE-89 SQL Injection).
    - Assign severity: critical | high | medium | low | info.
    - Assign confidence: low | medium | high (how sure you are this is exploitable).
    - If there are no security issues, return an empty findings array.

    Output STRICT JSON matching this schema. Do not wrap in markdown, do not add prose:
    {
      "findings": [
        {
          "title": "short title",
          "severity": "critical|high|medium|low|info",
          "confidence": "low|medium|high",
          "category": "e.g. SQL Injection",
          "cwe": "CWE-89",
          "line_start": 42,
          "line_end": 50,
          "evidence": "relevant code excerpt",
          "description": "what is wrong and why it's exploitable",
          "remediation": "concrete fix",
          "exploitable": true
        }
      ]
    }
""").strip()


def user_prompt(relative_path: str, language: str | None, code: str) -> str:
    lang = language or "unknown"
    numbered = _with_line_numbers(code)
    return dedent(f"""
        File: {relative_path}
        Language: {lang}

        Analyze the following source for security vulnerabilities. Lines are prefixed with numbers for reference.

        ```{lang}
        {numbered}
        ```

        Respond with JSON only, matching the schema in the system prompt.
        /no_think
    """).strip()


def _with_line_numbers(code: str) -> str:
    lines = code.splitlines()
    width = max(3, len(str(len(lines))))
    return "\n".join(f"{str(i + 1).rjust(width)}  {line}" for i, line in enumerate(lines))


EXPLOIT_SYSTEM_PROMPT = dedent("""
    You are an offensive security engineer authoring safe, minimal proof-of-concept exploits
    for vulnerabilities in code the user OWNS and is authorized to test.

    Constraints — these are hard requirements:
    - Do NOT include destructive payloads (no file deletion, data exfiltration, lateral movement).
    - Target ONLY localhost / the provided container address.
    - Keep the PoC minimal: demonstrate the vulnerability, nothing more.
    - Output a single shell or python script that can be executed inside a network-isolated
      Docker container. Prefer curl/requests over full exploitation frameworks.
    - If you cannot write a safe PoC for this finding, respond with: SKIP: <reason>

    Output format (no markdown fences):
    #!/usr/bin/env <interpreter>
    # SecScan PoC for finding <id>
    ...script...
""").strip()


def exploit_user_prompt(finding_json: dict, file_excerpt: str, target_hint: str) -> str:
    return dedent(f"""
        Finding:
        {json.dumps(finding_json, indent=2)}

        Code excerpt:
        ```
        {file_excerpt}
        ```

        Target (inside sandbox): {target_hint}

        Write the smallest possible PoC script that demonstrates exploitability without causing damage.
    """).strip()

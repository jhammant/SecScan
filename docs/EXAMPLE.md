# Worked example — scanning a single repo end-to-end

This walks through what happens when you run `secscan scan <owner>/<repo>`, using a fictional Python/Flask service as the target. No EU-wallet references — a generic example anyone can reproduce.

## Setup

```bash
# 1. Dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 2. LM Studio
lms server start
lms load bartowski/Meta-Llama-3.1-8B-Instruct-GGUF   # or any model you prefer

# 3. Quick health check
secscan doctor
# ✓ LMStudio reachable at http://localhost:1234
# ✓ 1 model(s) known; 1 loaded
#     ● bartowski/Meta-Llama-3.1-8B-Instruct-GGUF
# ! No GitHub token set — anonymous rate limit 48 / 60
```

## Scan

```bash
secscan scan some-user/flask-demo-app
```

Because no `--model` was given, you'll be prompted to pick one:

```text
                Available models
  #   loaded   identifier
  1   ●        bartowski/Meta-Llama-3.1-8B-Instruct-GGUF
Select model [1]: 1
```

From there, the pipeline runs and emits progress:

```text
[14:02:11] start some-user/flask-demo-app lenses=security,quality files=27 (skipped 82)
[14:02:11]   [1/27] app/__init__.py
[14:02:46]   [2/27] app/auth.py
[14:02:47]       → 2 finding(s)  (total: 2)
...
[14:10:23] end   some-user/flask-demo-app findings=7
[14:10:23]   ▸ secrets…
[14:10:23]     ✓ secrets (1 findings)
[14:10:23]   ▸ deps…
[14:10:25]     ✓ deps (3 pkgs)
[14:10:25]   ▸ architecture…
[14:12:51]     ✓ arch
[14:12:51]   ▸ synthesis…
[14:14:02]     ✓ synth

SecScan: some-user/flask-demo-app
  critical: 0
  high: 3
  medium: 8
  low: 2

Top findings
  HIGH  security   app/routes/api.py:42  Unbounded SQL query built with string concatenation
  HIGH  secrets    .env.example:12       GitHub PAT detected
  HIGH  synthesis  app/routes/admin.py:1 Admin routes registered outside auth middleware
  ...

✓ Report:  .secscan/reports/some-user__flask-demo-app.md
✓ JSON:    .secscan/reports/some-user__flask-demo-app.json
```

## What's in the report

Open `.secscan/reports/some-user__flask-demo-app.md`. You'll find, in order:

1. **Executive summary** — one paragraph from the synthesis pass: what this app is, what's most concerning.
2. **Severity table** — critical/high/medium/low/info counts.
3. **Counts by source** — how many findings from each lens / deterministic pass.
4. **Grades** — A-F per lens with justification.
5. **Systemic issues** — patterns that recur across files.
6. **Hotspots** — files with the highest concentration of findings.
7. **Architecture** — extracted components, external integrations, trust boundaries, data flows, auth model, secrets handling, unknowns. Worth reading on its own.
8. **Vulnerable dependencies** — OSV.dev advisories, grouped by package.
9. **Findings** — every individual finding with file:line citation, description, evidence excerpt, remediation.
10. **Skipped files** — coverage table (what was excluded and why).

## Triage workflow

Realistic way to use the report:

1. **Start at the Architecture section.** Read it. Ask: does this match what I know the app does? If not, the LLM misunderstood something fundamental and some findings will reflect that.
2. **Read the synthesis cross-cutting findings.** These are systemic issues — the most valuable output.
3. **Check the dependency CVEs.** Deterministic, high precision. Often the easiest wins.
4. **Check the secrets hits.** Regex is 100% precise for known patterns. Rotate + purge from Git history immediately.
5. **Review the per-file findings by severity.** For each CRITICAL/HIGH: **open the cited file at the cited line** and verify with your own eyes. LLM citations are often slightly off; the concept is usually right.
6. **Ignore most INFO/LOW findings** unless you're at zero true-positives and want to dig.

## If you find a real vulnerability

If it's your own code: fix it.

If it's a third-party repo you had permission to scan:

1. Read the project's `SECURITY.md` for their disclosure process.
2. File privately with a minimal PoC and a proposed remediation.
3. Agree a timeline (usually ≤90 days).
4. Publicly disclose with credit after the fix lands.

## Optional: try a sandboxed PoC

If Docker is running and you want to prove a finding is exploitable:

```bash
secscan exploit \
  ./.secscan/clones/some-user/flask-demo-app \
  <finding-id-from-report> \
  --report ./.secscan/reports/some-user__flask-demo-app.json
```

The tool will:

1. Detect how to run the target (Dockerfile, `npm start`, `python -m app`…)
2. Ask the LLM for the smallest safe PoC
3. Show you the script
4. On your confirmation, spin up the target in an internal-only Docker network and run the PoC
5. Tear everything down, leave you with the stdout/stderr/target logs

Review the script before confirming.

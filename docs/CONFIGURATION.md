# Configuration

SecScan reads config from environment variables, or from a `.env` file in the repo root (see `.env.example`). All settings are optional — the tool asks interactively when it needs something.

## Environment variables

| Variable | Default | What it does |
|---|---|---|
| `GITHUB_TOKEN` | *(unset)* | GitHub Personal Access Token. Required for private repos; recommended for rate limits. A fine-grained token with just `repo: read` and `metadata: read` is enough. |
| `LMSTUDIO_HOST` | `localhost:1234` | Host + port where `lms server start` is listening. Change this if you run LM Studio in a VM / on another machine. |
| `SECSCAN_MODEL` | *(unset)* | Default model identifier. When set, you don't need to pass `--model`. |
| `SECSCAN_WORKDIR` | `./.secscan` | Where clones, reports, and PoC scripts are written. Always gitignored. |
| `SECSCAN_EXPLOIT_CONFIRM` | `true` | If `false`, `secscan exploit` auto-runs without the confirmation prompt. **Leave this `true` unless you know what you're doing.** |
| `SECSCAN_RISK_FIRST` | *(unset)* | Set to `1` to enable risk-first file filtering — only scan files whose path or content looks security-relevant. Cuts per-file scan work 4-8× on typical backends. |

## `.env` file

Copy the example and fill in what you need:

```bash
cp .env.example .env
```

The format is plain `KEY=value`. The file is gitignored.

## CLI flags that override env

- `--model / -m` overrides `SECSCAN_MODEL` per-run
- `--no-files` / `--no-secrets` / `--no-deps` / `--no-arch` / `--no-synth` disable specific scan phases for that run only
- `--lens security,quality,...` or `--lens all` picks which lenses to run

See `secscan scan --help` (or any subcommand) for the full flag set.

## Lens selection

| Lens | When to use |
|---|---|
| `security` (default) | Always |
| `quality` (default) | Always — finds maintainability bugs, resource leaks, error-handling gaps |
| `performance` | Codebases with obvious hot paths (APIs under load, data pipelines) |
| `reliability` | Services with SLO requirements or extensive external dependencies |
| `correctness` | High-stakes logic (billing, auth, crypto) |
| `cicd` | Any repo with `.github/workflows/`, `Dockerfile`, or Terraform files — auto-scoped to those files |
| `all` | Full scan — expensive on a local LLM. Use for priority repos. |

## Picking an LM Studio model

The scanner has been tested with:

- `qwen/qwen3.6-27b@q8_k_xl` — slow on Apple Silicon (~60-90s/call for reasoning), thorough. Recommended for triage mode (`--no-files`).
- Smaller models (7B-14B class) — much faster; quality drops for cross-cutting synthesis but fine for per-file lenses.

Rules of thumb:

- **Reasoning models** (qwen3, DeepSeek-R1, etc.) burn tokens on `<think>`. Default `max_tokens` is 8192 to compensate.
- For per-file scanning on a slow model, turn on `SECSCAN_RISK_FIRST=1` to cut file count.
- For a huge org, use `--no-files` to get architecture + threat model + deps + secrets in ~15 min/repo.

## Checking your setup

Run `secscan doctor` — it probes the LM Studio server, lists loaded models, checks the GitHub token, and reports whether Docker (needed only for `secscan exploit`) is available.

## What SecScan will never do

- Upload your source code anywhere
- Phone home with telemetry
- Install browser extensions, shell hooks, or background daemons
- Bypass the exploit confirmation prompt unless you explicitly set `SECSCAN_EXPLOIT_CONFIRM=false` AND pass `--yes`

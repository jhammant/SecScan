# SecScan architecture

How it's put together, why, and what to look at when you want to change something.

## Top-down view

```text
  cli.py ─────────┐
                  │
          scanner.py ◀── orchestrator
                  │
 ┌────────────────┼─────────────────────────────────────────────────┐
 │                │                                                 │
 │   LLM passes (local, via LMStudio)                               │
 │   ──────────────────────────────                                 │
 │     lenses.py         ──► per-file review (one call per lens)    │
 │     architecture.py   ──► repo-level architecture extraction     │
 │     synthesis.py      ──► cross-cutting threat modeling          │
 │     verify.py         ──► adjudicator for any claimed finding    │
 │                                                                  │
 │   Deterministic passes                                           │
 │   ─────────────────────                                          │
 │     secrets_scan.py   ──► regex rules (gitleaks-style)           │
 │     deps.py           ──► manifest parse + OSV.dev batch lookup  │
 │                                                                  │
 │   Supporting                                                     │
 │   ──────────                                                     │
 │     filters.py        ──► include/skip rules + risk-first mode   │
 │     github.py         ──► list + shallow-clone public/private    │
 │     repo_context.py   ──► compact summary for whole-repo passes  │
 │     models.py         ──► Pydantic types, shared schema          │
 │     prompts.py        ──► shared prompt fragments                │
 │     lmstudio_client.py──► OpenAI-compat REST + lms CLI wrapper   │
 │                                                                  │
 │   Outputs                                                        │
 │   ───────                                                        │
 │     report.py         ──► Markdown + JSON                        │
 │     progress.py       ──► Rich Live (TTY) / plain log (non-TTY)  │
 │     tui.py            ──► Textual app to browse reports          │
 │                                                                  │
 │   Optional, opt-in                                               │
 │   ────────────────                                               │
 │     exploit/sandbox.py──► Docker --internal network runner       │
 │     exploit/poc.py    ──► LLM-authored PoC + sandboxed run       │
 └──────────────────────────────────────────────────────────────────┘
```

## The scan orchestration

`scanner.py::scan_local_repo` runs these phases in order:

1. **Walk + classify** (`filters.py::walk` + `classify`). Every file in the clone gets an `include` / `skip` decision. Skip reasons are preserved in the report for coverage tracking.
2. **Per-file lens pass** (skippable with `--no-files`). For every included file and every active lens, one LLM call produces JSON findings. Findings are tagged with the lens name in `Finding.source`.
3. **Secrets scan** (`secrets_scan.py::scan_secrets`). Deterministic regex over every includable file (plus `.env`-style files). Path-aware FP filters.
4. **Dependency scan** (`deps.py::scan_dependencies`). Parses manifests (`package.json`, `requirements.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `Gemfile`). Chunks + batch-queries OSV.dev for advisories. Emits one `Finding` per advisory, `Finding.source = "dependency"`.
5. **Architecture extraction** (`architecture.py::extract_architecture`). One LLM call with a compact repo summary built by `repo_context.py`. Produces `Architecture` (components, integrations, trust boundaries, data flows, auth model, secrets handling, unknowns).
6. **Threat-model synthesis** (`synthesis.py::synthesize`). One LLM call with the architecture + a compact view of per-file findings + any dep advisories. Produces systemic issues, hotspots, per-lens grades, and a list of **cross-cutting findings** — issues the per-file pass cannot see.
7. **Report** (`report.py::write_markdown`). Writes `<repo>.md` + `<repo>.json`.

Each phase emits progress events; `progress.py` renders them.

## Finding provenance

Every `Finding` carries a `source` field so you can always trace it back:

| `source` | Producer |
|---|---|
| `security`, `quality`, `performance`, `reliability`, `correctness`, `cicd` | per-file LLM lens |
| `secrets` | regex rule in `secrets_scan.py` |
| `dependency` | OSV.dev advisory translated by `scanner.py` |
| `synthesis` | architecture-aware threat model |

This matters for triage: `source=dependency` findings are near-100% precise; `source=synthesis` findings are interesting but less reliable and should be source-verified before action.

## LMStudio interaction

`lmstudio_client.py` wraps the LM Studio OpenAI-compatible REST endpoint. Two notable design points:

1. **`response_format` probing.** LM Studio's support for `response_format` varies per model. The client tries `{"type":"json_object"}`, falls back to `{"type":"text"}`, and finally to no format hint. The first mode that works is cached for the session.
2. **Defensive JSON recovery.** `_extract_json` handles plain JSON, fenced markdown, and noisy wrapper text — because local reasoning models sometimes leak `<think>` tags or leading whitespace into the content field.

Inference defaults: `temperature=0.1`, `max_tokens=8192` for structured calls (reasoning models burn most of the budget on `<think>`), `temperature=0.2` and `max_tokens=2048` for free-form text.

## Exploit sandbox

`secscan exploit` is **fully opt-in**. It needs a running Docker daemon.

The sandbox uses three hard-coded safety layers:

1. **Network isolation.** A fresh `docker network create --internal` means no outbound internet for the target or the prober. They can talk to each other via a DNS alias, nothing else.
2. **Container hardening.** `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--cpus`/`--memory`/`--pids-limit` caps.
3. **Human gate.** The LLM-generated PoC is shown to the user in Rich-highlighted form and a `Confirm.ask` prompt gates execution unless `--yes` is explicitly passed.

The PoC prompt (`prompts.py::EXPLOIT_SYSTEM_PROMPT`) instructs the model to produce the **smallest possible, non-destructive** script — and to reply `SKIP: <reason>` if it can't write a safe one.

## Performance notes

- **Per-file scanning is the slow path.** On a 27B local model on Apple Silicon we measured ~60-90s per call. For a 100-file repo with two lenses that's ~3 hours per repo.
- **Triage mode (`--no-files`)** is ~15 min per repo — architecture + synthesis passes only. Use this for large orgs or slow models.
- **Risk-first mode (`SECSCAN_RISK_FIRST=1`)** narrows the per-file file set to route/auth/crypto-heavy files by path pattern + content grep. Roughly 4-8× fewer files on typical backends. Trade-off: may miss issues in "plumbing" files.

## Where state lives

- **`.secscan/clones/<owner>/<name>/`** — shallow git clone. Reused on re-scan.
- **`.secscan/reports/<owner>__<name>.{md,json}`** — per-repo outputs.
- **`.secscan/exploits/<finding-id>.{py,sh}`** — LLM-generated PoC scripts (saved whether or not you ran them).

All of these are gitignored. **Never commit `.secscan/`.**

## Extending — typical change patterns

- **New lens:** add a `Lens(...)` instance in `lenses.py`, register in `REGISTRY`. No other files need changing.
- **New secret rule:** add a `SecretRule(...)` in `secrets_scan.py::_RULES`. Consider if you need an entropy filter.
- **New dep ecosystem:** add a `_parse_X(root)` function in `deps.py` and register it in `_parsers`. Use OSV batch — the existing code will enrich for free.
- **New non-LLM pass:** add the module, wire it in `scanner.py::scan_local_repo` between phases 4 and 5, and add a corresponding `--no-X` flag.
- **New sandbox preset:** add a branch to `exploit/poc.py::detect_spec` returning a tailored `SandboxSpec`.

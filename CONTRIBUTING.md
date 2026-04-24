# Contributing to SecScan

Thanks for considering a contribution. SecScan is an opinionated scaffold — small, deliberate, and extendable. Patches that add value without bloat are the most welcome.

## Quick start

```bash
git clone https://github.com/YOUR_USERNAME/SecScan
cd SecScan
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

If `pytest -q` is green, your environment is wired.

## Good first contributions

- **New lenses** (`src/secscan/lenses.py`) — a lens is a `name`, `description`, a system prompt, and a file-matcher function. Mobile security, binary/firmware, cloud-misconfig, LLM supply-chain, IaC per-provider — all would benefit.
- **New dependency ecosystems** (`src/secscan/deps.py`) — add Maven, NuGet, Hex, Pub, Composer. Each is ~15 lines of parser + reuses the OSV batch client.
- **Better false-positive filters** for the secrets regex (`src/secscan/secrets_scan.py`) — the current filter misses type/enum constants; improvements here directly reduce noise.
- **`SandboxSpec` presets** (`src/secscan/exploit/poc.py`) — detection for common frameworks (Django, Rails, FastAPI, NestJS, Spring Boot) would cut setup for users running `secscan exploit`.
- **TUI improvements** (`src/secscan/tui.py`) — search, filtering by severity, in-place verification.

## Principles

1. **Don't phone home.** No telemetry. No uploads. Not even "anonymous usage stats." This is the whole premise.
2. **Every LLM output is unreliable.** Design new features assuming the model hallucinates. Show deterministic passes (regex, OSV, AST) where possible. Always cite file+line.
3. **One opinion per module.** If you're tempted to add a second way to do the same thing, step back — SecScan values a small, comprehensible surface area.
4. **No dead code.** Remove a flag before adding a deprecation path. Tests go next to features, not in a separate PR.
5. **No destructive default.** The exploit sandbox is opt-in and asks before running. Keep it that way.

## Code style

- Python 3.11+. Type hints required on public functions. `from __future__ import annotations` at the top of new modules.
- Line length 100. Ruff is configured in `pyproject.toml`.
- Pydantic v2 for data models. Typer for CLI. Rich for terminal UI. Textual for the TUI. Don't pull new top-level deps without discussing first.
- Tests with `pytest`. Deterministic only — don't write a test that hits a real LLM or the network.

## Commit / PR etiquette

- One logical change per PR.
- Commit subject ≤ 72 chars, imperative (`add OSV batching`, not `added OSV batching`).
- If the change affects output (report shape, finding fields), update the README + the relevant docs in `docs/`.
- New public flag? Update `README.md` and add a test that verifies the flag plumbs through.

## Security disclosures

Found a vulnerability in **SecScan itself** (not in a scanned repo)? Email the maintainer — don't open a public issue. A working PoC is welcome but not required.

Found a vulnerability in **a repo you scanned**? That's for the scanned project's `SECURITY.md` / security contact, not ours. SecScan is a tool; the findings belong to the projects you point it at. Follow responsible disclosure — typical practice is private report + 90-day window + coordinated public disclosure.

## License

By contributing you agree your work is released under the MIT license (see `LICENSE`).

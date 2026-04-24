"""Typer CLI entry point."""
from __future__ import annotations
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.syntax import Syntax
from rich.table import Table

from .config import settings
from .github import GitHubClient
from .lenses import REGISTRY, resolve
from .lmstudio_client import LMStudioClient, LMStudioError, ModelInfo
from .models import RepoScanResult
from .progress import ScanProgress
from .report import print_summary, write_markdown
from .scanner import Scanner, ScanOptions


app = typer.Typer(help="SecScan — local-LLM-powered security scanner.", no_args_is_help=True)
console = Console()


# ---------------- shared helpers ----------------

def _ensure_lmstudio_server() -> bool:
    """Return True if the server is up (starting it if the lms CLI is available)."""
    probe = LMStudioClient(host=settings.lmstudio_host)
    if probe.health():
        probe.close()
        return True
    probe.close()
    if shutil.which("lms"):
        console.print("[dim]LMStudio server not running — starting via `lms server start`…[/dim]")
        try:
            subprocess.run(["lms", "server", "start"], check=True, capture_output=True, timeout=30)
        except Exception as e:
            console.print(f"[red]Failed to start LMStudio: {e}[/red]")
            return False
        probe = LMStudioClient(host=settings.lmstudio_host)
        up = probe.health()
        probe.close()
        return up
    return False


def _pick_model_interactively(available: list[ModelInfo]) -> str | None:
    if not available:
        return None
    table = Table(title="Available models")
    table.add_column("#", justify="right")
    table.add_column("loaded")
    table.add_column("identifier")
    for i, m in enumerate(available, 1):
        table.add_row(str(i), "●" if m.loaded else "○", m.identifier)
    console.print(table)
    loaded_default = next((str(i) for i, m in enumerate(available, 1) if m.loaded), "1")
    choice = Prompt.ask("Select model", default=loaded_default)
    try:
        return available[int(choice) - 1].identifier
    except (ValueError, IndexError):
        console.print("[red]Invalid selection.[/red]")
        return None


def _client(model: str | None, *, interactive: bool = True) -> LMStudioClient:
    if not _ensure_lmstudio_server():
        console.print(
            f"[red]LMStudio not reachable at http://{settings.lmstudio_host}[/red]\n"
            f"Install the lms CLI (from the LM Studio app) and run [bold]lms server start[/bold]."
        )
        raise typer.Exit(code=2)

    chosen = model or settings.secscan_model
    if not chosen and interactive:
        probe = LMStudioClient(host=settings.lmstudio_host)
        try:
            models = probe.list_models()
        finally:
            probe.close()
        chosen = _pick_model_interactively(models)
        if not chosen:
            console.print("[red]No model selected.[/red]")
            raise typer.Exit(code=2)

    client = LMStudioClient(host=settings.lmstudio_host, model=chosen)
    return client


def _github() -> GitHubClient:
    return GitHubClient(token=settings.github_token)


def _make_options(
    lenses: str,
    no_secrets: bool,
    no_deps: bool,
    no_arch: bool,
    no_synth: bool,
    no_files: bool = False,
) -> ScanOptions:
    try:
        selected = resolve([s.strip() for s in lenses.split(",") if s.strip()])
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(code=2)
    return ScanOptions(
        lenses=selected,
        enable_per_file=not no_files,
        enable_secrets=not no_secrets,
        enable_deps=not no_deps,
        enable_architecture=not no_arch,
        enable_synthesis=not no_synth,
    )


# ---------------- commands ----------------

@app.command()
def doctor() -> None:
    """Diagnose your SecScan setup: LMStudio, models, GitHub token, Docker."""
    ok = True

    # LMStudio
    if _ensure_lmstudio_server():
        console.print(f"[green]✓[/green] LMStudio reachable at http://{settings.lmstudio_host}")
    else:
        console.print(f"[red]✗[/red] LMStudio not reachable at http://{settings.lmstudio_host}")
        ok = False

    # Models
    try:
        with LMStudioClient(host=settings.lmstudio_host) as c:
            models = c.list_models() if c.health() else []
        loaded = [m for m in models if m.loaded]
        if models:
            console.print(
                f"[green]✓[/green] {len(models)} model(s) known; "
                f"{len(loaded)} loaded"
            )
            for m in loaded[:5]:
                console.print(f"    ● {m.identifier}")
        else:
            console.print("[yellow]![/yellow] No models. Load one with [bold]lms load <id>[/bold].")
    except Exception as e:
        console.print(f"[red]✗[/red] Could not list models: {e}")
        ok = False

    # GitHub token
    try:
        headers = {"User-Agent": "secscan-doctor"}
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"
        r = httpx.get("https://api.github.com/rate_limit", headers=headers, timeout=10.0)
        r.raise_for_status()
        data = r.json().get("rate", {})
        if settings.github_token:
            console.print(
                f"[green]✓[/green] GitHub token OK — "
                f"{data.get('remaining')} / {data.get('limit')} requests left"
            )
        else:
            console.print(
                f"[yellow]![/yellow] No GitHub token set — anonymous rate limit "
                f"{data.get('remaining')} / {data.get('limit')} (set GITHUB_TOKEN for private repos + headroom)"
            )
    except Exception as e:
        console.print(f"[red]✗[/red] GitHub reachability: {e}")
        ok = False

    # Docker (optional — only needed for exploit command)
    from .exploit.sandbox import docker_available
    if docker_available():
        console.print("[green]✓[/green] Docker available (exploit sandbox ready)")
    else:
        console.print("[yellow]![/yellow] Docker not available — `secscan exploit` will be disabled")

    # Lenses
    console.print(
        "[dim]Available lenses:[/dim] " + ", ".join(REGISTRY.keys())
    )
    sys.exit(0 if ok else 1)


@app.command()
def models(model: Optional[str] = typer.Option(None, "--model", "-m")) -> None:
    """List available LMStudio models."""
    if not _ensure_lmstudio_server():
        console.print(f"[red]LMStudio not reachable at http://{settings.lmstudio_host}[/red]")
        raise typer.Exit(code=2)
    with LMStudioClient(host=settings.lmstudio_host, model=model) as client:
        models = client.list_models()
    if not models:
        console.print("[yellow]No models found. Load one with `lms load <id>`.[/yellow]")
        return
    for m in models:
        mark = "[green]●[/green]" if m.loaded else "[dim]○[/dim]"
        console.print(f"  {mark} {m.identifier}")


_LENS_HELP = (
    "Comma-separated lenses to run (or 'all'). "
    f"Available: {', '.join(REGISTRY.keys())}"
)


@app.command()
def scan(
    repo: str = typer.Argument(..., help="owner/name or GitHub URL"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="LMStudio model id"),
    load: bool = typer.Option(False, "--load", help="Preload the model via `lms load`"),
    open_report: bool = typer.Option(False, "--open", help="Open the markdown report on completion"),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Also write a JSON artifact to this path"),
    lenses: str = typer.Option("security,quality", "--lens", help=_LENS_HELP),
    no_secrets: bool = typer.Option(False, "--no-secrets"),
    no_deps: bool = typer.Option(False, "--no-deps"),
    no_arch: bool = typer.Option(False, "--no-arch", help="Skip architecture extraction"),
    no_synth: bool = typer.Option(False, "--no-synth", help="Skip cross-cutting synthesis"),
    no_files: bool = typer.Option(False, "--no-files", help="Skip per-file LLM scan (fast triage only)"),
) -> None:
    """Scan a single GitHub repo."""
    settings.ensure_dirs()
    opts = _make_options(lenses, no_secrets, no_deps, no_arch, no_synth, no_files)
    client = _client(model)
    if load and model:
        client.load_model(model)
    with ScanProgress(console) as progress:
        try:
            with _github() as gh:
                scanner = Scanner(lmstudio=client, github=gh, progress=progress.as_callback(), options=opts)
                result = scanner.scan_repo_url(repo)
        except LMStudioError as e:
            console.print(f"[red]LMStudio error:[/red] {e}")
            raise typer.Exit(code=3)
    _finalize(result, open_report=open_report, json_out=json_out)


@app.command(name="scan-user")
def scan_user(
    user: str = typer.Argument(..., help="GitHub username or org"),
    model: Optional[str] = typer.Option(None, "--model", "-m"),
    forks: bool = typer.Option(False, "--forks/--no-forks"),
    limit: int = typer.Option(0, "--limit"),
    lenses: str = typer.Option("security,quality", "--lens", help=_LENS_HELP),
    no_secrets: bool = typer.Option(False, "--no-secrets"),
    no_deps: bool = typer.Option(False, "--no-deps"),
    no_arch: bool = typer.Option(False, "--no-arch"),
    no_synth: bool = typer.Option(False, "--no-synth"),
) -> None:
    """Scan every repo owned by a user/org."""
    settings.ensure_dirs()
    opts = _make_options(lenses, no_secrets, no_deps, no_arch, no_synth)
    client = _client(model)
    with _github() as gh:
        repos = gh.list_user_repos(user, include_forks=forks)
        if limit > 0:
            repos = repos[:limit]
        console.print(f"[bold]{len(repos)} repos queued for {user}[/bold]")
        for r in repos:
            try:
                path = gh.clone(r, settings.clones_dir)
                with ScanProgress(console) as progress:
                    scanner = Scanner(
                        lmstudio=client, github=gh,
                        progress=progress.as_callback(), options=opts,
                    )
                    result = scanner.scan_local_repo(path, repo_label=r.full_name)
                _finalize(result, open_report=False)
            except Exception as e:
                console.print(f"[red]✗ {r.full_name}: {e}[/red]")


@app.command(name="scan-local")
def scan_local(
    path: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    model: Optional[str] = typer.Option(None, "--model", "-m"),
    lenses: str = typer.Option("security,quality", "--lens", help=_LENS_HELP),
    no_secrets: bool = typer.Option(False, "--no-secrets"),
    no_deps: bool = typer.Option(False, "--no-deps"),
    no_arch: bool = typer.Option(False, "--no-arch"),
    no_synth: bool = typer.Option(False, "--no-synth"),
) -> None:
    """Scan a local directory (skip GitHub clone)."""
    settings.ensure_dirs()
    opts = _make_options(lenses, no_secrets, no_deps, no_arch, no_synth)
    client = _client(model)
    with ScanProgress(console) as progress:
        scanner = Scanner(lmstudio=client, progress=progress.as_callback(), options=opts)
        result = scanner.scan_local_repo(path.resolve())
    _finalize(result, open_report=False)


@app.command()
def exploit(
    repo: Path = typer.Argument(..., help="Path to the cloned repo"),
    finding_id: str = typer.Argument(..., help="Finding id from the scan report"),
    report: Path = typer.Option(..., "--report", exists=True, help="Path to scan JSON"),
    model: Optional[str] = typer.Option(None, "--model", "-m"),
    yes: bool = typer.Option(False, "--yes", help="Skip confirmation (dangerous)"),
) -> None:
    """Attempt a sandboxed PoC for a specific finding."""
    from .exploit.poc import try_exploit
    from .exploit.sandbox import docker_available

    if not docker_available():
        console.print("[red]Docker is not available. The exploit sandbox needs a running Docker daemon.[/red]")
        raise typer.Exit(code=4)

    data = json.loads(report.read_text())
    findings: list[dict] = []
    for fr in data.get("files", []) or []:
        findings.extend(fr.get("findings") or [])
    synth = (data.get("synthesis") or {}).get("cross_cutting_findings") or []
    findings.extend(synth)
    match = next((f for f in findings if f.get("id") == finding_id), None)
    if not match:
        console.print(f"[red]No finding with id {finding_id} in {report}[/red]")
        raise typer.Exit(code=5)

    from .models import Finding
    finding = Finding(**match)
    client = _client(model)

    def confirm(script: str, interpreter: str) -> bool:
        console.rule(f"PoC script ({interpreter})")
        console.print(Syntax(script, interpreter if interpreter == "python" else "bash"))
        if yes or not settings.secscan_exploit_confirm:
            return True
        return Confirm.ask("Run this inside the sandbox?", default=False)

    result = try_exploit(
        client=client, finding=finding, repo_path=repo.resolve(),
        confirm_cb=confirm, save_dir=settings.exploits_dir,
    )
    if result is None:
        console.print("[yellow]No result.[/yellow]")
        raise typer.Exit(code=6)
    console.rule("PoC outcome")
    console.print(f"executed: {result.executed}  success: {result.success}")
    console.print(result.evidence or "(no evidence)")


@app.command()
def tui() -> None:
    """Launch the interactive TUI."""
    from .tui import SecScanApp
    SecScanApp().run()


# ---------------- helpers ----------------

def _finalize(result: RepoScanResult, *, open_report: bool, json_out: Path | None = None) -> None:
    md = write_markdown(result, settings.reports_dir)
    json_path = json_out or (settings.reports_dir / (result.repo.replace("/", "__") + ".json"))
    json_path.write_text(result.model_dump_json(indent=2))
    print_summary(console, result)
    console.print(f"[green]✓[/green] Report:  {md}")
    console.print(f"[green]✓[/green] JSON:    {json_path}")
    if open_report:
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        subprocess.run([opener, str(md)], check=False)


if __name__ == "__main__":
    app()

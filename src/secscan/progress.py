"""Rich-based progress display for scans.

Translates the scanner's event stream into a live progress UI:
- Outer bar: files (X/Y) for the per-file lens pass
- Text lines: current file, findings so far, phase spinners for
  secrets/deps/architecture/synthesis.
"""
from __future__ import annotations
from typing import Callable

from rich.console import Console, Group
from rich.live import Live
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table


class ScanProgress:
    """Context manager wrapping a Rich `Live`. Feed it events via `as_callback`."""

    def __init__(self, console: Console):
        self.console = console
        # Non-TTY: don't use Live (it buffers/suppresses output when redirected).
        # Fall back to plain one-line-per-event logging.
        self._plain = not console.is_terminal
        self._files = Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TextColumn("{task.fields[status]}"),
            console=console,
        )
        self._phases = Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            TextColumn("{task.fields[status]}"),
            console=console,
        )
        self._file_task: int | None = None
        self._phase_tasks: dict[str, int] = {}
        self._findings_total = 0
        self._repo_label = ""
        self._total_files = 0
        self._done_files = 0
        self._live = (
            None if self._plain
            else Live(Group(self._files, self._phases),
                      console=console, refresh_per_second=8, transient=False)
        )

    def __enter__(self) -> "ScanProgress":
        if self._live is not None:
            self._live.__enter__()
        return self

    def __exit__(self, *a) -> None:
        if self._live is not None:
            for tid in self._phase_tasks.values():
                self._phases.update(tid, status="✓")
            self._live.__exit__(*a)

    def as_callback(self) -> Callable[[str, dict], None]:
        def cb(evt: str, data: dict) -> None:
            self.handle(evt, data)
        return cb

    def handle(self, evt: str, data: dict) -> None:
        if self._plain:
            self._handle_plain(evt, data)
            return
        if evt == "scan_start":
            self._repo_label = data.get("repo", "")
            lenses = ",".join(data.get("lenses", []))
            self._findings_total = 0
            self._file_task = self._files.add_task(
                description=f"{self._repo_label} [{lenses}]",
                total=data.get("included", 0),
                status="",
            )
        elif evt == "file_start" and self._file_task is not None:
            self._files.update(
                self._file_task,
                status=f"[dim]{data.get('file','')}[/dim]",
            )
        elif evt == "file_done" and self._file_task is not None:
            self._findings_total += int(data.get("findings", 0))
            self._files.update(
                self._file_task, advance=1,
                status=f"findings: [yellow]{self._findings_total}[/yellow]",
            )
        elif evt == "scan_end" and self._file_task is not None:
            self._files.update(
                self._file_task,
                status=f"[green]done[/green]  findings: [yellow]{data.get('findings',0)}[/yellow]",
            )

        # Phase spinners
        elif evt in ("secrets_start", "deps_start", "arch_start", "synth_start"):
            label = {
                "secrets_start": "scanning for secrets",
                "deps_start": "checking dependencies",
                "arch_start": "extracting architecture",
                "synth_start": "synthesizing + threat modeling",
            }[evt]
            tid = self._phases.add_task(description=label, total=None, status="…")
            self._phase_tasks[evt.replace("_start", "")] = tid
        elif evt in ("secrets_done", "deps_done", "arch_done", "synth_done"):
            key = evt.replace("_done", "")
            tid = self._phase_tasks.get(key)
            if tid is not None:
                detail = ""
                if key == "secrets":
                    detail = f"{data.get('findings',0)} finding(s)"
                elif key == "deps":
                    detail = f"{data.get('packages',0)} pkg(s)"
                self._phases.update(tid, status=f"[green]✓[/green] {detail}".strip())
        elif evt in ("secrets_error", "deps_error", "arch_error", "synth_error"):
            key = evt.replace("_error", "")
            tid = self._phase_tasks.get(key)
            if tid is not None:
                self._phases.update(tid, status=f"[red]✗ {data.get('err','')[:60]}[/red]")
        elif evt == "user_repos_listed":
            self.console.print(f"Found [bold]{data.get('count',0)}[/bold] repos for {data.get('user','')}")

    def _handle_plain(self, evt: str, data: dict) -> None:
        """Plain-text progress for non-TTY (log files, redirected output)."""
        import sys, time
        t = time.strftime("%H:%M:%S")
        if evt == "scan_start":
            self._repo_label = data.get("repo", "")
            lenses = ",".join(data.get("lenses", []))
            self._total_files = int(data.get("included", 0))
            self._done_files = 0
            self._findings_total = 0
            print(f"[{t}] start {self._repo_label} lenses={lenses} files={self._total_files} (skipped {data.get('skipped',0)})", flush=True)
        elif evt == "file_start":
            print(f"[{t}]   [{self._done_files+1}/{self._total_files}] {data.get('file','')}", flush=True)
        elif evt == "file_done":
            self._done_files += 1
            n = int(data.get("findings", 0))
            self._findings_total += n
            if n:
                print(f"[{t}]       → {n} finding(s)  (total: {self._findings_total})", flush=True)
        elif evt == "scan_end":
            print(f"[{t}] end   {self._repo_label} findings={data.get('findings',0)}", flush=True)
        elif evt in ("secrets_start", "deps_start", "arch_start", "synth_start"):
            label = {
                "secrets_start": "secrets",
                "deps_start": "deps",
                "arch_start": "architecture",
                "synth_start": "synthesis",
            }[evt]
            print(f"[{t}]   ▸ {label}…", flush=True)
        elif evt in ("secrets_done", "deps_done", "arch_done", "synth_done"):
            key = evt.replace("_done", "")
            detail = ""
            if key == "secrets":
                detail = f" ({data.get('findings',0)} findings)"
            elif key == "deps":
                detail = f" ({data.get('packages',0)} pkgs)"
            print(f"[{t}]     ✓ {key}{detail}", flush=True)
        elif evt in ("secrets_error", "deps_error", "arch_error", "synth_error"):
            print(f"[{t}]     ✗ {evt}: {data.get('err','')[:120]}", flush=True)
        elif evt == "user_repos_listed":
            print(f"[{t}] {data.get('count',0)} repos for {data.get('user','')}", flush=True)

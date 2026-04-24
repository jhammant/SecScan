"""Textual TUI for browsing scan results and driving scans interactively."""
from __future__ import annotations
import json
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Footer, Header, Input, Select, Static, Tree

from .config import settings
from .lmstudio_client import LMStudioClient
from .models import RepoScanResult


class SecScanApp(App):
    """Two-pane TUI:
      left: list of reports on disk
      right: findings table for the selected report
    The input bar drives new scans against owner/name or GitHub URLs.
    """

    CSS = """
    Screen { layout: vertical; }
    #top { height: 3; }
    #main { height: 1fr; }
    #left { width: 34%; border: solid $accent; }
    #right { width: 1fr; border: solid $accent; }
    #detail { height: 40%; border-top: solid $accent; padding: 1; }
    Input { width: 1fr; }
    Select { width: 40; }
    Button { margin: 0 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "reload", "Reload"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._models: list[str] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Horizontal(id="top"):
            yield Input(placeholder="owner/name or https://github.com/owner/name", id="repo_input")
            yield Select(options=[], id="model_select", prompt="model")
            yield Button("Scan", id="scan_btn", variant="primary")
            yield Button("Refresh models", id="refresh_models_btn")
        with Horizontal(id="main"):
            with Vertical(id="left"):
                yield Static("Reports", classes="title")
                yield Tree("reports", id="reports_tree")
            with Vertical(id="right"):
                yield Static("Findings", classes="title")
                yield DataTable(id="findings_table")
                yield Static("", id="detail")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings_table", DataTable)
        table.add_columns("sev", "conf", "file", "line", "title", "id")
        self._refresh_reports()
        self._refresh_models()

    # -------- actions --------

    def action_reload(self) -> None:
        self._refresh_reports()
        self._refresh_models()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "refresh_models_btn":
            self._refresh_models()
        elif event.button.id == "scan_btn":
            self._kick_off_scan()

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        data = event.node.data
        if isinstance(data, Path):
            self._load_report(data)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        table = self.query_one("#findings_table", DataTable)
        row = table.get_row(event.row_key)
        finding_id = row[-1]
        self._show_detail(finding_id)

    # -------- helpers --------

    def _refresh_reports(self) -> None:
        tree = self.query_one("#reports_tree", Tree)
        tree.clear()
        root = tree.root
        reports_dir = settings.reports_dir
        if not reports_dir.exists():
            root.add_leaf("(no reports yet)")
            return
        for path in sorted(reports_dir.glob("*.json")):
            root.add_leaf(path.name, data=path)
        root.expand()

    def _refresh_models(self) -> None:
        try:
            with LMStudioClient(host=settings.lmstudio_host) as c:
                models = c.list_models() if c.health() else []
        except Exception:
            models = []
        self._models = [m.identifier for m in models]
        select = self.query_one("#model_select", Select)
        select.set_options([(m, m) for m in self._models] or [("(no models)", "")])
        if settings.secscan_model and settings.secscan_model in self._models:
            select.value = settings.secscan_model

    def _load_report(self, path: Path) -> None:
        try:
            data = json.loads(path.read_text())
            result = RepoScanResult(**data)
        except Exception as e:
            self.query_one("#detail", Static).update(f"Failed to load: {e}")
            return
        self._current = result
        table = self.query_one("#findings_table", DataTable)
        table.clear()
        for f in sorted(result.findings, key=lambda x: (-x.severity.weight, x.file, x.line_start)):
            table.add_row(
                f.severity.value, f.confidence, f.file, str(f.line_start), f.title, f.id,
                key=f.id,
            )
        self.query_one("#detail", Static).update(
            f"{result.repo}  —  {len(result.findings)} findings  @ {result.commit or 'n/a'}"
        )

    def _show_detail(self, finding_id: str) -> None:
        result: RepoScanResult = getattr(self, "_current", None)
        if not result:
            return
        f = next((x for x in result.findings if x.id == finding_id), None)
        if not f:
            return
        txt = (
            f"[b]{f.title}[/b]  [{f.severity.value.upper()}]  ({f.category}{' '+f.cwe if f.cwe else ''})\n"
            f"{f.file}:{f.line_start}-{f.line_end}  confidence={f.confidence}\n\n"
            f"{f.description}\n\n"
            + (f"[dim]evidence[/dim]\n{f.evidence}\n\n" if f.evidence else "")
            + (f"[dim]remediation[/dim]\n{f.remediation}" if f.remediation else "")
        )
        self.query_one("#detail", Static).update(txt)

    def _kick_off_scan(self) -> None:
        repo = self.query_one("#repo_input", Input).value.strip()
        if not repo:
            return
        # TUI just shells out to the CLI so we keep orchestration in one place.
        # Threaded subprocess so the UI stays responsive; results appear on refresh.
        import subprocess, threading, sys
        model = self.query_one("#model_select", Select).value
        cmd = [sys.executable, "-m", "secscan.cli", "scan", repo]
        if model:
            cmd += ["--model", model]
        self.query_one("#detail", Static).update(f"Running: {' '.join(cmd)}")

        def run():
            subprocess.run(cmd, check=False)
            self.call_from_thread(self._refresh_reports)

        threading.Thread(target=run, daemon=True).start()

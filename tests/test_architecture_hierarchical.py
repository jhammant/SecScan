from pathlib import Path
from secscan.architecture_hierarchical import (
    discover_subsystems,
    flat_context_fits_budget,
    _mechanical_merge,
)
from secscan.models import Architecture, Component, ExternalIntegration


def test_discover_subsystems_monorepo(tmp_path: Path):
    # Mock a monorepo with packages/web and packages/api
    for sub in ("packages/web", "packages/api"):
        d = tmp_path / sub
        d.mkdir(parents=True)
        for i in range(10):
            (d / f"f{i}.py").write_text("pass\n")
    subs = discover_subsystems(tmp_path)
    names = {s.name for s in subs}
    assert "packages/web" in names
    assert "packages/api" in names


def test_discover_subsystems_skips_tests_docs(tmp_path: Path):
    # Create source dir + tests + docs
    for name, n_files in [("src", 10), ("tests", 10), ("docs", 10)]:
        d = tmp_path / name
        d.mkdir()
        for i in range(n_files):
            (d / f"f{i}.py").write_text("x")
    subs = discover_subsystems(tmp_path)
    names = {s.name for s in subs}
    assert "src" in names
    assert "tests" not in names
    assert "docs" not in names


def test_discover_subsystems_ignores_tiny_dirs(tmp_path: Path):
    # Create a 2-file dir — should be ignored (below _MIN_FILES_PER_SUBSYSTEM)
    d = tmp_path / "utils"
    d.mkdir()
    (d / "a.py").write_text("x")
    (d / "b.py").write_text("x")
    subs = discover_subsystems(tmp_path)
    # No significant subsystems → empty list
    assert not subs


def test_flat_context_fits_small_repo(tmp_path: Path):
    (tmp_path / "app.py").write_text("print('hi')\n")
    assert flat_context_fits_budget(tmp_path) is True


def test_mechanical_merge_dedups_components():
    a1 = Architecture(
        summary="API service",
        components=[Component(name="web-api", role="HTTP")],
        integrations=[ExternalIntegration(name="Postgres", kind="database")],
    )
    a2 = Architecture(
        summary="Worker",
        components=[Component(name="worker", role="background"),
                    Component(name="web-api", role="HTTP")],  # duplicate
        integrations=[ExternalIntegration(name="Redis", kind="cache")],
    )
    merged = _mechanical_merge([("api", a1), ("worker", a2)])
    names = [c.name for c in merged.components]
    assert names.count("web-api") == 1
    assert "worker" in names
    assert len(merged.integrations) == 2

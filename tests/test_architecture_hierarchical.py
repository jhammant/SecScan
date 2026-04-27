from pathlib import Path
from secscan.architecture_hierarchical import (
    discover_subsystems,
    extract_architecture_hierarchical,
    flat_context_fits_budget,
    _arch_is_empty,
    _mechanical_merge,
    _shrink_subs_payload,
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


def test_arch_is_empty_detects_empty_and_populated():
    assert _arch_is_empty(Architecture()) is True
    assert _arch_is_empty(Architecture(summary="some text")) is True  # no structure
    populated = Architecture(components=[Component(name="x", role="y")])
    assert _arch_is_empty(populated) is False


def test_shrink_subs_payload_emits_valid_json_at_every_level():
    import json
    a = Architecture(
        summary="s",
        components=[Component(name="c", role="r",
                              entry_points=["a.py"], notable_files=["b.py"])],
        integrations=[ExternalIntegration(
            name="db", kind="database", evidence_files=["x.py"], notes="hi",
        )],
    )
    sub_archs = [("api", a), ("worker", a)]
    # Generous budget → level 0
    text, level = _shrink_subs_payload(sub_archs, max_chars=10_000)
    assert level == 0
    assert json.loads(text)  # parses
    # Tight budget → falls down to skeleton; still valid JSON.
    text2, level2 = _shrink_subs_payload(sub_archs, max_chars=5)
    assert level2 == 3
    parsed = json.loads(text2)
    assert isinstance(parsed, list) and len(parsed) == 2
    # Skeleton drops the bulky fields.
    for entry in parsed:
        for c in entry["components"]:
            assert "notable_files" not in c
            assert "entry_points" not in c
        for ig in entry["integrations"]:
            assert "evidence_files" not in ig
            assert "notes" not in ig


def test_empty_llm_merge_falls_back_to_mechanical(tmp_path: Path):
    """Regression: chia-blockchain produced 25 valid subsystems but the LLM
    merge call returned an empty Architecture, which used to be returned
    as-is. After the fix we detect that and fall back to a mechanical concat
    so the per-subsystem work isn't thrown away."""
    # Repo with two non-trivial subsystems so the merge phase runs.
    for name in ("api", "worker"):
        d = tmp_path / name
        d.mkdir()
        for i in range(10):
            (d / f"f{i}.py").write_text("pass\n")

    class _StubClient:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def complete_json(self, system, user, *, model=None,
                           temperature=0.1, max_tokens=4096):
            # Distinguish merge vs subsystem prompts by the merge marker.
            if "Merge these subsystem architectures" in user:
                self.calls.append("merge")
                return {}  # the bug: parse-success but empty content
            self.calls.append("subsystem")
            tag = f"sub-{len(self.calls)}"
            return {
                "summary": f"{tag} summary",
                "components": [{"name": tag, "role": "service"}],
                "integrations": [{"name": f"{tag}-db", "kind": "database"}],
            }

    client = _StubClient()
    arch = extract_architecture_hierarchical(client, tmp_path)

    # Merge call did happen and the empty result triggered the fallback.
    assert client.calls.count("merge") == 1
    assert client.calls.count("subsystem") == 2
    # Mechanical merge preserved both subsystems' components + integrations.
    component_names = {c.name for c in arch.components}
    assert "sub-1" in component_names and "sub-2" in component_names
    integration_names = {i.name for i in arch.integrations}
    assert "sub-1-db" in integration_names and "sub-2-db" in integration_names
    # Fallback annotated unknowns so the failure mode is visible in the report.
    assert any("LLM merge returned empty" in u for u in arch.unknowns)

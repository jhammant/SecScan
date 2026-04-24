from pathlib import Path
from secscan.repo_context import RepoContext, build_context, DEFAULT_PROMPT_BUDGET_TOKENS


def test_to_prompt_text_respects_budget(tmp_path: Path):
    # Fabricate a RepoContext with way more content than any small budget
    ctx = RepoContext(
        tree=[f"src/file_{i}.py" for i in range(500)],
        entrypoints={f"main_{i}.py": "x" * 8000 for i in range(12)},
        config_snippets={f"config_{i}.yml": "y" * 8000 for i in range(6)},
        route_hints=[f"src/a.py:{i}: route" for i in range(60)],
        http_client_hints=[f"src/b.py:{i}: httpx.get" for i in range(60)],
        env_var_hints=[f"ENV_{i}" for i in range(60)],
        dep_summary={"PyPI": [f"pkg-{i}" for i in range(100)]},
    )

    full = ctx.to_prompt_text(budget_tokens=DEFAULT_PROMPT_BUDGET_TOKENS)
    # Under 12k tokens (≈ 42k chars at 3.5 chars/tok)
    assert len(full) <= int(DEFAULT_PROMPT_BUDGET_TOKENS * 3.5) + 200, \
        f"expected under budget, got {len(full)} chars"

    # A very small budget should still return *something* (doesn't error)
    tiny = ctx.to_prompt_text(budget_tokens=500)
    assert tiny  # non-empty
    # And respects the tighter budget
    assert len(tiny) <= 500 * 3.5 + 500, \
        f"tiny budget not respected, got {len(tiny)} chars"


def test_budget_preserves_tree_and_deps_first(tmp_path: Path):
    # When budget is *very* tight, bodies must drop entirely so tree + deps survive.
    ctx = RepoContext(
        tree=["src/app.py"],
        entrypoints={"main.py": "x" * 100_000},  # huge
        dep_summary={"PyPI": ["flask", "requests"]},
    )
    # 100 tokens ≈ 350 chars — must force file_budget to 0
    out = ctx.to_prompt_text(budget_tokens=100)
    assert "Repo tree" in out
    assert "flask" in out
    # Entrypoint body should be missing — any large run of x's means body leaked
    assert "x" * 100 not in out


def test_build_context_real_small_repo(tmp_path: Path):
    # Build against a toy repo on disk — sanity that nothing explodes.
    (tmp_path / "main.py").write_text("print('hi')\n")
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    ctx = build_context(tmp_path)
    text = ctx.to_prompt_text(budget_tokens=DEFAULT_PROMPT_BUDGET_TOKENS)
    assert "main.py" in text
    assert "Declared dependencies" in text
